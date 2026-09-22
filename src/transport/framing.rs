//! Length-disciplined framing for byte-stream transports.
//!
//! The WebSocket transport is message-oriented and frames through
//! tungstenite; every other stream (direct TLS, plaintext TCP, and every
//! caller-registered custom transport) is a bare byte stream and frames
//! through this module. One frame is one tag byte followed by a
//! tag-specific payload:
//!
//! - `0x00` data: one 16-byte prelude followed by its declared body. The
//!   prelude is the length prefix: the body length is validated against the
//!   frame rules *before* any body allocation, so a hostile declared length can
//!   never reserve attacker-chosen memory.
//! - `0x01` ping / `0x02` pong: keepalive control frames with no payload. A
//!   received ping is answered by the framing layer itself through the stream's
//!   shared write half, mirroring tungstenite's automatic WS-level answering; a
//!   received pong surfaces to the session's liveness clock exactly like a WS
//!   pong.
//! - `0x03` hint: `u16` big-endian payload length plus the listener's
//!   non-secret join hint. Every byte-stream listener sends exactly one hint
//!   frame as its first application frame (an empty one when it cannot admit
//!   mergers), the dialer reads it before returning from connect, and the join
//!   flow therefore observes the same `merge_hint()` availability the WebSocket
//!   upgrade headers provide.
//!
//! All bounds are fixed: data frames cannot exceed the aggregate WS
//! message ceiling, and hint payloads cannot exceed 65,535 bytes.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::connection::{FrameRules, Message, SharedWrite, encode_frame};
use crate::{
  Error, Result,
  protocol::{PRELUDE_LEN, Prelude, check_frame},
};

/// One data frame.
pub(crate) const TAG_DATA: u8 = 0x00;
/// One keepalive ping (no payload).
pub(crate) const TAG_PING: u8 = 0x01;
/// One keepalive pong answer (no payload).
pub(crate) const TAG_PONG: u8 = 0x02;
/// One listener join hint.
pub(crate) const TAG_HINT: u8 = 0x03;

/// The maximum hint payload length.
const MAX_HINT_BYTES: usize = u16::MAX as usize;

/// The hint-present flag of a hint payload.
const HINT_PRESENT: u8 = 0x01;

/// The non-secret merge hint a listener publishes inside its transport
/// channel before the handshake: the credential generation ID (a
/// handshake transcript input, never trusted on receipt) plus the
/// listener's current leaf certificate SubjectPublicKeyInfo, which the
/// joiner pins as the member-mode TLS trust anchor for reconnects.
///
/// The WebSocket transport encodes the same value as upgrade response
/// headers (`ws` module); byte-stream transports encode it as the hint
/// frame. Availability semantics are identical: a listener that cannot
/// admit mergers publishes no hint, and a merge dial fails typed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MergeHint {
  generation: [u8; 16],
  leaf_spki: Vec<u8>,
}

impl MergeHint {
  pub(crate) const fn new(generation: [u8; 16]) -> Self {
    Self {
      generation,
      leaf_spki: Vec::new(),
    }
  }

  /// Attaches the listener's current leaf certificate SPKI as the
  /// member-mode trust anchor for reconnect pinning.
  pub(crate) fn with_leaf_spki(mut self, spki: Vec<u8>) -> Self {
    self.leaf_spki = spki;
    self
  }

  pub(crate) fn leaf_spki(&self) -> &[u8] {
    &self.leaf_spki
  }

  pub(crate) const fn generation(&self) -> &[u8; 16] {
    &self.generation
  }
}

/// One decoded frame from a byte stream.
pub(crate) enum RawFrame {
  /// One wire message (validated against the frame rules).
  Data(Message),
  /// The peer answered our keepalive ping.
  Pong,
  /// The listener's join hint (the first application frame).
  Hint(Option<MergeHint>),
}

/// Writes one data frame: the tag byte followed by the rule-checked
/// prelude and body, composed into a single write.
pub(crate) async fn write_data<Write>(
  write: &mut Write, rules: FrameRules, schema_id: u16, kind_id: u16, flags: u16, body: &[u8],
) -> Result<()>
where
  Write: AsyncWrite + Unpin + Send, {
  let frame = encode_frame(rules, schema_id, kind_id, flags, body)?;
  let mut bytes = Vec::with_capacity(1 + frame.len());
  bytes.push(TAG_DATA);
  bytes.extend_from_slice(&frame);
  write_all(write, &bytes).await
}

/// Writes one keepalive ping.
pub(crate) async fn write_ping<Write>(write: &mut Write) -> Result<()>
where
  Write: AsyncWrite + Unpin + Send, {
  write_all(write, &[TAG_PING]).await
}

/// Writes the listener's single hint frame. `None` publishes an empty
/// hint so the dialer's connect-time read always completes.
pub(crate) async fn write_hint<Write>(write: &mut Write, hint: Option<&MergeHint>) -> Result<()>
where
  Write: AsyncWrite + Unpin + Send, {
  let Some(hint) = hint else {
    return write_all(write, &[TAG_HINT, 0x00, 0x00]).await;
  };
  let spki = hint.leaf_spki();
  let spki_len =
    u16::try_from(spki.len()).map_err(|_| Error::invalid_input("transport hint spki"))?;
  let mut payload = Vec::with_capacity(1 + hint.generation().len() + 2 + spki.len());
  payload.push(HINT_PRESENT);
  payload.extend_from_slice(hint.generation());
  payload.extend_from_slice(&spki_len.to_be_bytes());
  payload.extend_from_slice(spki);
  if payload.len() > MAX_HINT_BYTES {
    return Err(Error::invalid_input("transport hint spki"));
  }
  let mut bytes = Vec::with_capacity(3 + payload.len());
  bytes.push(TAG_HINT);
  bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  bytes.extend_from_slice(&payload);
  write_all(write, &bytes).await
}

/// Reads one frame from a byte stream. `Ok(None)` on a clean EOF before
/// the first byte of a frame. A received ping is answered inside the
/// framing layer and the read continues: a keepalive must never surface
/// as an orderly close, or every Raw-class session dies on its first
/// keepalive round. A truncated frame fails closed. The shared write
/// half answers pings, so the reader never needs the writer's exclusive
/// attention.
pub(crate) async fn read_frame(
  read: &mut (dyn AsyncRead + Unpin + Send), pong_write: &SharedWrite, rules: FrameRules,
) -> Result<Option<RawFrame>> {
  loop {
    let tag = match read.read_u8().await {
      Ok(tag) => tag,
      // An empty read is an orderly close; every later truncation is a
      // framing violation.
      Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
      Err(_) => {
        return Err(Error::provider(
          crate::ProviderErrorKind::Io,
          crate::ProviderErrorContext::TransportReceive,
        ));
      }
    };
    match tag {
      TAG_DATA => return read_data(read, rules).await.map(Some),
      TAG_PONG => return Ok(Some(RawFrame::Pong)),
      TAG_PING => {
        let mut write = pong_write.lock().await;
        write_all(&mut *write, &[TAG_PONG]).await?;
        // Answered: keep reading. Returning here would surface the
        // keepalive as an orderly peer close and tear down a healthy
        // session.
        continue;
      }
      TAG_HINT => return read_hint(read).await.map(Some),
      _ => return Err(Error::invalid_input("wire frame tag")),
    }
  }
}

/// Reads and validates one data frame: the prelude first, every rule
/// check before the body allocation, then the declared body.
async fn read_data(
  read: &mut (dyn AsyncRead + Unpin + Send), rules: FrameRules,
) -> Result<RawFrame> {
  let mut prelude_bytes = [0_u8; PRELUDE_LEN];
  read_exact(read, &mut prelude_bytes).await?;
  let prelude = Prelude::decode(&prelude_bytes)?;
  check_frame(
    prelude,
    rules.allowed_flags,
    rules.message_limit,
    rules.is_declared,
  )?;
  if prelude.body_len() > rules.receive_limit {
    return Err(Error::invalid_input("wire limits"));
  }
  let body_len =
    usize::try_from(prelude.body_len()).map_err(|_| Error::invalid_input("wire body length"))?;
  let mut body = vec![0_u8; body_len];
  read_exact(read, &mut body).await?;
  tracing::trace!(
    schema_id = prelude.schema_id(),
    kind_id = prelude.kind_id(),
    flags = prelude.flags(),
    body_len,
    "wire message received"
  );
  Ok(RawFrame::Data(Message {
    schema_id: prelude.schema_id(),
    kind_id: prelude.kind_id(),
    flags: prelude.flags(),
    body,
  }))
}

/// Reads the single hint frame payload. A truncated or malformed hint
/// fails closed: the first application frame is part of the transport
/// contract, never optional.
async fn read_hint(read: &mut (dyn AsyncRead + Unpin + Send)) -> Result<RawFrame> {
  let payload_len = read.read_u16().await.map_err(hint_io)?;
  // An empty payload is the listener's no-hint publication; anything
  // else must carry the present flag, the generation, and a
  // well-formed SPKI tail.
  if payload_len == 0 {
    return Ok(RawFrame::Hint(None));
  }
  let mut payload = vec![0_u8; payload_len as usize];
  read_exact(read, &mut payload).await?;
  match payload.split_first() {
    Some((&HINT_PRESENT, rest)) if rest.len() >= 16 + 2 => {
      let generation: [u8; 16] = rest[..16]
        .try_into()
        .map_err(|_| Error::invalid_input("transport hint"))?;
      let spki_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
      let spki = rest
        .get(18..)
        .ok_or_else(|| Error::invalid_input("transport hint"))?
        .to_vec();
      if spki.len() != spki_len {
        return Err(Error::invalid_input("transport hint"));
      }
      Ok(RawFrame::Hint(Some(
        MergeHint::new(generation).with_leaf_spki(spki),
      )))
    }
    _ => Err(Error::invalid_input("transport hint")),
  }
}

/// The boxed write half behind every byte-stream connection: data,
/// keepalive, and hint writes serialize through one mutex, so the split
/// reader can answer pings while the session writer sends frames.
pub(crate) fn shared_write(write: Box<dyn AsyncWrite + Unpin + Send>) -> SharedWrite {
  Arc::new(tokio::sync::Mutex::new(write))
}

async fn read_exact(read: &mut (dyn AsyncRead + Unpin + Send), buffer: &mut [u8]) -> Result<()> {
  read
    .read_exact(buffer)
    .await
    .map(|_| ())
    .map_err(|_| Error::invalid_input("wire frame"))
}

async fn write_all<Write>(write: &mut Write, bytes: &[u8]) -> Result<()>
where
  Write: AsyncWrite + Unpin + Send, {
  write.write_all(bytes).await.map_err(send_io)?;
  write.flush().await.map_err(send_io)
}

fn hint_io(_: std::io::Error) -> Error {
  Error::provider(
    crate::ProviderErrorKind::Io,
    crate::ProviderErrorContext::TransportReceive,
  )
}

fn send_io(_: std::io::Error) -> Error {
  Error::provider(
    crate::ProviderErrorKind::Io,
    crate::ProviderErrorContext::TransportSend,
  )
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex, split};

  use super::{FrameRules, RawFrame, SharedWrite, read_frame, write_data, write_ping};
  use crate::Result;

  fn rules() -> FrameRules {
    FrameRules {
      allowed_flags: 0,
      message_limit: 1_024,
      receive_limit: 1_024,
      is_declared: |schema, kind| schema == 1 && kind == 7,
    }
  }

  fn shared(write: tokio::io::WriteHalf<tokio::io::DuplexStream>) -> SharedWrite {
    Arc::new(tokio::sync::Mutex::new(
      Box::new(write) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>
    ))
  }

  /// A received keepalive ping is answered on the shared write half and
  /// the read CONTINUES to the next frame. The regression this guards is
  /// the ping surfacing as `Ok(None)` — the orderly-close value every
  /// caller maps to a peer close — which tore down every Raw-class
  /// session (tls, tcp, and custom media) on its first keepalive round.
  #[tokio::test]
  async fn a_ping_is_answered_and_the_read_continues_to_the_next_frame() -> Result<()> {
    let (mut client, server) = duplex(64);
    let (server_read, server_write) = split(server);
    let pong_write = shared(server_write);

    write_ping(&mut client).await?;
    write_data(&mut client, rules(), 1, 7, 0, b"payload").await?;

    let mut read = server_read;
    let frame = read_frame(&mut read, &pong_write, rules()).await?;
    let Some(RawFrame::Data(message)) = frame else {
      panic!("the data frame after the answered ping must arrive");
    };
    assert_eq!(message.body, b"payload");

    // The framing layer answered the ping on the shared write half: the
    // peer reads exactly one pong byte before any data.
    let mut pong = [0_u8; 1];
    client.read_exact(&mut pong).await.expect("pong byte");
    assert_eq!(pong[0], super::TAG_PONG);
    Ok(())
  }

  /// A ping followed by a clean peer close still reads as an orderly
  /// close: the ping is answered first, then the next read reports EOF.
  #[tokio::test]
  async fn a_ping_before_a_clean_close_still_reads_as_orderly_eof() -> Result<()> {
    let (mut client, server) = duplex(64);
    let (server_read, server_write) = split(server);
    let pong_write = shared(server_write);

    write_ping(&mut client).await.expect("ping write");
    // Close the client's write half only: the pong answer below must
    // still be deliverable to the client's read half.
    client.shutdown().await.expect("orderly client shutdown");

    let mut read = server_read;
    let frame = read_frame(&mut read, &pong_write, rules()).await?;
    assert!(
      frame.is_none(),
      "the close after the answered ping is orderly"
    );
    drop(client);
    Ok(())
  }
}
