//! Framed connection over the TLS WebSocket stream.
//!
//! A [`Connection`] carries exactly one binary WebSocket message per
//! wire message: one 16-byte prelude followed by one body. Encode
//! and decode reuse the `protocol::envelope` prelude and [`split_message`]
//! semantics, so kind declaration, flag, class-limit, receive-limit, and
//! trailing-byte checks are identical to the in-memory handshake harness.
//! Receive is bounded twice: tungstenite enforces the aggregate message
//! limit while reassembling frames, and `split_message` re-checks every
//! configured limit before exposing the body.
//!
//! The channel binding is the RFC 9266 `tls-exporter` channel binding:
//! exactly
//! `TLS-Exporter("EXPORTER-Channel-Binding", "", 32)`. It is read from the
//! local TLS connection immediately after the handshake completes, never
//! received as a wire field, never logged, and never treated as a secret.
//! The empty context is passed as an explicit empty slice (`Some(&[])`);
//! RFC 5705/8446 define an absent context as zero-length and rustls maps
//! both to the same exporter input, so there is no `None` ambiguity.

use std::{net::SocketAddr, sync::Arc};

use futures_util::{
  SinkExt, StreamExt,
  stream::{SplitSink, SplitStream},
};
use rustls::{ClientConfig, ConnectionCommon, ServerConfig, pki_types::ServerName};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_tungstenite::{
  WebSocketStream,
  tungstenite::{Bytes as WsBytes, Message as WsMessage},
};

use super::{ws, ws::MergeHint};
/// The local policy applied to every sent and received wire message
/// (defined in the protocol domain; re-exported for connection callers).
pub(crate) use crate::protocol::wire::FrameRules;
use crate::{
  Error, ProviderErrorContext, ProviderErrorKind, Result,
  protocol::{PRELUDE_LEN, Prelude, check_frame, split_message, wire::BASE_SCHEMA_ID},
};

/// The exact RFC 9266 exporter label.
pub(crate) const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// The channel binding length in bytes.
pub(crate) const CHANNEL_BINDING_LEN: usize = 32;

/// One decoded wire message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Message {
  /// The prelude schema ID.
  pub(crate) schema_id: u16,
  /// The prelude kind ID.
  pub(crate) kind_id: u16,
  /// The prelude flags.
  pub(crate) flags: u16,
  /// The exact body bytes.
  pub(crate) body: Vec<u8>,
}

/// One framed TLS WebSocket connection.
pub(crate) struct Connection {
  stream: WebSocketStream<TlsStream<TcpStream>>,
  rules: FrameRules,
  channel_binding: [u8; CHANNEL_BINDING_LEN],
  merge_hint: Option<MergeHint>,
  /// The accepted peer's socket address, carried raw for the upper
  /// layer: this transport knows nothing about admission semantics and
  /// never normalizes or interprets the address. It is `None` only when
  /// the kernel could not report the peer address on an accepted
  /// connection; dialer-side connections carry none.
  peer_addr: Option<SocketAddr>,
  /// UNIX-seconds of the last peer pong (keepalive liveness).
  pong_last_seen: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Connection {
  /// Accepts one connection: TLS 1.3 handshake, exporter derivation, then
  /// the WebSocket upgrade. No application frame is read before the TLS
  /// handshake completes. When the listener can admit joiners, `hint`
  /// publishes the non-secret cluster and credential generation IDs as
  /// upgrade response headers inside the TLS channel.
  pub(crate) async fn accept(
    tcp: TcpStream, config: Arc<ServerConfig>, rules: FrameRules, hint: Option<&MergeHint>,
  ) -> Result<Self> {
    // The packet data plane is ack-driven with small messages; the kernel
    // Nagle + delayed-ACK interaction would stall every burst by the
    // delayed-ACK window, so the transport owns low-latency sockets.
    let tcp = low_latency(tcp, ProviderErrorContext::TransportAccept)?;
    let peer_addr = tcp.peer_addr().ok();
    tracing::debug!("tls connection accepted");
    let tls = TlsAcceptor::from(config)
      .accept(tcp)
      .await
      .map_err(|_| Error::authentication_failed("tls accept"))?;
    let channel_binding = exporter_channel_binding(tls.get_ref().1)?;
    let stream = ws::accept(TlsStream::from(tls), hint).await?;
    Ok(Self {
      stream,
      rules,
      channel_binding,
      merge_hint: None,
      peer_addr,
      pong_last_seen: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
  }

  /// Connects to one listener: TLS 1.3 handshake, exporter derivation, then
  /// the WebSocket upgrade on the fixed `/mrly` path. The listener's
  /// non-secret join hint headers, when present, are retained for the
  /// session driver and are never trusted without the handshake and signed
  /// grant checks.
  pub(crate) async fn connect(
    tcp: TcpStream, config: Arc<ClientConfig>, server_name: ServerName<'static>, rules: FrameRules,
  ) -> Result<Self> {
    let tcp = low_latency(tcp, ProviderErrorContext::TransportConnect)?;
    tracing::debug!("tls connection established");
    let authority = tcp
      .peer_addr()
      .map_err(|_| {
        Error::provider(
          ProviderErrorKind::Io,
          ProviderErrorContext::TransportConnect,
        )
      })?
      .to_string();
    let tls = TlsConnector::from(config)
      .connect(server_name, tcp)
      .await
      .map_err(|_| Error::authentication_failed("tls connect"))?;
    let channel_binding = exporter_channel_binding(tls.get_ref().1)?;
    let (stream, merge_hint) = ws::connect(TlsStream::from(tls), &authority).await?;
    Ok(Self {
      stream,
      rules,
      channel_binding,
      merge_hint,
      peer_addr: None,
      pong_last_seen: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
  }

  /// The listener's non-secret join hints captured during the WebSocket
  /// upgrade (client side only).
  pub(crate) const fn merge_hint(&self) -> Option<&MergeHint> {
    self.merge_hint.as_ref()
  }

  /// The locally derived RFC 9266 channel binding.
  pub(crate) fn channel_binding(&self) -> &[u8; CHANNEL_BINDING_LEN] {
    &self.channel_binding
  }

  /// Sends one wire message. The message is checked against the local rules
  /// before encoding so a local bug fails fast instead of emitting bytes
  /// the peer must reject.
  pub(crate) async fn send(
    &mut self, schema_id: u16, kind_id: u16, flags: u16, body: &[u8],
  ) -> Result<()> {
    let frame = encode_frame(self.rules, schema_id, kind_id, flags, body)?;
    self
      .stream
      .send(WsMessage::binary(frame))
      .await
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend))
  }

  /// Receives the next wire message. Returns `Ok(None)` on an orderly
  /// close. Text messages, raw frames, oversize messages, and every
  /// prelude/limit violation fail closed. Ping and pong messages are
  /// answered by tungstenite and skipped.
  pub(crate) async fn receive(&mut self) -> Result<Option<Message>> {
    next_message(&mut self.stream, self.rules, &self.pong_last_seen).await
  }

  /// The accepted peer's raw socket address; dialer-side connections
  /// carry none (the initiator rate-limits nothing here). `None` on an
  /// accepted connection means the kernel could not report the peer
  /// address; interpreting that case is the admission layer's explicit
  /// decision, never this transport's.
  pub(crate) const fn peer_addr(&self) -> Option<SocketAddr> {
    self.peer_addr
  }

  /// Sends a WebSocket close frame and flushes the stream.
  pub(crate) async fn close(&mut self) -> Result<()> {
    self
      .stream
      .close(None)
      .await
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportClose))
  }

  /// Splits the connection into independent writer and reader halves for
  /// the post-authentication session phase.
  pub(crate) fn into_split(self) -> (ConnectionWriter, ConnectionReader) {
    let (sink, stream) = self.stream.split();
    let pong_last_seen = self.pong_last_seen;
    (
      ConnectionWriter {
        sink,
        rules: self.rules,
        pong_last_seen: Arc::clone(&pong_last_seen),
      },
      ConnectionReader {
        stream,
        rules: self.rules,
        pong_last_seen,
      },
    )
  }
}

impl core::fmt::Debug for Connection {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("Connection(..)")
  }
}

/// The write half of a split session-phase connection. Each send is one
/// wire message checked against the local frame rules before encoding.
pub(crate) struct ConnectionWriter {
  sink: SplitSink<WebSocketStream<TlsStream<TcpStream>>, WsMessage>,
  rules: FrameRules,
  pong_last_seen: Arc<std::sync::atomic::AtomicU64>,
}

impl ConnectionWriter {
  /// Sends one WebSocket ping for keepalive.
  pub(crate) async fn ping(&mut self) -> Result<()> {
    self
      .sink
      .send(WsMessage::Ping(WsBytes::new()))
      .await
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend))
  }

  /// UNIX-seconds of the last peer pong.
  #[allow(dead_code)]
  pub(crate) fn pong_last_seen(&self) -> u64 {
    self
      .pong_last_seen
      .load(std::sync::atomic::Ordering::Relaxed)
  }

  /// Sends one base-schema wire message of `kind_id` with no flags.
  pub(crate) async fn send(&mut self, kind_id: u16, body: &[u8]) -> Result<()> {
    let frame = encode_frame(self.rules, BASE_SCHEMA_ID, kind_id, 0, body)?;
    tracing::trace!(kind_id, body_len = body.len(), "wire message sent");
    self
      .sink
      .send(WsMessage::binary(frame))
      .await
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend))
  }
}

/// The read half of a split session-phase connection, with exactly the
/// receive semantics of [`Connection::receive`].
pub(crate) struct ConnectionReader {
  stream: SplitStream<WebSocketStream<TlsStream<TcpStream>>>,
  rules: FrameRules,
  pong_last_seen: Arc<std::sync::atomic::AtomicU64>,
}

impl ConnectionReader {
  /// UNIX-seconds of the last peer pong (host clock), used by the session
  /// reader to reflect keepalive responses into its injected clock.
  pub(crate) fn pong_last_seen(&self) -> u64 {
    self
      .pong_last_seen
      .load(std::sync::atomic::Ordering::Relaxed)
  }

  /// Receives the next wire message. Returns `Ok(None)` on an orderly
  /// close; every limit or framing violation fails closed. The semantics
  /// are exactly [`Connection::receive`] over the split stream half.
  pub(crate) async fn receive(&mut self) -> Result<Option<Message>> {
    next_message(&mut self.stream, self.rules, &self.pong_last_seen).await
  }
}

type WsResult = std::result::Result<WsMessage, tokio_tungstenite::tungstenite::Error>;

/// The single receive loop shared by [`Connection::receive`] and
/// [`ConnectionReader::receive`]: binary messages are split and limit-
/// checked, pongs refresh the shared liveness stamp, and every other
/// control shape fails closed or is skipped exactly as documented.
async fn next_message<S>(
  stream: &mut S, rules: FrameRules, pong_last_seen: &std::sync::atomic::AtomicU64,
) -> Result<Option<Message>>
where
  S: futures_util::Stream<Item = WsResult> + Unpin, {
  loop {
    let Some(item) = stream.next().await else {
      return Ok(None);
    };
    let message = item.map_err(receive_error)?;
    match message {
      WsMessage::Binary(bytes) => {
        let (prelude, body) = split_message(
          &bytes,
          rules.allowed_flags,
          rules.message_limit,
          rules.receive_limit,
          rules.is_declared,
        )?;
        tracing::trace!(
          schema_id = prelude.schema_id(),
          kind_id = prelude.kind_id(),
          flags = prelude.flags(),
          body_len = body.len(),
          "wire message received"
        );
        return Ok(Some(Message {
          schema_id: prelude.schema_id(),
          kind_id: prelude.kind_id(),
          flags: prelude.flags(),
          body: body.to_vec(),
        }));
      }
      WsMessage::Text(_) => return Err(Error::invalid_input("websocket text message")),
      WsMessage::Ping(_) => continue,
      WsMessage::Pong(_) => {
        // The peer answered a keepalive ping; record the liveness time
        // (tungstenite answers pings itself, so this observes the peer's
        // own pong responses).
        pong_last_seen.store(
          crate::time::now_seconds(),
          std::sync::atomic::Ordering::Relaxed,
        );
        continue;
      }
      WsMessage::Close(_) => return Ok(None),
      WsMessage::Frame(_) => return Err(Error::invalid_input("websocket raw frame")),
    }
  }
}

/// Encodes one wire message after checking it against the local frame
/// rules, so a local bug fails fast instead of emitting bytes the peer
/// must reject. The single frame builder for both connection halves.
fn encode_frame(
  rules: FrameRules, schema_id: u16, kind_id: u16, flags: u16, body: &[u8],
) -> Result<Vec<u8>> {
  let body_len = u32::try_from(body.len()).map_err(|_| Error::invalid_input("wire body length"))?;
  let prelude = Prelude::new(schema_id, kind_id, flags, body_len);
  // The send side shares the declared/flags/message-limit trio with the
  // decode direction and deliberately skips `receive_limit`: that bound
  // protects the receiving peer's allocation, so only `split_message`
  // applies it on arrival.
  check_frame(
    prelude,
    rules.allowed_flags,
    rules.message_limit,
    rules.is_declared,
  )?;
  let mut frame = Vec::with_capacity(PRELUDE_LEN + body.len());
  frame.extend_from_slice(&prelude.encode());
  frame.extend_from_slice(body);
  Ok(frame)
}

/// Disables the kernel Nagle algorithm so ack-driven small-message bursts
/// are not stalled by the delayed-ACK window.
fn low_latency(tcp: TcpStream, context: ProviderErrorContext) -> Result<TcpStream> {
  tcp
    .set_nodelay(true)
    .map_err(|_| Error::provider(ProviderErrorKind::Io, context))?;
  Ok(tcp)
}

/// Reads the RFC 9266 `tls-exporter` channel binding from the local TLS
/// connection. Called only after the handshake completed, so the exporter
/// is always available; the empty context is an explicit empty slice.
fn exporter_channel_binding<Data>(
  connection: &ConnectionCommon<Data>,
) -> Result<[u8; CHANNEL_BINDING_LEN]> {
  connection
    .export_keying_material([0_u8; CHANNEL_BINDING_LEN], EXPORTER_LABEL, Some(&[]))
    .map_err(|_| Error::internal("channel binding"))
}

fn receive_error(error: tokio_tungstenite::tungstenite::Error) -> Error {
  use tokio_tungstenite::tungstenite::Error as WsError;
  match error {
    WsError::Io(_) => Error::provider(
      ProviderErrorKind::Io,
      ProviderErrorContext::TransportReceive,
    ),
    WsError::Capacity(_) => Error::provider(
      ProviderErrorKind::Overloaded,
      ProviderErrorContext::TransportReceive,
    ),
    _ => Error::invalid_input("websocket message"),
  }
}

#[cfg(test)]
mod tests;
