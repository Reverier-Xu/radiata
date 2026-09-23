//! Framed connection over a transport stream.
//!
//! A [`Connection`] carries exactly one wire message per transport
//! message: one 16-byte prelude followed by one body. Two stream classes
//! exist behind one type:
//!
//! - the WebSocket class (`TransportIo::Ws`): TLS 1.3 with one binary WebSocket
//!   message per wire message, tungstenite enforcing the aggregate message
//!   bound and answering pings;
//! - the raw class (`TransportIo::Raw`): any ordered reliable byte stream — the
//!   direct TLS stream, the plaintext TCP stream, or a caller-registered custom
//!   transport stream — framed by the `framing` module's tag discipline with
//!   the same message bounds and keepalive semantics.
//!
//! Encode and decode reuse the `protocol::envelope` prelude and
//! [`split_message`] semantics on every class, so kind declaration,
//! flag, class-limit, receive-limit, and trailing-byte checks are
//! identical to the in-memory handshake harness. Receive is bounded
//! twice on both classes: the stream layer enforces the aggregate bound
//! while assembling the message, and `split_message`/`read_data`
//! re-check every configured limit before the body is exposed or
//! allocated.
//!
//! The channel binding is the RFC 9266 `tls-exporter` channel binding
//! on the TLS classes: exactly
//! `TLS-Exporter("EXPORTER-Channel-Binding", "", 32)`. It is read from
//! the local TLS connection immediately after the handshake completes,
//! never received as a wire field, never logged, and never treated as a
//! secret. The byte-stream classes without TLS bind to a fixed per-class
//! constant instead (see [`plaintext_channel_binding`] and the custom
//! transport adapter): a distinct derivation salt per transport class,
//! so a proof derived on one class never verifies on another. Such a
//! constant provides no man-in-the-middle protection — on those classes
//! the session handshake's identity proofs carry the authentication.

use std::{net::SocketAddr, sync::Arc};

use futures_util::{
  SinkExt, StreamExt,
  stream::{SplitSink, SplitStream},
};
use rustls::{ClientConfig, ConnectionCommon, ServerConfig, pki_types::ServerName};
use sha2::Digest;
use tokio::{
  io::{AsyncRead, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_tungstenite::{
  WebSocketStream,
  tungstenite::{Bytes as WsBytes, Message as WsMessage},
};

use super::{framing, framing::MergeHint, ws};
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

/// The derivation label of every non-TLS channel-binding class constant.
const CLASS_BINDING_LABEL: &[u8] = b"radiata:transport-binding:";

/// The write half of a raw byte-stream connection behind one mutex, so
/// data frames, keepalive answers, and hint writes serialize without
/// exposing the writer to the reader half.
pub(crate) type SharedWrite = Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Unpin + Send>>>;

/// The stream class one connection rides on.
pub(crate) enum TransportIo {
  /// TLS 1.3 with the WebSocket message layer.
  Ws(Box<WebSocketStream<TlsStream<TcpStream>>>),
  /// A framed bare byte stream (direct TLS, plaintext TCP, or a custom
  /// transport stream).
  Raw {
    read: Box<dyn AsyncRead + Unpin + Send>,
    write: SharedWrite,
  },
}

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

#[cfg(test)]
impl Received {
  /// Unwraps the message variant for tests exercising the message-only
  /// reader contract; a pong there means the wake contract regressed.
  pub(crate) fn expect_message(self) -> Message {
    match self {
      Received::Message(message) => message,
      Received::Pong => panic!("unexpected keepalive pong wake"),
    }
  }
}

/// One framed connection over a transport stream.
pub(crate) struct Connection {
  io: TransportIo,
  rules: FrameRules,
  channel_binding: [u8; CHANNEL_BINDING_LEN],
  merge_hint: Option<MergeHint>,
  /// The accepted peer's socket address, carried raw for the upper
  /// layer: this transport knows nothing about admission semantics and
  /// never normalizes or interprets the address. It is `None` only when
  /// the medium could not report a peer address (custom transports
  /// always; the kernel failing on a TCP accept); dialer-side
  /// connections carry none.
  peer_addr: Option<SocketAddr>,
  /// Whether the medium attributes its accepted connections to peers at
  /// all. TCP classes always do (a kernel failure to report the address
  /// is a transport fault, not a property of the medium); custom
  /// media never do, by contract. Admission semantics consume this
  /// distinction: a missing address on an attributing medium fails
  /// closed, while an addressless medium attributes to its shared class
  /// bucket.
  attributable: bool,
  /// UNIX-seconds of the last peer pong (keepalive liveness).
  pong_last_seen: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Connection {
  /// Accepts one WebSocket-class connection: TLS 1.3 handshake, exporter
  /// derivation, then the WebSocket upgrade. No application frame is
  /// read before the TLS handshake completes. When the listener can
  /// admit joiners, `hint` publishes the non-secret credential
  /// generation ID as an upgrade response header inside the TLS channel.
  pub(crate) async fn accept_tls_ws(
    tcp: TcpStream, config: Arc<ServerConfig>, rules: FrameRules, hint: Option<&MergeHint>,
  ) -> Result<Self> {
    let peer_addr = tcp.peer_addr().ok();
    tracing::debug!("tls connection accepted");
    let tls = TlsAcceptor::from(config)
      .accept(tcp)
      .await
      .map_err(|_| Error::authentication_failed("tls accept"))?;
    let channel_binding = exporter_channel_binding(tls.get_ref().1)?;
    let stream = ws::accept(TlsStream::from(tls), hint).await?;
    Ok(Self {
      io: TransportIo::Ws(Box::new(stream)),
      rules,
      channel_binding,
      merge_hint: None,
      peer_addr,
      attributable: true,
      pong_last_seen: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
  }

  /// Connects to one WebSocket-class listener: TLS 1.3 handshake,
  /// exporter derivation, then the WebSocket upgrade on the fixed
  /// `/mrly` path. The listener's non-secret join hint headers, when
  /// present, are retained for the session driver and are never trusted
  /// without the handshake and signed grant checks.
  pub(crate) async fn connect_tls_ws(
    tcp: TcpStream, config: Arc<ClientConfig>, server_name: ServerName<'static>, rules: FrameRules,
  ) -> Result<Self> {
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
      io: TransportIo::Ws(Box::new(stream)),
      rules,
      channel_binding,
      merge_hint,
      peer_addr: None,
      attributable: true,
      pong_last_seen: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
  }

  /// Accepts one raw-class connection over an established stream (the
  /// TLS handshake, when any, already completed). Publishes the single
  /// hint frame — empty when the listener cannot admit mergers — so the
  /// dialer's connect-time read always completes.
  pub(crate) async fn accept_raw(
    read: Box<dyn AsyncRead + Unpin + Send>, write: SharedWrite,
    channel_binding: [u8; CHANNEL_BINDING_LEN], rules: FrameRules, peer_addr: Option<SocketAddr>,
    attributable: bool, hint: Option<&MergeHint>,
  ) -> Result<Self> {
    {
      let mut write = write.lock().await;
      framing::write_hint(&mut *write, hint).await?;
    }
    Ok(Self {
      io: TransportIo::Raw { read, write },
      rules,
      channel_binding,
      merge_hint: None,
      peer_addr,
      attributable,
      pong_last_seen: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
  }

  /// Connects to one raw-class listener over an established stream.
  /// Reads the listener's single hint frame before returning, so the
  /// join flow observes the same hint availability as the WebSocket
  /// class.
  pub(crate) async fn connect_raw(
    mut read: Box<dyn AsyncRead + Unpin + Send>, write: SharedWrite,
    channel_binding: [u8; CHANNEL_BINDING_LEN], rules: FrameRules,
  ) -> Result<Self> {
    // No lock is held across the read: the framing layer locks the shared
    // write half itself only when a ping must be answered.
    let merge_hint = match framing::read_frame(&mut *read, &write, rules).await? {
      Some(framing::RawFrame::Hint(hint)) => hint,
      _ => return Err(Error::invalid_input("transport hint")),
    };
    Ok(Self {
      io: TransportIo::Raw { read, write },
      rules,
      channel_binding,
      merge_hint,
      peer_addr: None,
      attributable: true,
      pong_last_seen: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
  }

  /// The listener's non-secret join hints captured during establishment
  /// (client side only).
  pub(crate) const fn merge_hint(&self) -> Option<&MergeHint> {
    self.merge_hint.as_ref()
  }

  /// The locally derived channel binding.
  pub(crate) fn channel_binding(&self) -> &[u8; CHANNEL_BINDING_LEN] {
    &self.channel_binding
  }

  /// Sends one wire message. The message is checked against the local rules
  /// before encoding so a local bug fails fast instead of emitting bytes
  /// the peer must reject.
  pub(crate) async fn send(
    &mut self, schema_id: u16, kind_id: u16, flags: u16, body: &[u8],
  ) -> Result<()> {
    match &mut self.io {
      TransportIo::Ws(stream) => {
        let frame = encode_frame(self.rules, schema_id, kind_id, flags, body)?;
        stream
          .send(WsMessage::binary(frame))
          .await
          .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend))
      }
      TransportIo::Raw { write, .. } => {
        let mut write = write.lock().await;
        framing::write_data(&mut *write, self.rules, schema_id, kind_id, flags, body).await
      }
    }
  }

  /// Receives the next wire message. Returns `Ok(None)` on an orderly
  /// close. Text messages, raw frames, oversize messages, and every
  /// prelude/limit violation fail closed. Pings are answered by the
  /// stream layer; pongs are skipped.
  pub(crate) async fn receive(&mut self) -> Result<Option<Message>> {
    loop {
      return match self.receive_once().await? {
        Some(Received::Message(message)) => Ok(Some(message)),
        Some(Received::Pong) => continue,
        None => Ok(None),
      };
    }
  }

  /// One receive wake of the unsplit connection, class-dispatched.
  async fn receive_once(&mut self) -> Result<Option<Received>> {
    match &mut self.io {
      TransportIo::Ws(stream) => next_message(stream, self.rules, &self.pong_last_seen).await,
      TransportIo::Raw { read, write } => {
        match framing::read_frame(&mut **read, write, self.rules).await? {
          Some(framing::RawFrame::Data(message)) => Ok(Some(Received::Message(message))),
          Some(framing::RawFrame::Pong) => {
            self.pong_last_seen.store(
              crate::time::now_seconds(),
              std::sync::atomic::Ordering::Relaxed,
            );
            Ok(Some(Received::Pong))
          }
          Some(framing::RawFrame::Hint(_)) => Err(Error::invalid_input("transport hint")),
          None => Ok(None),
        }
      }
    }
  }

  /// The accepted peer's raw socket address; dialer-side connections
  /// carry none (the initiator rate-limits nothing here). `None` on an
  /// accepted connection means the medium could not report a peer
  /// address; interpreting that case is the admission layer's explicit
  /// decision, never this transport's.
  pub(crate) const fn peer_addr(&self) -> Option<SocketAddr> {
    self.peer_addr
  }

  /// Whether the medium attributes accepted connections to peers by
  /// design. A missing address on an attributing medium is a transport
  /// fault; on an addressless medium it is the normal state.
  pub(crate) const fn attributable(&self) -> bool {
    self.attributable
  }

  /// Sends a class-appropriate close (WebSocket close frame, TLS
  /// close_notify, or a stream shutdown) and flushes.
  pub(crate) async fn close(&mut self) -> Result<()> {
    match &mut self.io {
      TransportIo::Ws(stream) => (**stream)
        .close(None)
        .await
        .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportClose)),
      TransportIo::Raw { write, .. } => {
        let mut write = write.lock().await;
        AsyncWriteExt::shutdown(&mut *write)
          .await
          .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportClose))
      }
    }
  }

  /// Splits the connection into independent writer and reader halves for
  /// the post-authentication session phase. Only the reader carries the
  /// pong clock: pongs arrive on the read half, and a writer-side
  /// timestamp no one reads is dead weight.
  pub(crate) fn into_split(self) -> (ConnectionWriter, ConnectionReader) {
    let pong_last_seen = self.pong_last_seen;
    match self.io {
      TransportIo::Ws(stream) => {
        let (sink, stream) = stream.split();
        (
          ConnectionWriter {
            sink: WriterSink::Ws(sink),
            rules: self.rules,
          },
          ConnectionReader {
            source: ReaderSource::Ws(stream),
            rules: self.rules,
            pong_last_seen,
          },
        )
      }
      TransportIo::Raw { read, write } => {
        let pong_write = std::sync::Arc::clone(&write);
        (
          ConnectionWriter {
            sink: WriterSink::Raw(write),
            rules: self.rules,
          },
          ConnectionReader {
            source: ReaderSource::Raw { read, pong_write },
            rules: self.rules,
            pong_last_seen,
          },
        )
      }
    }
  }
}

impl core::fmt::Debug for Connection {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("Connection(..)")
  }
}

/// The write half of a split session-phase connection.
pub(crate) struct ConnectionWriter {
  sink: WriterSink,
  rules: FrameRules,
}

enum WriterSink {
  Ws(SplitSink<Box<WebSocketStream<TlsStream<TcpStream>>>, WsMessage>),
  Raw(SharedWrite),
}

impl ConnectionWriter {
  /// Sends one keepalive ping.
  pub(crate) async fn ping(&mut self) -> Result<()> {
    match &mut self.sink {
      WriterSink::Ws(sink) => sink
        .send(WsMessage::Ping(WsBytes::new()))
        .await
        .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend)),
      WriterSink::Raw(write) => {
        let mut write = write.lock().await;
        framing::write_ping(&mut *write).await
      }
    }
  }

  /// Sends one base-schema wire message of `kind_id` with no flags.
  pub(crate) async fn send(&mut self, kind_id: u16, body: &[u8]) -> Result<()> {
    match &mut self.sink {
      WriterSink::Ws(sink) => {
        let frame = encode_frame(self.rules, BASE_SCHEMA_ID, kind_id, 0, body)?;
        tracing::trace!(kind_id, body_len = body.len(), "wire message sent");
        sink
          .send(WsMessage::binary(frame))
          .await
          .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend))
      }
      WriterSink::Raw(write) => {
        tracing::trace!(kind_id, body_len = body.len(), "wire message sent");
        let mut write = write.lock().await;
        framing::write_data(&mut *write, self.rules, BASE_SCHEMA_ID, kind_id, 0, body).await
      }
    }
  }
}

/// The read half of a split session-phase connection, with exactly the
/// receive semantics of [`Connection::receive`].
pub(crate) struct ConnectionReader {
  source: ReaderSource,
  rules: FrameRules,
  pong_last_seen: Arc<std::sync::atomic::AtomicU64>,
}

enum ReaderSource {
  Ws(SplitStream<Box<WebSocketStream<TlsStream<TcpStream>>>>),
  Raw {
    read: Box<dyn AsyncRead + Unpin + Send>,
    pong_write: SharedWrite,
  },
}

impl ConnectionReader {
  /// UNIX-seconds of the last peer pong (host clock), used by the session
  /// reader to reflect keepalive responses into its injected clock.
  pub(crate) fn pong_last_seen(&self) -> u64 {
    self
      .pong_last_seen
      .load(std::sync::atomic::Ordering::Relaxed)
  }

  /// Receives the next wire message or keepalive pong. Returns `Ok(None)`
  /// on an orderly close; every limit or framing violation fails closed.
  /// The session read loop consumes this event form: a pong wake must
  /// reach the loop so it can refresh the session's activity mark.
  pub(crate) async fn receive_event(&mut self) -> Result<Option<Received>> {
    match &mut self.source {
      ReaderSource::Ws(stream) => next_message(stream, self.rules, &self.pong_last_seen).await,
      ReaderSource::Raw { read, pong_write } => {
        match framing::read_frame(&mut **read, pong_write, self.rules).await? {
          Some(framing::RawFrame::Data(message)) => Ok(Some(Received::Message(message))),
          Some(framing::RawFrame::Pong) => {
            // The peer answered a keepalive ping; record the liveness
            // time and wake the caller so it can reflect the response
            // into the session's activity mark.
            self.pong_last_seen.store(
              crate::time::now_seconds(),
              std::sync::atomic::Ordering::Relaxed,
            );
            Ok(Some(Received::Pong))
          }
          Some(framing::RawFrame::Hint(_)) => Err(Error::invalid_input("transport hint")),
          None => Ok(None),
        }
      }
    }
  }
}

/// What one receive wake observed: a wire message, or a keepalive pong
/// the caller must reflect into its own liveness clock. Surfacing pongs
/// (instead of swallowing them) lets a frame-silent session stay alive
/// on keepalone responses alone.
pub(crate) enum Received {
  Message(Message),
  Pong,
}

/// The single receive loop of the WebSocket class: binary messages are
/// split and limit-checked, pongs refresh the shared liveness stamp and
/// surface as [`Received::Pong`], and every other control shape fails
/// closed or is skipped exactly as documented.
async fn next_message<S>(
  stream: &mut S, rules: FrameRules, pong_last_seen: &std::sync::atomic::AtomicU64,
) -> Result<Option<Received>>
where
  S: futures_util::Stream<
      Item = std::result::Result<WsMessage, tokio_tungstenite::tungstenite::Error>,
    > + Unpin, {
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
        return Ok(Some(Received::Message(Message {
          schema_id: prelude.schema_id(),
          kind_id: prelude.kind_id(),
          flags: prelude.flags(),
          body: body.to_vec(),
        })));
      }
      WsMessage::Text(_) => return Err(Error::invalid_input("websocket text message")),
      WsMessage::Ping(_) => continue,
      WsMessage::Pong(_) => {
        // The peer answered a keepalive ping; record the liveness time
        // (tungstenite answers pings itself, so this observes the peer's
        // own pong responses) and wake the caller so it can reflect the
        // response into the session's activity mark.
        pong_last_seen.store(
          crate::time::now_seconds(),
          std::sync::atomic::Ordering::Relaxed,
        );
        return Ok(Some(Received::Pong));
      }
      WsMessage::Close(_) => return Ok(None),
      WsMessage::Frame(_) => return Err(Error::invalid_input("websocket raw frame")),
    }
  }
}

/// Encodes one wire message after checking it against the local frame
/// rules, so a local bug fails fast instead of emitting bytes the peer
/// must reject. The single frame builder for both classes.
pub(crate) fn encode_frame(
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

/// Reads the RFC 9266 `tls-exporter` channel binding from the local TLS
/// connection. Called only after the handshake completed, so the exporter
/// is always available; the empty context is an explicit empty slice.
pub(crate) fn exporter_channel_binding<Data>(
  connection: &ConnectionCommon<Data>,
) -> Result<[u8; CHANNEL_BINDING_LEN]> {
  connection
    .export_keying_material([0_u8; CHANNEL_BINDING_LEN], EXPORTER_LABEL, Some(&[]))
    .map_err(|_| Error::internal("channel binding"))
}

/// The channel-binding class constant of the plaintext TCP transport: a
/// fixed derivation over the transport class label. It salts the
/// handshake proofs so a proof derived on this class never verifies on a
/// TLS class (whose exporter bindings are unpredictable), and it must
/// never be mistaken for man-in-the-middle protection — the plaintext
/// class has none; the handshake identity proofs carry authentication.
pub(crate) fn plaintext_channel_binding() -> Result<[u8; CHANNEL_BINDING_LEN]> {
  class_channel_binding("tcp-plaintext:v1")
}

/// The channel-binding class constant of one caller-registered custom
/// transport, derived over its canonical tag so proofs stay distinct per
/// transport class.
pub(crate) fn custom_channel_binding(tag: &str) -> Result<[u8; CHANNEL_BINDING_LEN]> {
  class_channel_binding(&format!("custom:{tag}"))
}

fn class_channel_binding(label: &str) -> Result<[u8; CHANNEL_BINDING_LEN]> {
  let mut hasher = sha2::Sha256::new();
  hasher.update(CLASS_BINDING_LABEL);
  hasher.update(label.as_bytes());
  hasher
    .finalize()
    .as_slice()
    .try_into()
    .map_err(|_| Error::internal("channel binding class"))
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
