//! The built-in plaintext TCP transport.
//!
//! **Scope: closed intranet segments that cannot operate TLS 1.3.** The
//! intended occupants are constrained IoT devices — microcontrollers
//! with kilobytes of RAM, no hardware acceleration, and no prospect of
//! a TLS 1.3 stack — attached to a physically or administratively closed
//! network segment. On this transport the operator owns
//! confidentiality and integrity entirely: there is no encryption, no
//! server certificate, and no man-in-the-middle protection at the
//! channel layer. The session handshake above it still authenticates
//! both endpoints (identity proofs over the transcript and the
//! transport's class channel binding), but authentication is not
//! confidentiality: never expose a `tcp://` listener to an untrusted
//! network.
//!
//! The wire format is the framing layer's tag discipline — the same
//! bounds and keepalive semantics as the TLS classes, and the same
//! single-frame join hint before the handshake.

use std::fmt;

use tokio::net::TcpListener;

use super::{
  connection::{Connection, FrameRules, plaintext_channel_binding},
  endpoint::{Endpoint, TransportScheme},
  framing::MergeHint,
  registry::{Transport, TransportListener, TransportTrust},
  tcp,
};
use crate::{
  Error, ProviderErrorContext, Result, TransportTag, api::BoxFuture,
  protocol::wire::connection_frame_rules,
};

/// The canonical tag of the built-in plaintext transport: the
/// closed-intranet IoT choice, selected by `tcp://` endpoints.
pub(crate) const BUILTIN_TRANSPORT_TCP: &str = "radiata.woooo.tech/transports/tcp";

/// The built-in plaintext TCP transport.
pub(crate) struct PlainTransport;

impl fmt::Debug for PlainTransport {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("PlainTransport")
      .finish_non_exhaustive()
  }
}

impl PlainTransport {
  pub(crate) fn new() -> Self {
    Self
  }

  /// The canonical tag of the built-in transport, parsed once.
  pub(crate) fn tag() -> Result<TransportTag> {
    // The literal is a fixed canonical constant; parse once and surface the
    // impossible failure as an internal error instead of panicking.
    static TAG: std::sync::OnceLock<std::result::Result<TransportTag, ()>> =
      std::sync::OnceLock::new();
    TAG
      .get_or_init(|| TransportTag::parse(BUILTIN_TRANSPORT_TCP).map_err(|_| ()))
      .clone()
      .map_err(|_| crate::Error::internal("built-in transport tag"))
  }
}

impl Transport for PlainTransport {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    Box::pin(async move {
      let (listener, bound) = tcp::bind(&endpoint, TransportScheme::Tcp).await?;
      let rules = connection_frame_rules()?;
      let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
      Ok(Box::new(PlainListener {
        listener,
        shutdown_tx,
        shutdown: shutdown_rx,
        rules,
        bound,
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect(
    &self, endpoint: Endpoint, trust: TransportTrust,
  ) -> BoxFuture<'static, Result<Connection>> {
    Box::pin(async move {
      // The plaintext transport only accepts plaintext trust: a TLS
      // trust mode arriving here is a caller bug (the endpoint scheme
      // and the trust intent disagree) and fails typed instead of
      // silently downgrading the intended channel.
      if !matches!(trust, TransportTrust::Plaintext) {
        return Err(Error::invalid_input("transport trust"));
      }
      let tcp = tcp::dial(&endpoint, ProviderErrorContext::TransportConnect).await?;
      let rules = connection_frame_rules()?;
      let channel_binding = plaintext_channel_binding()?;
      let (read, write) = tokio::io::split(tcp);
      Connection::connect_raw(
        Box::new(read),
        super::framing::shared_write(Box::new(write)),
        channel_binding,
        rules,
      )
      .await
    })
  }
}

/// A [`TransportListener`] for the built-in plaintext transport.
pub(crate) struct PlainListener {
  listener: TcpListener,
  shutdown_tx: tokio::sync::watch::Sender<()>,
  shutdown: tokio::sync::watch::Receiver<()>,
  rules: FrameRules,
  bound: Endpoint,
}

impl fmt::Debug for PlainListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("PlainListener")
      .field("bound", &self.bound)
      .finish_non_exhaustive()
  }
}

impl TransportListener for PlainListener {
  fn local_endpoint(&self) -> Endpoint {
    self.bound.clone()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let rules = self.rules;
    let mut shutdown = self.shutdown.clone();
    Box::pin(async move {
      let tcp = tcp::accept(
        &self.listener,
        &mut shutdown,
        ProviderErrorContext::TransportAccept,
      )
      .await?;
      let peer_addr = tcp.peer_addr().ok();
      // The plaintext class serves no leaf SPKI: there is no certificate
      // to pin, so member-mode reconnects over `tcp://` rely on the
      // handshake proofs alone.
      let hint = hint();
      let channel_binding = plaintext_channel_binding()?;
      let (read, write) = tokio::io::split(tcp);
      Connection::accept_raw(
        Box::new(read),
        super::framing::shared_write(Box::new(write)),
        channel_binding,
        rules,
        peer_addr,
        true,
        hint.as_ref(),
      )
      .await
    })
  }

  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      // Signalling only wakes a pending accept (it returns the shutdown
      // error); the socket stays bound until the owner drops the
      // listener, which is what releases the address for a rebind.
      let _ = self.shutdown_tx.send(());
      Ok(())
    })
  }
}
