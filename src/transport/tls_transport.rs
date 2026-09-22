//! The built-in direct TLS transport: TLS 1.3 straight over TCP.
//!
//! **This is the default transport.** It is the simplest and cheapest
//! stream the crate offers: one TLS 1.3 channel, no upgrade layer, no
//! per-message framing overhead beyond the wire prelude. New
//! deployments should advertise `tls://` endpoints unless a middlebox
//! scenario forces the `wss://` form (firewalls and proxies that only
//! pass web traffic) or the segment cannot operate TLS 1.3 at all
//! (then `tcp://`, with the operator owning channel security).
//!
//! Security identity matches the WebSocket class exactly: the same
//! ephemeral listener certificate, the same verifier trust modes, the
//! same RFC 9266 exporter channel binding — only the message layer
//! differs. The join hint travels as the framing layer's single hint
//! frame instead of WebSocket upgrade headers.

use std::fmt;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::{
  connection::{Connection, FrameRules, exporter_channel_binding},
  endpoint::{Endpoint, TransportScheme},
  framing::MergeHint,
  registry::{Transport, TransportListener, TransportTrust},
  tcp, tls,
};
use crate::{
  Error, ProviderErrorContext, Result, TransportTag,
  api::{BoxFuture, SystemEntropy},
  protocol::wire::connection_frame_rules,
};

/// The canonical tag of the built-in direct TLS transport: the default
/// choice, selected by `tls://` endpoints.
pub(crate) const BUILTIN_TRANSPORT_TLS: &str = "radiata.woooo.tech/transports/tls";

/// The built-in direct TLS transport.
pub(crate) struct TlsTransport;

impl fmt::Debug for TlsTransport {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TlsTransport")
      .finish_non_exhaustive()
  }
}

impl TlsTransport {
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
      .get_or_init(|| TransportTag::parse(BUILTIN_TRANSPORT_TLS).map_err(|_| ()))
      .clone()
      .map_err(|_| crate::Error::internal("built-in transport tag"))
  }
}

impl Transport for TlsTransport {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    Box::pin(async move {
      let (listener, bound) = tcp::bind(&endpoint, TransportScheme::Tls).await?;
      let security = tls::listener_tls(&SystemEntropy)?;
      let rules = connection_frame_rules()?;
      let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
      Ok(Box::new(TlsListener {
        listener,
        shutdown_tx,
        shutdown: shutdown_rx,
        acceptor: TlsAcceptor::from(security.config),
        rules,
        leaf: security.leaf_spki,
        bound,
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect(
    &self, endpoint: Endpoint, trust: TransportTrust,
  ) -> BoxFuture<'static, Result<Connection>> {
    Box::pin(async move {
      // Reject a mismatched trust intent before any wire activity: a
      // plaintext trust on a TLS transport is a caller bug and fails
      // typed instead of downgrading the channel.
      let config = tls::client_config_for_trust(&trust)?;
      let tcp = tcp::dial(&endpoint, ProviderErrorContext::TransportConnect).await?;
      let server_name = endpoint.server_name()?;
      tracing::debug!("tls connection established");
      let tls_stream = tokio_rustls::TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .map_err(|_| Error::authentication_failed("tls connect"))?;
      let channel_binding = exporter_channel_binding(tls_stream.get_ref().1)?;
      let rules = connection_frame_rules()?;
      let (read, write) = tokio::io::split(tls_stream);
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

/// A [`TransportListener`] for the built-in direct TLS transport.
pub(crate) struct TlsListener {
  listener: TcpListener,
  shutdown_tx: tokio::sync::watch::Sender<()>,
  shutdown: tokio::sync::watch::Receiver<()>,
  acceptor: TlsAcceptor,
  rules: FrameRules,
  leaf: Option<Vec<u8>>,
  bound: Endpoint,
}

impl fmt::Debug for TlsListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TlsListener")
      .field("bound", &self.bound)
      .finish_non_exhaustive()
  }
}

impl TransportListener for TlsListener {
  fn local_endpoint(&self) -> Endpoint {
    self.bound.clone()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let rules = self.rules;
    let mut shutdown = self.shutdown.clone();
    let leaf = self.leaf.clone();
    Box::pin(async move {
      let tcp = tcp::accept(
        &self.listener,
        &mut shutdown,
        ProviderErrorContext::TransportAccept,
      )
      .await?;
      // The hint is evaluated after the kernel accept, exactly like the
      // WebSocket class: the served generation is always the issuer's
      // current one.
      let mut hint = hint();
      if let Some(hint) = hint.as_mut()
        && let Some(spki) = leaf
      {
        *hint = hint.clone().with_leaf_spki(spki);
      }
      tracing::debug!("tls connection accepted");
      let tls_stream = self
        .acceptor
        .accept(tcp)
        .await
        .map_err(|_| Error::authentication_failed("tls accept"))?;
      let peer_addr = tls_stream.get_ref().0.peer_addr().ok();
      let channel_binding = exporter_channel_binding(tls_stream.get_ref().1)?;
      let (read, write) = tokio::io::split(tls_stream);
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
