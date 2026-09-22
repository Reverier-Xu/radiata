//! The built-in WebSocket transport: TLS 1.3 WebSocket over TCP.
//!
//! **This is the firewall-traversal transport, not the default.** The
//! HTTP upgrade layer makes every session look like ordinary HTTPS web
//! traffic to middleboxes, so a node can operate behind corporate
//! proxies, egress filters, and captive networks that only pass web
//! protocols. That camouflage costs one extra protocol layer and its
//! per-message framing overhead; deployments without such constraints
//! should advertise the direct `tls://` form instead. Choose `wss://`
//! endpoints when inbound connections must traverse web-traffic-only
//! infrastructure.
//!
//! The upgrade runs on the fixed `/mrly` path with binary messages only
//! and no per-message compression (the tungstenite permessage-deflate
//! feature is not compiled in). The upgrade response carries the
//! listener's non-secret join hints (credential generation ID, leaf
//! SPKI) inside the TLS channel.

use std::{fmt, sync::Arc};

use tokio::net::TcpListener;

use super::{
  connection::{Connection, FrameRules},
  endpoint::{Endpoint, TransportScheme},
  framing::MergeHint,
  registry::{Transport, TransportListener, TransportTrust},
  tcp, tls,
};
use crate::{
  ProviderErrorContext, Result, TransportTag,
  api::{BoxFuture, SystemEntropy},
  protocol::wire::connection_frame_rules,
};

/// The canonical tag of the built-in WebSocket transport: the
/// firewall-traversal choice, selected by `wss://` endpoints.
pub(crate) const BUILTIN_TRANSPORT_WSS: &str = "radiata.woooo.tech/transports/wss";

/// The built-in WebSocket transport.
pub(crate) struct WssTransport;

impl fmt::Debug for WssTransport {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WssTransport")
      .finish_non_exhaustive()
  }
}

impl WssTransport {
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
      .get_or_init(|| TransportTag::parse(BUILTIN_TRANSPORT_WSS).map_err(|_| ()))
      .clone()
      .map_err(|_| crate::Error::internal("built-in transport tag"))
  }
}

impl Transport for WssTransport {
  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    Box::pin(async move {
      let (listener, bound) = tcp::bind(&endpoint, TransportScheme::Wss).await?;
      let security = tls::listener_tls(&SystemEntropy)?;
      let rules = connection_frame_rules()?;
      let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
      Ok(Box::new(WssListener {
        listener,
        shutdown_tx,
        shutdown: shutdown_rx,
        config: security.config,
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
      let rules = connection_frame_rules()?;
      Connection::connect_tls_ws(tcp, config, server_name, rules).await
    })
  }
}

/// A [`TransportListener`] for the built-in WebSocket transport.
pub(crate) struct WssListener {
  listener: TcpListener,
  shutdown_tx: tokio::sync::watch::Sender<()>,
  shutdown: tokio::sync::watch::Receiver<()>,
  config: Arc<rustls::ServerConfig>,
  rules: FrameRules,
  leaf: Option<Vec<u8>>,
  bound: Endpoint,
}

impl fmt::Debug for WssListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WssListener")
      .field("bound", &self.bound)
      .finish_non_exhaustive()
  }
}

impl TransportListener for WssListener {
  fn local_endpoint(&self) -> Endpoint {
    self.bound.clone()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let config = Arc::clone(&self.config);
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
      // The hint is evaluated after the kernel accept: the served
      // generation is the issuer's current one, not a snapshot from when
      // the listener started blocking. The listener's leaf SPKI is
      // attached here so reconnect pinning travels with the hint.
      let mut hint = hint();
      if let Some(hint) = hint.as_mut()
        && let Some(spki) = leaf
      {
        *hint = hint.clone().with_leaf_spki(spki);
      }
      Connection::accept_tls_ws(tcp, config, rules, hint.as_ref()).await
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
