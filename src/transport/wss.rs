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
//! listener's non-secret join hint (the credential generation ID) inside
//! the TLS channel.

use std::{fmt, sync::Arc};

use super::{
  connection::{Connection, FrameRules},
  endpoint::{Endpoint, TransportScheme},
  framing::MergeHint,
  registry::{Transport, TransportAdmission, TransportListener},
  tcp::{self, TcpListenerBase},
  tls,
};
use crate::{
  ProviderErrorContext, Result,
  api::{BoxFuture, SystemEntropy},
  protocol::wire::connection_frame_rules,
};

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
}

impl Transport for WssTransport {
  fn admission(&self) -> TransportAdmission {
    TransportAdmission::PeerAddressed
  }

  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    let admission = self.admission();
    Box::pin(async move {
      let base = TcpListenerBase::bind(&endpoint, TransportScheme::Wss).await?;
      let config = tls::listener_tls(&SystemEntropy)?;
      let rules = connection_frame_rules()?;
      Ok(Box::new(WssListener {
        base,
        config,
        rules,
        admission,
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Connection>> {
    Box::pin(async move {
      // The client configuration is unconditional: the TLS 1.3 channel
      // always comes up, and the session handshake authenticates over
      // its exporter binding.
      let config = tls::merge_client_config()?;
      let tcp = tcp::dial(&endpoint, ProviderErrorContext::TransportConnect).await?;
      let server_name = endpoint.server_name()?;
      let rules = connection_frame_rules()?;
      Connection::connect_tls_ws(tcp, config, server_name, rules).await
    })
  }
}

/// A [`TransportListener`] for the built-in WebSocket transport.
pub(crate) struct WssListener {
  base: TcpListenerBase,
  config: Arc<rustls::ServerConfig>,
  rules: FrameRules,
  admission: TransportAdmission,
}

impl fmt::Debug for WssListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WssListener")
      .field("bound", &self.base.local_endpoint())
      .finish_non_exhaustive()
  }
}

impl TransportListener for WssListener {
  fn local_endpoint(&self) -> Endpoint {
    self.base.local_endpoint()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let config = Arc::clone(&self.config);
    let rules = self.rules;
    let admission = self.admission;
    Box::pin(async move {
      let tcp = self.base.accept_tcp().await?;
      // The hint is evaluated after the kernel accept: the served
      // generation is the issuer's current one, not a snapshot from when
      // the listener started blocking.
      let hint = hint();
      Connection::accept_tls_ws(tcp, config, rules, admission, hint.as_ref()).await
    })
  }

  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      self.base.close();
      Ok(())
    })
  }
}
