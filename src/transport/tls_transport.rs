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
//! ephemeral listener certificate, the same verifier trust relaxation, the
//! same RFC 9266 exporter channel binding — only the message layer
//! differs. The join hint travels as the framing layer's single hint
//! frame instead of WebSocket upgrade headers.

use std::{fmt, sync::Arc};

use super::{
  connection::{Connection, FrameRules, accept_tls_raw, connect_tls_raw},
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
}

impl Transport for TlsTransport {
  fn admission(&self) -> TransportAdmission {
    TransportAdmission::PeerAddressed
  }

  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    let admission = self.admission();
    Box::pin(async move {
      let base = TcpListenerBase::bind(&endpoint, TransportScheme::Tls).await?;
      let config = tls::listener_tls(&SystemEntropy)?;
      let rules = connection_frame_rules()?;
      Ok(Box::new(TlsListener {
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
      let (tls_stream, channel_binding) = connect_tls_raw(tcp, config, server_name).await?;
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
  base: TcpListenerBase,
  config: Arc<rustls::ServerConfig>,
  rules: FrameRules,
  admission: TransportAdmission,
}

impl fmt::Debug for TlsListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TlsListener")
      .field("bound", &self.base.local_endpoint())
      .finish_non_exhaustive()
  }
}

impl TransportListener for TlsListener {
  fn local_endpoint(&self) -> Endpoint {
    self.base.local_endpoint()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let config = Arc::clone(&self.config);
    let rules = self.rules;
    Box::pin(async move {
      let tcp = self.base.accept_tcp().await?;
      // The hint is evaluated after the kernel accept, exactly like the
      // WebSocket class: the served generation is always the issuer's
      // current one.
      let hint = hint();
      let (tls_stream, peer_addr, channel_binding) = accept_tls_raw(tcp, config).await?;
      let (read, write) = tokio::io::split(tls_stream);
      Connection::accept_raw(
        Box::new(read),
        super::framing::shared_write(Box::new(write)),
        channel_binding,
        rules,
        peer_addr,
        self.admission,
        hint.as_ref(),
      )
      .await
    })
  }

  fn close<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      self.base.close();
      Ok(())
    })
  }
}
