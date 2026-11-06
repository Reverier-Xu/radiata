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

use std::fmt;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::{
  connection::{Connection, FrameRules},
  endpoint::{Endpoint, TransportScheme},
  framing::MergeHint,
  registry::{Transport, TransportAdmission, TransportListener},
  tcp, tls,
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
      let (listener, bound) = tcp::bind(&endpoint, TransportScheme::Tls).await?;
      let config = tls::listener_tls(&SystemEntropy)?;
      let rules = connection_frame_rules()?;
      let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
      Ok(Box::new(TlsListener {
        listener,
        shutdown_tx,
        shutdown: shutdown_rx,
        acceptor: TlsAcceptor::from(config),
        rules,
        bound,
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
      let tls_stream = tokio_rustls::TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .map_err(|error| {
          super::connection::tls_handshake_error(
            &error,
            ProviderErrorContext::TransportConnect,
            "tls connect",
          )
        })?;
      let channel_binding = super::connection::exporter_channel_binding(tls_stream.get_ref().1)?;
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
  bound: Endpoint,
  admission: TransportAdmission,
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
      let hint = hint();
      let tls_stream = self.acceptor.accept(tcp).await.map_err(|error| {
        super::connection::tls_handshake_error(
          &error,
          ProviderErrorContext::TransportAccept,
          "tls accept",
        )
      })?;
      let peer_addr = tls_stream.get_ref().0.peer_addr().ok();
      let channel_binding = super::connection::exporter_channel_binding(tls_stream.get_ref().1)?;
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
      // Signalling only wakes a pending accept (it returns the shutdown
      // error); the socket stays bound until the owner drops the
      // listener, which is what releases the address for a rebind.
      let _ = self.shutdown_tx.send(());
      Ok(())
    })
  }
}
