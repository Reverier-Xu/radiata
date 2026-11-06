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

use super::{
  connection::{Connection, FrameRules, plaintext_channel_binding},
  endpoint::{Endpoint, TransportScheme},
  framing::MergeHint,
  registry::{Transport, TransportAdmission, TransportListener},
  tcp::{self, TcpListenerBase},
};
use crate::{ProviderErrorContext, Result, api::BoxFuture, protocol::wire::connection_frame_rules};

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
}

impl Transport for PlainTransport {
  fn admission(&self) -> TransportAdmission {
    TransportAdmission::PeerAddressed
  }

  fn bind(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Box<dyn TransportListener>>> {
    let admission = self.admission();
    Box::pin(async move {
      let base = TcpListenerBase::bind(&endpoint, TransportScheme::Tcp).await?;
      let rules = connection_frame_rules()?;
      Ok(Box::new(PlainListener {
        base,
        rules,
        admission,
      }) as Box<dyn TransportListener>)
    })
  }

  fn connect(&self, endpoint: Endpoint) -> BoxFuture<'static, Result<Connection>> {
    Box::pin(async move {
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
  base: TcpListenerBase,
  rules: FrameRules,
  admission: TransportAdmission,
}

impl fmt::Debug for PlainListener {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("PlainListener")
      .field("bound", &self.base.local_endpoint())
      .finish_non_exhaustive()
  }
}

impl TransportListener for PlainListener {
  fn local_endpoint(&self) -> Endpoint {
    self.base.local_endpoint()
  }

  fn accept<'a>(
    &'a self, hint: &'a (dyn Fn() -> Option<MergeHint> + Send + Sync),
  ) -> BoxFuture<'a, Result<Connection>> {
    let rules = self.rules;
    Box::pin(async move {
      let tcp = self.base.accept_tcp().await?;
      let peer_addr = tcp.peer_addr().ok();
      // The plaintext class serves no TLS material: the member-mode
      // reconnects over `tcp://` rely on the handshake proofs alone.
      let hint = hint();
      let channel_binding = plaintext_channel_binding()?;
      let (read, write) = tokio::io::split(tcp);
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
