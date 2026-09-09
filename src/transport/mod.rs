//! Built-in TLS 1.3 WebSocket transport.
//!
//! The module is crate-private infrastructure for the session driver and
//! the public facade; only the [`Endpoint`] value type crosses the crate
//! boundary (re-exported at the crate root). Ownership boundaries:
//!
//! - [`tls`] builds the TLS 1.3-only rustls client/server configurations: ring
//!   provider, no TLS 1.2 (the rustls `tls12` feature is not compiled in), no
//!   early data, no session resumption, no ALPN requirement.
//! - [`verify`] holds the security-critical server certificate verifier: join
//!   mode relaxes chain and hostname trust, but every mode fully validates the
//!   TLS 1.3 `CertificateVerify` signature. There is no accept-anything path.
//! - [`cert`] generates the receiver's ephemeral self-signed listener
//!   certificate from injected entropy. The certificate is memory-only, fresh
//!   per listener, and never a node identity or trust record.
//! - [`ws`] runs the WebSocket handshake over the TLS stream on the fixed
//!   `/mrly` path with binary messages only and no per-message compression. The
//!   upgrade response carries the listener's non-secret join hints (cluster ID,
//!   credential generation ID) inside the TLS channel.
//! - [`connection`] frames prelude messages over the WebSocket stream with
//!   bounded receive and derives the RFC 9266 `tls-exporter` channel binding
//!   from the local TLS connection.
//! - [`endpoint`] carries the public `Endpoint` value type (canonical
//!   `wss://host[:port]` text) used to address listeners and peers.

pub(crate) mod candidates;
pub(crate) mod cert;
pub(crate) mod connection;
mod endpoint;
pub(crate) mod registry;
pub(crate) mod tls;
pub(crate) mod verify;
pub(crate) mod ws;

pub use endpoint::Endpoint;
pub use registry::{ChannelBinding, Discovery, DiscoveryPage, EndpointCandidate, PageCursor};

/// Shared test harness for the transport module lanes.
#[cfg(test)]
pub(crate) mod testing {
  use rustls::pki_types::ServerName;

  use crate::api::Entropy;

  /// Deterministic entropy filling every requested byte with one seed
  /// value; shared so certificate, tls, verifier, and connection tests
  /// cannot drift in how they seed ephemeral keys.
  #[derive(Debug)]
  pub(crate) struct SeedEntropy(pub u8);

  impl Entropy for SeedEntropy {
    fn fill(&self, output: &mut [u8]) -> crate::Result<()> {
      output.fill(self.0);
      Ok(())
    }
  }

  /// The TLS SNI used by verifier and connection loopback tests.
  pub(crate) fn server_name() -> ServerName<'static> {
    ServerName::try_from("receiver.test").unwrap().to_owned()
  }
}
