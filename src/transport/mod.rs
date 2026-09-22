//! The transport layer: pluggable session channels under one framed
//! connection contract.
//!
//! The layer is open by construction: a transport owns the
//! listener/connection lifecycle for one canonical [`TransportTag`],
//! the endpoint's [`TransportSelector`] is the resolution key, and the
//! extension registry is the single map from selector to implementation.
//! Callers register custom media (an ESP-NOW radio, an 802.11 link, a
//! serial bus) through [`crate::CustomTransport`]; the three built-ins
//! cover the ordinary deployment space:
//!
//! - [`tls_transport`] — direct TLS 1.3 over TCP. **The default**: the
//!   simplest, cheapest stream; advertise `tls://` endpoints unless a
//!   constraint below applies.
//! - [`wss`] — WebSocket over TLS 1.3. The **firewall-traversal** choice: the
//!   HTTP upgrade masquerades as web traffic, for nodes behind proxies and
//!   web-traffic-only filters.
//! - [`plain`] — plaintext TCP. For **closed intranet segments with constrained
//!   IoT devices** that cannot deploy TLS 1.3; the operator owns channel
//!   confidentiality there.
//!
//! Ownership boundaries:
//!
//! - [`tls`] builds the TLS 1.3-only rustls client/server configurations:
//!   aws-lc-rs provider, no TLS 1.2 (the rustls `tls12` feature is not compiled
//!   in), no early data, no session resumption, no ALPN requirement.
//! - [`verify`] holds the security-critical server certificate verifier: join
//!   mode relaxes chain and hostname trust, but every mode fully validates the
//!   TLS 1.3 `CertificateVerify` signature. There is no accept-anything path.
//! - [`cert`] generates the receiver's ephemeral self-signed listener
//!   certificate from injected entropy. The certificate is memory-only, fresh
//!   per listener, and never a node identity or trust record.
//! - [`framing`] frames wire messages over bare byte streams (direct TLS,
//!   plaintext TCP, custom transports) with bounded length discipline,
//!   keepalive, and the single-frame join hint; the WebSocket class frames
//!   through tungstenite with the same bounds.
//! - [`connection`] carries the framed wire messages of every class with
//!   identical prelude and limit semantics, and derives the channel binding
//!   each class authenticates over.
//! - [`endpoint`] carries the public `Endpoint` value type (canonical
//!   `<scheme>host[:port]` and `<tag>+<opaque>` forms) used to address
//!   listeners and peers.
//! - [`registry`] carries the open transport map: the internal
//!   [`registry::Transport`] boundary, the public [`registry::CustomTransport`]
//!   extension surface, and the trust intent dials carry.

pub(crate) mod cert;
pub(crate) mod connection;
pub(crate) use connection::Received;
mod endpoint;
pub(crate) mod framing;
pub(crate) mod plain;
pub(crate) mod registry;
pub(crate) mod tcp;
pub(crate) mod tls;
pub(crate) mod tls_transport;
pub(crate) mod verify;
pub(crate) mod ws;
pub(crate) mod wss;

pub use endpoint::{Endpoint, TransportScheme, TransportSelector};
pub use registry::{CustomListener, CustomTransport, TransportStream};

pub use crate::paging::PageCursor;

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
