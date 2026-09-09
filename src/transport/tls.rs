//! TLS 1.3-only rustls configuration.
//!
//! Every bootstrap and member session uses TLS 1.3:
//!
//! - The provider is rustls's `ring` provider. The rustls `tls12` feature is
//!   not compiled in, so the provider exposes only TLS 1.3 cipher suites; both
//!   configurations additionally pin `&[&TLS13]` explicitly. A TLS 1.2
//!   ClientHello therefore cannot negotiate.
//! - Early data is off: the server keeps `max_early_data_size = 0` and the
//!   client keeps `enable_early_data = false`.
//! - Session resumption is off: the server sends zero TLS 1.3 tickets
//!   (`send_tls13_tickets = 0`) and stores no sessions. rustls has no
//!   client-side `enable_tls13_tickets` switch; the client equivalent is
//!   `Resumption::disabled()`, which never retains or offers a ticket even if a
//!   server sends one.
//! - ALPN is not required: `alpn_protocols` stays empty on both sides; the
//!   WebSocket upgrade runs directly over the TLS stream.
//! - The merge-mode client verifier is the custom [`BootstrapCertVerifier`],
//!   never the WebPKI chain verifier.

use std::sync::Arc;

use rustls::{
  ClientConfig, ServerConfig,
  client::Resumption,
  crypto::{CryptoProvider, ring::default_provider},
  pki_types::SubjectPublicKeyInfoDer,
  server::NoServerSessionStorage,
  version::TLS13,
};

use super::{
  cert::EphemeralCertificate,
  verify::{BootstrapCertVerifier, TrustMode},
};
use crate::{Error, Result};

/// The ring-backed TLS 1.3-only provider.
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
  Arc::new(default_provider())
}

/// Builds the listener-side TLS configuration for one ephemeral
/// certificate. Client authentication is not requested: peer authentication
/// happens at the application proof layer.
pub(crate) fn server_config(certificate: &EphemeralCertificate) -> Result<Arc<ServerConfig>> {
  let mut config = ServerConfig::builder_with_provider(crypto_provider())
    .with_protocol_versions(&[&TLS13])
    .map_err(|_| Error::internal("tls server versions"))?
    .with_no_client_auth()
    .with_single_cert(certificate.chain(), certificate.private_key())
    .map_err(|_| Error::internal("tls server certificate"))?;

  config.max_early_data_size = 0;
  config.send_tls13_tickets = 0;
  config.session_storage = Arc::new(NoServerSessionStorage {});
  config.alpn_protocols = Vec::new();

  Ok(Arc::new(config))
}

/// Builds the merge-mode client configuration: chain and hostname trust are
/// relaxed, while the TLS 1.3 `CertificateVerify` signature remains fully
/// validated. The WebPKI chain
/// verifier is never used in join mode.
pub(crate) fn merge_client_config() -> Result<Arc<ClientConfig>> {
  client_config(TrustMode::Merge)
}

/// Builds the member-mode client configuration: the merge-mode relaxation
/// plus an exact expected leaf SubjectPublicKeyInfo binding. The durable
/// Ed25519 identity check happens at the application proof layer; the SPKI
/// pin is the TLS-layer anchor learned during a join.
pub(crate) fn member_client_config(
  expected_spki: SubjectPublicKeyInfoDer<'static>,
) -> Result<Arc<ClientConfig>> {
  client_config(TrustMode::Member { expected_spki })
}

fn client_config(mode: TrustMode) -> Result<Arc<ClientConfig>> {
  let provider = crypto_provider();
  let verifier = BootstrapCertVerifier::new(provider.signature_verification_algorithms, mode);
  let mut config = ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&TLS13])
    .map_err(|_| Error::internal("tls client versions"))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(verifier))
    .with_no_client_auth();

  config.resumption = Resumption::disabled();
  config.enable_early_data = false;
  config.alpn_protocols = Vec::new();

  Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
  use rustls::SupportedCipherSuite;

  use super::{crypto_provider, merge_client_config, server_config};
  use crate::transport::{cert::EphemeralCertificate, testing::SeedEntropy};

  #[test]
  fn tls_transport_provider_offers_only_tls13_cipher_suites() {
    let provider = crypto_provider();

    assert!(!provider.cipher_suites.is_empty());
    for suite in &provider.cipher_suites {
      assert!(
        matches!(suite, SupportedCipherSuite::Tls13(_)),
        "suite: {suite:?}"
      );
    }
  }

  #[test]
  fn tls_transport_configs_forbid_early_data_resumption_and_alpn() {
    let certificate = EphemeralCertificate::generate(&SeedEntropy(3)).unwrap();
    let server = server_config(&certificate).unwrap();
    let client = merge_client_config().unwrap();

    // Server: no early data, no TLS 1.3 tickets, no session storage, no
    // ALPN offer.
    assert_eq!(server.max_early_data_size, 0);
    assert_eq!(server.send_tls13_tickets, 0);
    assert!(server.alpn_protocols.is_empty());
    // Session storage is `NoServerSessionStorage` by construction; rustls
    // exposes no downcast on the trait object, so the assignment is asserted
    // by construction review and the resumption tests instead of a type id.
    assert_eq!(server.send_tls13_tickets, 0);

    // Client: no early data and no ALPN offer. The resumption store is
    // `Resumption::disabled()` by construction in `client_config`; rustls
    // exposes no `enable_tls13_tickets` switch, so disabling the store is
    // the client-side ticket opt-out (see module documentation).
    assert!(!client.enable_early_data);
    assert!(client.alpn_protocols.is_empty());
  }

  #[tokio::test]
  async fn tls_transport_rejects_tls12_only_client_hello() {
    use tokio::net::{TcpListener, TcpStream};

    let certificate = EphemeralCertificate::generate(&SeedEntropy(5)).unwrap();
    let config = server_config(&certificate).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let client = tokio::spawn(async move {
      let mut stream = TcpStream::connect(address).await.unwrap();
      // A TLS 1.2-only ClientHello: legacy version 0x0303 and a
      // supported_versions extension listing exactly 0x0303.
      let mut hello_body = vec![0x03, 0x03];
      hello_body.extend_from_slice(&[0xAA; 32]);
      hello_body.push(0); // empty session id
      hello_body.extend_from_slice(&[0x00, 0x02, 0xC0, 0x2F]); // one TLS 1.2 suite
      hello_body.extend_from_slice(&[0x01, 0x00]); // null compression
      hello_body.extend_from_slice(&[0x00, 0x07]); // extensions block length
      hello_body.extend_from_slice(&[0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x03]);
      let mut handshake = vec![0x01];
      handshake.extend_from_slice(&(hello_body.len() as u32).to_be_bytes()[1..]);
      handshake.extend_from_slice(&hello_body);
      let mut record = vec![0x16, 0x03, 0x01];
      record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
      record.extend_from_slice(&handshake);

      use tokio::io::AsyncWriteExt;
      stream.write_all(&record).await.unwrap();
      // The server aborts the handshake; the peer sees an error or EOF.
      let mut buffer = [0_u8; 64];
      use tokio::io::AsyncReadExt;
      let _ = stream.read(&mut buffer).await;
    });

    let (tcp, _) = listener.accept().await.unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    assert!(acceptor.accept(tcp).await.is_err());

    client.await.unwrap();
  }
}
