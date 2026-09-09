//! Security-critical server certificate verifier.
//!
//! Join mode relaxes certificate-chain and hostname trust only, because the
//! receiver presents an unknown self-signed ephemeral certificate.
//! Unconditional certificate or handshake-signature acceptance is forbidden:
//! the TLS 1.3 `CertificateVerify` signature must always be fully validated
//! against the presented leaf key, and unsupported signature schemes must be
//! rejected. This module is the single implementation of that rule; it has
//! no accept-anything path.
//!
//! - [`TrustMode::Merge`]: chain, hostname, and validity-window trust are
//!   relaxed. The certificate is not a node identity or trust record; receiver
//!   authentication happens at the application proof layer over the RFC 9266
//!   channel binding.
//! - [`TrustMode::Member`]: the same relaxed chain/hostname policy plus an
//!   exact binding of the presented leaf SubjectPublicKeyInfo to an expected
//!   key. The exact Ed25519 identity check (proof of possession over the
//!   exporter-bound transcript) happens at the application proof layer, not
//!   here.
//!
//! Focused review notes:
//!
//! - `verify_tls13_signature` delegates to rustls's WebPKI signature
//!   verification, which rejects signature schemes that are not valid for TLS
//!   1.3, schemes outside the provider's mapping, malformed certificates, and
//!   invalid signatures.
//! - `verify_tls12_signature` rejects unconditionally: TLS 1.2 is compiled out
//!   (no rustls `tls12` feature) and both endpoint configurations pin TLS 1.3,
//!   so a TLS 1.2 `CertificateVerify` can never be legitimate.
//! - `verify_server_cert` rejects empty and malformed leaves even in join mode;
//!   relaxation never extends to undecodable input.

use rustls::{
  CertificateError, DigitallySignedStruct, Error as RustlsError, PeerIncompatible, SignatureScheme,
  client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
  crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature},
  pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
  server::ParsedCertificate,
};

/// The trust relaxation applied for one authentication mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TrustMode {
  /// Merge mode: the receiver's self-signed ephemeral certificate is unknown
  /// up front, so chain and hostname trust are relaxed. Credential and
  /// identity proofs over the channel binding authenticate the receiver.
  Merge,
  /// Member mode: the merge-mode relaxation plus an exact expected leaf
  /// SubjectPublicKeyInfo binding. The durable Ed25519 identity binding is
  /// still established by the application proof layer, not by this
  /// verifier.
  #[allow(dead_code)] // wired through member-mode dialing; loopback tests construct it directly.
  Member {
    /// The exact expected leaf SubjectPublicKeyInfo.
    expected_spki: SubjectPublicKeyInfoDer<'static>,
  },
}

/// The bootstrap server certificate verifier.
#[derive(Debug)]
pub(crate) struct BootstrapCertVerifier {
  supported: WebPkiSupportedAlgorithms,
  mode: TrustMode,
}

impl BootstrapCertVerifier {
  pub(crate) const fn new(supported: WebPkiSupportedAlgorithms, mode: TrustMode) -> Self {
    Self { supported, mode }
  }
}

impl ServerCertVerifier for BootstrapCertVerifier {
  fn verify_server_cert(
    &self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
    _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
  ) -> Result<ServerCertVerified, RustlsError> {
    // The mode relaxes chain, hostname, and validity-window trust. The leaf
    // must still carry bytes and decode as a well-formed X.509 certificate;
    // anything less fails closed.
    if end_entity.as_ref().is_empty() {
      return Err(RustlsError::InvalidCertificate(
        CertificateError::BadEncoding,
      ));
    }
    let parsed = ParsedCertificate::try_from(end_entity)
      .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;

    if let TrustMode::Member { expected_spki } = &self.mode
      && parsed.subject_public_key_info() != *expected_spki
    {
      return Err(RustlsError::InvalidCertificate(
        CertificateError::ApplicationVerificationFailure,
      ));
    }

    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    // TLS 1.2 is compiled out and both configurations pin TLS 1.3, so this
    // path is unreachable; refuse unconditionally instead of accepting
    // anything.
    Err(PeerIncompatible::Tls12NotOffered.into())
  }

  fn verify_tls13_signature(
    &self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    // Full validation of the TLS 1.3 CertificateVerify signature against
    // the presented leaf key. rustls rejects schemes that are not valid for
    // TLS 1.3, schemes outside the provider mapping, malformed
    // certificates, and invalid signatures.
    verify_tls13_signature(message, cert, dss, &self.supported)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    // TLS 1.3 CertificateVerify schemes only; TLS 1.2 RSA-PKCS1 and SHA-1
    // schemes are never advertised even though the provider lists them.
    self
      .supported
      .supported_schemes()
      .into_iter()
      .filter(|scheme| {
        matches!(
          scheme,
          SignatureScheme::ED25519
            | SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512
        )
      })
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use rustls::{
    SignatureScheme,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, UnixTime},
    server::ParsedCertificate,
  };

  use super::{BootstrapCertVerifier, TrustMode};
  use crate::transport::{
    cert::EphemeralCertificate,
    testing::{SeedEntropy, server_name},
    tls::crypto_provider,
  };

  fn verifier(mode: TrustMode) -> BootstrapCertVerifier {
    BootstrapCertVerifier::new(crypto_provider().signature_verification_algorithms, mode)
  }

  fn certificate(seed: u8) -> EphemeralCertificate {
    EphemeralCertificate::generate(&SeedEntropy(seed)).unwrap()
  }

  #[test]
  fn tls_transport_verifier_join_mode_accepts_unknown_self_signed_leaf() {
    let certificate = certificate(7);
    let verifier = verifier(TrustMode::Merge);

    verifier
      .verify_server_cert(
        certificate.end_entity(),
        &[],
        &server_name(),
        &[],
        UnixTime::now(),
      )
      .unwrap();
  }

  #[test]
  fn tls_transport_verifier_rejects_empty_and_malformed_leaves() {
    let verifier = verifier(TrustMode::Merge);

    let empty = CertificateDer::from(Vec::new());
    assert!(
      verifier
        .verify_server_cert(&empty, &[], &server_name(), &[], UnixTime::now())
        .is_err()
    );

    for garbage in [
      vec![0x30],
      vec![0x30, 0x03, 0x02, 0x01],
      b"not a certificate".to_vec(),
    ] {
      let malformed = CertificateDer::from(garbage);
      assert!(
        verifier
          .verify_server_cert(&malformed, &[], &server_name(), &[], UnixTime::now())
          .is_err()
      );
    }
  }

  #[test]
  fn tls_transport_verifier_member_mode_binds_expected_leaf_key() {
    let expected = certificate(7);
    let other = certificate(9);
    let expected_spki = ParsedCertificate::try_from(expected.end_entity())
      .unwrap()
      .subject_public_key_info();
    let verifier = verifier(TrustMode::Member { expected_spki });

    verifier
      .verify_server_cert(
        expected.end_entity(),
        &[],
        &server_name(),
        &[],
        UnixTime::now(),
      )
      .unwrap();
    assert!(
      verifier
        .verify_server_cert(
          other.end_entity(),
          &[],
          &server_name(),
          &[],
          UnixTime::now()
        )
        .is_err()
    );
  }

  // `verify_tls12_signature` cannot be exercised in isolation because
  // rustls exposes no `DigitallySignedStruct` constructor; its unconditional
  // rejection is covered end to end by the raw TLS 1.2 ClientHello test in
  // `super::tls` and by review of its single `Err` return.

  #[test]
  fn tls_transport_verifier_signature_schemes_are_tls13_capable() {
    let verifier = verifier(TrustMode::Merge);

    for scheme in verifier.supported_verify_schemes() {
      assert!(!matches!(
        scheme,
        SignatureScheme::RSA_PKCS1_SHA256
          | SignatureScheme::RSA_PKCS1_SHA384
          | SignatureScheme::RSA_PKCS1_SHA512
          | SignatureScheme::ECDSA_SHA1_Legacy
          | SignatureScheme::RSA_PKCS1_SHA1
      ));
    }
    assert!(
      verifier
        .supported_verify_schemes()
        .contains(&SignatureScheme::ED25519)
    );
  }

  #[test]
  fn tls_transport_verifier_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BootstrapCertVerifier>();
    assert_send_sync::<TrustMode>();
    let _ = Arc::new(verifier(TrustMode::Merge));
  }
}
