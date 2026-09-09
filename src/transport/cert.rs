//! Ephemeral self-signed listener certificates.
//!
//! Every listener generates a fresh ephemeral certificate key pair from the
//! injected entropy boundary. The certificate is memory-only, never
//! persisted, never derived from the durable identity key, and never a node
//! identity or trust record; it may change on every restart and on every
//! `Listen`.
//!
//! Algorithm choice: Ed25519. rcgen's `ring` crypto backend supports Ed25519
//! signing and PKCS#8 import, so the certificate key shares no code path
//! with the durable identity key even though both use Ed25519. (ECDSA P-256
//! would be the fallback if ring Ed25519 support were
//! unavailable.) The 32-byte seed comes entirely from the injected
//! [`Entropy`]; rcgen's own randomness is only used internally for ECDSA
//! key import, which Ed25519 never touches.

use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::Zeroizing;

use crate::{Error, Result, api::Entropy};

/// PKCS#8 v1 `OneAsymmetricKey` DER prefix wrapping a raw 32-byte Ed25519
/// seed: `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING {
/// OCTET STRING <seed> } }`.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
  0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const SEED_LEN: usize = 32;

/// One memory-only ephemeral listener certificate and its private key.
pub(crate) struct EphemeralCertificate {
  cert: CertificateDer<'static>,
  key: PrivateKeyDer<'static>,
}

impl EphemeralCertificate {
  /// Generates a fresh self-signed Ed25519 certificate from injected
  /// entropy. rcgen fixes the validity window to 1975-01-01 through
  /// 4096-01-01 and derives the serial number from the public key, so the
  /// output is deterministic in the seed and independent of any clock.
  pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
    let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
    entropy.fill(&mut seed[..])?;

    let mut pkcs8 = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + SEED_LEN);
    pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(&seed[..]);
    let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8);
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
      .map_err(|_| Error::internal("ephemeral certificate key"))?;

    let mut params = CertificateParams::default();
    params
      .distinguished_name
      .push(DnType::CommonName, "radiata ephemeral listener");
    let cert = params
      .self_signed(&key_pair)
      .map_err(|_| Error::internal("ephemeral certificate"))?;

    Ok(Self {
      cert: cert.der().clone(),
      key: PrivateKeyDer::Pkcs8(pkcs8),
    })
  }

  /// The single-certificate chain presented to TLS peers.
  pub(crate) fn chain(&self) -> Vec<CertificateDer<'static>> {
    vec![self.cert.clone()]
  }

  /// A clone of the certificate private key handle.
  pub(crate) fn private_key(&self) -> PrivateKeyDer<'static> {
    self.key.clone_key()
  }

  /// The leaf certificate bytes.
  pub(crate) fn end_entity(&self) -> &CertificateDer<'static> {
    &self.cert
  }

  /// The leaf SubjectPublicKeyInfo, the member-mode TLS pinning anchor.
  pub(crate) fn leaf_spki(&self) -> Result<rustls::pki_types::SubjectPublicKeyInfoDer<'static>> {
    rustls::server::ParsedCertificate::try_from(self.end_entity())
      .map(|parsed| parsed.subject_public_key_info())
      .map_err(|_| Error::internal("ephemeral certificate spki"))
  }
}

impl core::fmt::Debug for EphemeralCertificate {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("EphemeralCertificate(..)")
  }
}

#[cfg(test)]
mod tests {
  use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData};
  use rustls::{pki_types::PrivatePkcs8KeyDer, server::ParsedCertificate};

  use super::{ED25519_PKCS8_PREFIX, EphemeralCertificate, SEED_LEN};
  use crate::transport::testing::SeedEntropy;

  fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
      .windows(needle.len())
      .filter(|window| *window == needle)
      .count()
  }

  #[test]
  fn tls_transport_ephemeral_certificate_parses_and_is_self_signed() {
    let certificate = EphemeralCertificate::generate(&SeedEntropy(42)).unwrap();
    let der = certificate.end_entity().as_ref();

    // The leaf parses as a well-formed X.509 certificate.
    let parsed = ParsedCertificate::try_from(certificate.end_entity()).unwrap();

    // The certificate key matches the generated key pair.
    let mut pkcs8 = Vec::from(ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(&[42; SEED_LEN]);
    let key_pair =
      KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(pkcs8), &PKCS_ED25519)
        .unwrap();
    assert_eq!(
      parsed.subject_public_key_info().as_ref(),
      key_pair.subject_public_key_info().as_slice()
    );

    // The rcgen x509-parser feature is intentionally disabled, so assert
    // the structural properties that hold for a self-signed DER document
    // without pinning the string encoding: the common-name OID appears at
    // least once (issuer and subject), the bytes form a DER sequence, and
    // generation is deterministic for the same seed.
    let cn_oid = [0x06, 0x03, 0x55, 0x04, 0x03];
    assert!(count_occurrences(der, &cn_oid) >= 2);
    assert_eq!(der[0], 0x30);
    let regenerated = EphemeralCertificate::generate(&SeedEntropy(42)).unwrap();
    assert_eq!(der, regenerated.end_entity().as_ref());
  }

  #[test]
  fn tls_transport_ephemeral_certificate_uses_injected_entropy() {
    let first = EphemeralCertificate::generate(&SeedEntropy(1)).unwrap();
    let same = EphemeralCertificate::generate(&SeedEntropy(1)).unwrap();
    let other = EphemeralCertificate::generate(&SeedEntropy(2)).unwrap();

    // Same injected seed: identical certificate bytes (deterministic, fresh
    // per call). Different seed: different key and therefore different
    // certificate.
    assert_eq!(first.end_entity(), same.end_entity());
    assert_ne!(first.end_entity(), other.end_entity());
  }

  #[test]
  fn tls_transport_ephemeral_certificate_is_send_able() {
    fn assert_send<T: Send>() {}
    assert_send::<EphemeralCertificate>();
    assert_send::<rustls::pki_types::PrivateKeyDer>();
  }
}
