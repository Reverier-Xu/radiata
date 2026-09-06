//! ADR-0001 join-mode credential proof derivation.
//!
//! The derivation is exact:
//!
//! ```text
//! prk = HKDF-Extract-SHA256(salt = cb, IKM = credential_bytes)
//! responder_key = HKDF-Expand-SHA256(prk, "radiata.woooo.tech/crypto/bootstrap-v1-responder", 32)
//! initiator_key = HKDF-Expand-SHA256(prk, "radiata.woooo.tech/crypto/bootstrap-v1-initiator", 32)
//! proof = HMAC-SHA256(role_key, transcript_digest)
//! ```
//!
//! `cb` is the locally read RFC 9266 `tls-exporter` channel binding; it is
//! never a wire field and never a secret. The credential body, the derived
//! role keys, and the proofs are never logged or persisted. Role-separated
//! keys prevent reflection, and verification compares HMAC values in
//! constant time through `Mac::verify_slice`.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Digest, Error, MergeCredential, Result};

/// The exact ADR-0001 responder bootstrap key info label.
pub(crate) const RESPONDER_KEY_INFO: &[u8] = b"radiata.woooo.tech/crypto/bootstrap-v1-responder";
/// The exact ADR-0001 initiator bootstrap key info label.
pub(crate) const INITIATOR_KEY_INFO: &[u8] = b"radiata.woooo.tech/crypto/bootstrap-v1-initiator";

const ROLE_KEY_LEN: usize = 32;
pub(crate) const PROOF_LEN: usize = 32;

/// The role a credential proof authenticates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProofRole {
  Responder,
  Initiator,
}

impl ProofRole {
  const fn info(self) -> &'static [u8] {
    match self {
      Self::Responder => RESPONDER_KEY_INFO,
      Self::Initiator => INITIATOR_KEY_INFO,
    }
  }
}

/// The 32-byte join credential body held for proof derivation.
///
/// Cloning duplicates secret bytes inside the crate for handshake endpoint
/// configuration; the value never crosses the crate boundary, is never
/// logged, and is zeroized on drop.
#[derive(Clone)]
pub(crate) struct CredentialSecret(Zeroizing<[u8; ROLE_KEY_LEN]>);

impl CredentialSecret {
  pub(crate) fn from_bytes(value: [u8; ROLE_KEY_LEN]) -> Self {
    Self(Zeroizing::new(value))
  }

  /// Copies the secret body out of a parsed join credential.
  pub(crate) fn from_credential(credential: &MergeCredential) -> Self {
    Self::from_bytes(*credential.expose_secret_bytes())
  }

  fn as_bytes(&self) -> &[u8; ROLE_KEY_LEN] {
    &self.0
  }
}

impl core::fmt::Debug for CredentialSecret {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("CredentialSecret(..)")
  }
}

/// A 32-byte role-separated credential proof.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct CredentialProof([u8; PROOF_LEN]);

impl CredentialProof {
  pub(crate) const fn from_bytes(value: [u8; PROOF_LEN]) -> Self {
    Self(value)
  }

  pub(crate) const fn as_bytes(&self) -> &[u8; PROOF_LEN] {
    &self.0
  }
}

impl core::fmt::Debug for CredentialProof {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("CredentialProof(..)")
  }
}

fn role_key(
  channel_binding: &[u8; 32], secret: &CredentialSecret, info: &[u8],
) -> Result<Zeroizing<[u8; ROLE_KEY_LEN]>> {
  let hkdf = Hkdf::<Sha256>::new(Some(channel_binding), secret.as_bytes());
  let mut key = Zeroizing::new([0_u8; ROLE_KEY_LEN]);
  hkdf
    .expand(info, key.as_mut())
    .map_err(|_| Error::internal("credential proof kdf"))?;
  Ok(key)
}

fn proof_mac(role_key: &[u8; ROLE_KEY_LEN], transcript_digest: &Digest) -> Result<Hmac<Sha256>> {
  let mut mac = Hmac::<Sha256>::new_from_slice(role_key)
    .map_err(|_| Error::internal("credential proof mac"))?;
  mac.update(transcript_digest.as_bytes());
  Ok(mac)
}

/// Derives the role-separated credential proof over the transcript digest.
pub(crate) fn derive_proof(
  role: ProofRole, channel_binding: &[u8; 32], secret: &CredentialSecret,
  transcript_digest: &Digest,
) -> Result<CredentialProof> {
  let key = role_key(channel_binding, secret, role.info())?;
  let mac = proof_mac(&key, transcript_digest)?;
  Ok(CredentialProof(mac.finalize().into_bytes().into()))
}

/// Verifies a received proof against the local derivation in constant time.
pub(crate) fn verify_proof(
  role: ProofRole, channel_binding: &[u8; 32], secret: &CredentialSecret,
  transcript_digest: &Digest, expected: &CredentialProof,
) -> Result<bool> {
  let key = role_key(channel_binding, secret, role.info())?;
  let mac = proof_mac(&key, transcript_digest)?;
  Ok(mac.verify_slice(expected.as_bytes()).is_ok())
}

#[cfg(test)]
mod tests {
  use hmac::Mac;

  use super::{
    CredentialProof, CredentialSecret, INITIATOR_KEY_INFO, ProofRole, RESPONDER_KEY_INFO,
    derive_proof, proof_mac, role_key, verify_proof,
  };
  use crate::{Digest, MergeCredential};

  const CHANNEL_BINDING: [u8; 32] = [0xCB; 32];
  const CREDENTIAL: [u8; 32] = [0x42; 32];
  const TRANSCRIPT_DIGEST: [u8; 32] = [0xD1; 32];

  // Independently computed from RFC 5869 extract-then-expand with a single
  // 32-byte output block and RFC 2104 HMAC-SHA256 over the digest.
  const EXPECTED_PRK_HEX: &str = "27b8df2164d66f6cca05beb2b54f8cd40188814fc29022f890c0bd0ad6adc6f7";
  const EXPECTED_RESPONDER_KEY_HEX: &str =
    "9eeaa14504d7e577ebad1f92d826872607bb5cbcbe07be1ec5a69d0fc2c8b907";
  const EXPECTED_INITIATOR_KEY_HEX: &str =
    "a0d7b7783f1a1fe85b0e10427714d97e1850cd0b385d62f04852a21fdb42e42c";
  const EXPECTED_RESPONDER_PROOF_HEX: &str =
    "f8377c0931f46833a71b2eb1095bd20a5f4a6d4212819f9ba9eae2c2983064f2";
  const EXPECTED_INITIATOR_PROOF_HEX: &str =
    "d269973797d0a42bdc5f3313c4ec484122c57a5ad27ce9dea92c6ddbf8c60091";

  use crate::hex::encode as hex;

  fn secret() -> CredentialSecret {
    CredentialSecret::from_bytes(CREDENTIAL)
  }

  fn digest() -> Digest {
    Digest::from_bytes(TRANSCRIPT_DIGEST)
  }

  #[test]
  fn tls_transport_proof_vectors_are_exact() {
    assert_eq!(
      RESPONDER_KEY_INFO,
      b"radiata.woooo.tech/crypto/bootstrap-v1-responder"
    );
    assert_eq!(
      INITIATOR_KEY_INFO,
      b"radiata.woooo.tech/crypto/bootstrap-v1-initiator"
    );
    assert!(RESPONDER_KEY_INFO.is_ascii());
    assert!(INITIATOR_KEY_INFO.is_ascii());

    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&CHANNEL_BINDING), &CREDENTIAL);
    assert_eq!(hex(prk.as_slice()), EXPECTED_PRK_HEX);
    assert_eq!(
      hex(
        role_key(&CHANNEL_BINDING, &secret(), RESPONDER_KEY_INFO)
          .unwrap()
          .as_slice()
      ),
      EXPECTED_RESPONDER_KEY_HEX
    );
    assert_eq!(
      hex(
        role_key(&CHANNEL_BINDING, &secret(), INITIATOR_KEY_INFO)
          .unwrap()
          .as_slice()
      ),
      EXPECTED_INITIATOR_KEY_HEX
    );
    assert_eq!(
      hex(
        derive_proof(ProofRole::Responder, &CHANNEL_BINDING, &secret(), &digest())
          .unwrap()
          .as_bytes()
      ),
      EXPECTED_RESPONDER_PROOF_HEX
    );
    assert_eq!(
      hex(
        derive_proof(ProofRole::Initiator, &CHANNEL_BINDING, &secret(), &digest())
          .unwrap()
          .as_bytes()
      ),
      EXPECTED_INITIATOR_PROOF_HEX
    );

    // Honest derivations verify in both roles.
    for role in [ProofRole::Responder, ProofRole::Initiator] {
      let proof = derive_proof(role, &CHANNEL_BINDING, &secret(), &digest()).unwrap();
      assert!(verify_proof(role, &CHANNEL_BINDING, &secret(), &digest(), &proof).unwrap());
    }
  }

  #[test]
  fn tls_transport_proof_derivation_accepts_parsed_credentials() {
    let credential =
      MergeCredential::parse("join_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
    let from_credential = CredentialSecret::from_credential(&credential);
    let from_bytes = CredentialSecret::from_bytes([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
      0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
      0x1E, 0x1F,
    ]);
    assert_eq!(
      derive_proof(
        ProofRole::Responder,
        &CHANNEL_BINDING,
        &from_credential,
        &digest()
      )
      .unwrap(),
      derive_proof(
        ProofRole::Responder,
        &CHANNEL_BINDING,
        &from_bytes,
        &digest()
      )
      .unwrap()
    );
    assert_eq!(format!("{from_credential:?}"), "CredentialSecret(..)");
  }

  #[test]
  fn tls_transport_proof_verification_rejects_wrong_channel_binding() {
    let proof = derive_proof(ProofRole::Responder, &CHANNEL_BINDING, &secret(), &digest()).unwrap();
    let wrong_binding = [0xBC; 32];
    assert_ne!(wrong_binding, CHANNEL_BINDING);
    assert!(
      !verify_proof(
        ProofRole::Responder,
        &wrong_binding,
        &secret(),
        &digest(),
        &proof
      )
      .unwrap()
    );
  }

  #[test]
  fn tls_transport_proof_verification_rejects_wrong_credential() {
    let proof = derive_proof(ProofRole::Initiator, &CHANNEL_BINDING, &secret(), &digest()).unwrap();
    let wrong_secret = CredentialSecret::from_bytes([0x24; 32]);
    assert!(
      !verify_proof(
        ProofRole::Initiator,
        &CHANNEL_BINDING,
        &wrong_secret,
        &digest(),
        &proof
      )
      .unwrap()
    );
  }

  #[test]
  fn tls_transport_proof_verification_rejects_mutations_and_reflection() {
    let proof = derive_proof(ProofRole::Responder, &CHANNEL_BINDING, &secret(), &digest()).unwrap();

    // A single flipped proof bit fails.
    let mut mutated = *proof.as_bytes();
    mutated[0] ^= 0x01;
    assert!(
      !verify_proof(
        ProofRole::Responder,
        &CHANNEL_BINDING,
        &secret(),
        &digest(),
        &CredentialProof::from_bytes(mutated),
      )
      .unwrap()
    );

    // A different transcript digest fails.
    let wrong_digest = Digest::from_bytes([0x1D; 32]);
    assert!(
      !verify_proof(
        ProofRole::Responder,
        &CHANNEL_BINDING,
        &secret(),
        &wrong_digest,
        &proof
      )
      .unwrap()
    );

    // Role separation: the responder proof never verifies as initiator.
    assert!(
      !verify_proof(
        ProofRole::Initiator,
        &CHANNEL_BINDING,
        &secret(),
        &digest(),
        &proof
      )
      .unwrap()
    );
    let initiator_proof =
      derive_proof(ProofRole::Initiator, &CHANNEL_BINDING, &secret(), &digest()).unwrap();
    assert_ne!(proof, initiator_proof);

    // The MAC interface itself rejects truncated tags.
    let key = role_key(&CHANNEL_BINDING, &secret(), RESPONDER_KEY_INFO).unwrap();
    let mac = proof_mac(&key, &digest()).unwrap();
    assert!(mac.verify_slice(&proof.as_bytes()[..16]).is_err());
  }
}
