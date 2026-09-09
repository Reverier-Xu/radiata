use sha2::{Digest as ShaDigest, Sha256};

use crate::{Digest, Error, PublicKey, Result, Signature};

pub(crate) const MERGE_GRANT_V1_DOMAIN: &[u8] = b"radiata.woooo.tech/crypto/merge-grant-v1";

pub(crate) fn body_digest(canonical_body: &[u8]) -> Digest {
  Digest::from_bytes(Sha256::digest(canonical_body).into())
}

pub(crate) fn signature_message(domain: &[u8], canonical_body: &[u8]) -> Vec<u8> {
  let digest = body_digest(canonical_body);
  let mut message = Vec::with_capacity(domain.len() + digest.as_bytes().len());
  message.extend_from_slice(domain);
  message.extend_from_slice(digest.as_bytes());
  message
}

pub(crate) fn verify_strict(
  domain: &[u8], canonical_body: &[u8], public_key: &PublicKey, signature: &Signature,
  context: &'static str,
) -> Result<()> {
  verify_strict_message(
    domain,
    &signature_message(domain, canonical_body),
    public_key,
    signature,
    context,
  )
}

/// Verifies one signature over a prebuilt signature message (domain‖digest
/// for callers that hold a digest already proven to bind the body).
pub(crate) fn verify_strict_message(
  _domain: &[u8], message: &[u8], public_key: &PublicKey, signature: &Signature,
  context: &'static str,
) -> Result<()> {
  let key = ed25519_dalek::VerifyingKey::from_bytes(public_key.as_bytes())
    .map_err(|_| Error::authentication_failed(context))?;
  let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
  key
    .verify_strict(message, &signature)
    .map_err(|_| Error::authentication_failed(context))
}

#[cfg(test)]
mod tests {
  use ed25519_dalek::{Signer, SigningKey};

  use super::{MERGE_GRANT_V1_DOMAIN, body_digest, signature_message, verify_strict};
  use crate::{ErrorKind, PublicKey, Signature};

  const BODY: &[u8] = b"\x85\x01\x02\x03\x04\x05";
  const SIGNING_SEED: [u8; 32] = [7; 32];

  fn signed(body: &[u8], domain: &[u8]) -> (PublicKey, Signature) {
    let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
    let signature = signing_key.sign(&signature_message(domain, body));
    (
      PublicKey::from_bytes(signing_key.verifying_key().to_bytes()),
      Signature::from_bytes(signature.to_bytes()),
    )
  }

  #[test]
  fn identity_records_signature_domains_are_exact_ascii_labels() {
    assert_eq!(
      MERGE_GRANT_V1_DOMAIN,
      b"radiata.woooo.tech/crypto/merge-grant-v1"
    );
    assert!(MERGE_GRANT_V1_DOMAIN.is_ascii());
  }

  #[test]
  fn identity_records_signature_message_is_domain_then_body_digest() {
    let message = signature_message(MERGE_GRANT_V1_DOMAIN, BODY);

    assert_eq!(
      &message[..MERGE_GRANT_V1_DOMAIN.len()],
      MERGE_GRANT_V1_DOMAIN
    );
    assert_eq!(
      &message[MERGE_GRANT_V1_DOMAIN.len()..],
      body_digest(BODY).as_bytes()
    );
    assert_eq!(message.len(), MERGE_GRANT_V1_DOMAIN.len() + 32);
  }

  #[test]
  fn identity_records_strict_verification_accepts_valid_signature() {
    let (public_key, signature) = signed(BODY, MERGE_GRANT_V1_DOMAIN);

    verify_strict(
      MERGE_GRANT_V1_DOMAIN,
      BODY,
      &public_key,
      &signature,
      "merge grant signature",
    )
    .unwrap();
  }

  #[test]
  fn identity_records_strict_verification_rejects_wrong_domain_body_and_key() {
    let (public_key, signature) = signed(BODY, MERGE_GRANT_V1_DOMAIN);

    let wrong_domain = verify_strict(
      b"radiata.woooo.tech/crypto/leave-record-v1",
      BODY,
      &public_key,
      &signature,
      "merge grant signature",
    );
    let wrong_body = verify_strict(
      MERGE_GRANT_V1_DOMAIN,
      b"\x85\x01\x02\x03\x04\x06",
      &public_key,
      &signature,
      "merge grant signature",
    );
    let other_key = SigningKey::from_bytes(&[9; 32]).verifying_key();
    let wrong_key = verify_strict(
      MERGE_GRANT_V1_DOMAIN,
      BODY,
      &PublicKey::from_bytes(other_key.to_bytes()),
      &signature,
      "merge grant signature",
    );

    for result in [wrong_domain, wrong_body, wrong_key] {
      let error = result.unwrap_err();
      assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    }
  }

  #[test]
  fn identity_records_strict_verification_rejects_noncanonical_signature_scalar() {
    let (public_key, signature) = signed(BODY, MERGE_GRANT_V1_DOMAIN);
    let mut malleated = *signature.as_bytes();
    for byte in &mut malleated[32..] {
      *byte = 0xFF;
    }

    let error = verify_strict(
      MERGE_GRANT_V1_DOMAIN,
      BODY,
      &public_key,
      &Signature::from_bytes(malleated),
      "merge grant signature",
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  }

  #[test]
  fn identity_records_strict_verification_rejects_undecompressible_public_key() {
    let (_, signature) = signed(BODY, MERGE_GRANT_V1_DOMAIN);

    let error = verify_strict(
      MERGE_GRANT_V1_DOMAIN,
      BODY,
      &PublicKey::from_bytes([0xFF; 32]),
      &signature,
      "merge grant signature",
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    assert_eq!(error.context(), "merge grant signature");
  }

  #[test]
  fn identity_records_authentication_errors_are_redacted() {
    let (public_key, signature) = signed(BODY, MERGE_GRANT_V1_DOMAIN);

    let error = verify_strict(
      b"radiata.woooo.tech/crypto/leave-record-v1",
      BODY,
      &public_key,
      &signature,
      "merge grant signature",
    )
    .unwrap_err();
    let rendered = format!("{error:?}");
    assert_eq!(
      rendered,
      "Error { kind: AuthenticationFailed, context: \"merge grant signature\" }"
    );
    let key_hex: String = public_key
      .as_bytes()
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    let signature_hex: String = signature
      .as_bytes()
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    assert!(!rendered.contains(&key_hex));
    assert!(!rendered.contains(&signature_hex));
  }
}
