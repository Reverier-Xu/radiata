//! Join credential secrets and the receiver's in-memory credential
//! generation lifecycle.
//!
//! A join credential is exactly 32 uniformly random bytes rendered as
//! unpadded base64url with the sensitive `join_` prefix. Credential text,
//! derived proof keys, and proof values are never persisted, replicated,
//! logged, or included in an admission grant. Each receiver holds at most
//! one active generation: valid for ten minutes, memory-only, invalidated
//! by rotation, reserved by at most one in-progress commit, and consumed by
//! exactly one successfully committed new identity. Consumption erases the
//! secret and every stored secret is zeroized on drop.

use std::{
  fmt,
  time::{Duration, SystemTime},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use zeroize::Zeroizing;

use crate::{Error, Result, api::Entropy};

const PREFIX: &str = "join_";
const BODY_LEN: usize = 32;
const CREDENTIAL_LEN: usize = PREFIX.len() + 43;
const LIFETIME: Duration = Duration::from_secs(600);
pub(crate) const GENERATION_ID_LEN: usize = 16;

/// A receiver-issued join credential secret.
///
/// The value implements neither `Clone`, `Copy`, serialization, `Display`,
/// nor revealing `Debug`; the secret text is reachable only through
/// [`MergeCredential::expose_secret`] and the secret bytes only through the
/// crate-private proof-derivation boundary.
pub struct MergeCredential {
  text: SecretString,
  body: SecretBox<[u8; BODY_LEN]>,
}

impl MergeCredential {
  /// Parses the exact canonical form: the `join_` prefix followed by the
  /// unpadded base64url rendering of a 32-byte body. Any other prefix,
  /// length, alphabet, padding, or non-canonical trailing bits are
  /// rejected.
  pub fn parse(value: &str) -> Result<Self> {
    if value.len() != CREDENTIAL_LEN || !value.starts_with(PREFIX) {
      return Err(Error::invalid_input("join credential"));
    }
    let encoded = &value[PREFIX.len()..];
    let decoded = Zeroizing::new(
      URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::invalid_input("join credential"))?,
    );
    let body: [u8; BODY_LEN] = decoded
      .as_slice()
      .try_into()
      .map_err(|_| Error::invalid_input("join credential"))?;
    if URL_SAFE_NO_PAD.encode(body) != encoded {
      return Err(Error::invalid_input("join credential"));
    }
    Ok(Self::from_body(body))
  }

  /// Exposes the full secret credential text, prefix included.
  pub fn expose_secret(&self) -> &str {
    self.text.expose_secret()
  }

  /// Exposes the raw 32-byte secret body for the crate-private HKDF proof
  /// derivation. The bytes are never logged, persisted, or sent on the
  /// wire.
  pub(crate) fn expose_secret_bytes(&self) -> &[u8; BODY_LEN] {
    self.body.expose_secret()
  }

  fn from_body(body: [u8; BODY_LEN]) -> Self {
    let mut text = String::with_capacity(CREDENTIAL_LEN);
    text.push_str(PREFIX);
    URL_SAFE_NO_PAD.encode_string(body, &mut text);
    Self {
      text: SecretString::from(text),
      body: SecretBox::new(Box::new(body)),
    }
  }
}

impl fmt::Debug for MergeCredential {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("MergeCredential(..)")
  }
}

/// A freshly issued join credential together with its expiry.
///
/// This is the only value a receiver may hand to an operator; it carries no
/// generation ID and implements neither `Clone` nor revealing `Debug`.
pub struct IssuedMergeCredential {
  credential: MergeCredential,
  expires_at: SystemTime,
}

impl IssuedMergeCredential {
  /// The issued credential secret.
  pub fn credential(&self) -> &MergeCredential {
    &self.credential
  }

  /// The instant after which the credential generation is invalid.
  pub fn expires_at(&self) -> SystemTime {
    self.expires_at
  }

  /// Consumes the wrapper and returns the credential secret.
  pub fn into_credential(self) -> MergeCredential {
    self.credential
  }
}

impl fmt::Debug for IssuedMergeCredential {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("IssuedMergeCredential(..)")
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationState {
  Active,
  Reserved,
  Consumed,
}

struct ActiveGeneration {
  credential: Option<MergeCredential>,
  generation_id: [u8; GENERATION_ID_LEN],
  expires_at: SystemTime,
  state: GenerationState,
}

impl ActiveGeneration {
  fn live(&self, now: SystemTime) -> Result<()> {
    if self.state == GenerationState::Consumed {
      return Err(Error::authentication_failed("join credential consumed"));
    }
    if now >= self.expires_at {
      return Err(Error::authentication_failed("join credential expired"));
    }
    Ok(())
  }
}

/// The receiver's memory-only join credential generation state.
///
/// At most one generation exists at a time. Process restart erases it;
/// rotation invalidates the previous value by dropping and zeroizing its
/// secret. The session driver's admission commit owns the durable
/// single-use semantics; this type owns only the in-memory lifecycle.
pub(crate) struct MergeCredentialIssuer {
  generation: Option<ActiveGeneration>,
}

impl MergeCredentialIssuer {
  pub(crate) const fn new() -> Self {
    Self { generation: None }
  }

  /// Issues the first generation, rejecting the call while a live
  /// (unexpired, unconsumed) generation already exists. Production only
  /// ever rotates (the first generation is issued by `rotate` on the
  /// fresh issuer), so this entry point is exercised by tests only.
  #[cfg(test)]
  pub(crate) fn issue(
    &mut self, entropy: &dyn Entropy, now: SystemTime,
  ) -> Result<IssuedMergeCredential> {
    if let Some(generation) = &self.generation
      && generation.live(now).is_ok()
    {
      return Err(Error::conflict("join credential active"));
    }
    self.replace(entropy, now)
  }

  /// Rotates the credential at any time: the old generation is invalidated
  /// immediately and a new independent value becomes the single active
  /// generation.
  pub(crate) fn rotate(
    &mut self, entropy: &dyn Entropy, now: SystemTime,
  ) -> Result<IssuedMergeCredential> {
    self.replace(entropy, now)
  }

  /// The non-secret 16-byte generation ID of the current generation. It may
  /// be persisted for idempotence and audit correlation.
  pub(crate) fn generation_id(&self) -> Option<[u8; GENERATION_ID_LEN]> {
    self
      .generation
      .as_ref()
      .map(|generation| generation.generation_id)
  }

  /// The live credential secret, reserved or active, for proof derivation
  /// and verification. Expired or consumed generations fail closed.
  pub(crate) fn active_credential(&self, now: SystemTime) -> Result<&MergeCredential> {
    let generation = self
      .generation
      .as_ref()
      .ok_or_else(|| Error::authentication_failed("join credential absent"))?;
    generation.live(now)?;
    generation
      .credential
      .as_ref()
      .ok_or_else(|| Error::authentication_failed("join credential consumed"))
  }

  /// Reserves the live generation for one in-progress admission commit. At
  /// most one reservation can be outstanding.
  pub(crate) fn reserve(&mut self, now: SystemTime) -> Result<()> {
    let generation = self
      .generation
      .as_mut()
      .ok_or_else(|| Error::authentication_failed("join credential absent"))?;
    generation.live(now)?;
    match generation.state {
      GenerationState::Active => {
        generation.state = GenerationState::Reserved;
        Ok(())
      }
      GenerationState::Reserved => Err(Error::conflict("join credential reserved")),
      GenerationState::Consumed => Err(Error::authentication_failed("join credential consumed")),
    }
  }

  /// Returns a reserved generation to active after a failed proof,
  /// collision, or definitely aborted transaction.
  pub(crate) fn release(&mut self) -> Result<()> {
    let generation = self
      .generation
      .as_mut()
      .ok_or_else(|| Error::authentication_failed("join credential absent"))?;
    match generation.state {
      GenerationState::Reserved => {
        generation.state = GenerationState::Active;
        Ok(())
      }
      _ => Err(Error::conflict("join credential not reserved")),
    }
  }

  /// Consumes a reserved generation after exactly one successfully
  /// committed new identity. The secret is erased immediately; the
  /// generation ID remains for audit correlation.
  pub(crate) fn consume(&mut self) -> Result<()> {
    let generation = self
      .generation
      .as_mut()
      .ok_or_else(|| Error::authentication_failed("join credential absent"))?;
    match generation.state {
      GenerationState::Reserved => {
        // Dropping the credential zeroizes the secret text and body.
        generation.credential = None;
        generation.state = GenerationState::Consumed;
        Ok(())
      }
      _ => Err(Error::conflict("join credential not reserved")),
    }
  }

  fn replace(&mut self, entropy: &dyn Entropy, now: SystemTime) -> Result<IssuedMergeCredential> {
    let mut body = Zeroizing::new([0_u8; BODY_LEN]);
    entropy.fill(body.as_mut())?;
    let mut generation_id = [0_u8; GENERATION_ID_LEN];
    entropy.fill(&mut generation_id)?;
    let expires_at = now
      .checked_add(LIFETIME)
      .ok_or_else(|| Error::internal("join credential expiry"))?;
    // Replacing the generation drops and zeroizes the previous secret.
    self.generation = Some(ActiveGeneration {
      credential: Some(MergeCredential::from_body(*body)),
      generation_id,
      expires_at,
      state: GenerationState::Active,
    });
    Ok(IssuedMergeCredential {
      credential: MergeCredential::from_body(*body),
      expires_at,
    })
  }
}

impl Default for MergeCredentialIssuer {
  fn default() -> Self {
    Self::new()
  }
}

impl fmt::Debug for MergeCredentialIssuer {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("MergeCredentialIssuer(..)")
  }
}

#[cfg(test)]
mod tests {
  use std::{
    sync::Mutex,
    time::{Duration, SystemTime},
  };

  use super::{
    BODY_LEN, CREDENTIAL_LEN, GENERATION_ID_LEN, LIFETIME, MergeCredential, MergeCredentialIssuer,
  };
  use crate::{Error, ErrorKind, Result, api::Entropy};

  const GOLDEN_BODY: [u8; BODY_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  ];
  const GOLDEN_TEXT: &str = "join_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  const ISSUED_AT: SystemTime = SystemTime::UNIX_EPOCH;

  /// Deterministic entropy: fill `n` produces bytes `n, n+1, n+2, ...`.
  #[derive(Debug, Default)]
  struct SequenceEntropy(Mutex<u8>);

  impl Entropy for SequenceEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<()> {
      let mut state = self.0.lock().unwrap();
      let start = *state;
      for (index, byte) in output.iter_mut().enumerate() {
        *byte = start.wrapping_add(u8::try_from(index).unwrap());
      }
      *state = start.wrapping_add(1);
      Ok(())
    }
  }

  #[derive(Debug)]
  struct FailingEntropy;

  impl Entropy for FailingEntropy {
    fn fill(&self, _output: &mut [u8]) -> Result<()> {
      Err(Error::provider(
        crate::ProviderErrorKind::Io,
        crate::ProviderErrorContext::Entropy,
      ))
    }
  }

  fn at(seconds: u64) -> SystemTime {
    ISSUED_AT + Duration::from_secs(seconds)
  }

  #[test]
  fn tls_transport_credential_parse_accepts_exact_canonical_form() {
    assert_eq!(GOLDEN_TEXT.len(), CREDENTIAL_LEN);
    let credential = MergeCredential::parse(GOLDEN_TEXT).unwrap();
    assert_eq!(credential.expose_secret(), GOLDEN_TEXT);
    assert_eq!(credential.expose_secret_bytes(), &GOLDEN_BODY);
  }

  #[test]
  fn tls_transport_credential_parse_rejects_noncanonical_forms() {
    let mut noncanonical_trailing_bits = GOLDEN_TEXT.to_owned();
    noncanonical_trailing_bits.replace_range(CREDENTIAL_LEN - 1.., "9");
    let rejected = [
      String::new(),
      "join_".to_owned(),
      GOLDEN_TEXT[..CREDENTIAL_LEN - 1].to_owned(),
      format!("{GOLDEN_TEXT}="),
      format!(" {GOLDEN_TEXT}"),
      format!("{GOLDEN_TEXT} "),
      GOLDEN_TEXT.replacen("join_", "JOIN_", 1),
      GOLDEN_TEXT.replacen("join_", "join-", 1),
      GOLDEN_TEXT.replacen('A', "+", 1),
      GOLDEN_TEXT.replacen('8', "/", 1),
      noncanonical_trailing_bits,
    ];
    for value in &rejected {
      assert_ne!(value, GOLDEN_TEXT);
      assert_eq!(
        MergeCredential::parse(value).unwrap_err().kind(),
        ErrorKind::InvalidInput,
        "value: {value:?}"
      );
    }
    assert!(MergeCredential::parse(GOLDEN_TEXT).is_ok());
  }

  #[test]
  fn tls_transport_credential_debug_and_errors_redact_the_secret() {
    let credential = MergeCredential::parse(GOLDEN_TEXT).unwrap();
    let debug = format!("{credential:?}");
    assert_eq!(debug, "MergeCredential(..)");
    assert!(!debug.contains(GOLDEN_TEXT));

    let error = MergeCredential::parse("join_").unwrap_err();
    assert_eq!(
      format!("{error:?}"),
      "Error { kind: InvalidInput, context: \"join credential\" }"
    );
    assert!(!format!("{error}").contains(GOLDEN_TEXT));
  }

  #[test]
  fn tls_transport_credential_issue_uses_entropy_and_expires_after_ten_minutes() {
    let entropy = SequenceEntropy::default();
    let mut issuer = MergeCredentialIssuer::new();
    let issued = issuer.issue(&entropy, ISSUED_AT).unwrap();

    assert_eq!(issued.credential().expose_secret(), GOLDEN_TEXT);
    assert_eq!(issued.expires_at(), ISSUED_AT + LIFETIME);
    let mut generation = [0_u8; GENERATION_ID_LEN];
    for (index, byte) in generation.iter_mut().enumerate() {
      *byte = 1 + u8::try_from(index).unwrap();
    }
    assert_eq!(issuer.generation_id(), Some(generation));
    assert_eq!(
      issuer
        .active_credential(at(599))
        .unwrap()
        .expose_secret_bytes(),
      &GOLDEN_BODY
    );

    // A second issue while the generation is live conflicts; rotation is
    // always allowed.
    assert_eq!(
      issuer.issue(&entropy, ISSUED_AT).unwrap_err().kind(),
      ErrorKind::Conflict
    );

    // Entropy failure propagates without mutating any existing state.
    let mut fresh = MergeCredentialIssuer::new();
    assert_eq!(
      fresh.issue(&FailingEntropy, ISSUED_AT).unwrap_err().kind(),
      ErrorKind::Io
    );
    assert!(fresh.generation_id().is_none());
    assert_eq!(
      issuer
        .active_credential(ISSUED_AT)
        .unwrap()
        .expose_secret_bytes(),
      &GOLDEN_BODY
    );
  }

  #[test]
  fn tls_transport_credential_expiry_and_rotation_invalidate_generations() {
    let entropy = SequenceEntropy::default();
    let mut issuer = MergeCredentialIssuer::new();
    let first = issuer.issue(&entropy, ISSUED_AT).unwrap();
    let first_generation = issuer.generation_id().unwrap();

    // The generation is live until, not including, its expiry instant.
    assert!(issuer.active_credential(at(600)).is_err());
    assert_eq!(
      issuer.active_credential(at(600)).unwrap_err().kind(),
      ErrorKind::AuthenticationFailed
    );
    assert_eq!(
      issuer.reserve(at(600)).unwrap_err().kind(),
      ErrorKind::AuthenticationFailed
    );

    // Rotation invalidates the old value and creates an independent one.
    let second = issuer.rotate(&entropy, at(600)).unwrap();
    assert_ne!(
      second.credential().expose_secret(),
      first.credential().expose_secret()
    );
    assert_ne!(issuer.generation_id().unwrap(), first_generation);
    assert_eq!(second.expires_at(), at(600) + LIFETIME);
    assert_eq!(
      issuer.active_credential(at(600)).unwrap().expose_secret(),
      second.credential().expose_secret()
    );

    // A clone-free API: the issued credential moves out exactly once.
    let credential = second.into_credential();
    assert_eq!(credential.expose_secret_bytes().len(), BODY_LEN);
  }

  #[test]
  fn tls_transport_credential_reservation_is_single_use() {
    let entropy = SequenceEntropy::default();
    let mut issuer = MergeCredentialIssuer::new();
    issuer.issue(&entropy, ISSUED_AT).unwrap();

    // One outstanding reservation only.
    issuer.reserve(ISSUED_AT).unwrap();
    assert_eq!(
      issuer.reserve(ISSUED_AT).unwrap_err().kind(),
      ErrorKind::Conflict
    );

    // The reserved generation still verifies proofs.
    assert!(
      issuer
        .active_credential(ISSUED_AT)
        .unwrap()
        .expose_secret()
        .starts_with("join_")
    );

    // A failed attempt returns the generation to active.
    issuer.release().unwrap();
    assert_eq!(issuer.release().unwrap_err().kind(), ErrorKind::Conflict);
    issuer.reserve(ISSUED_AT).unwrap();

    // Exactly one successful commit consumes and erases the secret.
    issuer.consume().unwrap();
    assert_eq!(issuer.consume().unwrap_err().kind(), ErrorKind::Conflict);
    assert_eq!(issuer.release().unwrap_err().kind(), ErrorKind::Conflict);
    assert_eq!(
      issuer.active_credential(ISSUED_AT).unwrap_err().kind(),
      ErrorKind::AuthenticationFailed
    );
    assert_eq!(
      issuer.reserve(ISSUED_AT).unwrap_err().kind(),
      ErrorKind::AuthenticationFailed
    );

    // The consumed generation ID remains for audit correlation, and a fresh
    // issue replaces the consumed generation.
    assert!(issuer.generation_id().is_some());
    let reissued = issuer.issue(&entropy, ISSUED_AT).unwrap();
    assert!(reissued.credential().expose_secret().starts_with("join_"));
  }

  #[test]
  fn tls_transport_credential_issuer_state_is_redacted() {
    let entropy = SequenceEntropy::default();
    let mut issuer = MergeCredentialIssuer::new();
    let issued = issuer.issue(&entropy, ISSUED_AT).unwrap();
    assert_eq!(format!("{issuer:?}"), "MergeCredentialIssuer(..)");
    assert_eq!(format!("{issued:?}"), "IssuedMergeCredential(..)");
    let debug = format!("{issuer:?}{issued:?}");
    assert!(!debug.contains(issued.credential().expose_secret()));
  }
}
