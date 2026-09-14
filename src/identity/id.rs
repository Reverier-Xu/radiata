use std::{fmt, str::FromStr};

use crate::{Error, Result, api::Entropy};

/// The length of every identifier's random suffix.
const RANDOM_SUFFIX_LEN: usize = 21;
/// The suffix alphabet: lowercase letters and digits only, so
/// identifiers survive case-folding, URL, and human-transcription
/// paths unchanged.
const SUFFIX_ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
/// The one separator between a family prefix and its suffix.
const SEPARATOR: char = '-';
/// The rejection-sampling draw width: 14 bytes (112 bits) cover the
/// suffix space (36²¹ ≈ 4.4e32 < 2¹¹² ≈ 5.2e33) with an ~8% acceptance
/// rate, while a full u128 draw would reject all but ~10⁻⁶ candidates.
const SUFFIX_DRAW_BYTES: usize = 14;
const SUFFIX_SPACE: u128 = suffix_space();

const fn suffix_space() -> u128 {
  let mut space = 1_u128;
  let mut exponent = 0;
  while exponent < RANDOM_SUFFIX_LEN {
    space *= 36;
    exponent += 1;
  }
  space
}

pub(crate) fn encode_suffix(mut value: u128) -> Result<String> {
  let mut suffix = [0_u8; RANDOM_SUFFIX_LEN];
  let mut index = RANDOM_SUFFIX_LEN;
  while index > 0 {
    index -= 1;
    let digit = usize::try_from(value % 36).map_err(|_| Error::internal("id suffix digit"))?;
    suffix[index] = SUFFIX_ALPHABET[digit];
    value /= 36;
  }
  core::str::from_utf8(&suffix)
    .map(str::to_owned)
    .map_err(|_| Error::internal("id suffix"))
}

/// Composes one deterministic identifier: `{prefix}-{suffix}` with the
/// suffix encoded from `value`. The single naming generator for the
/// derived identifier families (migration and receipt transactions);
/// random identifiers compose through [`random_prefixed_id`], and both
/// share this exact shape.
pub(crate) fn prefixed_id(prefix: &str, value: u128) -> Result<String> {
  Ok(format!("{prefix}{SEPARATOR}{}", encode_suffix(value)?))
}

/// Draws one canonical identifier suffix and composes
/// `{prefix}-{suffix}`: 112-bit rejection sampling below the exact
/// suffix space, so every generated identifier validates and every
/// valid suffix is equally likely.
pub(crate) fn random_prefixed_id(prefix: &str, entropy: &dyn Entropy) -> Result<String> {
  loop {
    let mut draw = [0_u8; SUFFIX_DRAW_BYTES];
    entropy.fill(&mut draw)?;
    let mut candidate = [0_u8; 16];
    candidate[16 - SUFFIX_DRAW_BYTES..].copy_from_slice(&draw);
    let value = u128::from_be_bytes(candidate);
    if value < SUFFIX_SPACE {
      return prefixed_id(prefix, value);
    }
  }
}

macro_rules! canonical_id {
  ($name:ident, $prefix:literal, $context:literal) => {
    #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct $name(String);

    impl $name {
      pub fn parse(value: &str) -> Result<Self> {
        validate_id(value, $prefix, $context)?;
        Ok(Self(value.to_owned()))
      }

      pub fn as_str(&self) -> &str {
        &self.0
      }
    }

    impl FromStr for $name {
      type Err = Error;

      fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
      }
    }

    impl fmt::Debug for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
          .debug_tuple(stringify!($name))
          .field(&self.0)
          .finish()
      }
    }
  };
}

canonical_id!(NodeId, "node", "node id");
canonical_id!(TraceId, "trace", "trace id");
canonical_id!(TransactionId, "txn", "transaction id");
canonical_id!(ListenerId, "listener", "listener id");
canonical_id!(SessionId, "session", "session id");

macro_rules! generated_id {
  ($name:ident, $prefix:literal) => {
    impl $name {
      pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
        Ok(Self(random_prefixed_id($prefix, entropy)?))
      }
    }
  };
}

generated_id!(NodeId, "node");
generated_id!(TraceId, "trace");
generated_id!(TransactionId, "txn");
generated_id!(ListenerId, "listener");
generated_id!(SessionId, "session");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId([u8; 16]);

impl OperationId {
  pub(crate) const fn from_bytes(value: [u8; 16]) -> Self {
    Self(value)
  }

  pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
    &self.0
  }

  pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
    let mut value = [0_u8; 16];
    entropy.fill(&mut value)?;
    Ok(Self(value))
  }
}

impl fmt::Debug for OperationId {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("OperationId(..)")
  }
}

/// Validates one canonical prefixed identifier: exact `prefix`, one
/// `-` separator, and [`RANDOM_SUFFIX_LEN`] lowercase alphanumeric
/// characters. Shared by every identifier family (operation,
/// key-operation, credential, trace) so the naming rules cannot
/// diverge between callers.
pub(crate) fn validate_id(value: &str, prefix: &str, context: &'static str) -> Result<()> {
  let bytes = value.as_bytes();
  let separator = prefix.len();
  let expected_len = separator + 1 + RANDOM_SUFFIX_LEN;
  if bytes.len() != expected_len
    || !bytes.starts_with(prefix.as_bytes())
    || bytes[separator] != SEPARATOR as u8
    || !bytes[separator + 1..].iter().copied().all(is_suffix_char)
  {
    return Err(Error::invalid_input(context));
  }

  Ok(())
}

const fn is_suffix_char(byte: u8) -> bool {
  byte.is_ascii_digit() || byte.is_ascii_lowercase()
}
