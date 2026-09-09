use std::{fmt, str::FromStr};

use crate::{Error, Result, api::Entropy};

const RANDOM_SUFFIX_LEN: usize = 21;
const BASE62_ALPHABET: &[u8; 62] =
  b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const BASE62_SUFFIX_SPACE: u128 = base62_suffix_space();

const fn base62_suffix_space() -> u128 {
  let mut space = 1_u128;
  let mut exponent = 0;
  while exponent < RANDOM_SUFFIX_LEN {
    space *= 62;
    exponent += 1;
  }
  space
}

pub(crate) fn encode_base62_suffix(mut value: u128) -> Result<String> {
  let mut suffix = [0_u8; RANDOM_SUFFIX_LEN];
  let mut index = RANDOM_SUFFIX_LEN;
  while index > 0 {
    index -= 1;
    let digit = usize::try_from(value % 62).map_err(|_| Error::internal("id suffix digit"))?;
    suffix[index] = BASE62_ALPHABET[digit];
    value /= 62;
  }
  core::str::from_utf8(&suffix)
    .map(str::to_owned)
    .map_err(|_| Error::internal("id suffix"))
}

pub(crate) fn random_base62_suffix(entropy: &dyn Entropy) -> Result<String> {
  loop {
    let mut candidate = [0_u8; 16];
    entropy.fill(&mut candidate)?;
    let value = u128::from_be_bytes(candidate);
    if value >= BASE62_SUFFIX_SPACE {
      continue;
    }
    return encode_base62_suffix(value);
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

canonical_id!(NodeId, "node_", "node id");
canonical_id!(TraceId, "trace_", "trace id");
canonical_id!(TransactionId, "txn_", "transaction id");
canonical_id!(ListenerId, "listener_", "listener id");
canonical_id!(SessionId, "session_", "session id");

macro_rules! generated_id {
  ($name:ident, $prefix:literal) => {
    impl $name {
      pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
        let suffix = random_base62_suffix(entropy)?;
        Ok(Self(format!(concat!($prefix, "{}"), suffix)))
      }
    }
  };
}

generated_id!(NodeId, "node_");
generated_id!(TraceId, "trace_");
generated_id!(TransactionId, "txn_");
generated_id!(ListenerId, "listener_");
generated_id!(SessionId, "session_");

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

/// Validates one canonical prefixed base62 identifier: exact `prefix`
/// length plus [`RANDOM_SUFFIX_LEN`] base62 characters. Shared by every
/// identifier family (operation, key-operation, credential, trace) so the
/// suffix rules cannot diverge between callers.
pub(crate) fn validate_id(value: &str, prefix: &str, context: &'static str) -> Result<()> {
  let expected_len = prefix.len() + RANDOM_SUFFIX_LEN;
  if value.len() != expected_len || !value.starts_with(prefix) {
    return Err(Error::invalid_input(context));
  }

  let suffix = &value.as_bytes()[prefix.len()..];
  if !suffix.iter().copied().all(is_base62) {
    return Err(Error::invalid_input(context));
  }

  Ok(())
}

const fn is_base62(byte: u8) -> bool {
  byte.is_ascii_digit() || byte.is_ascii_lowercase() || byte.is_ascii_uppercase()
}
