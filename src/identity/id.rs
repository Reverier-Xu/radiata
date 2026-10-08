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
canonical_id!(TaskId, "task", "task id");

/// The task-id admission-counter space: the low [`TASK_COUNTER_BITS`]
/// bits of a composed [`TaskId`]. The bound is admissions per node
/// incarnation, never anything durable — task ids are in-memory
/// observations of admitted intent and do not outlive the process.
const TASK_COUNTER_BITS: u32 = 40;
/// One past the largest admissible admission counter (`2^40`).
const TASK_COUNTER_LIMIT: u128 = 1_u128 << TASK_COUNTER_BITS;
/// The per-incarnation base mask: bits `[40, 108)`. The 21-character
/// base36 suffix space is `36^21 ≈ 2^108.57`, so a base whose top bits
/// reach above `2^108` lets `base | counter` overflow the suffix space —
/// `encode_suffix` would silently drop the high bits and break the
/// id-ordering contract. Masking the draw into bits `[40, 108)` keeps
/// every composition inside the space (`base | counter ≤ 2^108 − 1 <
/// 36^21`); the 68 remaining base bits are per-incarnation entropy only,
/// which is the whole durability class of a task id.
const TASK_BASE_MASK: u128 = ((1_u128 << 108) - 1) & !(TASK_COUNTER_LIMIT - 1);

impl TaskId {
  /// Composes one per-incarnation task id: the startup base with its
  /// counter space (and the overflow bits above the suffix space) masked
  /// out, OR'd with the monotonic admission counter. The suffix encoding
  /// is fixed-width big-endian base36, so lexicographic id order equals
  /// admission order within one incarnation — a `BTreeMap<TaskId, _>`
  /// iterates the manager's deterministic queue order for free.
  ///
  /// The counter bound is the admission count per incarnation: past
  /// `2^40` admissions the composition is refused typed instead of
  /// wrapping onto an earlier id.
  #[allow(dead_code)] // driven by the task manager constructor; the runtime wiring lands with the supervisor stages
  pub(crate) fn compose(base: u128, counter: u64) -> Result<Self> {
    let counter = u128::from(counter);
    if counter >= TASK_COUNTER_LIMIT {
      return Err(Error::resource_exhausted("task id counter"));
    }
    Self::parse(&prefixed_id("task", (base & TASK_BASE_MASK) | counter)?)
  }

  /// Draws the per-incarnation id base: exactly one 14-byte fill,
  /// right-aligned into the 112-bit composition space. The counter and
  /// overflow masks are applied by [`TaskId::compose`], so the draw needs
  /// no rejection loop and the startup entropy budget gains exactly one
  /// fill (pinned by the lifecycle entropy-sequence test).
  #[allow(dead_code)] // driven by the task manager constructor; the runtime wiring lands with the supervisor stages
  pub(crate) fn draw_base(entropy: &dyn Entropy) -> Result<u128> {
    let mut draw = [0_u8; SUFFIX_DRAW_BYTES];
    entropy.fill(&mut draw)?;
    let mut candidate = [0_u8; 16];
    candidate[16 - SUFFIX_DRAW_BYTES..].copy_from_slice(&draw);
    Ok(u128::from_be_bytes(candidate))
  }
}

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

#[cfg(test)]
mod task_id_tests {
  use super::{SUFFIX_DRAW_BYTES, TASK_BASE_MASK, TaskId};
  use crate::{ErrorKind, identity::testing::SequenceEntropy};

  fn compose(base: u128, counter: u64) -> TaskId {
    TaskId::compose(base, counter).expect("composition inside the bound")
  }

  /// The composed form is exactly the canonical family shape:
  /// `task-` plus the fixed 21-character suffix, parse-round-trippable.
  #[test]
  fn task_ids_round_trip_through_parse() {
    let id = compose(0, 0);
    assert!(id.as_str().starts_with("task-"));
    assert_eq!(id.as_str().len(), "task-".len() + 21);
    assert_eq!(TaskId::parse(id.as_str()).ok(), Some(id.clone()));
    assert_eq!(id.to_string(), id.as_str());
  }

  /// The ordering property the manager's queue relies on: within one
  /// base, id order equals admission-counter order, both lexicographically
  /// and through a `BTreeMap`'s key iteration.
  #[test]
  fn fixed_base_ids_order_by_admission_counter() {
    let ids: Vec<TaskId> = (0..64).map(|counter| compose(u128::MAX, counter)).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "lexicographic order == admission order");
    let table: std::collections::BTreeMap<TaskId, u64> = ids.iter().cloned().zip(0..).collect();
    assert!(table.into_keys().eq(ids));
  }

  /// Distinct bases stay distinct after masking and keep base-major
  /// ordering ahead of the counter.
  #[test]
  fn distinct_bases_order_ahead_of_counters() {
    let high = compose((1_u128 << 107) | (1_u128 << 50), 0);
    let low = compose(1_u128 << 50, (1_u64 << 40) - 1);
    assert!(high > low, "a higher masked base outranks any counter");
  }

  /// The counter bound is `2^40`: the last admissible counter composes,
  /// the bound itself is a typed resource exhaustion.
  #[test]
  fn the_counter_bound_is_refused_typed() {
    assert!(TaskId::compose(0, (1_u64 << 40) - 1).is_ok());
    let error = TaskId::compose(0, 1_u64 << 40).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
    assert_eq!(error.context(), "task id counter");
  }

  /// The mask owns the suffix-space invariant, not the caller: any base
  /// (including ones above the space and ones with counter-space bits
  /// set) composes to a valid parseable id, and stray counter-space bits
  /// never leak into the counter.
  #[test]
  fn masking_keeps_every_composition_inside_the_suffix_space() {
    for base in [
      0,
      u128::MAX,
      u128::MAX >> 4,
      (1_u128 << 108) - 1,
      1_u128 << 108,
    ] {
      let id = TaskId::compose(base, 123).expect("masked composition");
      assert!(TaskId::parse(id.as_str()).is_ok(), "{base}");
    }
    assert_eq!(compose(u128::MAX, 7), compose(TASK_BASE_MASK, 7));
    assert_eq!(compose(0xFFFF_FFFF, 7), compose(0, 7));
  }

  /// The startup draw is exactly one 14-byte fill — the lifecycle
  /// entropy-sequence test budgets precisely that one addition.
  #[test]
  fn draw_base_is_one_fourteen_byte_fill() {
    let entropy = SequenceEntropy::default();
    let base = TaskId::draw_base(&entropy).expect("draw");
    assert_eq!(entropy.fills(), 1);
    assert_eq!(base, 1);
    assert!(TaskId::compose(base, 0).is_ok());
    assert_eq!(SUFFIX_DRAW_BYTES, 14);
  }
}
