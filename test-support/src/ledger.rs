//! The release-evidence ledger validator.
//!
//! One sealed, typed validator for the canonical evidence ledgers: the
//! test-attestation records produced by every test, fuzz, soak, and SLO
//! attempt, the soak attempt lines, and the release-candidate SLO ledger.
//! Validation is strict and fails closed: missing fields, reduced
//! budgets, interrupted runs, mismatched commit or lock digests, masked
//! attempt lineages, and post-start sample exclusions are all rejections,
//! never warnings. The validator accepts only complete current-semantic
//! evidence; any unknown schema tag or superseded field set fails.

use std::collections::BTreeMap;

use sha2::{Digest as ShaDigest, Sha256};

/// The canonical test-attestation schema tag.
pub const ATTESTATION_SCHEMA: &str = "radiata.woooo.tech/schemas/test-attestation";
/// The canonical soak attempt schema tag.
pub const SOAK_ATTEMPT_SCHEMA: &str = "radiata.woooo.tech/schemas/soak-attempt-v1";
/// The canonical SLO ledger schema tag.
pub const SLO_LEDGER_SCHEMA: &str = "radiata.woooo.tech/schemas/slo-ledger-v1";

/// The closed retry classification set. A lineage continues only through
/// an independently classified infrastructure failure; every other value
/// (and every unknown value) fails the validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
  /// The attempt ran to its configured budget without interruption.
  Complete,
  /// The provider infrastructure failed independently of the product.
  Infrastructure,
}

impl RetryClass {
  fn parse(value: &str) -> Option<Self> {
    match value {
      "complete" => Some(Self::Complete),
      "infrastructure" => Some(Self::Infrastructure),
      _ => None,
    }
  }

  fn as_str(self) -> &'static str {
    match self {
      Self::Complete => "complete",
      Self::Infrastructure => "infrastructure",
    }
  }
}

/// The closed result set of one attested attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptResult {
  Pass,
  Fail,
}

impl AttemptResult {
  fn parse(value: &str) -> Option<Self> {
    match value {
      "pass" => Some(Self::Pass),
      "fail" => Some(Self::Fail),
      _ => None,
    }
  }
}

/// One parsed and validated test-attestation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attestation {
  /// The exact tested commit revision.
  pub commit: String,
  /// The exact Cargo.lock digest bound to the attempt.
  pub lock_digest: String,
  /// The provider run identifier.
  pub provider_run_id: String,
  /// The attempt number inside the run.
  pub attempt: String,
  /// The job or shard identifier.
  pub job: String,
  /// The attested target name.
  pub target: String,
  /// The configured budget in seconds.
  pub budget_seconds: u64,
  /// The actually attested duration in seconds.
  pub duration_seconds: u64,
  /// Whether the run was uninterrupted.
  pub uninterrupted: bool,
  /// The closed retry classification.
  pub retry: RetryClass,
  /// The digest of the predecessor attempt line, empty for a first
  /// attempt.
  pub predecessor: String,
  /// The attempt result.
  pub result: AttemptResult,
}

/// One validation rejection. Every variant is a hard failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
  /// The schema tag is not a known current-semantic schema.
  UnknownSchema(String),
  /// A required field is missing or empty.
  MissingField(&'static str),
  /// A field failed its closed value set or digest shape.
  InvalidField(&'static str),
  /// The attested duration is under the configured budget.
  UnderBudget,
  /// The run was interrupted; it can never attest a budget.
  Interrupted,
  /// The commit or lock digest does not match the candidate.
  CommitMismatch,
  /// The lineage masks retained failed evidence or breaks its chain.
  MaskedLineage(&'static str),
  /// The SLO ledger misses required samples, values, or records.
  IncompleteLedger(&'static str),
  /// A sample was excluded, replaced, or reclassified after start.
  SampleExcludedAfterStart,
}

impl core::fmt::Display for ValidationError {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::UnknownSchema(schema) => write!(formatter, "unknown schema {schema}"),
      Self::MissingField(field) => write!(formatter, "missing field {field}"),
      Self::InvalidField(field) => write!(formatter, "invalid field {field}"),
      Self::UnderBudget => write!(formatter, "attested duration under budget"),
      Self::Interrupted => write!(formatter, "interrupted run cannot attest"),
      Self::CommitMismatch => write!(formatter, "commit or lock digest mismatch"),
      Self::MaskedLineage(why) => write!(formatter, "masked attempt lineage: {why}"),
      Self::IncompleteLedger(why) => write!(formatter, "incomplete ledger: {why}"),
      Self::SampleExcludedAfterStart => {
        write!(formatter, "sample excluded after start")
      }
    }
  }
}

impl std::error::Error for ValidationError {}

/// Minimal bounded JSON object extraction for the flat attestation
/// records. The ledger producers emit canonical flat objects; the parser
/// pulls exactly the allowlisted string keys and rejects duplicate keys.
fn flat_object(line: &str) -> Result<BTreeMap<String, String>, ValidationError> {
  let trimmed = line.trim();
  let Some(inner) = trimmed
    .strip_prefix('{')
    .and_then(|rest| rest.strip_suffix('}'))
  else {
    return Err(ValidationError::InvalidField("object shape"));
  };
  let mut fields = BTreeMap::new();
  let mut rest = inner.trim();
  while !rest.is_empty() {
    let Some(key) = scan_string(&mut rest) else {
      return Err(ValidationError::InvalidField("object key"));
    };
    rest = rest.trim_start();
    let Some(after_colon) = rest.strip_prefix(':') else {
      return Err(ValidationError::InvalidField("object colon"));
    };
    rest = after_colon.trim_start();
    let value = if rest.starts_with('"') {
      scan_string(&mut rest).ok_or(ValidationError::InvalidField("object value"))?
    } else {
      let end = rest.find(',').unwrap_or(rest.len());
      let raw = rest[..end].trim().to_owned();
      if raw.is_empty() {
        return Err(ValidationError::InvalidField("object value"));
      }
      rest = &rest[end..];
      raw
    };
    rest = rest
      .trim_start()
      .strip_prefix(',')
      .unwrap_or(rest)
      .trim_start();
    if fields.insert(key, value).is_some() {
      return Err(ValidationError::InvalidField("duplicate key"));
    }
  }
  Ok(fields)
}

/// Scans one quoted string from the front of `rest`, advancing past the
/// closing quote. Escapes are not recognized: producers emit canonical
/// text without them.
fn scan_string(rest: &mut &str) -> Option<String> {
  let after = rest.trim_start().strip_prefix('"')?;
  let end = after.find('"')?;
  let value = after[..end].to_owned();
  *rest = &after[end + 1..];
  Some(value)
}

fn require(
  fields: &BTreeMap<String, String>, name: &'static str,
) -> Result<String, ValidationError> {
  fields
    .get(name)
    .cloned()
    .filter(|value| !value.is_empty())
    .ok_or(ValidationError::MissingField(name))
}

fn require_u64(
  fields: &BTreeMap<String, String>, name: &'static str,
) -> Result<u64, ValidationError> {
  require(fields, name)?
    .parse()
    .map_err(|_| ValidationError::InvalidField(name))
}

fn require_bool(
  fields: &BTreeMap<String, String>, name: &'static str,
) -> Result<bool, ValidationError> {
  match require(fields, name)?.as_str() {
    "true" => Ok(true),
    "false" => Ok(false),
    _ => Err(ValidationError::InvalidField(name)),
  }
}

/// Parses one canonical test-attestation line.
///
/// # Errors
/// Fails closed on unknown schema tags, missing fields, and malformed
/// values.
pub fn parse_attestation(line: &str) -> Result<Attestation, ValidationError> {
  let fields = flat_object(line)?;
  if fields.get("schema").map(String::as_str) != Some(ATTESTATION_SCHEMA) {
    return Err(ValidationError::UnknownSchema(
      fields.get("schema").cloned().unwrap_or_default(),
    ));
  }
  let uninterrupted = require_bool(&fields, "uninterrupted")?;
  let result = AttemptResult::parse(&require(&fields, "result")?)
    .ok_or(ValidationError::InvalidField("result"))?;
  let retry =
    RetryClass::parse(&require(&fields, "retry")?).ok_or(ValidationError::InvalidField("retry"))?;
  Ok(Attestation {
    commit: require(&fields, "commit")?,
    lock_digest: require(&fields, "lock_digest")?,
    provider_run_id: require(&fields, "provider_run_id")?,
    attempt: require(&fields, "attempt")?,
    job: require(&fields, "job")?,
    target: require(&fields, "target")?,
    budget_seconds: require_u64(&fields, "budget_seconds")?,
    duration_seconds: require_u64(&fields, "duration_seconds")?,
    uninterrupted,
    retry,
    predecessor: fields.get("predecessor").cloned().unwrap_or_default(),
    result,
  })
}

/// Validates one attestation against the candidate identity and the
/// target's required budget.
///
/// # Errors
/// Fails closed on budget, interruption, and identity mismatches.
pub fn validate_attestation(
  attestation: &Attestation, expected_commit: &str, expected_lock: &str, required_budget: u64,
) -> Result<(), ValidationError> {
  if attestation.commit != expected_commit || attestation.lock_digest != expected_lock {
    return Err(ValidationError::CommitMismatch);
  }
  if !attestation.uninterrupted {
    return Err(ValidationError::Interrupted);
  }
  if attestation.duration_seconds < attestation.budget_seconds
    || attestation.budget_seconds < required_budget
  {
    return Err(ValidationError::UnderBudget);
  }
  Ok(())
}

/// Validates one complete attempt lineage in ledger order.
///
/// Rules: every non-first attempt must name its predecessor's
/// digest; only an `Infrastructure` classification may follow a failed
/// attempt; a failed product attempt can never be superseded — the
/// lineage fails if any failure is followed by a successful attempt
/// without an infrastructure classification, and the failed attempts stay
/// in the ledger regardless.
///
/// # Errors
/// Fails closed on any masked or broken lineage.
pub fn validate_lineage(attestations: &[Attestation]) -> Result<(), ValidationError> {
  let mut predecessor = String::new();
  let mut failed_pending = false;
  for (index, attestation) in attestations.iter().enumerate() {
    let digest = attempt_digest(attestation);
    if index == 0 {
      if !attestation.predecessor.is_empty() {
        return Err(ValidationError::MaskedLineage(
          "first attempt names a predecessor",
        ));
      }
    } else {
      if attestation.predecessor != predecessor {
        return Err(ValidationError::MaskedLineage(
          "predecessor digest mismatch",
        ));
      }
      if failed_pending && attestation.retry != RetryClass::Infrastructure {
        return Err(ValidationError::MaskedLineage(
          "success supersedes retained failure without infrastructure classification",
        ));
      }
    }
    if attestation.retry == RetryClass::Complete && attestation.result == AttemptResult::Fail {
      failed_pending = true;
    } else if attestation.retry == RetryClass::Infrastructure {
      failed_pending = false;
    }
    predecessor = digest;
  }
  Ok(())
}

/// The canonical digest of one raw ledger line (the soak attempt chain
/// link). Trailing line breaks are not part of the digest, so producers
/// chain append-mode NDJSON records without retaining newline bytes.
///
/// # Panics
/// Never: the SHA-256 digest of a fixed input cannot fail.
#[must_use]
pub fn line_digest(line: &str) -> String {
  let mut hasher = Sha256::new();
  hasher.update(line.trim_end().as_bytes());
  hex(&hasher.finalize())
}

/// The canonical digest of one attempt record (the lineage chain link).
///
/// # Panics
/// Never: the SHA-256 digest of a fixed input cannot fail.
#[must_use]
pub fn attempt_digest(attestation: &Attestation) -> String {
  let mut hasher = Sha256::new();
  hasher.update(attestation.commit.as_bytes());
  hasher.update([0]);
  hasher.update(attestation.lock_digest.as_bytes());
  hasher.update([0]);
  hasher.update(attestation.provider_run_id.as_bytes());
  hasher.update([0]);
  hasher.update(attestation.attempt.as_bytes());
  hasher.update([0]);
  hasher.update(attestation.job.as_bytes());
  hasher.update([0]);
  hasher.update(attestation.target.as_bytes());
  hasher.update([0]);
  hasher.update(attestation.retry.as_str().as_bytes());
  hasher.update([0]);
  hasher.update(attestation.duration_seconds.to_le_bytes());
  hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
  let mut text = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
    text.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
  }
  text
}

/// One raw SLO sample of the release-candidate ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SloSample {
  /// The predeclared sample identifier (run 1..=5, sample 1..=25).
  pub sample_id: String,
  /// The workload stratum of the sample.
  pub stratum: SloStratum,
  /// The raw start wall-clock observation.
  pub started_at_ms: u128,
  /// The raw end wall-clock observation.
  pub ended_at_ms: u128,
}

/// The five exact workload strata of the SLO profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SloStratum {
  Admission,
  DirectPacket,
  RoutedPacket,
  NodeMetadata,
  ResourceMetadata,
}

impl SloStratum {
  fn parse(value: &str) -> Option<Self> {
    match value {
      "admission" => Some(Self::Admission),
      "direct-packet" => Some(Self::DirectPacket),
      "routed-packet" => Some(Self::RoutedPacket),
      "node-metadata" => Some(Self::NodeMetadata),
      "resource-metadata" => Some(Self::ResourceMetadata),
      _ => None,
    }
  }
}

/// The validation outcome of the complete candidate SLO ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SloValidation {
  /// The number of accepted samples (must be exactly 125 to release).
  pub samples: usize,
  /// The maximum observed sample latency in milliseconds.
  pub maximum_latency_ms: u128,
}

/// Validates the complete candidate SLO ledger.
///
/// Rules: exactly 125 samples across five runs
/// and five strata (five samples per stratum per run); every sample
/// carries its predeclared identifier and raw start/end observations; no
/// sample is excluded, replaced, or reclassified after start; every
/// sample is at most `deadline_ms`; and the ledger records the profile
/// constants and the cleanup status.
///
/// # Errors
/// Fails closed on any missing sample, malformed value, exclusion, or
/// deadline breach.
pub fn validate_slo_ledger(
  samples: &[SloSample], deadline_ms: u128, profile_members: u64, release_samples: usize,
  cleanup_complete: bool,
) -> Result<SloValidation, ValidationError> {
  if !cleanup_complete {
    return Err(ValidationError::IncompleteLedger("cleanup status"));
  }
  if profile_members != 16 {
    return Err(ValidationError::IncompleteLedger("profile member count"));
  }
  if samples.len() != release_samples {
    return Err(ValidationError::IncompleteLedger("sample count"));
  }
  let mut runs: BTreeMap<String, [usize; 5]> = BTreeMap::new();
  let mut maximum: u128 = 0;
  for sample in samples {
    if sample.ended_at_ms < sample.started_at_ms {
      return Err(ValidationError::InvalidField("sample window"));
    }
    if sample.started_at_ms == 0 {
      return Err(ValidationError::MissingField("raw start value"));
    }
    if sample.sample_id.is_empty() {
      return Err(ValidationError::MissingField("sample id"));
    }
    let latency = sample.ended_at_ms - sample.started_at_ms;
    if latency > deadline_ms {
      return Err(ValidationError::SampleExcludedAfterStart);
    }
    maximum = maximum.max(latency);
    let run = sample.sample_id.split('/').next().unwrap_or("");
    let Some(slot) = stratum_slot(sample.stratum) else {
      return Err(ValidationError::InvalidField("stratum"));
    };
    let slots = runs.entry(run.to_owned()).or_default();
    slots[slot] += 1;
  }
  let runs_expected = 5_u64;
  if runs.len() as u64 != runs_expected {
    return Err(ValidationError::IncompleteLedger("run count"));
  }
  let per_run = release_samples / runs.len();
  let per_stratum = per_run / 5;
  for slots in runs.values() {
    if slots.iter().sum::<usize>() != per_run {
      return Err(ValidationError::IncompleteLedger("run sample count"));
    }
    for count in slots {
      if *count != per_stratum {
        return Err(ValidationError::IncompleteLedger("stratum sample count"));
      }
    }
  }
  Ok(SloValidation {
    samples: samples.len(),
    maximum_latency_ms: maximum,
  })
}

/// Parses one canonical SLO ledger sample line:
/// `{"schema":".../slo-ledger-v1","sample_id":"<run>/<index>",
///   "stratum":"<closed stratum>","started_at_ms":<raw>,"ended_at_ms":<raw>}`.
///
/// # Errors
/// Fails closed on unknown schema, missing fields, and malformed values.
pub fn parse_slo_sample(line: &str) -> Result<SloSample, ValidationError> {
  let fields = flat_object(line)?;
  if fields.get("schema").map(String::as_str) != Some(SLO_LEDGER_SCHEMA) {
    return Err(ValidationError::UnknownSchema(
      fields.get("schema").cloned().unwrap_or_default(),
    ));
  }
  Ok(SloSample {
    sample_id: require(&fields, "sample_id")?,
    stratum: SloStratum::parse(&require(&fields, "stratum")?)
      .ok_or(ValidationError::InvalidField("stratum"))?,
    started_at_ms: require_u64(&fields, "started_at_ms")?.into(),
    ended_at_ms: require_u64(&fields, "ended_at_ms")?.into(),
  })
}

fn stratum_slot(stratum: SloStratum) -> Option<usize> {
  match stratum {
    SloStratum::Admission => Some(0),
    SloStratum::DirectPacket => Some(1),
    SloStratum::RoutedPacket => Some(2),
    SloStratum::NodeMetadata => Some(3),
    SloStratum::ResourceMetadata => Some(4),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const COMMIT: &str = "3f2a1b";
  const LOCK: &str = "9c8d7e";

  fn attestation_line(overrides: &[(&str, String)]) -> String {
    let mut fields: Vec<(String, String)> = vec![
      ("schema".into(), ATTESTATION_SCHEMA.into()),
      ("commit".into(), COMMIT.into()),
      ("lock_digest".into(), LOCK.into()),
      ("provider_run_id".into(), "run-1".into()),
      ("attempt".into(), "1".into()),
      ("job".into(), "fuzz-wire_decode".into()),
      ("target".into(), "wire_decode".into()),
      ("budget_seconds".into(), "300".into()),
      ("duration_seconds".into(), "300".into()),
      ("uninterrupted".into(), "true".into()),
      ("retry".into(), "complete".into()),
      ("predecessor".into(), String::new()),
      ("result".into(), "pass".into()),
    ];
    for (key, value) in overrides {
      if let Some(slot) = fields.iter_mut().find(|(name, _)| name == key) {
        slot.1 = value.clone();
      } else {
        fields.push(((*key).to_owned(), value.clone()));
      }
    }
    let rendered = fields
      .iter()
      .map(|(key, value)| format!("\"{key}\":\"{value}\""))
      .collect::<Vec<_>>()
      .join(",");
    format!("{{{rendered}}}")
  }

  fn passing_attestation() -> Attestation {
    parse_attestation(&attestation_line(&[])).unwrap()
  }

  // The soak lineage chain links raw attempt lines by exact-content
  // digest; trailing line breaks never enter the digest.
  #[test]
  fn line_digest_links_raw_ledger_lines_without_line_breaks() {
    let line = "{\"schema\":\"x\",\"result\":\"pass\"}";
    assert_eq!(line_digest(line), line_digest(&format!("{line}\n")));
    assert_ne!(line_digest(line), line_digest("{\"schema\":\"x\"}"));
    assert_eq!(line_digest("").len(), 64);
  }

  // The complete current-semantic record passes preflight.
  #[test]
  fn complete_attestation_passes_preflight() {
    let attestation = passing_attestation();
    assert_eq!(attestation.commit, COMMIT);
    validate_attestation(&attestation, COMMIT, LOCK, 300).unwrap();
    validate_lineage(&[attestation]).unwrap();
  }

  // Interrupted runs, missing attestations, short
  // durations, and identity mismatches all fail closed.
  #[test]
  fn incomplete_or_under_budget_evidence_is_rejected() {
    let interrupted =
      parse_attestation(&attestation_line(&[("uninterrupted", "false".into())])).unwrap();
    assert_eq!(
      validate_attestation(&interrupted, COMMIT, LOCK, 300),
      Err(ValidationError::Interrupted)
    );

    let short =
      parse_attestation(&attestation_line(&[("duration_seconds", "299".into())])).unwrap();
    assert_eq!(
      validate_attestation(&short, COMMIT, LOCK, 300),
      Err(ValidationError::UnderBudget)
    );

    let reduced_budget =
      parse_attestation(&attestation_line(&[("budget_seconds", "60".into())])).unwrap();
    assert_eq!(
      validate_attestation(&reduced_budget, COMMIT, LOCK, 300),
      Err(ValidationError::UnderBudget)
    );

    let wrong_commit = passing_attestation();
    assert_eq!(
      validate_attestation(&wrong_commit, "other-commit", LOCK, 300),
      Err(ValidationError::CommitMismatch)
    );
    let wrong_lock = passing_attestation();
    assert_eq!(
      validate_attestation(&wrong_lock, COMMIT, "other-lock", 300),
      Err(ValidationError::CommitMismatch)
    );

    // A missing field is a rejection, not a default.
    let missing = attestation_line(&[("commit", String::new())]);
    assert!(matches!(
      parse_attestation(&missing),
      Err(ValidationError::MissingField("commit"))
    ));

    // An unknown schema tag is a rejection.
    let stale = attestation_line(&[(
      "schema",
      "radiata.woooo.tech/schemas/test-attestation-v0".into(),
    )]);
    assert!(matches!(
      parse_attestation(&stale),
      Err(ValidationError::UnknownSchema(_))
    ));

    // A missing attestation cannot pass: there is nothing to validate.
    assert!(parse_attestation("").is_err());
    assert!(parse_attestation("not-json").is_err());
  }

  // A product failure, a missing predecessor, an invalid
  // retry classification, a replacement run, and a later successful rerun
  // can never supersede retained failed evidence.
  #[test]
  fn masked_attempt_lineages_are_rejected() {
    // A later successful attempt cannot mask a retained product failure.
    let failed = parse_attestation(&attestation_line(&[("result", "fail".into())])).unwrap();
    let mut rerun = passing_attestation();
    rerun.attempt = "2".into();
    rerun.predecessor = attempt_digest(&failed);
    assert_eq!(
      validate_lineage(&[failed, rerun]),
      Err(ValidationError::MaskedLineage(
        "success supersedes retained failure without infrastructure classification"
      ))
    );

    // A missing predecessor breaks the chain.
    let mut orphan = passing_attestation();
    orphan.attempt = "2".into();
    assert_eq!(
      validate_lineage(&[passing_attestation(), orphan]),
      Err(ValidationError::MaskedLineage(
        "predecessor digest mismatch"
      ))
    );

    // An invalid retry classification fails closed.
    let invalid = attestation_line(&[("retry", "retried-because-green-please".into())]);
    assert!(matches!(
      parse_attestation(&invalid),
      Err(ValidationError::InvalidField("retry"))
    ));

    // A replacement run that reuses attempt 1 with a different predecessor
    // is a broken chain.
    let mut replacement = passing_attestation();
    replacement.predecessor = "fabricated".into();
    assert_eq!(
      validate_lineage(&[passing_attestation(), replacement]),
      Err(ValidationError::MaskedLineage(
        "predecessor digest mismatch"
      ))
    );

    // An independently classified infrastructure failure may start a new
    // lineage segment: the failed attempt stays retained and the retry
    // passes only through the infrastructure classification.
    let failed = parse_attestation(&attestation_line(&[("result", "fail".into())])).unwrap();
    let mut retried = passing_attestation();
    retried.attempt = "2".into();
    retried.retry = RetryClass::Infrastructure;
    retried.predecessor = attempt_digest(&failed);
    validate_lineage(&[failed, retried]).unwrap();
  }

  // The complete synthetic SLO ledger passes and every
  // incomplete or post-start-excluded variant fails.
  #[test]
  fn slo_ledger_validation() {
    let mut samples = Vec::new();
    for run in 1..=5_u32 {
      for stratum in [
        SloStratum::Admission,
        SloStratum::DirectPacket,
        SloStratum::RoutedPacket,
        SloStratum::NodeMetadata,
        SloStratum::ResourceMetadata,
      ] {
        for index in 1..=5_u32 {
          let line = format!(
            "{{\"schema\":\"{SLO_LEDGER_SCHEMA}\",\"sample_id\":\"run-{run}/sample-{index}\",\"stratum\":\"{}\",\"started_at_ms\":{},\"ended_at_ms\":{}}}",
            stratum_name(stratum),
            1_000 + u128::from(index),
            2_000 + u128::from(index),
          );
          samples.push(parse_slo_sample(&line).unwrap());
        }
      }
    }
    assert_eq!(samples.len(), 125);
    let outcome = validate_slo_ledger(&samples, 10_000, 16, 125, true).unwrap();
    assert_eq!(outcome.samples, 125);
    assert_eq!(outcome.maximum_latency_ms, 1_000);

    // A profile member count that differs from the validator's constant
    // fails.
    assert_eq!(
      validate_slo_ledger(&samples, 10_000, 32, 125, true),
      Err(ValidationError::IncompleteLedger("profile member count"))
    );

    // A missing sample fails the count.
    assert_eq!(
      validate_slo_ledger(&samples[..124], 10_000, 16, 125, true),
      Err(ValidationError::IncompleteLedger("sample count"))
    );

    // A sample above the deadline is a failed sample, never an exclusion.
    let mut over = samples.clone();
    over[0].ended_at_ms = 20_000;
    assert_eq!(
      validate_slo_ledger(&over, 10_000, 16, 125, true),
      Err(ValidationError::SampleExcludedAfterStart)
    );

    // An incomplete run (24 samples in one run, 26 in another) fails.
    let mut uneven = samples.clone();
    uneven[0].sample_id = "run-2/sample-99".into();
    assert!(validate_slo_ledger(&uneven, 10_000, 16, 125, true).is_err());

    // Missing cleanup status fails.
    assert_eq!(
      validate_slo_ledger(&samples, 10_000, 16, 125, false),
      Err(ValidationError::IncompleteLedger("cleanup status"))
    );

    // A sample without raw values fails.
    let line = format!(
      "{{\"schema\":\"{SLO_LEDGER_SCHEMA}\",\"sample_id\":\"run-1/sample-1\",\"stratum\":\"admission\",\"started_at_ms\":0,\"ended_at_ms\":1}}"
    );
    let zero = parse_slo_sample(&line).unwrap();
    let mut with_zero = samples.clone();
    with_zero[0] = zero;
    assert_eq!(
      validate_slo_ledger(&with_zero, 10_000, 16, 125, true),
      Err(ValidationError::MissingField("raw start value"))
    );
  }

  fn stratum_name(stratum: SloStratum) -> &'static str {
    match stratum {
      SloStratum::Admission => "admission",
      SloStratum::DirectPacket => "direct-packet",
      SloStratum::RoutedPacket => "routed-packet",
      SloStratum::NodeMetadata => "node-metadata",
      SloStratum::ResourceMetadata => "resource-metadata",
    }
  }
}
