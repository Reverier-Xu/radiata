//! Shared value-construction helpers for storage test lanes.
//!
//! The JSON adapter lane (`json/helpers.rs`) and the backend-neutral
//! contract suite (`contract.rs`) previously declared their own copies of
//! these constructors; a single definition prevents them from drifting.

use std::sync::Arc;

use crate::{QualifiedTag, StoreKey, StoreNamespace, StoreValue, TransactionId};

pub(crate) fn namespace(name: &str) -> StoreNamespace {
  StoreNamespace::new(QualifiedTag::parse(&format!("radiata.woooo.tech/metadata/{name}")).unwrap())
}

pub(crate) fn key(bytes: &[u8]) -> StoreKey {
  StoreKey::new(Arc::from(bytes))
}

pub(crate) fn value(bytes: &[u8]) -> StoreValue {
  StoreValue::new(Arc::from(bytes))
}

pub(crate) fn transaction_id(index: u64) -> TransactionId {
  TransactionId::parse(&format!("txn-{index:021}")).unwrap()
}

/// The store requirements of the subprocess durability lanes (single
/// source): unix directory barriers make the plain metadata profile
/// sufficient; other platforms must require process-crash atomicity
/// explicitly.
#[cfg_attr(not(feature = "json"), allow(dead_code))]
pub(crate) fn crash_requirements() -> crate::StoreRequirements {
  #[cfg(unix)]
  {
    crate::StoreRequirements::metadata()
  }
  #[cfg(not(unix))]
  {
    crate::StoreRequirements::metadata()
      .with_required_durability(crate::DurabilityLevel::ProcessCrashAtomic)
  }
}

/// The crash-matrix child wait bound shared by every subprocess lane.
/// The crash-matrix child timeout; crash-matrix lanes are test-only and
/// never compile into fuzz builds.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
pub(crate) const CRASH_CHILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The environment variable through which a crash-matrix parent hands its
/// child the path of the crash-point record. The path is the parent's
/// choice alone: children never derive it, so no lane carries its own
/// filename convention.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
pub(crate) const CRASH_RECORD_ENV: &str = "RADIATA_CRASH_POINT_RECORD";

/// How much of each captured child stream a missing-record failure
/// reports: enough for the child's own panic and the head of its
/// backtrace.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
const CHILD_OUTPUT_TAIL_CHARS: usize = 2_000;

/// Records that the scripted crash point was reached, then aborts the
/// process — the single abort site behind every `crash_hook`.
///
/// A crash matrix is only evidence when the child is proven to have died
/// AT its scripted boundary: a child that panics earlier also exits
/// abnormally, and the parent's exact-old-state assertions still pass on
/// the untouched seed, so an unproven abort rots the matrix into a false
/// green. [`run_crash_child`] therefore requires this record and asserts
/// that it names the requested point.
///
/// The record is one unbuffered `std::fs::write` of the decimal point, so
/// the kernel owns the bytes before `abort()` runs and the parent reads
/// them back through the same page cache. No `sync_all`: the reader is a
/// sibling process on this machine, not a post-power-loss reader. A point
/// that cannot be recorded panics instead of aborting, so the parent
/// reports that cause from the captured stderr tail rather than an
/// unexplained missing record.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
pub(crate) fn abort_at_crash_point(point: u8) -> ! {
  let path = match std::env::var_os(CRASH_RECORD_ENV) {
    Some(path) => std::path::PathBuf::from(path),
    None => panic!(
      "crash point {point} reached but {CRASH_RECORD_ENV} is unset: only a crash-matrix parent \
       hands out a crash-point record path"
    ),
  };
  if let Err(error) = std::fs::write(&path, point.to_string()) {
    panic!(
      "crash point {point} reached but its record {} cannot be written: {error}",
      path.display()
    );
  }
  std::process::abort()
}

/// Spawns the current test binary as one crash-matrix child (single
/// source for the JSON adapter and resource register lanes): exact test
/// filter, environment-selected crash directory and point, and the
/// crash-point record path.
///
/// Panics unless the child terminates abnormally within the timeout AND
/// its record proves the scripted crash point was reached. Only the pair
/// is evidence: an abnormal exit alone cannot distinguish a scripted
/// abort from a child that panicked before its boundary, and the parent's
/// old-state assertions would still pass on the untouched seed.
///
/// Child stdout and stderr go to files, never pipes: the parent reads
/// them only after the child is reaped, so no read can deadlock against a
/// still-writing child, and their tails explain a missing record without
/// a re-run.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
pub(crate) fn run_crash_child(
  test_name: &str, dir_env: &str, point_env: &str, dir: &std::path::Path, point: u8, label: &str,
  extra_env: &[(&'static str, String)],
) {
  use std::{
    fs,
    process::{Command, Stdio},
  };

  use wait_timeout::ChildExt as _;

  let capture = tempfile::tempdir().expect("crash child capture directory");
  let record_path = capture.path().join("crash-point");
  let stdout_path = capture.path().join("child-stdout");
  let stderr_path = capture.path().join("child-stderr");
  // The proof below is "THIS child wrote the record", so a record left at
  // the path by an earlier spawn must never stand in for it.
  match fs::remove_file(&record_path) {
    Ok(()) => {}
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
    Err(error) => panic!(
      "{label} crash child at point {point}: stale crash-point record {} cannot be removed: \
       {error}",
      record_path.display()
    ),
  }
  let stdout_file = fs::File::create(&stdout_path).expect("crash child stdout capture");
  let stderr_file = fs::File::create(&stderr_path).expect("crash child stderr capture");

  let executable = std::env::current_exe().unwrap();
  let mut command = Command::new(executable);
  command
    .args(["--exact", test_name, "--ignored", "--nocapture"])
    .env(dir_env, dir)
    .env(point_env, point.to_string())
    .env(CRASH_RECORD_ENV, &record_path);
  for (name, value) in extra_env {
    command.env(name, value);
  }
  let mut child = command
    .stdin(Stdio::null())
    .stdout(Stdio::from(stdout_file))
    .stderr(Stdio::from(stderr_file))
    .spawn()
    .unwrap();
  let status = match child.wait_timeout(CRASH_CHILD_TIMEOUT).unwrap() {
    Some(status) => status,
    None => {
      child.kill().unwrap();
      panic!("{label} crash child at point {point} did not exit within {CRASH_CHILD_TIMEOUT:?}");
    }
  };
  assert!(
    !status.success(),
    "{label} crash child at point {point} must terminate abnormally"
  );

  let expected = point.to_string();
  let recorded = fs::read_to_string(&record_path)
    .ok()
    .map(|text| text.trim().to_owned());
  if recorded.as_deref() != Some(expected.as_str()) {
    let observed = match recorded {
      Some(text) => format!("the crash-point record names {text:?}"),
      None => format!(
        "no crash-point record was written to {}",
        record_path.display()
      ),
    };
    panic!(
      "{label} crash child at point {point} aborted without reaching its scripted crash point: \
       {observed}, expected {expected:?}.\n--- child stdout (tail) ---\n{}\n--- child stderr (tail) \
       ---\n{}",
      captured_tail(&stdout_path),
      captured_tail(&stderr_path),
    );
  }
}

/// The last [`CHILD_OUTPUT_TAIL_CHARS`] characters of one captured child
/// stream: the child's own panic is the real cause of a missing
/// crash-point record, and reporting it here saves a re-run.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
fn captured_tail(path: &std::path::Path) -> String {
  let bytes = std::fs::read(path).unwrap_or_default();
  let text = String::from_utf8_lossy(&bytes);
  let total = text.chars().count();
  if total <= CHILD_OUTPUT_TAIL_CHARS {
    return text.into_owned();
  }
  let tail: String = text.chars().skip(total - CHILD_OUTPUT_TAIL_CHARS).collect();
  format!("…{tail}")
}

/// The crash matrices' lock-window reopen helpers, compiled only where
/// their caller matrices exist (test builds with the json or redb
/// backend): a SIGKILLed crash child releases its lock when the process
/// dies, but a loaded runner may schedule the parent's reopen before
/// the release lands. Crash-matrix parents reopen through these, never
/// through a bare open.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
pub(crate) mod crash_reopen {
  use std::{sync::Arc, time::Duration};

  use crate::{ErrorKind, provider::StorageFactory};

  /// Opens the store retrying the cross-process lock window: the
  /// crashed child releases its lock when the process dies, but a
  /// loaded or overlay-filesystem runner may schedule the reopen before
  /// the release lands. Parents AND crash children reopen through this,
  /// never through a bare open — a bare open in a child aborts it
  /// before its scripted crash point, which the crash matrices read as
  /// a spurious abort and report as a non-monotonic boundary.
  ///
  /// Unix-gated with its callers: every store-level crash matrix is
  /// unix-only (its children need the directory-barrier crash hooks),
  /// while the provider-level twin below is used by the all-platform
  /// adapter children.
  #[cfg(all(test, unix))]
  pub(crate) async fn open_store_with_lock_retry(
    factory: &Arc<dyn StorageFactory>,
  ) -> crate::storage::MetadataStore {
    use crate::storage::MetadataStore;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
      match MetadataStore::open(factory, Duration::from_secs(10)).await {
        Ok(store) => return store,
        Err(error) if error.kind() == ErrorKind::StorageLocked => {
          assert!(
            std::time::Instant::now() < deadline,
            "store lock never released: {error:?}"
          );
          tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(error) => panic!("crash-store reopen failed: {error:?}"),
      }
    }
  }

  /// The provider-level twin: the same lock-window retry for matrices
  /// that assert on the raw provider.
  pub(crate) async fn open_provider_with_lock_retry(
    factory: &Arc<dyn StorageFactory>, requirements: crate::StoreRequirements,
  ) -> Box<dyn crate::provider::Storage> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
      match factory.open(requirements).await {
        Ok(provider) => return provider,
        Err(error) if error.kind() == ErrorKind::StorageLocked => {
          assert!(
            std::time::Instant::now() < deadline,
            "provider lock never released: {error:?}"
          );
          tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(error) => panic!("crash provider reopen failed: {error:?}"),
      }
    }
  }
}
