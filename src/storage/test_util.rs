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

/// Spawns the current test binary as one crash-matrix child (single
/// source for the JSON adapter and resource register lanes): exact test
/// filter, environment-selected crash directory and point, no stdio.
/// Panics unless the child terminates abnormally within the timeout.
#[cfg(all(test, any(feature = "json", feature = "redb")))]
pub(crate) fn run_crash_child(
  test_name: &str, dir_env: &str, point_env: &str, dir: &std::path::Path, point: u8, label: &str,
  extra_env: &[(&'static str, String)],
) {
  use std::process::{Command, Stdio};

  use wait_timeout::ChildExt as _;

  let executable = std::env::current_exe().unwrap();
  let mut command = Command::new(executable);
  command
    .args(["--exact", test_name, "--ignored", "--nocapture"])
    .env(dir_env, dir)
    .env(point_env, point.to_string());
  for (name, value) in extra_env {
    command.env(name, value);
  }
  let mut child = command
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
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
}
