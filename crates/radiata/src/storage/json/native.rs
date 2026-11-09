//! Native platform robustness suite for the JSON adapter.
//!
//! These tests exercise OS-level behavior that cannot be proven by the
//! backend-neutral contract alone: cross-process lock contention and
//! release, aliased opens, permission and cleanup failures, and exact
//! per-platform capability claims. The suite runs unmodified on Linux,
//! macOS, and Windows CI through the normal test jobs.

use std::{
  fs,
  io::{BufRead, BufReader, Read},
  process::{Command, Stdio},
  sync::Arc,
  time::Duration,
};

use tempfile::TempDir;
use wait_timeout::ChildExt as _;

use super::{JsonStoreFactory, helpers};
// The unix lock lane asserts the OS-crash durability claim; other platforms
// never reference the level.
#[cfg(unix)]
use crate::DurabilityLevel;
use crate::{
  CommitOutcome, ErrorKind, StoreRequirements,
  provider::{Storage, StorageFactory},
};

const NATIVE_DIR_ENV: &str = "RADIATA_JSON_NATIVE_DIR";
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

fn requirements() -> StoreRequirements {
  crate::storage::test_util::crash_requirements()
}

async fn open(factory: &Arc<dyn StorageFactory>) -> Box<dyn Storage> {
  factory.open(requirements()).await.unwrap()
}

/// Child entry point: holds the store lock until stdin closes.
#[ignore = "native lock-holding child process entry point"]
#[tokio::test]
async fn json_native_child_hold_lock() {
  let directory = std::env::var_os(NATIVE_DIR_ENV).expect("native directory");
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(directory.into()));
  let _storage = factory.open(requirements()).await.unwrap();
  use std::io::Write as _;

  println!("ready");
  let _ = std::io::stdout().flush();
  let mut stdin = std::io::stdin();
  let mut buffer = [0_u8; 1];
  while matches!(stdin.read(&mut buffer), Ok(1)) {}
}

fn spawn_lock_child(
  dir: &TempDir,
) -> (
  std::process::Child,
  std::process::ChildStdin,
  BufReader<std::process::ChildStdout>,
) {
  let executable = std::env::current_exe().unwrap();
  let mut child = Command::new(executable)
    .args([
      "--exact",
      "storage::json::native::json_native_child_hold_lock",
      "--ignored",
      "--nocapture",
    ])
    .env(NATIVE_DIR_ENV, dir.path())
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
  let mut stdout = BufReader::new(child.stdout.take().unwrap());
  let mut ready = false;
  for _ in 0..16 {
    let mut line = String::new();
    if stdout.read_line(&mut line).unwrap() == 0 {
      break;
    }
    if line.trim_end() == "ready" {
      ready = true;
      break;
    }
  }
  assert!(ready, "child must report lock readiness");
  let stdin = child.stdin.take().unwrap();
  (child, stdin, stdout)
}

fn drain_stdout(mut stdout: BufReader<std::process::ChildStdout>) {
  let mut line = String::new();
  for _ in 0..64 {
    line.clear();
    match stdout.read_line(&mut line) {
      Ok(0) | Err(_) => break,
      Ok(_) => {}
    }
  }
}

fn wait_child(child: &mut std::process::Child, context: &str) -> std::process::ExitStatus {
  match child.wait_timeout(CHILD_TIMEOUT).unwrap() {
    Some(status) => status,
    None => {
      let _ = child.kill();
      let _ = child.wait();
      panic!("native child did not exit within {CHILD_TIMEOUT:?}: {context}");
    }
  }
}

#[tokio::test]
async fn json_native_concurrent_open_from_second_process_is_storage_locked_until_exit() {
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let (mut child, stdin, stdout) = spawn_lock_child(&dir);

  let error = factory.open(requirements()).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageLocked);

  drop(stdin);
  drain_stdout(stdout);
  let status = wait_child(&mut child, "lock release on stdin close");
  assert!(status.success(), "child exit: {status}");

  // Windows LockFileEx is mandatory: the lock file is only readable while
  // no store holds it, so compare contents outside any open window.
  let lock_before = fs::read(dir.path().join("radiata.lock")).unwrap();
  let storage = open(&factory).await;
  drop(storage);
  let storage = open(&factory).await;
  drop(storage);
  assert_eq!(
    fs::read(dir.path().join("radiata.lock")).unwrap(),
    lock_before,
    "the stale lock file is retained and reused"
  );
}

#[tokio::test]
async fn json_native_lock_released_after_process_kill_and_store_recovers() {
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let storage = open(&factory).await;
  let revision = storage.snapshot().await.unwrap().revision().clone();
  assert!(matches!(
    storage
      .commit(helpers::put_transaction(1, revision, &[("seed", b"seed")]))
      .await
      .unwrap(),
    CommitOutcome::Committed(_)
  ));
  drop(storage);

  let (mut child, _stdin, stdout) = spawn_lock_child(&dir);
  let error = factory.open(requirements()).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageLocked);

  child.kill().unwrap();
  let status = wait_child(&mut child, "killed child");
  drop(stdout);
  assert!(!status.success());

  let reopened = open(&factory).await;
  let snapshot = reopened.snapshot().await.unwrap();
  assert_eq!(snapshot.revision().as_bytes(), &1_u64.to_be_bytes());
  let namespace = helpers::namespace("one");
  assert_eq!(
    snapshot
      .get(&namespace, &helpers::key(b"key-seed"))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"seed",
    "process death releases the OS lock and the chain stays valid"
  );
}

#[cfg(windows)]
#[tokio::test]
async fn json_native_alias_open_through_junction_is_storage_locked() {
  let dir = tempfile::tempdir().unwrap();
  let alias_root = tempfile::tempdir().unwrap();
  let alias = alias_root.path().join("junction");
  let status = Command::new("cmd")
    .args(["/c", "mklink", "/J"])
    .arg(&alias)
    .arg(dir.path())
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .unwrap();
  assert!(
    status.success(),
    "mklink /J must succeed on the native lane"
  );

  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let storage = open(&factory).await;
  let alias_factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(alias));
  let error = alias_factory.open(requirements()).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageLocked);
  drop(storage);
}

#[cfg(unix)]
fn running_as_root() -> bool {
  rustix::process::geteuid().as_raw() == 0
}

#[cfg(unix)]
#[tokio::test]
async fn json_native_permission_failures_are_typed_and_fail_closed() {
  use std::os::unix::fs::PermissionsExt as _;

  if running_as_root() {
    // Root bypasses directory permission modes (CAP_DAC_OVERRIDE), so the
    // permission-denied assertion is not observable; CI containers run as
    // root while native developer/CI shells exercise the denial path.
    return;
  }
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let original = fs::metadata(dir.path()).unwrap().permissions();
  fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();

  let error = factory.open(requirements()).await.unwrap_err();
  assert!(
    matches!(
      error.kind(),
      ErrorKind::PermissionDenied | ErrorKind::Io | ErrorKind::StorageLocked
    ),
    "permission failure must be typed, not panic or corruption: {error:?}"
  );
  assert_ne!(error.kind(), ErrorKind::StorageCorrupt);

  // The failed open released its in-process guard: restoring permissions
  // allows a clean open.
  fs::set_permissions(dir.path(), original).unwrap();
  let storage = open(&factory).await;
  drop(storage);
}

#[cfg(unix)]
#[tokio::test]
async fn json_native_failed_cleanup_is_typed_and_recovers_after_permission_fix() {
  use std::os::unix::fs::PermissionsExt as _;

  if running_as_root() {
    // See the euid note in the permission-failure test above.
    return;
  }
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let storage = open(&factory).await;
  let revision = storage.snapshot().await.unwrap().revision().clone();
  assert!(matches!(
    storage
      .commit(helpers::put_transaction(1, revision, &[("seed", b"seed")]))
      .await
      .unwrap(),
    CommitOutcome::Committed(_)
  ));
  drop(storage);

  let stale = dir
    .path()
    .join("tmp-00000000000000000002-txn-000000000000000000099-0.tmp");
  fs::write(&stale, b"partial").unwrap();
  let original = fs::metadata(dir.path()).unwrap().permissions();
  fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();

  let error = factory.open(requirements()).await.unwrap_err();
  assert!(
    matches!(error.kind(), ErrorKind::PermissionDenied | ErrorKind::Io),
    "failed deletion cleanup must be typed: {error:?}"
  );
  assert_ne!(error.kind(), ErrorKind::StorageCorrupt);

  fs::set_permissions(dir.path(), original).unwrap();
  let reopened = open(&factory).await;
  assert!(
    !stale.exists(),
    "cleanup recovers after permissions are restored"
  );
  drop(reopened);
}

#[tokio::test]
async fn json_native_unrelated_and_lookalike_files_are_never_mutated() {
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let storage = open(&factory).await;
  let revision = storage.snapshot().await.unwrap().revision().clone();
  assert!(matches!(
    storage
      .commit(helpers::put_transaction(1, revision, &[("seed", b"seed")]))
      .await
      .unwrap(),
    CommitOutcome::Committed(_)
  ));

  let unrelated = dir.path().join("unrelated.txt");
  fs::write(&unrelated, b"original").unwrap();
  let lookalike = dir.path().join("tmp-lookalike.tmp");
  fs::write(&lookalike, b"keep").unwrap();
  fs::write(&unrelated, b"modified-by-user").unwrap();

  drop(storage);
  let reopened = open(&factory).await;
  assert_eq!(fs::read(&unrelated).unwrap(), b"modified-by-user");
  assert_eq!(fs::read(&lookalike).unwrap(), b"keep");
  drop(reopened);
}

#[tokio::test]
async fn json_native_invalid_highest_generation_fails_closed() {
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let storage = open(&factory).await;
  for index in 1..=2_u64 {
    let revision = storage.snapshot().await.unwrap().revision().clone();
    assert!(matches!(
      storage
        .commit(helpers::put_transaction(
          index,
          revision,
          &[(&index.to_string(), &[index as u8])],
        ))
        .await
        .unwrap(),
      CommitOutcome::Committed(_)
    ));
  }
  drop(storage);

  let files = helpers::generation_files(dir.path());
  fs::write(&files[1], b"not json at all").unwrap();
  let error = factory.open(requirements()).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageCorrupt);

  // The adapter never silently selects the older valid generation.
  assert_eq!(helpers::generation_files(dir.path()).len(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn json_native_observed_directory_barrier_allows_os_crash_claim() {
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let storage = open(&factory).await;
  assert_eq!(
    storage.capabilities().durability(),
    DurabilityLevel::OsCrashDurable,
    "the unix claim requires an observed directory barrier at open"
  );
  let revision = storage.snapshot().await.unwrap().revision().clone();
  assert!(matches!(
    storage
      .commit(helpers::put_transaction(1, revision, &[("seed", b"seed")]))
      .await
      .unwrap(),
    CommitOutcome::Committed(_)
  ));
  storage.flush().await.unwrap();
}

#[cfg(not(unix))]
#[tokio::test]
async fn json_native_os_crash_requirement_is_refused_with_typed_error() {
  let dir = tempfile::tempdir().unwrap();
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
  let error = factory
    .open(StoreRequirements::metadata())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::UnsupportedCapability);
}
