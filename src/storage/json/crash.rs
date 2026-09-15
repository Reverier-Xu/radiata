//! Subprocess durability matrix for the JSON adapter.
//!
//! A parent test seeds one generation, then spawns the library test binary
//! itself with an exact child filter and an environment-selected crash
//! point. The child aborts inside the commit path through the compiled-in
//! test hook. The parent then reopens the store and asserts the exact old
//! or new state, receipt reconcilability, and chain validity. No sleeps or
//! timing assumptions are used: the child always reaches its abort point
//! deterministically, and the parent only bounds the wait.

use std::sync::Arc;

use tempfile::TempDir;

use super::{JsonStoreFactory, helpers};
use crate::{
  CommitOutcome, ReconcileOutcome, StoreRequirements, StoreRevision, provider::StorageFactory,
};

const CRASH_DIR_ENV: &str = "RADIATA_JSON_CRASH_DIR";
const CRASH_POINT_ENV: &str = "RADIATA_JSON_CRASH_POINT";

/// Crash points inside the commit path.
///
/// 1: before temp create; 2: before the temp open attempt; 3: after temp
/// create; 4: after write; 5: before file flush; 6: after file flush;
/// 7: before rename; 8: after rename; 9: before directory barrier; 10:
/// after barrier; 11: after in-memory result update; 12: after cleanup
/// deletion; 13: after cleanup barrier.
const FIRST_COMMITTED_POINT: u8 = 8;
const LAST_POINT: u8 = 13;

fn requirements() -> StoreRequirements {
  crate::storage::test_util::crash_requirements()
}

fn seed_transaction() -> StoreTransactionAlias {
  helpers::put_transaction(
    1,
    StoreRevision::new(Arc::from(0_u64.to_be_bytes())).unwrap(),
    &[("seed", b"seed-value")],
  )
}

fn child_transaction(base: StoreRevision) -> StoreTransactionAlias {
  helpers::put_transaction(2, base, &[("child", b"child-value")])
}

type StoreTransactionAlias = crate::StoreTransaction;

#[ignore = "crash-matrix child process entry point"]
#[tokio::test]
async fn json_crash_child_entry() {
  let directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
  let point: u8 = std::env::var(CRASH_POINT_ENV)
    .expect("crash point")
    .parse()
    .expect("numeric crash point");
  super::store::select_crash_point(point);
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(directory.into()));
  let storage = factory.open(requirements()).await.unwrap();
  let base = storage.snapshot().await.unwrap().revision().clone();
  let outcome = storage.commit(child_transaction(base)).await.unwrap();
  match outcome {
    CommitOutcome::Committed(_) => {}
    other => panic!("child commit must reach a decisive outcome, got {other:?}"),
  }
}

/// Spawns the child at one crash point and returns once it died.
fn run_child(dir: &TempDir, point: u8) {
  crate::storage::test_util::run_crash_child(
    "storage::json::crash::json_crash_child_entry",
    CRASH_DIR_ENV,
    CRASH_POINT_ENV,
    dir.path(),
    point,
    "json",
    &[],
  );
}

#[tokio::test]
async fn json_crash_boundaries_recover_exact_old_or_new_state() {
  for point in 1..=LAST_POINT {
    let dir = tempfile::tempdir().unwrap();
    let factory: Arc<dyn StorageFactory> =
      Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
    let seeded = factory.open(requirements()).await.unwrap();
    assert!(matches!(
      seeded.commit(seed_transaction()).await.unwrap(),
      CommitOutcome::Committed(_)
    ));
    drop(seeded);

    run_child(&dir, point);

    let reopened = crate::storage::test_util::crash_reopen::open_provider_with_lock_retry(
      &factory,
      requirements(),
    )
    .await;
    let snapshot = reopened.snapshot().await.unwrap();
    let namespace = helpers::namespace("one");
    let seed_value = snapshot
      .get(&namespace, &helpers::key(b"key-seed"))
      .await
      .unwrap();
    let child_value = snapshot
      .get(&namespace, &helpers::key(b"key-child"))
      .await
      .unwrap();
    assert_eq!(
      seed_value.as_ref().map(|value| value.as_bytes()),
      Some(b"seed-value".as_slice()),
      "point {point} must preserve the seeded generation"
    );
    drop(snapshot);

    // The child transaction is fully deterministic, so the parent can
    // reconcile its exact identity.
    let child = child_transaction(StoreRevision::new(Arc::from(1_u64.to_be_bytes())).unwrap());
    let outcome = reopened
      .reconcile(child.id(), child.operation_digest())
      .await
      .unwrap();

    if point < FIRST_COMMITTED_POINT {
      assert!(
        child_value.is_none(),
        "point {point} must reopen to the old state"
      );
      assert_eq!(
        helpers::generation_files(dir.path()).len(),
        1,
        "point {point} must not leave a second final generation"
      );
      assert!(
        matches!(outcome, ReconcileOutcome::Aborted),
        "point {point} must reconcile the uncommitted transaction as aborted"
      );
    } else {
      assert_eq!(
        child_value.as_ref().map(|value| value.as_bytes()),
        Some(b"child-value".as_slice()),
        "point {point} must reopen to the new state"
      );
      assert_eq!(
        helpers::generation_files(dir.path()).len(),
        2,
        "point {point} must keep both final generations"
      );
      assert!(
        matches!(outcome, ReconcileOutcome::Committed(_)),
        "point {point} must reconcile the committed receipt"
      );
    }
    assert!(
      helpers::temp_files(dir.path()).is_empty(),
      "point {point} must clean strictly recognized temporary files"
    );
    drop(reopened);
  }
}
