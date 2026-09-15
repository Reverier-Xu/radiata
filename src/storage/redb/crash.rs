//! Subprocess durability matrix for the redb adapter.
//!
//! A parent test seeds one generation, then spawns the library test binary
//! itself with an exact child filter and an environment-selected crash
//! point. The child aborts inside the commit path through the compiled-in
//! test hook. The parent then reopens the store and asserts the exact old
//! or new state: entries, revision, and receipt always agree, so no partial
//! cross-family transaction is ever exposed.

use std::sync::Arc;

use tempfile::TempDir;

use super::RedbStoreFactory;
use crate::{
  CommitOutcome, ReconcileOutcome, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
  StoreRequirements, StoreRevision, StoreTransaction, StoreValue, provider::StorageFactory,
};

const CRASH_DIR_ENV: &str = "RADIATA_REDB_CRASH_DIR";
const CRASH_POINT_ENV: &str = "RADIATA_REDB_CRASH_POINT";

/// Crash points inside the commit path.
///
/// 1: after write-transaction begin; 2: after conditions pass, before
/// mutations; 3: after mutations, before revision bump; 4: after revision
/// bump, before receipt insert; 5: after receipt insert, before redb
/// commit; 6: after the durable redb commit returns.
const FIRST_COMMITTED_POINT: u8 = 6;
const LAST_POINT: u8 = 6;

fn requirements() -> StoreRequirements {
  StoreRequirements::metadata()
}

fn namespace() -> StoreNamespace {
  StoreNamespace::new(crate::QualifiedTag::parse("radiata.woooo.tech/crash/redb-v1").unwrap())
}

fn put_transaction(index: u64, base: StoreRevision, name: &[u8], value: &[u8]) -> StoreTransaction {
  StoreTransaction::new(
    crate::storage::test_util::transaction_id(index),
    base,
    vec![StoreOperation::Put {
      namespace: namespace(),
      key: StoreKey::new(Arc::from(name)),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(value)),
    }],
  )
  .unwrap()
}

#[ignore = "crash-matrix child process entry point"]
#[tokio::test]
async fn redb_crash_child_entry() {
  let directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
  let point: u8 = std::env::var(CRASH_POINT_ENV)
    .expect("crash point")
    .parse()
    .expect("numeric crash point");
  super::store::select_crash_point(point);
  let factory: Arc<dyn StorageFactory> = Arc::new(RedbStoreFactory::new(directory.into()));
  let storage = factory.open(requirements()).await.unwrap();
  let base = storage.snapshot().await.unwrap().revision().clone();
  let transaction = put_transaction(2, base, b"key-child", b"child-value");
  let outcome = storage.commit(transaction).await.unwrap();
  match outcome {
    CommitOutcome::Committed(_) => {}
    other => panic!("child commit must reach a decisive outcome, got {other:?}"),
  }
}

fn run_child(dir: &TempDir, point: u8) {
  crate::storage::test_util::run_crash_child(
    "storage::redb::crash::redb_crash_child_entry",
    CRASH_DIR_ENV,
    CRASH_POINT_ENV,
    &dir.path().join("store.redb"),
    point,
    "redb",
    &[],
  );
}

#[tokio::test]
async fn redb_crash_boundaries_recover_exact_old_or_new_state() {
  for point in 1..=LAST_POINT {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    let factory: Arc<dyn StorageFactory> = Arc::new(RedbStoreFactory::new(path.clone()));
    let seeded = factory.open(requirements()).await.unwrap();
    assert!(matches!(
      seeded
        .commit(put_transaction(
          1,
          StoreRevision::new(Arc::from(0_u64.to_be_bytes())).unwrap(),
          b"key-seed",
          b"seed-value"
        ))
        .await
        .unwrap(),
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
    let namespace = namespace();
    let seed_value = snapshot
      .get(
        &namespace,
        &StoreKey::new(Arc::from(b"key-seed".as_slice())),
      )
      .await
      .unwrap();
    let child_value = snapshot
      .get(
        &namespace,
        &StoreKey::new(Arc::from(b"key-child".as_slice())),
      )
      .await
      .unwrap();
    assert_eq!(
      seed_value.as_ref().map(|value| value.as_bytes()),
      Some(b"seed-value".as_slice()),
      "point {point} must preserve the seeded generation"
    );

    let child = put_transaction(
      2,
      StoreRevision::new(Arc::from(1_u64.to_be_bytes())).unwrap(),
      b"key-child",
      b"child-value",
    );
    let outcome = reopened
      .reconcile(child.id(), child.operation_digest())
      .await
      .unwrap();
    drop(snapshot);

    if point < FIRST_COMMITTED_POINT {
      assert!(
        child_value.is_none(),
        "point {point} must reopen to the old state"
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
      assert!(
        matches!(outcome, ReconcileOutcome::Committed(_)),
        "point {point} must reconcile the committed receipt"
      );
    }
    drop(reopened);
  }
}
