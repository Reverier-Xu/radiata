//! Subprocess durability matrix for resource registers (SC-G07-P0-07).
//!
//! Mirrors the JSON adapter's crash lane: a parent test seeds one register
//! value, spawns the library test binary itself with an environment-
//! selected crash point, and the child commits one newer signed record
//! through [`commit_record_ctx`] while aborting deterministically inside
//! the commit path. The parent reopens the store, asserts the register
//! holds exactly the old or the new whole record, and reconciles the
//! child's exact transaction identity — reproduced by a deterministic
//! seeded-entropy dry run — as committed or aborted, consistent with the
//! observed content.

use std::{sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use tempfile::TempDir;

use super::{
  ResourceName, ResourceRecordV1,
  store::{ResourceCommitOutcome, commit_record_ctx, read_record_ctx},
};
use crate::{
  CommitReceipt, LabelKey, LabelSet, LabelValue, NodeId, ReconcileOutcome, StoreRequirements,
  TransactionId,
  api::SystemEntropy,
  provider::StorageFactory,
  storage::{MetadataStore, json::JsonStoreFactory},
  transport::testing::SeedEntropy,
};

const CRASH_DIR_ENV: &str = "RADIATA_RESOURCE_CRASH_DIR";
const CRASH_POINT_ENV: &str = "RADIATA_RESOURCE_CRASH_POINT";

/// The child commits under this deterministic entropy so the parent can
/// reproduce its exact pending-transaction identity.
const CHILD_ENTROPY_SEED: u8 = 7;

/// The delete lane's transaction-id entropy: distinct from the
/// commit lane seed so install and delete in one store never reuse an id.
const DELETE_ENTROPY_SEED: u8 = 9;

/// Crash points inside the JSON adapter's commit path; the exact
/// committed-from boundary is discovered monotonically rather than
/// hardcoded, so adapter changes cannot desynchronize this lane.
const LAST_POINT: u8 = 13;

fn requirements() -> StoreRequirements {
  crate::storage::test_util::crash_requirements()
}

fn name() -> ResourceName {
  ResourceName::parse("radiata.woooo.tech/resources/crash-demo").unwrap()
}

fn labels() -> LabelSet {
  LabelSet::new()
    .insert(
      LabelKey::parse("example.org/labels/tier").unwrap(),
      LabelValue::parse("bronze").unwrap(),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn record(timestamp_millis: u64, removed: bool, uri: &str) -> ResourceRecordV1 {
  ResourceRecordV1::sign(
    name(),
    LabelValue::parse("document").unwrap(),
    crate::ResourceUri::parse(uri).unwrap(),
    labels(),
    timestamp_millis,
    NodeId::parse("node_000000000000000000001").unwrap(),
    if removed { 1 } else { 0 },
    removed,
    &SigningKey::from_bytes(&[21; 32]),
  )
  .unwrap()
}

fn old_record() -> ResourceRecordV1 {
  record(1_000, false, "file:///old")
}

fn new_record() -> ResourceRecordV1 {
  record(2_000, true, "file:///removed")
}

async fn open_store(factory: &Arc<dyn StorageFactory>) -> MetadataStore {
  MetadataStore::open(factory, Duration::from_secs(10))
    .await
    .unwrap()
}

fn factory(dir: &TempDir) -> Arc<dyn StorageFactory> {
  Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()))
}

/// Seeds the old live record into a fresh store.
async fn seed(factory: &Arc<dyn StorageFactory>) -> MetadataStore {
  let store = open_store(factory).await;
  match commit_record_ctx(&store, &SystemEntropy, &old_record())
    .await
    .unwrap()
  {
    ResourceCommitOutcome::Installed(_) => {}
    other => panic!("seed commit must install, got {other:?}"),
  }
  store
}

/// Reproduces the child's exact pending-transaction identity: the child
/// generates its transaction id from the same seeded entropy over the same
/// deterministic record bytes, so a crash-free replay of its steps yields
/// the identical receipt identity.
async fn child_identity() -> CommitReceipt {
  let dir = TempDir::new().unwrap();
  let factory = factory(&dir);
  let store = seed(&factory).await;
  match commit_record_ctx(&store, &SeedEntropy(CHILD_ENTROPY_SEED), &new_record())
    .await
    .unwrap()
  {
    ResourceCommitOutcome::Installed(ref receipt) => receipt.clone(),
    other => panic!("dry-run child commit must install, got {other:?}"),
  }
}

fn run_child(dir: &TempDir, point: u8) {
  crate::storage::test_util::run_crash_child(
    "resource::crash::resource_crash_child_entry",
    CRASH_DIR_ENV,
    CRASH_POINT_ENV,
    dir.path(),
    point,
    "resource",
    &[],
  );
}

#[ignore = "resource crash-matrix child process entry point"]
#[tokio::test]
async fn resource_crash_child_entry() {
  let _directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
  let point: u8 = std::env::var(CRASH_POINT_ENV)
    .expect("crash point")
    .parse()
    .expect("numeric crash point");
  crate::storage::json::select_crash_point(point);
  let directory = std::path::PathBuf::from(_directory);
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(directory));
  // The parent seeds the register before spawning this process; opening a
  // fresh store here would crash inside the seed commit instead of the
  // child's own routed-record transaction.
  let store = MetadataStore::open(&factory, Duration::from_secs(10))
    .await
    .unwrap();
  let outcome = commit_record_ctx(&store, &SeedEntropy(CHILD_ENTROPY_SEED), &new_record())
    .await
    .unwrap();
  match outcome {
    ResourceCommitOutcome::Installed(_) => {}
    other => panic!("child commit must reach a decisive outcome, got {other:?}"),
  }
}

/// Opens the provider with a bounded retry: on overlay filesystems the
/// crashed child's file lock can linger for a few milliseconds after the
/// process is reaped, surfacing as one transient StorageLocked.
async fn open_provider_with_retry(
  factory: &Arc<dyn StorageFactory>,
) -> crate::Result<Box<dyn crate::provider::Storage>> {
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
  loop {
    match factory.open(requirements()).await {
      Ok(provider) => return Ok(provider),
      Err(error) if error.kind() == crate::ErrorKind::StorageLocked => {
        assert!(
          std::time::Instant::now() < deadline,
          "provider lock never released: {error:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
      }
      Err(error) => return Err(error),
    }
  }
}

/// Every crash boundary reopens to exactly the old or the new whole
/// record, never partial labels, and the pending identity reconciles
/// consistently with the observed content.
#[tokio::test]
async fn resource_crash_boundaries_recover_exact_old_or_new_register() {
  let identity = child_identity().await;
  let mut aborted_points = Vec::new();
  let mut committed_points = Vec::new();
  for point in 1..=LAST_POINT {
    let dir = TempDir::new().unwrap();
    let factory = factory(&dir);
    let seeded = seed(&factory).await;
    drop(seeded);

    run_child(&dir, point);

    // Content assertion through the metadata layer: the register decodes
    // to exactly one whole signed record.
    let reopened = open_store(&factory).await;
    let stored = read_record_ctx(&reopened, &name()).await.unwrap();
    let observed_old = stored.as_ref() == Some(&old_record());
    let observed_new = stored.as_ref() == Some(&new_record());
    assert!(
      observed_old ^ observed_new,
      "point {point} must reopen to exactly one whole record, got {stored:?}"
    );

    // Identity assertion at the provider layer: reconciliation must agree
    // with the observed content.
    drop(reopened);
    let provider = open_provider_with_retry(&factory).await.unwrap();
    let outcome = provider
      .reconcile(identity.transaction(), identity.operation_digest())
      .await
      .unwrap();
    match outcome {
      ReconcileOutcome::Aborted => {
        assert!(
          observed_old,
          "point {point} reconciled aborted but the register shows the new record"
        );
        aborted_points.push(point);
      }
      ReconcileOutcome::Committed(_) => {
        assert!(
          observed_new,
          "point {point} reconciled committed but the register shows the old record"
        );
        committed_points.push(point);
      }
      other => panic!("point {point} must reconcile decisively, got {other:?}"),
    }
  }

  // The boundary is monotonic: early points abort, late points commit,
  // and there is no interleaving.
  assert_eq!(aborted_points.first().copied(), Some(1));
  assert_eq!(committed_points.last().copied(), Some(LAST_POINT));
  if let (Some(last_aborted), Some(first_committed)) =
    (aborted_points.last(), committed_points.first())
  {
    assert!(
      last_aborted < first_committed,
      "crash boundary must be monotonic"
    );
  }
}

/// The seeded removal record the delete lane deletes at every crash
/// point; its tuple is deterministic so the dry-run identity matches.
fn removal_record() -> ResourceRecordV1 {
  record(1_000, true, "file:///removed")
}

/// Reproduces the delete child's exact pending-transaction identity the
/// same way `child_identity` does for the commit lane.
async fn delete_identity() -> CommitReceipt {
  let dir = TempDir::new().unwrap();
  let factory = factory(&dir);
  let store = MetadataStore::open(&factory, Duration::from_secs(10))
    .await
    .unwrap();
  match commit_record_ctx(&store, &SeedEntropy(CHILD_ENTROPY_SEED), &removal_record())
    .await
    .unwrap()
  {
    ResourceCommitOutcome::Installed(_) => {}
    other => panic!("delete-lane seed must install, got {other:?}"),
  }
  // Release the metadata handle so the raw provider lane can reopen the
  // store (one exclusive handle per store).
  drop(store);
  let provider = factory.open(requirements()).await.unwrap();
  let snapshot = provider.snapshot().await.unwrap();
  let namespace = crate::StoreNamespace::new(
    crate::QualifiedTag::parse(super::store::RESOURCE_RECORD_NAMESPACE).unwrap(),
  );
  let key = crate::StoreKey::new(Arc::from(name().as_str().as_bytes().to_vec()));
  let stored = snapshot
    .get(&namespace, &key)
    .await
    .unwrap()
    .expect("seeded removal must be present");
  let transaction = crate::StoreTransaction::new(
    TransactionId::generate(&SeedEntropy(DELETE_ENTROPY_SEED)).unwrap(),
    snapshot.revision().clone(),
    vec![crate::StoreOperation::Delete {
      namespace,
      key,
      expected: stored.digest().clone(),
    }],
  )
  .unwrap();
  match provider.commit(transaction).await.unwrap() {
    crate::CommitOutcome::Committed(receipt) => receipt,
    other => panic!("delete-lane dry run must commit, got {other:?}"),
  }
}

fn run_delete_child(dir: &TempDir, point: u8) {
  crate::storage::test_util::run_crash_child(
    "resource::crash::resource_delete_child_entry",
    CRASH_DIR_ENV,
    CRASH_POINT_ENV,
    dir.path(),
    point,
    "resource delete",
    &[],
  );
}

#[ignore = "resource delete crash-matrix child process entry point"]
#[tokio::test]
async fn resource_delete_child_entry() {
  let _directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
  let point: u8 = std::env::var(CRASH_POINT_ENV)
    .expect("crash point")
    .parse()
    .expect("numeric crash point");
  crate::storage::json::select_crash_point(point);
  let directory = std::path::PathBuf::from(_directory);
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(directory));
  let store = MetadataStore::open(&factory, Duration::from_secs(10))
    .await
    .unwrap();
  drop(store);
  let provider = factory.open(requirements()).await.unwrap();
  let snapshot = provider.snapshot().await.unwrap();
  let namespace = crate::StoreNamespace::new(
    crate::QualifiedTag::parse(super::store::RESOURCE_RECORD_NAMESPACE).unwrap(),
  );
  let key = crate::StoreKey::new(Arc::from(name().as_str().as_bytes().to_vec()));
  let stored = snapshot
    .get(&namespace, &key)
    .await
    .unwrap()
    .expect("seeded removal must be present before the child deletes it");
  let transaction = crate::StoreTransaction::new(
    TransactionId::generate(&SeedEntropy(DELETE_ENTROPY_SEED)).unwrap(),
    snapshot.revision().clone(),
    vec![crate::StoreOperation::Delete {
      namespace,
      key,
      expected: stored.digest().clone(),
    }],
  )
  .unwrap();
  match provider.commit(transaction).await.unwrap() {
    crate::CommitOutcome::Committed(_) => {}
    other => panic!("delete child must reach a decisive outcome, got {other:?}"),
  }
}

/// SC-G07-P0-14: every cleanup/delete boundary reopens to old-or-new —
/// the removal record is fully present or fully gone, never partial, and
/// the delete transaction's identity reconciles consistently.
#[tokio::test]
async fn resource_delete_boundaries_recover_old_or_new_presence() {
  let identity = delete_identity().await;
  let mut aborted_points = Vec::new();
  let mut committed_points = Vec::new();
  for point in 1..=LAST_POINT {
    let dir = TempDir::new().unwrap();
    let factory = factory(&dir);
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    match commit_record_ctx(&store, &SystemEntropy, &removal_record())
      .await
      .unwrap()
    {
      ResourceCommitOutcome::Installed(_) => {}
      other => panic!("delete-lane seed must install, got {other:?}"),
    }
    drop(store);

    run_delete_child(&dir, point);

    let reopened = open_store(&factory).await;
    let stored = read_record_ctx(&reopened, &name()).await.unwrap();
    let present = stored.as_ref() == Some(&removal_record());
    let absent = stored.is_none();
    assert!(
      present ^ absent,
      "point {point} must reopen to old-or-new presence, got {stored:?}"
    );

    drop(reopened);
    let provider = open_provider_with_retry(&factory).await.unwrap();
    let outcome = provider
      .reconcile(identity.transaction(), identity.operation_digest())
      .await
      .unwrap();
    match outcome {
      ReconcileOutcome::Aborted => {
        assert!(
          present,
          "point {point} reconciled aborted but the record is gone"
        );
        aborted_points.push(point);
      }
      ReconcileOutcome::Committed(_) => {
        assert!(
          absent,
          "point {point} reconciled committed but the record remains"
        );
        committed_points.push(point);
      }
      other => panic!("point {point} must reconcile decisively, got {other:?}"),
    }
  }
  assert_eq!(aborted_points.first().copied(), Some(1));
  assert_eq!(committed_points.last().copied(), Some(LAST_POINT));
  if let (Some(last_aborted), Some(first_committed)) =
    (aborted_points.last(), committed_points.first())
  {
    assert!(
      last_aborted < first_committed,
      "delete boundary must be monotonic"
    );
  }
}
