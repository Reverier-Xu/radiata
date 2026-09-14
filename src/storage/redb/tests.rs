//! redb adapter unit tests.
//!
//! Every test name is prefixed `redb_adapter_` so the task verifier can
//! prove a nonempty lane. The all-family contract runs unchanged against
//! the redb adapter through the shared contract runner.

use std::sync::Arc;

use tempfile::TempDir;

use super::RedbStoreFactory;
use crate::{
  CommitOutcome, Digest, ErrorKind, StoreExpectation, StoreOperation, StoreRequirements,
  StoreTransaction, StoreValue, TransactionId, provider::StorageFactory,
};

fn factory(directory: &TempDir) -> Arc<dyn StorageFactory> {
  Arc::new(RedbStoreFactory::new(directory.path().join("store.redb")))
}

#[tokio::test]
async fn redb_adapter_passes_the_unchanged_all_family_storage_contract() {
  crate::storage::contract::run_storage_contract(|| {
    let directory = TempDir::new().unwrap();
    Arc::new(RedbStoreFactory::new(directory.keep().join("store.redb"))) as Arc<dyn StorageFactory>
  })
  .await;
}

#[tokio::test]
async fn redb_adapter_holds_an_exclusive_lifetime_lock() {
  let directory = TempDir::new().unwrap();
  let factory = factory(&directory);
  let _first = factory.open(StoreRequirements::metadata()).await.unwrap();
  let error = factory
    .open(StoreRequirements::metadata())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageLocked);
}

#[tokio::test]
async fn redb_adapter_refuses_unsupported_capability_requirements() {
  let directory = TempDir::new().unwrap();
  let factory = factory(&directory);
  let error = factory
    .open(StoreRequirements::metadata().transactional_migration(true))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::UnsupportedCapability);
}

#[tokio::test]
async fn redb_adapter_reopen_preserves_entries_receipts_and_revision() {
  let directory = TempDir::new().unwrap();
  let path = directory.path().join("store.redb");
  let transaction_id = TransactionId::parse("txn-000000000000000000042").unwrap();
  {
    let factory = Arc::new(RedbStoreFactory::new(path.clone()));
    let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
    let snapshot = storage.snapshot().await.unwrap();
    let namespace = crate::storage::test_util::namespace("redb-reopen");
    let transaction = StoreTransaction::new(
      transaction_id.clone(),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace,
        key: crate::storage::test_util::key(b"persisted"),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(b"survives-reopen".as_slice())),
      }],
    )
    .unwrap();
    let receipt = match storage.commit(transaction).await.unwrap() {
      CommitOutcome::Committed(receipt) => receipt,
      outcome => panic!("unexpected outcome: {outcome:?}"),
    };
    let outcome = storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap();
    assert!(matches!(outcome, crate::ReconcileOutcome::Committed(_)));
  }

  let factory = Arc::new(RedbStoreFactory::new(path));
  let reopened = factory.open(StoreRequirements::metadata()).await.unwrap();
  let snapshot = reopened.snapshot().await.unwrap();
  let namespace = crate::storage::test_util::namespace("redb-reopen");
  let stored = snapshot
    .get(&namespace, &crate::storage::test_util::key(b"persisted"))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(stored.as_bytes(), b"survives-reopen");
  let outcome = reopened
    .reconcile(&transaction_id, &Digest::from_bytes([0; 32]))
    .await
    .unwrap();
  assert!(matches!(outcome, crate::ReconcileOutcome::DigestConflict));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redb_adapter_concurrent_same_generation_commits_exactly_once() {
  let directory = TempDir::new().unwrap();
  let factory = factory(&directory);
  let storage = Arc::new(factory.open(StoreRequirements::metadata()).await.unwrap());
  let base = storage.snapshot().await.unwrap().revision().clone();
  let namespace = crate::storage::test_util::namespace("redb-race");

  let make = |id: u64, value: &'static [u8]| {
    StoreTransaction::new(
      crate::storage::test_util::transaction_id(id),
      base.clone(),
      vec![StoreOperation::Put {
        namespace: namespace.clone(),
        key: crate::storage::test_util::key(b"contended"),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(value)),
      }],
    )
    .unwrap()
  };
  let first = make(31, b"first");
  let second = make(32, b"second");

  let storage_a = Arc::clone(&storage);
  let storage_b = Arc::clone(&storage);
  let (outcome_a, outcome_b) =
    tokio::join!(async move { storage_a.commit(first).await }, async move {
      storage_b.commit(second).await
    },);
  let committed = [outcome_a.unwrap(), outcome_b.unwrap()]
    .into_iter()
    .filter(|outcome| matches!(outcome, CommitOutcome::Committed(_)))
    .count();
  assert_eq!(committed, 1, "exactly one contending transaction commits");

  let snapshot = storage.snapshot().await.unwrap();
  let stored = snapshot
    .get(&namespace, &crate::storage::test_util::key(b"contended"))
    .await
    .unwrap()
    .unwrap();
  assert!(
    stored.as_bytes() == b"first" || stored.as_bytes() == b"second",
    "the surviving value must come from the committed transaction"
  );
}

#[tokio::test]
async fn redb_adapter_transaction_digest_conflicts_fail_closed() {
  let directory = TempDir::new().unwrap();
  let factory = factory(&directory);
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let base = storage.snapshot().await.unwrap().revision().clone();
  let namespace = crate::storage::test_util::namespace("redb-digest");

  let original = StoreTransaction::new(
    TransactionId::parse("txn-000000000000000000041").unwrap(),
    base,
    vec![StoreOperation::Put {
      namespace: namespace.clone(),
      key: crate::storage::test_util::key(b"bound"),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(b"original".as_slice())),
    }],
  )
  .unwrap();
  let receipt = match storage.commit(original.clone()).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };

  // The same transaction identity with a different operation digest must
  // fail closed instead of recommitting.
  let forged = StoreTransaction::new(
    TransactionId::parse("txn-000000000000000000041").unwrap(),
    receipt.committed_revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace.clone(),
      key: crate::storage::test_util::key(b"other"),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(b"forged".as_slice())),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(forged).await.unwrap(),
    CommitOutcome::Conflict
  ));

  // Reconciliation of the exact identity stays authoritative, and a wrong
  // digest reports DigestConflict rather than deleting the receipt.
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    crate::ReconcileOutcome::Committed(_)
  ));
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), &Digest::from_bytes([3; 32]))
      .await
      .unwrap(),
    crate::ReconcileOutcome::DigestConflict
  ));

  // Receipt cleanup removes only the exactly matching receipt and leaves
  // every other receipt intact.
  let other_base = storage.snapshot().await.unwrap().revision().clone();
  let other = StoreTransaction::new(
    TransactionId::parse("txn-000000000000000000042").unwrap(),
    other_base,
    vec![StoreOperation::Put {
      namespace: namespace.clone(),
      key: crate::storage::test_util::key(b"other"),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(b"other".as_slice())),
    }],
  )
  .unwrap();
  let other_receipt = match storage.commit(other).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  let forget_base = storage.snapshot().await.unwrap().revision().clone();
  let wrong_forget = StoreTransaction::new(
    TransactionId::parse("txn-000000000000000000043").unwrap(),
    forget_base,
    vec![
      StoreOperation::ForgetReceipt {
        transaction: receipt.transaction().clone(),
        expected_operation_digest: Digest::from_bytes([4; 32]),
      },
      StoreOperation::Put {
        namespace: namespace.clone(),
        key: crate::storage::test_util::key(b"must-not-commit"),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(b"x".as_slice())),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(wrong_forget).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    crate::ReconcileOutcome::Committed(_)
  ));

  let exact_forget = StoreTransaction::new(
    TransactionId::parse("txn-000000000000000000044").unwrap(),
    storage.snapshot().await.unwrap().revision().clone(),
    vec![StoreOperation::ForgetReceipt {
      transaction: receipt.transaction().clone(),
      expected_operation_digest: receipt.operation_digest().clone(),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(exact_forget).await.unwrap(),
    CommitOutcome::Committed(_)
  ));
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    crate::ReconcileOutcome::Aborted
  ));
  assert!(matches!(
    storage
      .reconcile(
        other_receipt.transaction(),
        other_receipt.operation_digest()
      )
      .await
      .unwrap(),
    crate::ReconcileOutcome::Committed(_)
  ));
}
