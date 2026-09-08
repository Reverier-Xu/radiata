use std::{
  collections::VecDeque,
  future,
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
};

use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, Error, ErrorKind, ProviderErrorContext,
  ProviderErrorKind, QualifiedTag, ReconcileOutcome, Result, StoreCapabilities, StoreExpectation,
  StoreKey, StoreNamespace, StoreOperation, StoreRequirements, StoreRevision, StoreTransaction,
  StoreValue, TransactionId,
  provider::{Storage, StorageFactory, StoreScan, StoreSnapshot},
  storage::{
    MetadataStore,
    contract::helpers,
    receipt::{PreparedTransaction, prepare_internal_transaction},
    test_util::transaction_id,
  },
};

#[derive(Clone, Debug)]
enum CommitScript {
  Outcome(CommitOutcome),
  Error(ProviderErrorKind),
  Pending,
}

#[derive(Clone, Debug)]
enum ReconcileScript {
  Outcome(ReconcileOutcome),
  Error,
  Pending,
}

#[derive(Debug)]
struct ScriptState {
  commits: Mutex<VecDeque<CommitScript>>,
  reconciles: Mutex<VecDeque<ReconcileScript>>,
  commit_calls: AtomicUsize,
  reconcile_calls: AtomicUsize,
  snapshot_calls: AtomicUsize,
  reconcile_arguments: Mutex<Vec<(TransactionId, Digest)>>,
}

#[derive(Debug)]
struct ScriptStorage {
  state: Arc<ScriptState>,
}

#[derive(Debug)]
struct ScriptFactory {
  state: Arc<ScriptState>,
}

#[derive(Debug)]
struct EmptySnapshot {
  revision: StoreRevision,
}

#[derive(Debug)]
struct EmptyScan;

impl StoreScan for EmptyScan {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<crate::StoreEntry>>> {
    Box::pin(async { Ok(None) })
  }
}

impl StoreSnapshot for EmptySnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    Box::pin(async move {
      // The scripted store presents the production schema baseline, so
      // the open-time migration pass takes its idempotent Current path
      // and the scripted commits stay reserved for the test's own
      // transactions.
      let schema = crate::storage::migration::schema_namespace()?;
      if namespace == &schema && key == &crate::storage::migration::schema_key() {
        return Ok(Some(crate::storage::migration::encode_schema_record(
          crate::storage::migration::BASE_RECORD_KIND,
          crate::storage::migration::METADATA_SCHEMA_V1,
          None,
        )));
      }
      Ok(None)
    })
  }

  fn scan<'a>(
    &'a self, _namespace: &'a StoreNamespace, _prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    Box::pin(async { Ok(Box::new(EmptyScan) as Box<dyn StoreScan>) })
  }
}

impl Storage for ScriptStorage {
  fn capabilities(&self) -> StoreCapabilities {
    complete_capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    self.state.snapshot_calls.fetch_add(1, Ordering::SeqCst);
    Box::pin(async {
      Ok(Box::new(EmptySnapshot {
        revision: revision(1),
      }) as Box<dyn StoreSnapshot>)
    })
  }

  fn commit<'a>(&'a self, _transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    self.state.commit_calls.fetch_add(1, Ordering::SeqCst);
    let script = self.state.commits.lock().unwrap().pop_front().unwrap();
    Box::pin(async move {
      match script {
        CommitScript::Outcome(outcome) => Ok(outcome),
        CommitScript::Error(kind) => {
          Err(Error::provider(kind, ProviderErrorContext::StorageCommit))
        }
        CommitScript::Pending => future::pending().await,
      }
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    self.state.reconcile_calls.fetch_add(1, Ordering::SeqCst);
    self
      .state
      .reconcile_arguments
      .lock()
      .unwrap()
      .push((transaction.clone(), digest.clone()));
    let script = self.state.reconciles.lock().unwrap().pop_front().unwrap();
    Box::pin(async move {
      match script {
        ReconcileScript::Outcome(outcome) => Ok(outcome),
        ReconcileScript::Error => Err(Error::provider(
          ProviderErrorKind::Io,
          ProviderErrorContext::StorageReconcile,
        )),
        ReconcileScript::Pending => future::pending().await,
      }
    })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

impl StorageFactory for ScriptFactory {
  fn open<'a>(
    &'a self, _requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let state = Arc::clone(&self.state);
    Box::pin(async { Ok(Box::new(ScriptStorage { state }) as Box<dyn Storage>) })
  }
}

#[tokio::test]
async fn storage_contract_engine_definitive_outcomes_and_ordinary_errors_restore_ready() {
  let first = transaction(0);
  let receipt = CommitReceipt::new(
    first.id().clone(),
    first.operation_digest().clone(),
    revision(2),
  );
  let (store, state) = scripted(
    vec![
      CommitScript::Outcome(CommitOutcome::Committed(receipt)),
      CommitScript::Outcome(CommitOutcome::Aborted),
      CommitScript::Outcome(CommitOutcome::Conflict),
      CommitScript::Error(ProviderErrorKind::Io),
      CommitScript::Outcome(CommitOutcome::Aborted),
    ],
    vec![],
  )
  .await;

  assert!(matches!(
    store.commit(first).await.unwrap(),
    CommitOutcome::Committed(_)
  ));
  assert!(matches!(
    store.commit(transaction(1)).await.unwrap(),
    CommitOutcome::Aborted
  ));
  assert!(matches!(
    store.commit(transaction(2)).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(
    store.commit(transaction(3)).await.unwrap_err().kind(),
    ErrorKind::Io
  );
  assert!(matches!(
    store.commit(transaction(4)).await.unwrap(),
    CommitOutcome::Aborted
  ));
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn storage_contract_engine_malformed_commit_outcomes_retain_freeze() {
  let submitted = transaction(0);
  let malformed_receipt = CommitReceipt::new(
    transaction_id(1),
    submitted.operation_digest().clone(),
    revision(2),
  );
  let (store, state) = scripted(
    vec![CommitScript::Outcome(CommitOutcome::Committed(
      malformed_receipt,
    ))],
    vec![],
  )
  .await;

  let error = store.commit(transaction(0)).await.unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageCorrupt);
  assert_eq!(
    store.commit(transaction(2)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 1);

  let malformed_digest_receipt = CommitReceipt::new(
    submitted.id().clone(),
    Digest::from_bytes([8; 32]),
    revision(2),
  );
  let (store, state) = scripted(
    vec![CommitScript::Outcome(CommitOutcome::Committed(
      malformed_digest_receipt,
    ))],
    vec![],
  )
  .await;
  assert_eq!(
    store.commit(transaction(0)).await.unwrap_err().kind(),
    ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    store.commit(transaction(2)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 1);

  let malformed_unknown = CommitOutcome::Unknown {
    transaction: transaction_id(4),
    operation_digest: Digest::from_bytes([9; 32]),
  };
  let (store, state) = scripted(vec![CommitScript::Outcome(malformed_unknown)], vec![]).await;
  assert_eq!(
    store.commit(transaction(0)).await.unwrap_err().kind(),
    ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    store.commit(transaction(2)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn storage_contract_engine_unknown_and_commit_unknown_freeze_writes_but_allow_snapshots() {
  let submitted = transaction(0);
  let unknown = CommitOutcome::Unknown {
    transaction: submitted.id().clone(),
    operation_digest: submitted.operation_digest().clone(),
  };
  let (store, state) = scripted(vec![CommitScript::Outcome(unknown)], vec![]).await;
  assert!(matches!(
    store.commit(submitted).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  assert!(store.snapshot().await.is_ok());
  // One snapshot from the test, one from the open-time schema pass.
  assert_eq!(state.snapshot_calls.load(Ordering::SeqCst), 2);
  assert_eq!(
    store.commit(transaction(1)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 1);

  let (store, state) = scripted(
    vec![CommitScript::Error(ProviderErrorKind::CommitUnknown)],
    vec![],
  )
  .await;
  assert_eq!(
    store.commit(transaction(0)).await.unwrap_err().kind(),
    ErrorKind::CommitUnknown,
  );
  assert_eq!(
    store.commit(transaction(1)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn storage_contract_engine_cancelled_commit_remains_frozen_and_reconciles_pending_identity() {
  let submitted = transaction(0);
  let expected_id = submitted.id().clone();
  let expected_digest = submitted.operation_digest().clone();
  let receipt = CommitReceipt::new(expected_id.clone(), expected_digest.clone(), revision(2));
  let (store, state) = scripted(
    vec![
      CommitScript::Pending,
      CommitScript::Outcome(CommitOutcome::Aborted),
    ],
    vec![ReconcileScript::Outcome(ReconcileOutcome::Committed(
      receipt,
    ))],
  )
  .await;
  let store = Arc::new(store);
  let task_store = Arc::clone(&store);
  let task = tokio::spawn(async move { task_store.commit(submitted).await });
  while state.commit_calls.load(Ordering::SeqCst) == 0 {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());

  assert_eq!(
    store.commit(transaction(1)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Committed(_)
  ));
  assert_eq!(
    state.reconcile_arguments.lock().unwrap().as_slice(),
    &[(expected_id, expected_digest)],
  );
  assert!(matches!(
    store.commit(transaction(2)).await.unwrap(),
    CommitOutcome::Aborted
  ));
}

#[tokio::test]
async fn storage_contract_engine_cancelled_reconcile_preserves_frozen_identity() {
  let submitted = transaction(0);
  let expected_id = submitted.id().clone();
  let expected_digest = submitted.operation_digest().clone();
  let unknown = CommitOutcome::Unknown {
    transaction: expected_id.clone(),
    operation_digest: expected_digest.clone(),
  };
  let receipt = CommitReceipt::new(expected_id.clone(), expected_digest.clone(), revision(2));
  let (store, state) = scripted(
    vec![
      CommitScript::Outcome(unknown),
      CommitScript::Outcome(CommitOutcome::Aborted),
    ],
    vec![
      ReconcileScript::Pending,
      ReconcileScript::Outcome(ReconcileOutcome::Committed(receipt)),
    ],
  )
  .await;
  let store = Arc::new(store);
  store.commit(submitted).await.unwrap();

  let task_store = Arc::clone(&store);
  let task = tokio::spawn(async move { task_store.reconcile().await });
  while state.reconcile_calls.load(Ordering::SeqCst) == 0 {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  assert_eq!(
    store.commit(transaction(1)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Committed(_)
  ));
  assert_eq!(
    state.reconcile_arguments.lock().unwrap().as_slice(),
    &[
      (expected_id.clone(), expected_digest.clone()),
      (expected_id, expected_digest),
    ],
  );
  assert!(matches!(
    store.commit(transaction(2)).await.unwrap(),
    CommitOutcome::Aborted
  ));
}

#[tokio::test]
async fn storage_contract_engine_reconcile_retains_or_clears_freeze_exactly() {
  let submitted = transaction(0);
  let unknown = CommitOutcome::Unknown {
    transaction: submitted.id().clone(),
    operation_digest: submitted.operation_digest().clone(),
  };
  let (store, state) = scripted(
    vec![
      CommitScript::Outcome(unknown),
      CommitScript::Outcome(CommitOutcome::Aborted),
    ],
    vec![
      ReconcileScript::Outcome(ReconcileOutcome::Unknown),
      ReconcileScript::Outcome(ReconcileOutcome::DigestConflict),
      ReconcileScript::Error,
      ReconcileScript::Outcome(ReconcileOutcome::Aborted),
    ],
  )
  .await;
  store.commit(submitted).await.unwrap();
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Unknown
  ));
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert_eq!(store.reconcile().await.unwrap_err().kind(), ErrorKind::Io);
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Aborted
  ));
  assert!(matches!(
    store.commit(transaction(1)).await.unwrap(),
    CommitOutcome::Aborted
  ));
  assert_eq!(state.reconcile_calls.load(Ordering::SeqCst), 4);
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn storage_contract_engine_malformed_reconcile_receipt_retains_freeze() {
  let submitted = transaction(0);
  let unknown = CommitOutcome::Unknown {
    transaction: submitted.id().clone(),
    operation_digest: submitted.operation_digest().clone(),
  };
  let malformed = CommitReceipt::new(
    transaction_id(7),
    submitted.operation_digest().clone(),
    revision(2),
  );
  let (store, state) = scripted(
    vec![CommitScript::Outcome(unknown)],
    vec![ReconcileScript::Outcome(ReconcileOutcome::Committed(
      malformed,
    ))],
  )
  .await;
  store.commit(submitted).await.unwrap();
  assert_eq!(
    store.reconcile().await.unwrap_err().kind(),
    ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    store.commit(transaction(1)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 1);

  let submitted = transaction(0);
  let unknown = CommitOutcome::Unknown {
    transaction: submitted.id().clone(),
    operation_digest: submitted.operation_digest().clone(),
  };
  let malformed_digest = CommitReceipt::new(
    submitted.id().clone(),
    Digest::from_bytes([6; 32]),
    revision(2),
  );
  let (store, state) = scripted(
    vec![CommitScript::Outcome(unknown)],
    vec![ReconcileScript::Outcome(ReconcileOutcome::Committed(
      malformed_digest,
    ))],
  )
  .await;
  store.commit(submitted).await.unwrap();
  assert_eq!(
    store.reconcile().await.unwrap_err().kind(),
    ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    store.commit(transaction(1)).await.unwrap_err().kind(),
    ErrorKind::NotReady,
  );
  assert_eq!(state.commit_calls.load(Ordering::SeqCst), 1);
}

async fn scripted(
  commits: Vec<CommitScript>, reconciles: Vec<ReconcileScript>,
) -> (MetadataStore, Arc<ScriptState>) {
  let state = Arc::new(ScriptState {
    commits: Mutex::new(commits.into()),
    reconciles: Mutex::new(reconciles.into()),
    commit_calls: AtomicUsize::new(0),
    reconcile_calls: AtomicUsize::new(0),
    snapshot_calls: AtomicUsize::new(0),
    reconcile_arguments: Mutex::new(Vec::new()),
  });
  let factory: Arc<dyn StorageFactory> = Arc::new(ScriptFactory {
    state: Arc::clone(&state),
  });
  (
    MetadataStore::open(&factory, std::time::Duration::from_secs(30))
      .await
      .unwrap(),
    state,
  )
}

fn complete_capabilities() -> StoreCapabilities {
  helpers::required_capabilities()
}

fn transaction(index: u8) -> PreparedTransaction {
  let namespace =
    StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/metadata/engine-test").unwrap());
  prepare_internal_transaction(
    transaction_id(u64::from(index)),
    revision(1),
    vec![StoreOperation::Put {
      namespace,
      key: StoreKey::new(Arc::from([index])),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from([index])),
    }],
  )
  .unwrap()
}

fn revision(index: u8) -> StoreRevision {
  StoreRevision::new(Arc::from([index])).unwrap()
}
