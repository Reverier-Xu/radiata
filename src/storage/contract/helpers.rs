use std::{
  sync::{Arc, Mutex},
  time::{Duration, SystemTime},
};

use super::reference::ReferenceFactory;
use crate::{
  CommitOutcome, CommitReceipt, DurabilityLevel, NodeId, Result, StoreCapabilities, StoreEntry,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRevision, StoreTransaction,
  TransactionId,
  identity::records::{identity_binding_key, local_identity_key},
  provider::{StorageFactory, StoreScan},
  storage::{
    MetadataStore,
    receipt::{PreparedTransaction, ReceiptIdentity},
  },
  time::WallClock,
};

#[derive(Debug)]
pub(crate) struct ManualClock {
  value: Mutex<SystemTime>,
}

impl ManualClock {
  pub(crate) fn new(value: SystemTime) -> Self {
    Self {
      value: Mutex::new(value),
    }
  }

  pub(crate) fn set(&self, value: SystemTime) {
    *self.value.lock().unwrap() = value;
  }
}

impl WallClock for ManualClock {
  fn now(&self) -> SystemTime {
    *self.value.lock().unwrap()
  }
}

pub(crate) async fn open_engine(
  factory: &Arc<ReferenceFactory>, retention: Duration, clock: Arc<ManualClock>,
) -> MetadataStore {
  let storage_factory: Arc<dyn StorageFactory> = factory.clone();
  let wall_clock: Arc<dyn WallClock> = clock;
  MetadataStore::open_with_clock(&storage_factory, retention, wall_clock)
    .await
    .unwrap()
}

pub(crate) async fn prepare_contract_put(
  store: &MetadataStore, transaction: u16, key: u8,
) -> PreparedTransaction {
  let snapshot = store.snapshot().await.unwrap();
  store
    .prepare_transaction(
      contract_transaction_id(transaction),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("recovered-open"),
        key: store_key(&[key]),
        expected: StoreExpectation::Absent,
        value: value(&[key]),
      }],
    )
    .unwrap()
}

pub(crate) async fn commit_target(
  store: &MetadataStore, transaction: u16,
) -> (PreparedTransaction, ReceiptIdentity) {
  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction(
      contract_transaction_id(transaction),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("receipt-target"),
        key: store_key(&transaction.to_be_bytes()),
        expected: StoreExpectation::Absent,
        value: value(b"target"),
      }],
    )
    .unwrap();
  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  let identity = ReceiptIdentity::from_receipt(&receipt);
  (prepared, identity)
}

pub(crate) fn committed(outcome: CommitOutcome) -> CommitReceipt {
  match outcome {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  }
}

/// The contract lanes' transaction-id helper, single-sourced in
/// `test_util` (one `txn_` format and parse for every lane).
pub(crate) use crate::storage::test_util::transaction_id;

/// Engine-lane alias for call-site readability; delegates to the
/// single-sourced [`transaction_id`].
pub(crate) fn contract_transaction_id(index: u16) -> TransactionId {
  transaction_id(u64::from(index))
}

pub(crate) async fn collect_scan(mut scan: Box<dyn StoreScan + '_>) -> Vec<StoreEntry> {
  let mut entries = Vec::new();
  while let Some(entry) = scan.next().await.unwrap() {
    entries.push(entry);
  }
  assert!(scan.next().await.unwrap().is_none());
  entries
}

pub(crate) fn required_capabilities() -> StoreCapabilities {
  StoreCapabilities::full_metadata(DurabilityLevel::OsCrashDurable)
}

pub(crate) use crate::storage::test_util::{key as store_key, namespace, value};

pub(crate) fn transaction(
  index: u64, base_revision: StoreRevision, operations: Vec<StoreOperation>,
) -> Result<StoreTransaction> {
  StoreTransaction::new(transaction_id(index), base_revision, operations)
}

pub(crate) fn reference_revision(generation: u64) -> StoreRevision {
  StoreRevision::new(Arc::from(generation.to_be_bytes())).unwrap()
}

pub(crate) fn owner_record_key() -> (StoreNamespace, StoreKey) {
  identity_binding_key(&NodeId::parse("node-100000000000000000000").unwrap()).unwrap()
}

pub(crate) fn pointer_record_key() -> (StoreNamespace, StoreKey) {
  local_identity_key().unwrap()
}
