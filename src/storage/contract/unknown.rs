use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

use super::{helpers::*, reference::*};
use crate::{
  CommitOutcome, CommitReceipt, Digest, DurabilityLevel, ReconcileOutcome, StoreCapabilities,
  StoreExpectation, StoreOperation, StoreRequirements, provider::StorageFactory,
};
#[tokio::test]
async fn storage_contract_unknown_fault_adapter_proves_exact_raw_reconciliation() {
  for (mode, expected) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let commit_calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::new(ReferenceFactory::new(required_capabilities())),
      mode,
      commit_calls: Arc::clone(&commit_calls),
    });
    storage_contract_unknown_reconciliation(factory, expected, &commit_calls).await;
  }
}

async fn storage_contract_unknown_reconciliation(
  factory: Arc<dyn StorageFactory>, applied: bool, commit_calls: &AtomicUsize,
) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let snapshot = storage.snapshot().await.unwrap();
  let submitted = transaction(
    30,
    snapshot.revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace("unknown"),
      key: store_key(b"key"),
      expected: StoreExpectation::Absent,
      value: value(b"value"),
    }],
  )
  .unwrap();
  let transaction_id = submitted.id().clone();
  let operation_digest = submitted.operation_digest().clone();
  assert_eq!(
    storage.commit(submitted).await.unwrap(),
    CommitOutcome::Unknown {
      transaction: transaction_id.clone(),
      operation_digest: operation_digest.clone(),
    },
  );
  assert_eq!(commit_calls.load(Ordering::SeqCst), 1);
  assert!(matches!(
    storage
      .reconcile(&transaction_id, &Digest::from_bytes([4; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  let reconciled = storage
    .reconcile(&transaction_id, &operation_digest)
    .await
    .unwrap();
  if applied {
    assert_eq!(
      reconciled,
      ReconcileOutcome::Committed(CommitReceipt::new(
        transaction_id,
        operation_digest,
        reference_revision(2),
      )),
    );
  } else {
    assert!(matches!(reconciled, ReconcileOutcome::Aborted));
  }
  assert_eq!(commit_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn storage_contract_capability_refusal_checks_each_phase_a_requirement() {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let capabilities = [
    StoreCapabilities::full_metadata(DurabilityLevel::ProcessCrashAtomic),
    required_capabilities().conditional_batch(false),
    required_capabilities().ordered_scan(false),
    required_capabilities().reconciliation(false),
    required_capabilities().exclusive_lifetime_lock(false),
  ];
  for capability in capabilities {
    let factory = ReferenceFactory::new(capability);
    let error = runtime
      .block_on(factory.open(StoreRequirements::metadata()))
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::UnsupportedCapability);
  }
  assert!(!StoreRequirements::metadata().requires_transactional_migration());
  assert!(
    runtime
      .block_on(ReferenceFactory::new(required_capabilities()).open(StoreRequirements::metadata()))
      .is_ok()
  );
}
