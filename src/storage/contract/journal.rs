use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, UNIX_EPOCH},
};

use super::{
  helpers::*,
  receipt_refs::{
    JOURNAL_PURPOSE, journaled_tokens, open_pending, prepare_journaled_owner_put, prepare_plain_put,
  },
  reference::*,
};
use crate::{
  CommitOutcome, CommitReceipt, Digest, ReconcileOutcome, StoreExpectation, StoreOperation,
  provider::StorageFactory,
  storage::{
    MetadataStore,
    pending::{PendingCleanupOutcome, PendingTransactionV1, pending_key, pending_namespace},
    receipt::{
      ACTIVE_MARKER_VALUE, ReceiptCleanupOutcome, ReceiptReferenceChange, ReceiptReferenceToken,
      WallClock, internal_namespace, reference_edge_key, reference_head_key, used_id_key,
    },
  },
};
#[tokio::test]
async fn identity_records_journaled_prepare_writes_exact_plan_record_and_marker() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(840)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (owner_namespace, owner_key) = owner_record_key();
  let (owner_token, pointer_token, pending_token) = journaled_tokens();
  let pending_namespace = pending_namespace().unwrap();
  let pending_key = pending_key(JOURNAL_PURPOSE);
  let internal = internal_namespace().unwrap();

  let snapshot = store.snapshot().await.unwrap();
  let base_revision = snapshot.revision().clone();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let prepared = prepare_journaled_owner_put(&store, 400).await;
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);

  let head_key = reference_head_key(prepared.id()).unwrap();
  let operations = prepared.operations();
  assert_eq!(operations.len(), 7);
  assert!(
    matches!(&operations[0], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &owner_namespace && key == &owner_key && put.as_bytes() == b"binding")
  );
  assert!(
    matches!(&operations[1], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &internal && key == &head_key && put.as_bytes() == 3_u64.to_be_bytes().as_slice())
  );
  for (index, token) in [&owner_token, &pointer_token, &pending_token]
    .iter()
    .enumerate()
  {
    let edge_key = reference_edge_key(prepared.id(), token).unwrap();
    assert!(
      matches!(&operations[2 + index], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &internal && key == &edge_key && put.as_bytes().is_empty()),
      "edge {index}"
    );
  }
  let StoreOperation::Put {
    namespace: record_namespace,
    key: record_key,
    expected: StoreExpectation::Absent,
    value: record_value,
  } = &operations[5]
  else {
    panic!("unexpected pending record operation: {:?}", operations[5]);
  };
  assert_eq!(record_namespace, &pending_namespace);
  assert_eq!(record_key, &pending_key);
  let record = PendingTransactionV1::decode(record_value.as_bytes()).unwrap();
  assert_eq!(record.purpose(), JOURNAL_PURPOSE);
  assert_eq!(record.transaction(), prepared.id());
  assert_eq!(record.base_revision(), &base_revision);
  assert_eq!(record.planned_operations(), &operations[..5]);
  let recovered = record.recover_identity(record_value).unwrap();
  assert_eq!(recovered.transaction(), prepared.id());
  assert_eq!(recovered.operation_digest(), prepared.operation_digest());
  assert!(
    matches!(&operations[6], StoreOperation::Put { namespace, key, expected: StoreExpectation::Absent, value: put } if namespace == &internal && key == &used_id_key(prepared.id()).unwrap() && put.as_bytes() == ACTIVE_MARKER_VALUE)
  );

  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    snapshot
      .get(&pending_namespace, &pending_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    record_value.as_bytes()
  );
  assert_eq!(
    snapshot
      .get(&internal, &head_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    3_u64.to_be_bytes().as_slice()
  );
  for token in [&owner_token, &pointer_token, &pending_token] {
    assert!(
      snapshot
        .get(
          &internal,
          &reference_edge_key(receipt.transaction(), token).unwrap()
        )
        .await
        .unwrap()
        .is_some()
    );
  }
  assert_eq!(
    snapshot
      .get(&internal, &used_id_key(receipt.transaction()).unwrap())
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    ACTIVE_MARKER_VALUE
  );
}

#[tokio::test]
async fn identity_records_journaled_prepare_rejects_forbidden_caller_operations() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(850)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let pending_namespace = pending_namespace().unwrap();
  let pending_key = pending_key(JOURNAL_PURPOSE);

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  for operation in [
    StoreOperation::Put {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"injected"),
    },
    StoreOperation::Check {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: StoreExpectation::Absent,
    },
    StoreOperation::Delete {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: Digest::from_bytes([0; 32]),
    },
    StoreOperation::Put {
      namespace: internal_namespace().unwrap(),
      key: store_key(b"injected"),
      expected: StoreExpectation::Absent,
      value: value(b"injected"),
    },
    StoreOperation::ForgetReceipt {
      transaction: contract_transaction_id(410),
      expected_operation_digest: Digest::from_bytes([0; 32]),
    },
  ] {
    let error = store
      .prepare_journaled_transaction(
        snapshot.as_ref(),
        contract_transaction_id(411),
        JOURNAL_PURPOSE,
        vec![operation],
        vec![],
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  }
  let error = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      contract_transaction_id(412),
      JOURNAL_PURPOSE,
      vec![],
      vec![ReceiptReferenceChange::AddSelf(vec![
        ReceiptReferenceToken::for_record(&pending_namespace, &pending_key),
      ])],
    )
    .await
    .unwrap_err();
  assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  let error = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      contract_transaction_id(413),
      "bad\tpurpose",
      vec![],
      vec![],
    )
    .await
    .unwrap_err();
  assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
}

#[tokio::test]
async fn identity_records_journaled_unknown_recovers_reconciles_and_cleans_up() {
  for (mode, applied) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let fault_calls = Arc::new(AtomicUsize::new(0));
    let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(860)));
    let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let prepared = prepare_journaled_owner_put(&store, 420).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    assert_eq!(
      store.commit(prepared).await.unwrap(),
      CommitOutcome::Unknown {
        transaction: transaction.clone(),
        operation_digest: digest.clone(),
      }
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
    drop(store);

    let (owner_namespace, owner_key) = owner_record_key();
    let (owner_token, pointer_token, pending_token) = journaled_tokens();
    let pending_namespace = pending_namespace().unwrap();
    let pending_key = pending_key(JOURNAL_PURPOSE);
    let internal = internal_namespace().unwrap();
    let head_key = reference_head_key(&transaction).unwrap();

    let plain_factory: Arc<dyn StorageFactory> = reference.clone();
    let (store, recovered) = open_pending(&plain_factory, 861).await;
    if !applied {
      assert!(recovered.is_none());
      assert!(reference.state.lock().unwrap().receipts.is_empty());
      let snapshot = store.snapshot().await.unwrap();
      assert!(
        snapshot
          .get(&pending_namespace, &pending_key)
          .await
          .unwrap()
          .is_none()
      );
      assert!(
        snapshot
          .get(&owner_namespace, &owner_key)
          .await
          .unwrap()
          .is_none()
      );
      assert!(
        snapshot
          .get(&internal, &used_id_key(&transaction).unwrap())
          .await
          .unwrap()
          .is_none()
      );
      assert!(snapshot.get(&internal, &head_key).await.unwrap().is_none());
      drop(snapshot);
      let unrelated = prepare_plain_put(&store, 421, 1).await;
      assert!(matches!(
        store.commit(unrelated).await.unwrap(),
        CommitOutcome::Committed(_)
      ));
      continue;
    }

    let identity = recovered.unwrap();
    assert_eq!(identity.transaction(), &transaction);
    assert_eq!(identity.operation_digest(), &digest);
    let unrelated = prepare_plain_put(&store, 422, 2).await;
    assert_eq!(
      store.commit(unrelated).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );

    let snapshot = store.snapshot().await.unwrap();
    assert_eq!(
      snapshot
        .get(&internal, &head_key)
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      3_u64.to_be_bytes().as_slice()
    );
    for token in [&owner_token, &pointer_token, &pending_token] {
      assert!(
        snapshot
          .get(&internal, &reference_edge_key(&transaction, token).unwrap())
          .await
          .unwrap()
          .is_some()
      );
    }
    drop(snapshot);

    let reconciled = store.reconcile().await.unwrap();
    assert!(matches!(reconciled, ReconcileOutcome::Committed(_)));
    let cleanup = store
      .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(423))
      .await
      .unwrap();
    assert!(matches!(cleanup, PendingCleanupOutcome::Applied(_)));

    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&pending_namespace, &pending_key)
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      snapshot
        .get(&internal, &head_key)
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      2_u64.to_be_bytes().as_slice()
    );
    for token in [&owner_token, &pointer_token] {
      assert!(
        snapshot
          .get(&internal, &reference_edge_key(&transaction, token).unwrap())
          .await
          .unwrap()
          .is_some()
      );
    }
    assert!(
      snapshot
        .get(
          &internal,
          &reference_edge_key(&transaction, &pending_token).unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      snapshot
        .get(&owner_namespace, &owner_key)
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      b"binding"
    );
    drop(snapshot);
    assert!(matches!(
      store
        .cleanup_receipt(&identity, contract_transaction_id(424))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Referenced
    ));
    assert!(matches!(
      store
        .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(425))
        .await
        .unwrap(),
      PendingCleanupOutcome::Absent
    ));
  }
}

#[tokio::test]
async fn identity_records_journaled_cancellation_after_submission_recovers() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::PendingApplied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(880)));
  let store = Arc::new(
    MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
      .await
      .unwrap(),
  );
  let prepared = prepare_journaled_owner_put(&store, 430).await;
  let transaction = prepared.id().clone();
  let digest = prepared.operation_digest().clone();
  let task_store = Arc::clone(&store);
  let task = tokio::spawn(async move { task_store.commit(prepared).await });
  while fault_calls.load(Ordering::SeqCst) == 0
    || !reference
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(&transaction)
  {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  drop(store);

  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let (store, recovered) = open_pending(&plain_factory, 881).await;
  let identity = recovered.unwrap();
  assert_eq!(identity.transaction(), &transaction);
  assert_eq!(identity.operation_digest(), &digest);
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Committed(_)
  ));
  assert!(matches!(
    store
      .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(431))
      .await
      .unwrap(),
    PendingCleanupOutcome::Applied(_)
  ));
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&pending_namespace().unwrap(), &pending_key(JOURNAL_PURPOSE))
      .await
      .unwrap()
      .is_none()
  );
}

#[tokio::test]
async fn identity_records_journaled_recovered_digest_conflict_stays_frozen() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::Applied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(900)));
  let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
    .await
    .unwrap();
  let prepared = prepare_journaled_owner_put(&store, 432).await;
  let transaction = prepared.id().clone();
  let digest = prepared.operation_digest().clone();
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  drop(store);

  let tampered = CommitReceipt::new(
    transaction.clone(),
    Digest::from_bytes([0x77; 32]),
    reference_revision(2),
  );
  reference
    .state
    .lock()
    .unwrap()
    .receipts
    .insert(transaction.clone(), tampered);

  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let (store, recovered) = open_pending(&plain_factory, 901).await;
  let identity = recovered.unwrap();
  assert_eq!(identity.transaction(), &transaction);
  assert_eq!(identity.operation_digest(), &digest);
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  let unrelated = prepare_plain_put(&store, 433, 3).await;
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
}

#[tokio::test]
async fn identity_records_journaled_malformed_and_multiple_pending_fail_closed() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let pending_namespace = pending_namespace().unwrap();
  let pending_key = pending_key(JOURNAL_PURPOSE);
  let (owner_namespace, owner_key) = owner_record_key();
  let planned = vec![StoreOperation::Put {
    namespace: owner_namespace.clone(),
    key: owner_key.clone(),
    expected: StoreExpectation::Absent,
    value: value(b"binding"),
  }];
  let valid = PendingTransactionV1::encode_for_test(
    JOURNAL_PURPOSE,
    &contract_transaction_id(440),
    &reference_revision(1),
    &planned,
  )
  .unwrap();
  let open = || {
    let factory = Arc::clone(&plain_factory);
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(920)));
    async move {
      MetadataStore::open_pending_recovered_with_clock(
        &factory,
        Duration::from_secs(10),
        JOURNAL_PURPOSE,
        clock,
      )
      .await
    }
  };

  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(b"not a pending record"),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&valid),
  );
  let (store, recovered) = open().await.unwrap();
  let identity = recovered.unwrap();
  assert_eq!(identity.transaction(), &contract_transaction_id(440));
  assert_eq!(
    store.reconcile().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
  let unrelated = prepare_plain_put(&store, 441, 4).await;
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
  drop(store);

  let mismatched = PendingTransactionV1::encode_for_test(
    "other-purpose",
    &contract_transaction_id(440),
    &reference_revision(1),
    &planned,
  )
  .unwrap();
  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&mismatched),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  let self_referencing = PendingTransactionV1::encode_for_test(
    JOURNAL_PURPOSE,
    &contract_transaction_id(440),
    &reference_revision(1),
    &[StoreOperation::Put {
      namespace: pending_namespace.clone(),
      key: pending_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"recursive"),
    }],
  )
  .unwrap();
  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&self_referencing),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  reference.state.lock().unwrap().entries.insert(
    (pending_namespace.clone(), pending_key.clone()),
    value(&valid),
  );
  reference.state.lock().unwrap().entries.insert(
    (
      pending_namespace.clone(),
      store_key(b"local-identity-extended"),
    ),
    value(&valid),
  );
  assert_eq!(
    open().await.unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );

  reference.state.lock().unwrap().entries.remove(&(
    pending_namespace.clone(),
    store_key(b"local-identity-extended"),
  ));
  let (store, recovered) = open().await.unwrap();
  assert!(recovered.is_some());
  drop(store);
}

#[tokio::test]
async fn identity_records_journaled_duplicate_pending_insertion_conflicts_without_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(940)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let first = prepare_journaled_owner_put(&store, 450).await;
  committed(store.commit(first).await.unwrap());

  let second = prepare_journaled_owner_put(&store, 451).await;
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  assert!(matches!(
    store.commit(second).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
  assert!(
    !factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(&contract_transaction_id(451))
  );
}

#[tokio::test]
async fn identity_records_journaled_cleanup_unknown_stays_exact_and_restart_retries() {
  for (mode, applied) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let plain_factory: Arc<dyn StorageFactory> = reference.clone();
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(960)));
    let seed = MetadataStore::open_with_clock(&plain_factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let prepared = prepare_journaled_owner_put(&seed, 460).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    committed(seed.commit(prepared).await.unwrap());
    drop(seed);

    let fault_calls = Arc::new(AtomicUsize::new(0));
    let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(960)));
    let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let cleanup_identity = match store
      .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(461))
      .await
      .unwrap()
    {
      PendingCleanupOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected cleanup outcome: {outcome:?}"),
    };
    assert_eq!(
      cleanup_identity.transaction(),
      &contract_transaction_id(461)
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
    let unrelated = prepare_plain_put(&store, 462, 5).await;
    assert_eq!(
      store.commit(unrelated).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    let reconciled = store.reconcile().await.unwrap();
    match mode {
      UnknownFaultMode::Applied => {
        assert!(matches!(reconciled, ReconcileOutcome::Committed(_)))
      }
      UnknownFaultMode::NotApplied => {
        assert!(matches!(reconciled, ReconcileOutcome::Aborted))
      }
      UnknownFaultMode::PendingApplied | UnknownFaultMode::PendingNotApplied => unreachable!(),
    }
    let pending_namespace = pending_namespace().unwrap();
    let pending_key = pending_key(JOURNAL_PURPOSE);
    let snapshot = store.snapshot().await.unwrap();
    assert_eq!(
      snapshot
        .get(&pending_namespace, &pending_key)
        .await
        .unwrap()
        .is_some(),
      !applied
    );
    drop(snapshot);
    drop(store);

    let (store, recovered) = open_pending(&plain_factory, 961).await;
    if applied {
      assert!(recovered.is_none());
      let unrelated = prepare_plain_put(&store, 463, 6).await;
      assert!(matches!(
        store.commit(unrelated).await.unwrap(),
        CommitOutcome::Committed(_)
      ));
      continue;
    }
    let identity = recovered.unwrap();
    assert_eq!(identity.transaction(), &transaction);
    assert_eq!(identity.operation_digest(), &digest);
    assert!(matches!(
      store.reconcile().await.unwrap(),
      ReconcileOutcome::Committed(_)
    ));
    assert!(matches!(
      store
        .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(464))
        .await
        .unwrap(),
      PendingCleanupOutcome::Applied(_)
    ));
    let (owner_token, pointer_token, pending_token) = journaled_tokens();
    let internal = internal_namespace().unwrap();
    let snapshot = store.snapshot().await.unwrap();
    assert!(
      snapshot
        .get(&pending_namespace, &pending_key)
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      snapshot
        .get(&internal, &reference_head_key(&transaction).unwrap())
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      2_u64.to_be_bytes().as_slice()
    );
    for token in [&owner_token, &pointer_token] {
      assert!(
        snapshot
          .get(&internal, &reference_edge_key(&transaction, token).unwrap())
          .await
          .unwrap()
          .is_some()
      );
    }
    assert!(
      snapshot
        .get(
          &internal,
          &reference_edge_key(&transaction, &pending_token).unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
  }
}

/// The concurrent same-generation merge defect found during the P2-3
/// acceptance run, at the storage layer: a same-purpose journal residue
/// resolved by one flow must stay resolvable for every later flow on the
/// same ready store — the resolution reads durable evidence idempotently
/// instead of parking on the ready-state refusal and failing with
/// NotReady after the full entry-wait bound.
#[tokio::test]
async fn identity_records_same_purpose_journal_residue_resolves_twice_from_evidence() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(870)));
  let factory: Arc<dyn StorageFactory> = Arc::clone(&reference) as _;
  let store = MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
    .await
    .unwrap();

  // Flow A leaves its journal residue behind: the transaction commits
  // atomically with the pending record, and the cleanup never runs.
  let prepared = prepare_journaled_owner_put(&store, 430).await;
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Committed(_)
  ));

  // The recovery resolutions are idempotent evidence reads: both return
  // committed, neither parks on the ready-state refusal, and both stay
  // well under the old code's 5-second ready-refusal timeout.
  let started = std::time::Instant::now();
  assert!(
    store
      .resolve_pending_journal(JOURNAL_PURPOSE)
      .await
      .unwrap()
  );
  assert!(
    store
      .resolve_pending_journal(JOURNAL_PURPOSE)
      .await
      .unwrap()
  );
  assert!(started.elapsed() < Duration::from_secs(2));
  assert!(!store.is_blocked().unwrap());

  // The residue cleanup removes the pending record; a third resolution
  // reports nothing to recover, and the business record is live.
  let operation = contract_transaction_id(431);
  assert!(matches!(
    store
      .cleanup_pending(JOURNAL_PURPOSE, operation)
      .await
      .unwrap(),
    PendingCleanupOutcome::Applied(_) | PendingCleanupOutcome::Absent
  ));
  assert!(
    !store
      .resolve_pending_journal(JOURNAL_PURPOSE)
      .await
      .unwrap()
  );
  let (owner_namespace, owner_key) = owner_record_key();
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .is_some()
  );
}

/// A ready store has no in-doubt commit: the reconcile refusal is
/// semantic and must surface immediately instead of parking for the
/// full entry-wait bound.
#[tokio::test]
async fn reconcile_on_a_ready_store_fails_immediately() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(875)));
  let factory: Arc<dyn StorageFactory> = Arc::clone(&reference) as _;
  let store = MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
    .await
    .unwrap();
  let started = std::time::Instant::now();
  let error = store.reconcile().await.unwrap_err();
  assert_eq!(error.kind(), crate::ErrorKind::NotReady);
  assert!(started.elapsed() < Duration::from_secs(1));
}

/// The permanent-contradiction freeze: the journaled transaction landed,
/// but the provider's receipt is gone, so reconciliation classifies as
/// aborted while the journal proves committed and the store fails
/// closed. The operator-confirmed uncommitted declaration deletes the
/// journal in one atomic transaction and unfreezes the store; the
/// resolution is durable — a reopen on the same storage (the crash
/// simulation) finds no pending journal and starts ready.
#[tokio::test]
async fn identity_records_declared_uncommitted_resolution_is_durable() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::Applied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(980)));
  let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
    .await
    .unwrap();
  let prepared = prepare_journaled_owner_put(&store, 470).await;
  let transaction = prepared.id().clone();
  let digest = prepared.operation_digest().clone();
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  drop(store);

  // The provider loses the receipt: the durable evidence now
  // permanently contradicts the pending journal.
  reference
    .state
    .lock()
    .unwrap()
    .receipts
    .remove(&transaction);

  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let (store, recovered) = open_pending(&plain_factory, 981).await;
  let identity = recovered.unwrap();
  assert_eq!(identity.transaction(), &transaction);
  assert_eq!(identity.operation_digest(), &digest);
  assert!(store.is_blocked().unwrap());
  let unrelated = prepare_plain_put(&store, 471, 7).await;
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );

  // Every reconcile re-derives the same contradiction: journal present,
  // receipt absent.
  assert_eq!(
    store
      .resolve_pending_journal(JOURNAL_PURPOSE)
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert!(store.is_blocked().unwrap());

  // The acknowledged declaration resolves the frozen journal: the
  // pending record is deleted in one atomic transaction and the store
  // unfreezes.
  store
    .resolve_frozen_journal_uncommitted(contract_transaction_id(472))
    .await
    .unwrap();
  assert!(!store.is_blocked().unwrap());
  let unrelated = prepare_plain_put(&store, 473, 8).await;
  assert!(matches!(
    store.commit(unrelated).await.unwrap(),
    CommitOutcome::Committed(_)
  ));
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&pending_namespace().unwrap(), &pending_key(JOURNAL_PURPOSE))
      .await
      .unwrap()
      .is_none()
  );
  drop(snapshot);

  // Crash simulation: the resolution survived a restart on the same
  // storage — no pending journal, no freeze.
  drop(store);
  let (store, recovered) = open_pending(&plain_factory, 982).await;
  assert!(recovered.is_none());
  assert!(!store.is_blocked().unwrap());
  let unrelated = prepare_plain_put(&store, 474, 9).await;
  assert!(matches!(
    store.commit(unrelated).await.unwrap(),
    CommitOutcome::Committed(_)
  ));
}

/// The declaration refuses every state it does not target: a ready store
/// and an in-flight commit freeze with no durable journal record behind
/// it reject typed with `Conflict` and change nothing.
#[tokio::test]
async fn identity_records_declared_uncommitted_resolution_refuses_unfrozen_and_non_journal_freezes()
{
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  {
    let factory: Arc<dyn StorageFactory> = Arc::clone(&reference) as _;
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(990)));
    let store = MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    assert_eq!(
      store
        .resolve_frozen_journal_uncommitted(contract_transaction_id(475))
        .await
        .unwrap_err()
        .kind(),
      crate::ErrorKind::Conflict
    );
    assert!(!store.is_blocked().unwrap());
  }

  let fault_calls = Arc::new(AtomicUsize::new(0));
  let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::NotApplied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(991)));
  let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
    .await
    .unwrap();
  let prepared = prepare_plain_put(&store, 476, 10).await;
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  assert!(store.is_blocked().unwrap());
  assert_eq!(
    store
      .resolve_frozen_journal_uncommitted(contract_transaction_id(477))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::Conflict
  );
  assert!(store.is_blocked().unwrap());
}

/// The declaration refuses to delete a journal the provider proves
/// committed: the fresh evidence read rejects typed and the store stays
/// frozen with its journal intact (a healed provider resolves the
/// journal through the normal reconciliation).
#[tokio::test]
async fn identity_records_declared_uncommitted_resolution_refuses_committed_evidence() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let fault_factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::Applied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> =
    Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
  let store = MetadataStore::open_with_clock(&fault_factory, Duration::from_secs(10), clock)
    .await
    .unwrap();
  let prepared = prepare_journaled_owner_put(&store, 479).await;
  let transaction = prepared.id().clone();
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  drop(store);

  // Lose the receipt, reopen frozen on the contradiction, then heal the
  // provider: the evidence read inside the resolution now proves the
  // journaled transaction committed.
  let healed_receipt = reference
    .state
    .lock()
    .unwrap()
    .receipts
    .get(&transaction)
    .unwrap()
    .clone();
  reference
    .state
    .lock()
    .unwrap()
    .receipts
    .remove(&transaction);
  let plain_factory: Arc<dyn StorageFactory> = reference.clone();
  let (store, recovered) = open_pending(&plain_factory, 1001).await;
  assert!(recovered.is_some());
  assert!(store.is_blocked().unwrap());
  reference
    .state
    .lock()
    .unwrap()
    .receipts
    .insert(transaction, healed_receipt);

  assert_eq!(
    store
      .resolve_frozen_journal_uncommitted(contract_transaction_id(480))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert!(store.is_blocked().unwrap());
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&pending_namespace().unwrap(), &pending_key(JOURNAL_PURPOSE))
      .await
      .unwrap()
      .is_some()
  );
}

/// Concurrent same-purpose journal flows serialize through the writer
/// permit: exactly one business commit lands, the others classify as
/// definitively not-applied, no flow observes a ready-state reconcile
/// refusal, and the slot ends ready with the journal cleaned.
#[tokio::test]
async fn concurrent_same_purpose_journal_flows_serialize_without_not_ready() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(885)));
  let factory: Arc<dyn StorageFactory> = Arc::clone(&reference) as _;
  let store = Arc::new(
    MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
      .await
      .unwrap(),
  );

  let flows = 8_u16;
  let results = futures_util::future::join_all((0..flows).map(|offset| {
    let store = Arc::clone(&store);
    async move {
      let _permit = store.write_permit().await;
      store
        .resolve_pending_journal(JOURNAL_PURPOSE)
        .await
        .map_err(|_| crate::Error::conflict("stage-resolve"))?;
      let prepared = prepare_journaled_owner_put(&store, 440 + offset).await;
      let outcome = store
        .commit(prepared)
        .await
        .map_err(|_| crate::Error::conflict("stage-commit"))?;
      match outcome {
        CommitOutcome::Committed(_) => {}
        CommitOutcome::Conflict | CommitOutcome::Aborted => {}
        CommitOutcome::Unknown { .. } => {
          return Err(crate::Error::conflict("unexpected unknown outcome"));
        }
      }
      store
        .cleanup_pending(JOURNAL_PURPOSE, contract_transaction_id(450 + offset))
        .await
        .map_err(|_| crate::Error::conflict("stage-cleanup"))?;
      Ok(())
    }
  }))
  .await;
  for (offset, result) in results.into_iter().enumerate() {
    if let Err(error) = result {
      panic!("flow {offset} failed: {error:?}");
    }
  }

  // Every flow either landed its business record or lost it to the
  // exact-version conflict; the journal is cleaned and the slot ready.
  assert!(!store.is_blocked().unwrap());
  assert!(
    !store
      .resolve_pending_journal(JOURNAL_PURPOSE)
      .await
      .unwrap()
  );
  let (owner_namespace, owner_key) = owner_record_key();
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .is_some()
  );
}
