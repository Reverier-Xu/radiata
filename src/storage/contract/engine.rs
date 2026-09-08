use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, UNIX_EPOCH},
};

use super::{helpers::*, reference::*};
use crate::{
  CommitOutcome, Digest, ReconcileOutcome, StoreExpectation, StoreOperation, StoreRequirements,
  StoreValue,
  provider::StorageFactory,
  storage::{
    MetadataStore,
    receipt::{
      ACTIVE_MARKER_VALUE, FORGOTTEN_MARKER_VALUE, ReceiptCleanupOutcome, ReceiptIdentity,
      ReceiptReferenceOutcome, ReceiptReferenceToken, WallClock, decode_anchor_value,
      decode_wall_time, eligibility_anchor_key, encode_anchor_value, encode_wall_time,
      increment_reference_count, internal_namespace, reference_edge_key, reference_head_key,
      used_id_key,
    },
  },
};
#[tokio::test]
async fn storage_contract_prepared_transactions_are_atomic_idempotent_and_permanently_used() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction(
      contract_transaction_id(1),
      snapshot.revision().clone(),
      vec![
        StoreOperation::Put {
          namespace: namespace("prepared-one"),
          key: store_key(b"one"),
          expected: StoreExpectation::Absent,
          value: value(b"one"),
        },
        StoreOperation::Put {
          namespace: namespace("prepared-two"),
          key: store_key(b"two"),
          expected: StoreExpectation::Absent,
          value: value(b"two"),
        },
      ],
    )
    .unwrap();
  let marker_key = used_id_key(prepared.id()).unwrap();
  assert_eq!(prepared.operations().len(), 3);
  assert!(prepared.operations().iter().any(|operation| {
    matches!(
      operation,
      StoreOperation::Put {
        namespace,
        key,
        expected: StoreExpectation::Absent,
        value,
      } if namespace.as_str() == internal_namespace().unwrap().as_str()
        && key == &marker_key
        && value.as_bytes() == ACTIVE_MARKER_VALUE
    )
  }));

  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  assert_eq!(
    committed(store.commit(prepared.clone()).await.unwrap()),
    receipt
  );
  assert_eq!(
    store
      .snapshot()
      .await
      .unwrap()
      .get(&internal_namespace().unwrap(), &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    ACTIVE_MARKER_VALUE,
  );

  let target = ReceiptIdentity::from_receipt(&receipt);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(2))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(3))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(50));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(4))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(100));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(5))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(110));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(6))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
  let forgotten_snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    forgotten_snapshot
      .get(&internal_namespace().unwrap(), &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    FORGOTTEN_MARKER_VALUE,
  );
  let reused = store
    .prepare_transaction(
      target.transaction().clone(),
      forgotten_snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("current-reuse"),
        key: store_key(b"otherwise-valid"),
        expected: StoreExpectation::Absent,
        value: value(b"must-not-commit"),
      }],
    )
    .unwrap();
  drop(forgotten_snapshot);
  let commits_before_reuse = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store.commit(reused).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before_reuse + 1,
  );
  drop(store);

  let reopened = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let stale_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([99; 32]));
  let state_before_stale_attempts = {
    let state = factory.state.lock().unwrap();
    (
      state.generation,
      state.entries.clone(),
      state.receipts.clone(),
    )
  };
  let commits_before_stale_attempts = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    reopened
      .add_receipt_reference(&target, &stale_token, contract_transaction_id(7))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert!(matches!(
    reopened
      .remove_receipt_reference(&target, &stale_token, contract_transaction_id(8))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert!(matches!(
    reopened
      .cleanup_receipt(&target, contract_transaction_id(9))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before_stale_attempts,
  );
  {
    let state = factory.state.lock().unwrap();
    assert_eq!(state.generation, state_before_stale_attempts.0);
    assert_eq!(state.entries, state_before_stale_attempts.1);
    assert_eq!(state.receipts, state_before_stale_attempts.2);
  }
  drop(reopened);

  let raw = factory.open(StoreRequirements::metadata()).await.unwrap();
  assert!(matches!(
    raw
      .reconcile(target.transaction(), target.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));
  assert!(matches!(
    raw.commit(prepared.0.clone()).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(
    raw
      .snapshot()
      .await
      .unwrap()
      .get(&internal_namespace().unwrap(), &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    FORGOTTEN_MARKER_VALUE,
  );
}

#[tokio::test]
async fn storage_contract_retention_sweep_forgets_only_past_deadline_anchored_receipts() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction(
      contract_transaction_id(20),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("retention-sweep"),
        key: store_key(b"record"),
        expected: StoreExpectation::Absent,
        value: value(b"payload"),
      }],
    )
    .unwrap();
  let receipt = committed(store.commit(prepared).await.unwrap());
  let identity = ReceiptIdentity::from_receipt(&receipt);

  // Nothing is anchored, so the sweep forgets nothing.
  let report = store.apply_receipt_retention().await.unwrap();
  assert_eq!(report.forgotten, 0);
  assert!(!report.remaining);

  // Anchoring starts the retention clock; inside the window the sweep
  // retains.
  assert!(matches!(
    store
      .cleanup_receipt(&identity, contract_transaction_id(21))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  let report = store.apply_receipt_retention().await.unwrap();
  assert_eq!(report.forgotten, 0);
  assert!(!report.remaining);

  // Past the deadline the same explicit pass forgets, and a repeat pass
  // is an idempotent no-op.
  clock.set(UNIX_EPOCH + Duration::from_secs(200));
  let report = store.apply_receipt_retention().await.unwrap();
  assert_eq!(report.forgotten, 1);
  assert!(!report.remaining);
  assert_eq!(
    store
      .snapshot()
      .await
      .unwrap()
      .get(
        &internal_namespace().unwrap(),
        &used_id_key(&contract_transaction_id(20)).unwrap()
      )
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    FORGOTTEN_MARKER_VALUE
  );
  let report = store.apply_receipt_retention().await.unwrap();
  assert_eq!(report.forgotten, 0);
}

#[tokio::test]
async fn storage_contract_opaque_reference_categories_block_cleanup_until_final_removal() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(200)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&store, 20).await;
  let owner = ReceiptReferenceToken::from_digest(Digest::from_bytes([1; 32]));
  let pending = ReceiptReferenceToken::from_digest(Digest::from_bytes([2; 32]));
  let provider_intent = ReceiptReferenceToken::from_digest(Digest::from_bytes([3; 32]));
  let migration = ReceiptReferenceToken::from_digest(Digest::from_bytes([4; 32]));
  let unknown = ReceiptReferenceToken::from_digest(Digest::from_bytes([5; 32]));
  let tokens = [owner, pending, provider_intent, migration, unknown];

  for (offset, token) in tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &target,
          token,
          contract_transaction_id(21 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let commits_before_cleanup = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(30))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Referenced
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before_cleanup
  );

  for (offset, token) in tokens[..4].iter().enumerate() {
    assert!(matches!(
      store
        .remove_receipt_reference(
          &target,
          token,
          contract_transaction_id(31 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
    let before = factory.commit_calls.load(Ordering::SeqCst);
    assert!(matches!(
      store
        .cleanup_receipt(
          &target,
          contract_transaction_id(40 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Referenced
    ));
    assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
  }
  assert!(matches!(
    store
      .remove_receipt_reference(&target, &tokens[4], contract_transaction_id(50))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(
        &internal_namespace().unwrap(),
        &reference_head_key(target.transaction()).unwrap(),
      )
      .await
      .unwrap()
      .is_none()
  );
  assert!(
    snapshot
      .get(
        &internal_namespace().unwrap(),
        &eligibility_anchor_key(target.transaction()).unwrap(),
      )
      .await
      .unwrap()
      .is_none()
  );
  drop(snapshot);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(51))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(210));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(52))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
}

#[tokio::test]
async fn storage_contract_reference_addition_and_final_disappearance_reset_retention() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(300)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&store, 60).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([9; 32]));

  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(61))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(305));
  assert!(matches!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(62))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  assert!(
    store
      .snapshot()
      .await
      .unwrap()
      .get(
        &internal_namespace().unwrap(),
        &eligibility_anchor_key(target.transaction()).unwrap(),
      )
      .await
      .unwrap()
      .is_none()
  );
  clock.set(UNIX_EPOCH + Duration::from_secs(310));
  assert!(matches!(
    store
      .remove_receipt_reference(&target, &token, contract_transaction_id(63))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(320));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(64))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  let anchor = store
    .snapshot()
    .await
    .unwrap()
    .get(
      &internal_namespace().unwrap(),
      &eligibility_anchor_key(target.transaction()).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
  // The anchor carries the anchoring time plus the conditioned digest.
  assert_eq!(
    decode_anchor_value(anchor.as_bytes()).unwrap(),
    (
      UNIX_EPOCH + Duration::from_secs(320),
      target.operation_digest().clone()
    )
  );
  clock.set(UNIX_EPOCH + Duration::from_secs(329));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(65))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(330));
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(66))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
}

#[tokio::test]
async fn storage_contract_reserved_injection_duplicates_corruption_and_overflow_fail_closed() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(400)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 70).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([10; 32]));
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    store
      .prepare_transaction(
        contract_transaction_id(71),
        snapshot.revision().clone(),
        vec![StoreOperation::Put {
          namespace: internal_namespace().unwrap(),
          key: store_key(b"injected"),
          expected: StoreExpectation::Absent,
          value: value(b"injected"),
        }],
      )
      .unwrap_err()
      .kind(),
    crate::ErrorKind::InvalidInput
  );
  assert_eq!(
    store
      .prepare_transaction(
        contract_transaction_id(711),
        snapshot.revision().clone(),
        vec![StoreOperation::ForgetReceipt {
          transaction: target.transaction().clone(),
          expected_operation_digest: target.operation_digest().clone(),
        }],
      )
      .unwrap_err()
      .kind(),
    crate::ErrorKind::InvalidInput
  );
  drop(snapshot);
  assert!(matches!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(72))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  let before_duplicate = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(73))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );
  let missing = ReceiptReferenceToken::from_digest(Digest::from_bytes([11; 32]));
  assert!(matches!(
    store
      .remove_receipt_reference(&target, &missing, contract_transaction_id(74))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Conflict
  ));
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );

  let head_key = reference_head_key(target.transaction()).unwrap();
  {
    let mut state = factory.state.lock().unwrap();
    state
      .entries
      .remove(&(internal_namespace().unwrap(), head_key.clone()));
  }
  assert_eq!(
    store
      .remove_receipt_reference(&target, &token, contract_transaction_id(75))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );
  {
    let mut state = factory.state.lock().unwrap();
    state.entries.insert(
      (internal_namespace().unwrap(), head_key.clone()),
      StoreValue::new(Arc::from([1_u8, 2, 3].as_slice())),
    );
  }
  assert_eq!(
    store
      .add_receipt_reference(&target, &token, contract_transaction_id(751))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  {
    let mut state = factory.state.lock().unwrap();
    state.entries.insert(
      (internal_namespace().unwrap(), head_key),
      StoreValue::new(Arc::from(u64::MAX.to_be_bytes())),
    );
  }
  let overflow_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([12; 32]));
  assert_eq!(
    store
      .add_receipt_reference(&target, &overflow_token, contract_transaction_id(76))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_duplicate
  );
}

#[test]
fn storage_contract_reference_count_overflow_is_resource_exhaustion() {
  assert_eq!(
    increment_reference_count(u64::MAX).unwrap_err().kind(),
    crate::ErrorKind::ResourceExhausted,
  );
  assert_eq!(increment_reference_count(u64::MAX - 1).unwrap(), u64::MAX);
}

#[tokio::test]
async fn storage_contract_streamed_edge_audit_rejects_orphans_and_count_mismatches() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(425)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let namespace = internal_namespace().unwrap();

  let (_, orphan_target) = commit_target(&store, 770).await;
  let orphan_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([21; 32]));
  let orphan_edge = reference_edge_key(orphan_target.transaction(), &orphan_token).unwrap();
  {
    factory.state.lock().unwrap().entries.insert(
      (namespace.clone(), orphan_edge),
      StoreValue::new(Arc::from([])),
    );
  }
  let orphan_state = factory.state.lock().unwrap().entries.clone();
  let before_orphan_cleanup = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .cleanup_receipt(&orphan_target, contract_transaction_id(771))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_orphan_cleanup,
  );
  assert_eq!(factory.state.lock().unwrap().entries, orphan_state);
  assert!(
    factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(orphan_target.transaction()),
  );

  let (_, undercount_target) = commit_target(&store, 780).await;
  let undercount_tokens = [
    ReceiptReferenceToken::from_digest(Digest::from_bytes([22; 32])),
    ReceiptReferenceToken::from_digest(Digest::from_bytes([23; 32])),
  ];
  for (offset, token) in undercount_tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &undercount_target,
          token,
          contract_transaction_id(781 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let undercount_head = reference_head_key(undercount_target.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (namespace.clone(), undercount_head),
    StoreValue::new(Arc::from(1_u64.to_be_bytes())),
  );
  let undercount_state = factory.state.lock().unwrap().entries.clone();
  let before_undercount = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .remove_receipt_reference(
        &undercount_target,
        &undercount_tokens[0],
        contract_transaction_id(783),
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    store
      .cleanup_receipt(&undercount_target, contract_transaction_id(784))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_undercount
  );
  assert_eq!(factory.state.lock().unwrap().entries, undercount_state);

  let (_, overcount_target) = commit_target(&store, 790).await;
  let overcount_tokens = [
    ReceiptReferenceToken::from_digest(Digest::from_bytes([24; 32])),
    ReceiptReferenceToken::from_digest(Digest::from_bytes([25; 32])),
  ];
  for (offset, token) in overcount_tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &overcount_target,
          token,
          contract_transaction_id(791 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let overcount_head = reference_head_key(overcount_target.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (namespace.clone(), overcount_head),
    StoreValue::new(Arc::from(3_u64.to_be_bytes())),
  );
  let before_overcount = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .cleanup_receipt(&overcount_target, contract_transaction_id(793))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_overcount
  );

  let (_, malformed_marker_target) = commit_target(&store, 800).await;
  let malformed_marker_key = used_id_key(malformed_marker_target.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (namespace, malformed_marker_key),
    StoreValue::new(Arc::from(b"\x01forgotten\0malformed".as_slice())),
  );
  let malformed_state = factory.state.lock().unwrap().entries.clone();
  let before_malformed = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .add_receipt_reference(
        &malformed_marker_target,
        &ReceiptReferenceToken::from_digest(Digest::from_bytes([26; 32])),
        contract_transaction_id(801),
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt,
  );
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    before_malformed
  );
  assert_eq!(factory.state.lock().unwrap().entries, malformed_state);
}

#[tokio::test]
async fn storage_contract_reference_provider_revision_exhaustion_is_atomic() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  factory.state.lock().unwrap().generation = u64::MAX - 1;

  let near_max = storage.snapshot().await.unwrap();
  let reaches_max = transaction(
    40,
    near_max.revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace("revision-overflow"),
      key: store_key(b"first"),
      expected: StoreExpectation::Absent,
      value: value(b"first"),
    }],
  )
  .unwrap();
  let receipt = committed(storage.commit(reaches_max).await.unwrap());
  assert_eq!(receipt.committed_revision(), &reference_revision(u64::MAX));

  let at_max = storage.snapshot().await.unwrap();
  let exhausted = transaction(
    41,
    at_max.revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace("revision-overflow"),
      key: store_key(b"second"),
      expected: StoreExpectation::Absent,
      value: value(b"second"),
    }],
  )
  .unwrap();
  let state_before = {
    let state = factory.state.lock().unwrap();
    (state.entries.clone(), state.receipts.clone())
  };
  assert_eq!(
    storage.commit(exhausted).await.unwrap_err().kind(),
    crate::ErrorKind::ResourceExhausted,
  );
  let state = factory.state.lock().unwrap();
  assert_eq!(state.generation, u64::MAX);
  assert_eq!(state.entries, state_before.0);
  assert_eq!(state.receipts, state_before.1);
}

#[tokio::test]
async fn storage_contract_malformed_reference_count_and_anchor_fail_without_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(450)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 85).await;
  let namespace = internal_namespace().unwrap();
  let head_key = reference_head_key(target.transaction()).unwrap();
  let anchor_key = eligibility_anchor_key(target.transaction()).unwrap();

  {
    let mut state = factory.state.lock().unwrap();
    state.entries.insert(
      (namespace.clone(), head_key.clone()),
      StoreValue::new(Arc::from([1_u8, 2, 3].as_slice())),
    );
  }
  let before = factory.commit_calls.load(Ordering::SeqCst);
  assert_eq!(
    store
      .remove_receipt_reference(
        &target,
        &ReceiptReferenceToken::from_digest(Digest::from_bytes([15; 32])),
        contract_transaction_id(861),
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(
    store
      .cleanup_receipt(&target, contract_transaction_id(86))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
  assert!(
    factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction())
  );

  {
    let mut state = factory.state.lock().unwrap();
    state.entries.remove(&(namespace.clone(), head_key));
    let mut malformed_time = [0_u8; 13];
    malformed_time[9..13].copy_from_slice(&1_000_000_000_u32.to_be_bytes());
    state.entries.insert(
      (namespace, anchor_key),
      StoreValue::new(Arc::from(malformed_time)),
    );
  }
  assert_eq!(
    store
      .cleanup_receipt(&target, contract_transaction_id(87))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
  assert!(
    factory
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction())
  );
}

#[test]
fn storage_contract_wall_time_encoding_is_canonical_pre_epoch_and_rejects_malformed_values() {
  let before_epoch = UNIX_EPOCH - Duration::new(7, 123_456_789);
  let encoded = encode_wall_time(before_epoch);
  assert_eq!(encoded.len(), 13);
  assert_eq!(decode_wall_time(&encoded).unwrap(), before_epoch);
  assert_eq!(
    encode_wall_time(decode_wall_time(&encoded).unwrap()),
    encoded
  );

  let mut invalid_nanos = encoded;
  invalid_nanos[9..13].copy_from_slice(&1_000_000_000_u32.to_be_bytes());
  assert_eq!(
    decode_wall_time(&invalid_nanos).unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
  let mut invalid_sign = encoded;
  invalid_sign[0] = 2;
  assert_eq!(
    decode_wall_time(&invalid_sign).unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
  assert_eq!(
    decode_wall_time(&encoded[..12]).unwrap_err().kind(),
    crate::ErrorKind::StorageCorrupt
  );
}

#[tokio::test]
async fn storage_contract_deadline_overflow_retains_without_provider_commit() {
  let Some(anchor_time) = UNIX_EPOCH.checked_add(Duration::from_secs(i64::MAX as u64)) else {
    return;
  };
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(anchor_time));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 80).await;
  {
    let mut state = factory.state.lock().unwrap();
    state.entries.insert(
      (
        internal_namespace().unwrap(),
        eligibility_anchor_key(target.transaction()).unwrap(),
      ),
      StoreValue::new(Arc::from(encode_anchor_value(
        anchor_time,
        &Digest::from_bytes([7; 32]),
      ))),
    );
  }
  let before = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(81))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Retained
  ));
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), before);
}

#[derive(Clone, Copy, Debug)]
enum FaultedReceiptOperation {
  Add,
  Remove,
  Anchor,
  Forget,
}

#[tokio::test]
async fn storage_contract_unknown_receipt_mutations_freeze_and_reconcile_exact_operation() {
  for mode in [UnknownFaultMode::Applied, UnknownFaultMode::NotApplied] {
    for phase in [
      FaultedReceiptOperation::Add,
      FaultedReceiptOperation::Remove,
      FaultedReceiptOperation::Anchor,
      FaultedReceiptOperation::Forget,
    ] {
      exercise_unknown_receipt_operation(mode, phase).await;
    }
  }
}

async fn exercise_unknown_receipt_operation(
  mode: UnknownFaultMode, phase: FaultedReceiptOperation,
) {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(500)));
  let seed = open_engine(&reference, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&seed, 90).await;
  let (_, unrelated) = commit_target(&seed, 91).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([13; 32]));
  if matches!(phase, FaultedReceiptOperation::Remove) {
    assert!(matches!(
      seed
        .add_receipt_reference(&target, &token, contract_transaction_id(92))
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  if matches!(phase, FaultedReceiptOperation::Forget) {
    assert!(matches!(
      seed
        .cleanup_receipt(&target, contract_transaction_id(93))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Anchored(_)
    ));
    clock.set(UNIX_EPOCH + Duration::from_secs(510));
  }
  drop(seed);

  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode,
    commit_calls: Arc::clone(&fault_calls),
  });
  let wall_clock: Arc<dyn WallClock> = clock.clone();
  let store = MetadataStore::open_with_clock(&factory, Duration::from_secs(10), wall_clock)
    .await
    .unwrap();
  let unknown = match phase {
    FaultedReceiptOperation::Add => match store
      .add_receipt_reference(&target, &token, contract_transaction_id(94))
      .await
      .unwrap()
    {
      ReceiptReferenceOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected add outcome: {outcome:?}"),
    },
    FaultedReceiptOperation::Remove => match store
      .remove_receipt_reference(&target, &token, contract_transaction_id(95))
      .await
      .unwrap()
    {
      ReceiptReferenceOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected remove outcome: {outcome:?}"),
    },
    FaultedReceiptOperation::Anchor | FaultedReceiptOperation::Forget => match store
      .cleanup_receipt(&target, contract_transaction_id(96))
      .await
      .unwrap()
    {
      ReceiptCleanupOutcome::Unknown(identity) => identity,
      outcome => panic!("unexpected cleanup outcome: {outcome:?}"),
    },
  };
  assert_eq!(
    unknown.transaction(),
    &contract_transaction_id(match phase {
      FaultedReceiptOperation::Add => 94,
      FaultedReceiptOperation::Remove => 95,
      FaultedReceiptOperation::Anchor | FaultedReceiptOperation::Forget => 96,
    })
  );
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
  let recovered_transaction = unknown.transaction().clone();
  let recovered_digest = unknown.operation_digest().clone();
  drop(store);
  let wall_clock: Arc<dyn WallClock> = clock;
  let store = MetadataStore::open_recovered_with_clock(
    &factory,
    Duration::from_secs(10),
    recovered_transaction,
    recovered_digest,
    wall_clock,
  )
  .await
  .unwrap();
  assert_eq!(
    store
      .cleanup_receipt(&unrelated, contract_transaction_id(97))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::NotReady
  );
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
  let reconciled = store.reconcile().await.unwrap();
  match mode {
    UnknownFaultMode::Applied => assert!(matches!(reconciled, ReconcileOutcome::Committed(_))),
    UnknownFaultMode::NotApplied => assert!(matches!(reconciled, ReconcileOutcome::Aborted)),
    UnknownFaultMode::PendingApplied | UnknownFaultMode::PendingNotApplied => {
      unreachable!("pending modes are tested through cancellation")
    }
  }
  assert_eq!(
    reference
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction()),
    !matches!(
      (mode, phase),
      (UnknownFaultMode::Applied, FaultedReceiptOperation::Forget)
    )
  );
}

#[tokio::test]
async fn storage_contract_recovered_open_resolves_applied_and_not_applied_unknown() {
  for (mode, applied) in [
    (UnknownFaultMode::Applied, true),
    (UnknownFaultMode::NotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let fault_calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    let prepared = prepare_contract_put(&store, 110, 0).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    assert_eq!(
      store.commit(prepared).await.unwrap(),
      CommitOutcome::Unknown {
        transaction: transaction.clone(),
        operation_digest: digest.clone(),
      }
    );
    let original_receipt = reference
      .state
      .lock()
      .unwrap()
      .receipts
      .get(&transaction)
      .cloned();
    assert_eq!(original_receipt.is_some(), applied);
    drop(store);

    let store =
      MetadataStore::open_recovered(&factory, Duration::from_secs(10), transaction, digest)
        .await
        .unwrap();
    let unrelated = prepare_contract_put(&store, 111, 1).await;
    assert_eq!(
      store.commit(unrelated.clone()).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);

    let reconciled = store.reconcile().await.unwrap();
    if let Some(receipt) = original_receipt {
      assert_eq!(reconciled, ReconcileOutcome::Committed(receipt));
    } else {
      assert!(matches!(reconciled, ReconcileOutcome::Aborted));
    }
    assert!(matches!(
      store.commit(unrelated).await.unwrap(),
      CommitOutcome::Unknown { .. }
    ));
    assert_eq!(fault_calls.load(Ordering::SeqCst), 2);

    drop(store);
    assert!(
      MetadataStore::open(&factory, Duration::from_secs(10))
        .await
        .is_ok()
    );
  }
}

#[tokio::test]
async fn storage_contract_recovered_open_keeps_wrong_digest_frozen() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference,
    mode: UnknownFaultMode::Applied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let store = MetadataStore::open(&factory, Duration::from_secs(10))
    .await
    .unwrap();
  let prepared = prepare_contract_put(&store, 112, 0).await;
  let transaction = prepared.id().clone();
  assert!(matches!(
    store.commit(prepared).await.unwrap(),
    CommitOutcome::Unknown { .. }
  ));
  drop(store);

  let wrong_digest = Digest::from_bytes([23; 32]);
  let store =
    MetadataStore::open_recovered(&factory, Duration::from_secs(10), transaction, wrong_digest)
      .await
      .unwrap();
  let unrelated = prepare_contract_put(&store, 113, 1).await;
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn storage_contract_recovered_open_reconciles_cancelled_provider_submission() {
  for (mode, applied) in [
    (UnknownFaultMode::PendingApplied, true),
    (UnknownFaultMode::PendingNotApplied, false),
  ] {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let fault_calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference: Arc::clone(&reference),
      mode,
      commit_calls: Arc::clone(&fault_calls),
    });
    let store = Arc::new(
      MetadataStore::open(&factory, Duration::from_secs(10))
        .await
        .unwrap(),
    );
    let prepared = prepare_contract_put(&store, 114, 0).await;
    let transaction = prepared.id().clone();
    let digest = prepared.operation_digest().clone();
    let task_store = Arc::clone(&store);
    let task = tokio::spawn(async move { task_store.commit(prepared).await });
    while fault_calls.load(Ordering::SeqCst) == 0
      || (applied
        && !reference
          .state
          .lock()
          .unwrap()
          .receipts
          .contains_key(&transaction))
    {
      tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let original_receipt = reference
      .state
      .lock()
      .unwrap()
      .receipts
      .get(&transaction)
      .cloned();
    assert_eq!(original_receipt.is_some(), applied);
    drop(store);

    let store = Arc::new(
      MetadataStore::open_recovered(&factory, Duration::from_secs(10), transaction, digest)
        .await
        .unwrap(),
    );
    let unrelated = prepare_contract_put(&store, 115, 1).await;
    assert_eq!(
      store.commit(unrelated.clone()).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    assert_eq!(fault_calls.load(Ordering::SeqCst), 1);
    let reconciled = store.reconcile().await.unwrap();
    if let Some(receipt) = original_receipt {
      assert_eq!(reconciled, ReconcileOutcome::Committed(receipt));
    } else {
      assert!(matches!(reconciled, ReconcileOutcome::Aborted));
    }
    let task_store = Arc::clone(&store);
    let task = tokio::spawn(async move { task_store.commit(unrelated).await });
    while fault_calls.load(Ordering::SeqCst) < 2 {
      tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(fault_calls.load(Ordering::SeqCst), 2);
  }
}

#[tokio::test]
async fn storage_contract_cancelled_receipt_mutations_stay_frozen_until_exact_reconciliation() {
  for phase in [
    FaultedReceiptOperation::Add,
    FaultedReceiptOperation::Remove,
    FaultedReceiptOperation::Anchor,
    FaultedReceiptOperation::Forget,
  ] {
    exercise_cancelled_receipt_operation(phase).await;
  }
}

async fn exercise_cancelled_receipt_operation(phase: FaultedReceiptOperation) {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(600)));
  let seed = open_engine(&reference, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&seed, 100).await;
  let (_, unrelated) = commit_target(&seed, 101).await;
  let token = ReceiptReferenceToken::from_digest(Digest::from_bytes([14; 32]));
  if matches!(phase, FaultedReceiptOperation::Remove) {
    assert!(matches!(
      seed
        .add_receipt_reference(&target, &token, contract_transaction_id(102))
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  if matches!(phase, FaultedReceiptOperation::Forget) {
    assert!(matches!(
      seed
        .cleanup_receipt(&target, contract_transaction_id(103))
        .await
        .unwrap(),
      ReceiptCleanupOutcome::Anchored(_)
    ));
    clock.set(UNIX_EPOCH + Duration::from_secs(610));
  }
  drop(seed);

  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::PendingNotApplied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let wall_clock: Arc<dyn WallClock> = clock;
  let store = Arc::new(
    MetadataStore::open_with_clock(&factory, Duration::from_secs(10), wall_clock)
      .await
      .unwrap(),
  );
  let task_store = Arc::clone(&store);
  let task_target = target.clone();
  let task_token = token.clone();
  let task = tokio::spawn(async move {
    match phase {
      FaultedReceiptOperation::Add => task_store
        .add_receipt_reference(&task_target, &task_token, contract_transaction_id(104))
        .await
        .map(|_| ()),
      FaultedReceiptOperation::Remove => task_store
        .remove_receipt_reference(&task_target, &task_token, contract_transaction_id(105))
        .await
        .map(|_| ()),
      FaultedReceiptOperation::Anchor | FaultedReceiptOperation::Forget => task_store
        .cleanup_receipt(&task_target, contract_transaction_id(106))
        .await
        .map(|_| ()),
    }
  });
  while fault_calls.load(Ordering::SeqCst) == 0 {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  assert_eq!(
    store
      .cleanup_receipt(&unrelated, contract_transaction_id(107))
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::NotReady
  );
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Aborted
  ));
  assert!(
    reference
      .state
      .lock()
      .unwrap()
      .receipts
      .contains_key(target.transaction())
  );
}

#[tokio::test]
async fn storage_contract_reference_provider_covers_raw_storage_semantics() {
  run_storage_contract(|| Arc::new(ReferenceFactory::new(required_capabilities()))).await;
}

#[tokio::test]
async fn storage_contract_reference_provider_holds_exclusive_lock_for_storage_lifetime() {
  let factory = ReferenceFactory::new(required_capabilities());
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();

  let unsupported = factory
    .open(StoreRequirements::metadata().transactional_migration(true))
    .await
    .unwrap_err();
  assert_eq!(unsupported.kind(), crate::ErrorKind::UnsupportedCapability);
  let locked = factory
    .open(StoreRequirements::metadata())
    .await
    .unwrap_err();
  assert_eq!(locked.kind(), crate::ErrorKind::StorageLocked);

  drop(storage);
  assert!(factory.open(StoreRequirements::metadata()).await.is_ok());
}
