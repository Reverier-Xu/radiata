use std::{
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, UNIX_EPOCH},
};

use super::{helpers::*, reference::*};
use crate::{
  CommitOutcome, CommitReceipt, Digest, NodeId, ReconcileOutcome, StoreExpectation, StoreOperation,
  StoreValue,
  identity::records::identity_binding_key,
  provider::StorageFactory,
  storage::{
    MetadataStore,
    pending::{pending_key, pending_namespace},
    receipt::{
      ACTIVE_MARKER_VALUE, PreparedTransaction, ReceiptCleanupOutcome, ReceiptIdentity,
      ReceiptReferenceChange, ReceiptReferenceOutcome, ReceiptReferenceToken, WallClock,
      eligibility_anchor_key, internal_namespace, reference_edge_key, reference_head_key,
      used_id_key,
    },
  },
};

#[test]
fn identity_records_record_reference_tokens_are_domain_separated_and_exact() {
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let owner = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
  let pointer = ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key);

  let golden: [u8; 32] = [
    0xB8, 0x54, 0xE9, 0x81, 0x2A, 0x42, 0x7A, 0xE1, 0x2E, 0x59, 0xDF, 0x34, 0x8D, 0x1A, 0xF1, 0xC3,
    0x2C, 0xF4, 0xE9, 0x48, 0xE1, 0x8F, 0x75, 0x98, 0x55, 0x0E, 0xA7, 0x34, 0xA4, 0x66, 0x0D, 0x4A,
  ];
  assert_eq!(
    owner,
    ReceiptReferenceToken::from_digest(Digest::from_bytes(golden))
  );
  assert_eq!(
    ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
    owner
  );
  assert_ne!(owner, pointer);
  let (other_namespace, other_key) =
    identity_binding_key(&NodeId::parse("node-200000000000000000000").unwrap()).unwrap();
  assert_eq!(other_namespace, owner_namespace);
  assert_ne!(
    owner,
    ReceiptReferenceToken::for_record(&owner_namespace, &other_key)
  );
}

#[tokio::test]
async fn identity_records_owner_put_and_self_references_commit_atomically() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(700)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let tokens = [
    ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
    ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
  ];

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(300),
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![ReceiptReferenceChange::AddSelf(tokens.to_vec())],
    )
    .await
    .unwrap();
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);

  let head_key = reference_head_key(prepared.id()).unwrap();
  let operations = prepared.operations();
  assert_eq!(operations.len(), 1 + 1 + 2 + 1);
  let head_operations: Vec<_> = operations
    .iter()
    .filter(|operation| matches!(operation, StoreOperation::Put { key, .. } if key == &head_key))
    .collect();
  assert_eq!(head_operations.len(), 1);
  assert!(
    matches!(head_operations[0], StoreOperation::Put { expected: StoreExpectation::Absent, value, .. } if value.as_bytes() == 2_u64.to_be_bytes().as_slice())
  );
  for token in &tokens {
    let edge_key = reference_edge_key(prepared.id(), token).unwrap();
    assert!(operations.iter().any(|operation| {
      matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &edge_key && value.as_bytes().is_empty())
    }));
  }
  let marker_key = used_id_key(prepared.id()).unwrap();
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &marker_key && value.as_bytes() == ACTIVE_MARKER_VALUE)
  }));

  let receipt = committed(store.commit(prepared.clone()).await.unwrap());
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );

  let internal = internal_namespace().unwrap();
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"binding"
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
  for token in &tokens {
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
      .get(&internal, &marker_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    ACTIVE_MARKER_VALUE
  );
  drop(snapshot);

  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  assert!(matches!(
    store
      .cleanup_receipt(
        &ReceiptIdentity::from_receipt(&receipt),
        contract_transaction_id(301),
      )
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Referenced
  ));
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
}

#[tokio::test]
async fn identity_records_finalization_moves_references_between_receipts_atomically() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(720)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, old_target) = commit_target(&store, 310).await;
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let old_token = ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key);
  assert!(matches!(
    store
      .add_receipt_reference(&old_target, &old_token, contract_transaction_id(311))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));
  let (owner_namespace, owner_key) = owner_record_key();
  let new_token = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(312),
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![
        ReceiptReferenceChange::Remove {
          target: old_target.clone(),
          tokens: vec![old_token.clone()],
        },
        ReceiptReferenceChange::AddSelf(vec![new_token.clone()]),
      ],
    )
    .await
    .unwrap();
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);

  let old_head = reference_head_key(old_target.transaction()).unwrap();
  let old_edge = reference_edge_key(old_target.transaction(), &old_token).unwrap();
  let old_anchor = eligibility_anchor_key(old_target.transaction()).unwrap();
  let self_head = reference_head_key(prepared.id()).unwrap();
  let operations = prepared.operations();
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Delete { key, .. } if key == &old_head)
  }));
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Delete { key, .. } if key == &old_edge)
  }));
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &self_head && value.as_bytes() == 1_u64.to_be_bytes().as_slice())
  }));
  assert!(!operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, .. } | StoreOperation::Delete { key, .. } if key == &old_anchor)
  }));

  let receipt = committed(store.commit(prepared).await.unwrap());
  assert_eq!(
    factory.commit_calls.load(Ordering::SeqCst),
    commits_before + 1
  );

  let internal = internal_namespace().unwrap();
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"binding"
  );
  assert!(snapshot.get(&internal, &old_head).await.unwrap().is_none());
  assert!(snapshot.get(&internal, &old_edge).await.unwrap().is_none());
  assert_eq!(
    snapshot
      .get(&internal, &self_head)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    1_u64.to_be_bytes().as_slice()
  );
  assert!(
    snapshot
      .get(
        &internal,
        &reference_edge_key(receipt.transaction(), &new_token).unwrap(),
      )
      .await
      .unwrap()
      .is_some()
  );
  assert_eq!(
    snapshot
      .get(&internal, &used_id_key(old_target.transaction()).unwrap())
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    ACTIVE_MARKER_VALUE
  );
  drop(snapshot);

  assert!(matches!(
    store
      .cleanup_receipt(&old_target, contract_transaction_id(313))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
}

#[tokio::test]
async fn identity_records_existing_target_add_uses_exact_expectations_and_removes_anchor() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(740)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 320).await;
  let (owner_namespace, owner_key) = owner_record_key();
  let first = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let second = ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key);

  assert!(matches!(
    store
      .cleanup_receipt(&target, contract_transaction_id(321))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  let internal = internal_namespace().unwrap();
  let anchor_key = eligibility_anchor_key(target.transaction()).unwrap();
  let snapshot = store.snapshot().await.unwrap();
  let anchor_digest = snapshot
    .get(&internal, &anchor_key)
    .await
    .unwrap()
    .unwrap()
    .digest()
    .clone();
  drop(snapshot);

  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(322),
      vec![],
      vec![ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![first.clone()],
      }],
    )
    .await
    .unwrap();
  drop(snapshot);
  let head_key = reference_head_key(target.transaction()).unwrap();
  let operations = prepared.operations();
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Absent, value, .. } if key == &head_key && value.as_bytes() == 1_u64.to_be_bytes().as_slice())
  }));
  assert!(operations.iter().any(|operation| {
    matches!(operation, StoreOperation::Delete { key, expected, .. } if key == &anchor_key && expected == &anchor_digest)
  }));
  committed(store.commit(prepared).await.unwrap());

  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&internal, &anchor_key)
      .await
      .unwrap()
      .is_none()
  );
  let head = snapshot.get(&internal, &head_key).await.unwrap().unwrap();
  assert_eq!(head.as_bytes(), 1_u64.to_be_bytes().as_slice());
  let head_digest = head.digest().clone();
  drop(snapshot);

  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(323),
      vec![],
      vec![ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![second.clone()],
      }],
    )
    .await
    .unwrap();
  drop(snapshot);
  assert!(prepared.operations().iter().any(|operation| {
    matches!(operation, StoreOperation::Put { key, expected: StoreExpectation::Exact(expected), value, .. } if key == &head_key && expected == &head_digest && value.as_bytes() == 2_u64.to_be_bytes().as_slice())
  }));
  committed(store.commit(prepared).await.unwrap());

  let stale_snapshot = store.snapshot().await.unwrap();
  let (..) = commit_target(&store, 324).await;
  let stale = store
    .prepare_transaction_with_receipt_changes(
      stale_snapshot.as_ref(),
      contract_transaction_id(325),
      vec![],
      vec![ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![ReceiptReferenceToken::from_digest(Digest::from_bytes(
          [30; 32],
        ))],
      }],
    )
    .await
    .unwrap();
  drop(stale_snapshot);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  assert!(matches!(
    store.commit(stale).await.unwrap(),
    CommitOutcome::Conflict
  ));
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
}

#[tokio::test]
async fn identity_records_receipt_change_requests_are_rejected_before_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(760)));
  let store = open_engine(&factory, Duration::from_secs(10), clock).await;
  let (_, target) = commit_target(&store, 330).await;
  let token_a = ReceiptReferenceToken::from_digest(Digest::from_bytes([31; 32]));
  let token_b = ReceiptReferenceToken::from_digest(Digest::from_bytes([32; 32]));
  let self_identity = ReceiptIdentity::from_receipt(&CommitReceipt::new(
    contract_transaction_id(332),
    Digest::from_bytes([0; 32]),
    reference_revision(1),
  ));
  let cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::AddSelf(vec![
      token_a.clone(),
      token_a.clone(),
    ])],
    vec![
      ReceiptReferenceChange::AddSelf(vec![token_a.clone()]),
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_a.clone()],
      },
    ],
    vec![
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_a.clone()],
      },
      ReceiptReferenceChange::Remove {
        target: target.clone(),
        tokens: vec![token_b.clone()],
      },
    ],
    vec![
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_a.clone()],
      },
      ReceiptReferenceChange::Add {
        target: target.clone(),
        tokens: vec![token_b.clone()],
      },
    ],
    vec![ReceiptReferenceChange::AddSelf(vec![])],
    vec![
      ReceiptReferenceChange::AddSelf(vec![token_a.clone()]),
      ReceiptReferenceChange::AddSelf(vec![token_b.clone()]),
    ],
    vec![ReceiptReferenceChange::Remove {
      target: self_identity,
      tokens: vec![token_a.clone()],
    }],
  ];

  let snapshot = store.snapshot().await.unwrap();
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  for (index, changes) in cases.into_iter().enumerate() {
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(332),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput, "case {index}");
  }
  for operation in [
    StoreOperation::Put {
      namespace: internal_namespace().unwrap(),
      key: store_key(b"injected"),
      expected: StoreExpectation::Absent,
      value: value(b"injected"),
    },
    StoreOperation::ForgetReceipt {
      transaction: target.transaction().clone(),
      expected_operation_digest: target.operation_digest().clone(),
    },
  ] {
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(333),
        vec![operation],
        vec![],
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  }
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);
}

#[tokio::test]
async fn identity_records_receipt_change_snapshot_mismatches_fail_before_mutation() {
  let factory = Arc::new(ReferenceFactory::new(required_capabilities()));
  let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(780)));
  let store = open_engine(&factory, Duration::from_secs(10), Arc::clone(&clock)).await;
  let (_, target) = commit_target(&store, 340).await;
  let (_, forgotten) = commit_target(&store, 341).await;
  assert!(matches!(
    store
      .cleanup_receipt(&forgotten, contract_transaction_id(342))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Anchored(_)
  ));
  clock.set(UNIX_EPOCH + Duration::from_secs(790));
  assert!(matches!(
    store
      .cleanup_receipt(&forgotten, contract_transaction_id(343))
      .await
      .unwrap(),
    ReceiptCleanupOutcome::Forgotten(_)
  ));
  let present = ReceiptReferenceToken::from_digest(Digest::from_bytes([33; 32]));
  assert!(matches!(
    store
      .add_receipt_reference(&target, &present, contract_transaction_id(344))
      .await
      .unwrap(),
    ReceiptReferenceOutcome::Applied(_)
  ));

  let missing = ReceiptReferenceToken::from_digest(Digest::from_bytes([34; 32]));
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let entries_before = factory.state.lock().unwrap().entries.clone();
  let conflict_cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::Remove {
      target: target.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Add {
      target: target.clone(),
      tokens: vec![present.clone()],
    }],
    vec![ReceiptReferenceChange::Add {
      target: forgotten.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Remove {
      target: forgotten.clone(),
      tokens: vec![present.clone()],
    }],
  ];
  for (index, changes) in conflict_cases.into_iter().enumerate() {
    let snapshot = store.snapshot().await.unwrap();
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(345),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Conflict, "case {index}");
  }
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, entries_before);

  let (_, orphan) = commit_target(&store, 346).await;
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let orphan_token = ReceiptReferenceToken::from_digest(Digest::from_bytes([35; 32]));
  factory.state.lock().unwrap().entries.insert(
    (
      internal_namespace().unwrap(),
      reference_edge_key(orphan.transaction(), &orphan_token).unwrap(),
    ),
    StoreValue::new(Arc::from([])),
  );
  let orphan_state = factory.state.lock().unwrap().entries.clone();
  let orphan_cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::Add {
      target: orphan.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Remove {
      target: orphan.clone(),
      tokens: vec![orphan_token.clone()],
    }],
  ];
  for (index, changes) in orphan_cases.into_iter().enumerate() {
    let snapshot = store.snapshot().await.unwrap();
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(347),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(
      error.kind(),
      crate::ErrorKind::StorageCorrupt,
      "case {index}"
    );
  }
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, orphan_state);

  let (_, undercount) = commit_target(&store, 348).await;
  let undercount_tokens = [
    ReceiptReferenceToken::from_digest(Digest::from_bytes([36; 32])),
    ReceiptReferenceToken::from_digest(Digest::from_bytes([37; 32])),
  ];
  for (offset, token) in undercount_tokens.iter().enumerate() {
    assert!(matches!(
      store
        .add_receipt_reference(
          &undercount,
          token,
          contract_transaction_id(349 + u16::try_from(offset).unwrap()),
        )
        .await
        .unwrap(),
      ReceiptReferenceOutcome::Applied(_)
    ));
  }
  let commits_before = factory.commit_calls.load(Ordering::SeqCst);
  let undercount_head = reference_head_key(undercount.transaction()).unwrap();
  factory.state.lock().unwrap().entries.insert(
    (internal_namespace().unwrap(), undercount_head.clone()),
    StoreValue::new(Arc::from(1_u64.to_be_bytes())),
  );
  let undercount_state = factory.state.lock().unwrap().entries.clone();
  let undercount_cases: Vec<Vec<ReceiptReferenceChange>> = vec![
    vec![ReceiptReferenceChange::Add {
      target: undercount.clone(),
      tokens: vec![missing.clone()],
    }],
    vec![ReceiptReferenceChange::Remove {
      target: undercount.clone(),
      tokens: vec![undercount_tokens[0].clone()],
    }],
  ];
  for (index, changes) in undercount_cases.into_iter().enumerate() {
    let snapshot = store.snapshot().await.unwrap();
    let error = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(351),
        vec![],
        changes,
      )
      .await
      .unwrap_err();
    assert_eq!(
      error.kind(),
      crate::ErrorKind::StorageCorrupt,
      "case {index}"
    );
  }
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, undercount_state);
  factory.state.lock().unwrap().entries.insert(
    (internal_namespace().unwrap(), undercount_head),
    StoreValue::new(Arc::from(u64::MAX.to_be_bytes())),
  );
  let overflow_state = factory.state.lock().unwrap().entries.clone();
  let snapshot = store.snapshot().await.unwrap();
  assert_eq!(
    store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(352),
        vec![],
        vec![ReceiptReferenceChange::Add {
          target: undercount.clone(),
          tokens: vec![missing.clone()],
        }],
      )
      .await
      .unwrap_err()
      .kind(),
    crate::ErrorKind::StorageCorrupt
  );
  drop(snapshot);
  assert_eq!(factory.commit_calls.load(Ordering::SeqCst), commits_before);
  assert_eq!(factory.state.lock().unwrap().entries, overflow_state);
}

#[tokio::test]
async fn identity_records_combined_commit_unknown_freezes_and_reconciles_exactly() {
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
    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(800)));
    let store = MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
      .await
      .unwrap();
    let (owner_namespace, owner_key) = owner_record_key();
    let token = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
    let snapshot = store.snapshot().await.unwrap();
    let prepared = store
      .prepare_transaction_with_receipt_changes(
        snapshot.as_ref(),
        contract_transaction_id(360),
        vec![StoreOperation::Put {
          namespace: owner_namespace.clone(),
          key: owner_key.clone(),
          expected: StoreExpectation::Absent,
          value: value(b"binding"),
        }],
        vec![ReceiptReferenceChange::AddSelf(vec![token.clone()])],
      )
      .await
      .unwrap();
    drop(snapshot);
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
    let unrelated = prepare_contract_put(&store, 361, 1).await;
    assert_eq!(
      store.commit(unrelated).await.unwrap_err().kind(),
      crate::ErrorKind::NotReady
    );
    drop(store);

    let clock: Arc<dyn WallClock> =
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(800)));
    let store = MetadataStore::open_recovered_with_clock(
      &factory,
      Duration::from_secs(10),
      transaction.clone(),
      digest,
      clock,
    )
    .await
    .unwrap();
    let reconciled = store.reconcile().await.unwrap();
    let internal = internal_namespace().unwrap();
    let snapshot = store.snapshot().await.unwrap();
    let edge_key = reference_edge_key(&transaction, &token).unwrap();
    if applied {
      assert!(matches!(reconciled, ReconcileOutcome::Committed(_)));
      assert_eq!(
        snapshot
          .get(&owner_namespace, &owner_key)
          .await
          .unwrap()
          .unwrap()
          .as_bytes(),
        b"binding"
      );
      assert!(snapshot.get(&internal, &edge_key).await.unwrap().is_some());
    } else {
      assert!(matches!(reconciled, ReconcileOutcome::Aborted));
      assert!(
        snapshot
          .get(&owner_namespace, &owner_key)
          .await
          .unwrap()
          .is_none()
      );
      assert!(snapshot.get(&internal, &edge_key).await.unwrap().is_none());
    }
  }
}

#[tokio::test]
async fn identity_records_cancelled_combined_commit_stays_frozen_until_exact_reconciliation() {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let fault_calls = Arc::new(AtomicUsize::new(0));
  let factory: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
    reference: Arc::clone(&reference),
    mode: UnknownFaultMode::PendingNotApplied,
    commit_calls: Arc::clone(&fault_calls),
  });
  let clock: Arc<dyn WallClock> = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(820)));
  let store = Arc::new(
    MetadataStore::open_with_clock(&factory, Duration::from_secs(10), clock)
      .await
      .unwrap(),
  );
  let (owner_namespace, owner_key) = owner_record_key();
  let token = ReceiptReferenceToken::for_record(&owner_namespace, &owner_key);
  let snapshot = store.snapshot().await.unwrap();
  let prepared = store
    .prepare_transaction_with_receipt_changes(
      snapshot.as_ref(),
      contract_transaction_id(370),
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![ReceiptReferenceChange::AddSelf(vec![token.clone()])],
    )
    .await
    .unwrap();
  drop(snapshot);
  let transaction = prepared.id().clone();
  let task_store = Arc::clone(&store);
  let task = tokio::spawn(async move { task_store.commit(prepared).await });
  while fault_calls.load(Ordering::SeqCst) == 0 {
    tokio::task::yield_now().await;
  }
  task.abort();
  assert!(task.await.unwrap_err().is_cancelled());
  assert_eq!(fault_calls.load(Ordering::SeqCst), 1);

  let unrelated = prepare_contract_put(&store, 371, 2).await;
  assert_eq!(
    store.commit(unrelated).await.unwrap_err().kind(),
    crate::ErrorKind::NotReady
  );
  assert!(matches!(
    store.reconcile().await.unwrap(),
    ReconcileOutcome::Aborted
  ));
  let internal = internal_namespace().unwrap();
  let snapshot = store.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&owner_namespace, &owner_key)
      .await
      .unwrap()
      .is_none()
  );
  assert!(
    snapshot
      .get(
        &internal,
        &reference_edge_key(&transaction, &token).unwrap()
      )
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
}

pub(crate) const JOURNAL_PURPOSE: &str = "local-identity";

pub(crate) fn journaled_tokens() -> (
  ReceiptReferenceToken,
  ReceiptReferenceToken,
  ReceiptReferenceToken,
) {
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  (
    ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
    ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
    ReceiptReferenceToken::for_record(&pending_namespace().unwrap(), &pending_key(JOURNAL_PURPOSE)),
  )
}

pub(crate) async fn prepare_journaled_owner_put(
  store: &MetadataStore, transaction: u16,
) -> PreparedTransaction {
  let (owner_namespace, owner_key) = owner_record_key();
  let (pointer_namespace, pointer_key) = pointer_record_key();
  let snapshot = store.snapshot().await.unwrap();
  store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      contract_transaction_id(transaction),
      JOURNAL_PURPOSE,
      vec![StoreOperation::Put {
        namespace: owner_namespace.clone(),
        key: owner_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"binding"),
      }],
      vec![ReceiptReferenceChange::AddSelf(vec![
        ReceiptReferenceToken::for_record(&owner_namespace, &owner_key),
        ReceiptReferenceToken::for_record(&pointer_namespace, &pointer_key),
      ])],
    )
    .await
    .unwrap()
}

pub(crate) async fn open_pending(
  factory: &Arc<dyn StorageFactory>, seconds: u64,
) -> (MetadataStore, Option<ReceiptIdentity>) {
  let clock: Arc<dyn WallClock> =
    Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(seconds)));
  MetadataStore::open_pending_recovered_with_clock(
    factory,
    Duration::from_secs(10),
    JOURNAL_PURPOSE,
    clock,
  )
  .await
  .unwrap()
}

pub(crate) async fn prepare_plain_put(
  store: &MetadataStore, transaction: u16, key: u8,
) -> PreparedTransaction {
  let snapshot = store.snapshot().await.unwrap();
  store
    .prepare_transaction(
      contract_transaction_id(transaction),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace("journaled-unrelated"),
        key: store_key(&[key]),
        expected: StoreExpectation::Absent,
        value: value(&[key]),
      }],
    )
    .unwrap()
}
