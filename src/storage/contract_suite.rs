//! The storage contract suite: the reference oracle a metadata backend
//! author runs their own backend through.
//!
//! The suite drives one [`StorageFactory`] through the backend-neutral
//! provider contract documented on [`Storage`](crate::provider::Storage):
//! provider-owned immutable snapshots, exact lookup, unsigned-byte
//! ordered scan streams (plain and positioned), receipt replay,
//! base-revision and per-key conditional commits, cross-family
//! atomicity, idempotent replays, and reconciliation verdicts — over
//! every family of the metadata catalog. The suite asserts each clause,
//! so a violation fails the caller's own test harness; it is opt-in by
//! construction: nothing in the crate runs it outside the crate's own
//! contract lanes, and a backend author invokes
//! [`run_storage_contract`] from their own tests.
//!
//! The failure style is deliberately the test tool's: the suite
//! `assert!`s and `panic!`s with the violated clause, so a failing run
//! surfaces in the author's test output with the exact divergence. That
//! style is why the unwrapped reads below are allowed in this one
//! module — they are the assertions, not silent invariants.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crate::{
  CommitOutcome, Digest, QualifiedTag, ReconcileOutcome, StoreExpectation, StoreKey,
  StoreNamespace, StoreOperation, StoreRequirements, StoreRevision, StoreTransaction, StoreValue,
  TransactionId,
  provider::{StorageFactory, StoreScan},
  storage::families::metadata_families,
};

/// The full contract suite, five lanes in dependency order: snapshot
/// semantics, conditional-commit semantics, positioned scans, the
/// all-family roundtrip, and cross-family atomicity. `fresh` builds one
/// factory per lane, so each lane starts from an empty store exactly as
/// a backend author's own per-test construction would.
pub async fn run_storage_contract<F>(fresh: F)
where
  F: Fn() -> Arc<dyn StorageFactory>, {
  storage_contract_snapshot_lookup_and_ordering(fresh()).await;
  storage_contract_conflicts_atomicity_and_idempotence(fresh()).await;
  storage_contract_positioned_scans(fresh()).await;
  storage_contract_all_family_roundtrip(fresh()).await;
  storage_contract_cross_family_atomicity(fresh()).await;
}

// ---- shared fixtures -------------------------------------------------

fn namespace(name: &str) -> StoreNamespace {
  StoreNamespace::new(QualifiedTag::parse(&format!("radiata.woooo.tech/metadata/{name}")).unwrap())
}

fn store_key(bytes: &[u8]) -> StoreKey {
  StoreKey::new(Arc::from(bytes))
}

fn value(bytes: &[u8]) -> StoreValue {
  StoreValue::new(Arc::from(bytes))
}

fn transaction_id(index: u64) -> TransactionId {
  TransactionId::parse(&format!("txn-{index:021}")).unwrap()
}

fn transaction(
  index: u64, base_revision: StoreRevision, operations: Vec<StoreOperation>,
) -> Result<StoreTransaction, crate::Error> {
  StoreTransaction::new(transaction_id(index), base_revision, operations)
}

async fn collect_scan(mut scan: Box<dyn StoreScan + '_>) -> Vec<crate::StoreEntry> {
  let mut entries = Vec::new();
  while let Some(entry) = scan.next().await.unwrap() {
    entries.push(entry);
  }
  assert!(scan.next().await.unwrap().is_none());
  entries
}

// ---- lane 1: snapshots, lookup, ordering -----------------------------

async fn storage_contract_snapshot_lookup_and_ordering(factory: Arc<dyn StorageFactory>) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let old = storage.snapshot().await.unwrap();
  assert!(!old.revision().as_bytes().is_empty());
  let old_revision = old.revision().clone();
  let target_namespace = namespace("one");
  let other_namespace = namespace("two");
  let keys = [
    vec![],
    vec![0x00],
    vec![0x7F],
    vec![0x80],
    vec![0xFF],
    vec![0xFF, 0x00],
    vec![0xFF, 0xFF],
  ];
  let operations = keys
    .iter()
    .enumerate()
    .map(|(index, key)| StoreOperation::Put {
      namespace: target_namespace.clone(),
      key: store_key(key),
      expected: StoreExpectation::Absent,
      value: value(&[index as u8]),
    })
    .chain([StoreOperation::Put {
      namespace: other_namespace.clone(),
      key: store_key(&[0x00]),
      expected: StoreExpectation::Absent,
      value: value(b"other"),
    }])
    .collect();
  let initial_transaction = transaction(0, old_revision.clone(), operations).unwrap();
  assert!(matches!(
    storage.commit(initial_transaction).await.unwrap(),
    CommitOutcome::Committed(_)
  ));

  assert_eq!(old.revision(), &old_revision);
  assert!(
    old
      .get(&target_namespace, &store_key(&[]))
      .await
      .unwrap()
      .is_none()
  );
  let current = storage.snapshot().await.unwrap();
  assert!(!current.revision().as_bytes().is_empty());
  assert_ne!(current.revision(), &old_revision);
  assert_eq!(
    current
      .get(&target_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    &[3],
  );
  assert!(
    current
      .get(&other_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .is_none()
  );

  let all = collect_scan(current.scan(&target_namespace, &[]).await.unwrap()).await;
  assert_eq!(
    all
      .iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect::<Vec<_>>(),
    keys,
  );
  assert!(
    all
      .iter()
      .all(|entry| entry.namespace() == &target_namespace)
  );
  let ff = collect_scan(current.scan(&target_namespace, &[0xFF]).await.unwrap()).await;
  assert_eq!(
    ff.iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect::<Vec<_>>(),
    vec![vec![0xFF], vec![0xFF, 0x00], vec![0xFF, 0xFF]],
  );
  let mut empty = current
    .scan(&target_namespace, &[0x01, 0x02])
    .await
    .unwrap();
  assert!(empty.next().await.unwrap().is_none());
  assert!(empty.next().await.unwrap().is_none());
  drop(empty);

  let overwrite_and_delete = transaction(
    1,
    current.revision().clone(),
    vec![
      StoreOperation::Put {
        namespace: target_namespace.clone(),
        key: store_key(&[0x80]),
        expected: StoreExpectation::Exact(value(&[3]).digest().clone()),
        value: value(b"overwritten"),
      },
      StoreOperation::Delete {
        namespace: target_namespace.clone(),
        key: store_key(&[0x7F]),
        expected: value(&[2]).digest().clone(),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(overwrite_and_delete).await.unwrap(),
    CommitOutcome::Committed(_)
  ));
  assert_eq!(
    current
      .get(&target_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    &[3],
  );
  assert_eq!(
    current
      .get(&target_namespace, &store_key(&[0x7F]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    &[2],
  );
  let retained = collect_scan(current.scan(&target_namespace, &[]).await.unwrap()).await;
  assert_eq!(
    retained
      .iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect::<Vec<_>>(),
    keys,
  );
  let latest = storage.snapshot().await.unwrap();
  assert_eq!(
    latest
      .get(&target_namespace, &store_key(&[0x80]))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"overwritten",
  );
  assert!(
    latest
      .get(&target_namespace, &store_key(&[0x7F]))
      .await
      .unwrap()
      .is_none()
  );
}

// ---- lane 2: conflicts, atomicity, idempotence -----------------------

async fn storage_contract_conflicts_atomicity_and_idempotence(factory: Arc<dyn StorageFactory>) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let initial = storage.snapshot().await.unwrap();
  let first_namespace = namespace("first");
  let second_namespace = namespace("second");
  let first_key = store_key(b"key");
  let second_key = store_key(b"key");
  let original = transaction(
    10,
    initial.revision().clone(),
    vec![StoreOperation::Put {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"first"),
    }],
  )
  .unwrap();
  let original_receipt = match storage.commit(original.clone()).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };

  let stale = transaction(
    11,
    initial.revision().clone(),
    vec![StoreOperation::Put {
      namespace: second_namespace.clone(),
      key: second_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"stale"),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(stale).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let current = storage.snapshot().await.unwrap();
  let failed_condition = transaction(
    12,
    current.revision().clone(),
    vec![StoreOperation::Put {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
      value: value(b"wrong"),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(failed_condition).await.unwrap(),
    CommitOutcome::Conflict
  ));

  let atomic_failure = transaction(
    13,
    current.revision().clone(),
    vec![
      StoreOperation::Put {
        namespace: first_namespace.clone(),
        key: store_key(b"new"),
        expected: StoreExpectation::Absent,
        value: value(b"new"),
      },
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: second_key.clone(),
        expected: StoreExpectation::Exact(Digest::from_bytes([0; 32])),
        value: value(b"second"),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(atomic_failure).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let unchanged = storage.snapshot().await.unwrap();
  assert!(
    unchanged
      .get(&first_namespace, &store_key(b"new"))
      .await
      .unwrap()
      .is_none()
  );
  assert!(
    unchanged
      .get(&second_namespace, &second_key)
      .await
      .unwrap()
      .is_none()
  );

  let delete_failure = transaction(
    18,
    unchanged.revision().clone(),
    vec![
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: store_key(b"delete-rollback"),
        expected: StoreExpectation::Absent,
        value: value(b"must-not-commit"),
      },
      StoreOperation::Delete {
        namespace: first_namespace.clone(),
        key: first_key.clone(),
        expected: Digest::from_bytes([8; 32]),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(delete_failure).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let after_delete_failure = storage.snapshot().await.unwrap();
  assert!(
    after_delete_failure
      .get(&second_namespace, &store_key(b"delete-rollback"))
      .await
      .unwrap()
      .is_none()
  );
  assert_eq!(
    after_delete_failure
      .get(&first_namespace, &first_key)
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"first",
  );
  for failed_id in [
    transaction_id(11),
    transaction_id(12),
    transaction_id(13),
    transaction_id(18),
  ] {
    assert!(matches!(
      storage
        .reconcile(&failed_id, &Digest::from_bytes([0; 32]))
        .await
        .unwrap(),
      ReconcileOutcome::Aborted
    ));
  }

  let repeated = match storage.commit(original.clone()).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  assert_eq!(repeated, original_receipt);
  let changed_digest = transaction(
    10,
    initial.revision().clone(),
    vec![StoreOperation::Check {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(changed_digest).await.unwrap(),
    CommitOutcome::Conflict
  ));

  let exact_digest = value(b"first").digest().clone();
  let successful_batch = transaction(
    14,
    unchanged.revision().clone(),
    vec![
      StoreOperation::Check {
        namespace: first_namespace.clone(),
        key: first_key.clone(),
        expected: StoreExpectation::Exact(exact_digest),
      },
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: second_key.clone(),
        expected: StoreExpectation::Absent,
        value: value(b"second"),
      },
    ],
  )
  .unwrap();
  let receipt = match storage.commit(successful_batch).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == receipt
  ));
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), &Digest::from_bytes([9; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert!(matches!(
    storage
      .reconcile(&transaction_id(99), &Digest::from_bytes([0; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));

  let forget_mismatch = transaction(
    19,
    receipt.committed_revision().clone(),
    vec![
      StoreOperation::ForgetReceipt {
        transaction: original_receipt.transaction().clone(),
        expected_operation_digest: Digest::from_bytes([7; 32]),
      },
      StoreOperation::Put {
        namespace: second_namespace.clone(),
        key: store_key(b"receipt-rollback"),
        expected: StoreExpectation::Absent,
        value: value(b"must-not-commit"),
      },
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(forget_mismatch).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let after_forget_mismatch = storage.snapshot().await.unwrap();
  assert!(
    after_forget_mismatch
      .get(&second_namespace, &store_key(b"receipt-rollback"))
      .await
      .unwrap()
      .is_none()
  );
  assert!(matches!(
    storage
      .reconcile(
        original_receipt.transaction(),
        original_receipt.operation_digest(),
      )
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == original_receipt
  ));

  let forget = transaction(
    20,
    after_forget_mismatch.revision().clone(),
    vec![StoreOperation::ForgetReceipt {
      transaction: original_receipt.transaction().clone(),
      expected_operation_digest: original_receipt.operation_digest().clone(),
    }],
  )
  .unwrap();
  let forget_receipt = match storage.commit(forget).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  assert!(matches!(
    storage
      .reconcile(
        original_receipt.transaction(),
        original_receipt.operation_digest(),
      )
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));
  assert!(matches!(
    storage
      .reconcile(
        forget_receipt.transaction(),
        forget_receipt.operation_digest(),
      )
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == forget_receipt
  ));

  let duplicate = vec![
    StoreOperation::Check {
      namespace: first_namespace.clone(),
      key: first_key.clone(),
      expected: StoreExpectation::Absent,
    },
    StoreOperation::Delete {
      namespace: first_namespace,
      key: first_key,
      expected: Digest::from_bytes([0; 32]),
    },
  ];
  assert!(transaction(15, receipt.committed_revision().clone(), duplicate).is_err());
  assert!(transaction(16, receipt.committed_revision().clone(), vec![]).is_err());

  let duplicate_receipt = vec![
    StoreOperation::ForgetReceipt {
      transaction: transaction_id(20),
      expected_operation_digest: Digest::from_bytes([1; 32]),
    },
    StoreOperation::ForgetReceipt {
      transaction: transaction_id(20),
      expected_operation_digest: Digest::from_bytes([2; 32]),
    },
  ];
  assert!(transaction(17, receipt.committed_revision().clone(), duplicate_receipt).is_err());
}

// ---- lane 3: positioned scans ----------------------------------------

/// The positioned-scan (seek) contract, shared by every storage backend:
/// `scan_from` positions strictly past the keyset cursor with the exact
/// plain-scan order and filters, `None` equals a plain scan, and
/// out-of-bounds positions are empty scans, never errors.
async fn storage_contract_positioned_scans(factory: Arc<dyn StorageFactory>) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let initial = storage.snapshot().await.unwrap();
  let target_namespace = namespace("one");
  let other_namespace = namespace("two");
  let keys = [
    vec![],
    vec![0x00],
    vec![0x7F],
    vec![0x80],
    vec![0xFF],
    vec![0xFF, 0x00],
    vec![0xFF, 0xFF],
  ];
  let operations = keys
    .iter()
    .enumerate()
    .map(|(index, key)| StoreOperation::Put {
      namespace: target_namespace.clone(),
      key: store_key(key),
      expected: StoreExpectation::Absent,
      value: value(&[index as u8]),
    })
    .chain([StoreOperation::Put {
      namespace: other_namespace.clone(),
      key: store_key(&[0x00]),
      expected: StoreExpectation::Absent,
      value: value(b"other"),
    }])
    .collect();
  assert!(matches!(
    storage
      .commit(transaction(0, initial.revision().clone(), operations).unwrap())
      .await
      .unwrap(),
    CommitOutcome::Committed(_)
  ));

  let current = storage.snapshot().await.unwrap();
  let key_list = |entries: &[crate::StoreEntry]| {
    entries
      .iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect::<Vec<Vec<u8>>>()
  };

  // `None` observes exactly the plain scan.
  let plain = collect_scan(current.scan(&target_namespace, &[]).await.unwrap()).await;
  let unpositioned = collect_scan(
    current
      .scan_from(&target_namespace, &[], None)
      .await
      .unwrap(),
  )
  .await;
  assert_eq!(key_list(&plain), keys);
  assert_eq!(key_list(&plain), key_list(&unpositioned));
  assert!(
    plain
      .iter()
      .all(|entry| entry.namespace() == &target_namespace)
  );

  // The first key's cursor returns the remainder; the last key's cursor
  // is an empty scan, and exhaustion stays exhausted.
  let head = collect_scan(
    current
      .scan_from(&target_namespace, &[], Some(&[]))
      .await
      .unwrap(),
  )
  .await;
  assert_eq!(key_list(&head), keys[1..].to_vec());
  let mut tail = current
    .scan_from(&target_namespace, &[], Some(&[0xFF, 0xFF]))
    .await
    .unwrap();
  assert!(tail.next().await.unwrap().is_none());
  assert!(tail.next().await.unwrap().is_none());
  drop(tail);

  // Positioning is by key order: an absent `from` between two stored
  // keys starts at the next stored key.
  let between = collect_scan(
    current
      .scan_from(&target_namespace, &[], Some(&[0xC0]))
      .await
      .unwrap(),
  )
  .await;
  assert_eq!(
    key_list(&between),
    vec![vec![0xFF], vec![0xFF, 0x00], vec![0xFF, 0xFF]]
  );

  // Prefix and position compose: `from` before the prefix range returns
  // the whole prefixed scan, inside it the strictly-later remainder,
  // past its last key an empty scan.
  let prefixed = keys
    .iter()
    .filter(|key| key.starts_with(&[0xFF]))
    .cloned()
    .collect::<Vec<_>>();
  let before = collect_scan(
    current
      .scan_from(&target_namespace, &[0xFF], Some(&[0x00]))
      .await
      .unwrap(),
  )
  .await;
  assert_eq!(key_list(&before), prefixed);
  let inside = collect_scan(
    current
      .scan_from(&target_namespace, &[0xFF], Some(&[0xFF, 0x00]))
      .await
      .unwrap(),
  )
  .await;
  assert_eq!(key_list(&inside), vec![vec![0xFF, 0xFF]]);
  let inside_gap = collect_scan(
    current
      .scan_from(&target_namespace, &[0xFF], Some(&[0xFF, 0x00, 0x00]))
      .await
      .unwrap(),
  )
  .await;
  assert_eq!(key_list(&inside_gap), vec![vec![0xFF, 0xFF]]);
  let mut past = current
    .scan_from(&target_namespace, &[0xFF], Some(&[0xFF, 0xFF]))
    .await
    .unwrap();
  assert!(past.next().await.unwrap().is_none());
  drop(past);

  // Namespaces bound positioned scans exactly like plain scans: the
  // positioned plain scan of the second namespace yields only its own
  // entries, its own last key's cursor is empty, and a cursor past the
  // first namespace's end never leaks the second namespace's entries.
  let other_plain = collect_scan(
    current
      .scan_from(&other_namespace, &[], None)
      .await
      .unwrap(),
  )
  .await;
  assert_eq!(key_list(&other_plain), vec![vec![0x00]]);
  let other_positioned = collect_scan(
    current
      .scan_from(&other_namespace, &[], Some(&[0x00]))
      .await
      .unwrap(),
  )
  .await;
  assert!(other_positioned.is_empty());
  let beyond = collect_scan(
    current
      .scan_from(&target_namespace, &[], Some(&[0xFF, 0xFF, 0xFF]))
      .await
      .unwrap(),
  )
  .await;
  assert!(beyond.is_empty());
}

// ---- lanes 4 and 5: the metadata catalog ------------------------------

/// One representative key set per family: three keys in unsigned-byte
/// order.
const ROUNDTRIP_KEYS: [&[u8]; 3] = [b"", b"mid", b"\xFF\x00"];

fn family_namespaces() -> Vec<StoreNamespace> {
  metadata_families()
    .iter()
    .map(|family| crate::storage::families::namespace(family.namespace_tag()).unwrap())
    .collect()
}

fn digest_of(bytes: &[u8]) -> Digest {
  value(bytes).digest().clone()
}

fn put(namespace: &StoreNamespace, key: &[u8], contents: &[u8]) -> StoreOperation {
  StoreOperation::Put {
    namespace: namespace.clone(),
    key: store_key(key),
    expected: StoreExpectation::Absent,
    value: value(contents),
  }
}

/// Every family round-trips puts, exact lookup, ordered scans, conditional
/// updates, and conditional deletes through one shared contract body.
async fn storage_contract_all_family_roundtrip(factory: Arc<dyn StorageFactory>) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let families = family_namespaces();

  let initial = storage.snapshot().await.unwrap();
  let operations: Vec<StoreOperation> = families
    .iter()
    .flat_map(|family| {
      ROUNDTRIP_KEYS
        .iter()
        .enumerate()
        .map(move |(index, key)| put(family, key, &[index as u8, 0xAA]))
    })
    .collect();
  let first = transaction(1, initial.revision().clone(), operations).unwrap();
  let first_receipt = match storage.commit(first.clone()).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };
  assert!(
    matches!(
      storage
        .reconcile(first_receipt.transaction(), first_receipt.operation_digest())
        .await
        .unwrap(),
      ReconcileOutcome::Committed(found) if found == first_receipt
    ),
    "committed cross-family receipt must reconcile"
  );

  let current = storage.snapshot().await.unwrap();
  for family in &families {
    for (index, key) in ROUNDTRIP_KEYS.iter().enumerate() {
      let stored = current.get(family, &store_key(key)).await.unwrap();
      assert_eq!(
        stored.as_ref().map(|entry| entry.as_bytes().to_vec()),
        Some(vec![index as u8, 0xAA]),
        "exact lookup failed for family {}",
        family.as_str(),
      );
    }

    let scanned = collect_scan(current.scan(family, &[]).await.unwrap()).await;
    let keys: Vec<Vec<u8>> = scanned
      .iter()
      .map(|entry| entry.key().as_bytes().to_vec())
      .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "scan order violated in {}", family.as_str());
    assert_eq!(keys.len(), ROUNDTRIP_KEYS.len());

    for key in ROUNDTRIP_KEYS {
      let prefixed = collect_scan(current.scan(family, key).await.unwrap()).await;
      let expected = ROUNDTRIP_KEYS
        .iter()
        .filter(|candidate| candidate.starts_with(key))
        .count();
      assert_eq!(prefixed.len(), expected);
    }
  }

  // Conditional update and conditional delete per family on the current
  // revision, then a stale-revision and a failed per-key condition must
  // both conflict without mutating any family.
  let updates: Vec<StoreOperation> = families
    .iter()
    .flat_map(|family| {
      [
        StoreOperation::Put {
          namespace: family.clone(),
          key: store_key(b"mid"),
          expected: StoreExpectation::Exact(digest_of(&[1, 0xAA])),
          value: value(b"updated"),
        },
        StoreOperation::Delete {
          namespace: family.clone(),
          key: store_key(b"\xFF\x00"),
          expected: digest_of(&[2, 0xAA]),
        },
      ]
    })
    .collect();
  let second = transaction(2, current.revision().clone(), updates).unwrap();
  assert!(matches!(
    storage.commit(second).await.unwrap(),
    CommitOutcome::Committed(_)
  ));

  let latest = storage.snapshot().await.unwrap();
  let stale = transaction(
    3,
    initial.revision().clone(),
    vec![put(&families[0], b"stale", b"x")],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(stale).await.unwrap(),
    CommitOutcome::Conflict
  ));
  let failed_condition = transaction(
    4,
    latest.revision().clone(),
    vec![StoreOperation::Put {
      namespace: families[0].clone(),
      key: store_key(b"mid"),
      expected: StoreExpectation::Exact(digest_of(&[1, 0xAA])),
      value: value(b"wrong"),
    }],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(failed_condition).await.unwrap(),
    CommitOutcome::Conflict
  ));

  let unchanged = storage.snapshot().await.unwrap();
  for family in &families {
    assert!(
      unchanged
        .get(family, &store_key(b"stale"))
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      unchanged
        .get(family, &store_key(b"mid"))
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      b"updated"
    );
    assert!(
      unchanged
        .get(family, &store_key(b"\xFF\x00"))
        .await
        .unwrap()
        .is_none()
    );
  }
  assert!(matches!(
    storage
      .reconcile(&transaction_id(4), &digest_of(&[0, 0xAA]))
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));
}

/// One transaction spanning every metadata family commits or aborts
/// atomically, and its single receipt reconciles per family.
async fn storage_contract_cross_family_atomicity(factory: Arc<dyn StorageFactory>) {
  let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
  let families = family_namespaces();

  let initial = storage.snapshot().await.unwrap();
  let mut aborted: Vec<StoreOperation> = families
    .iter()
    .map(|family| put(family, b"cross", b"must-not-commit"))
    .collect();
  aborted.push(StoreOperation::Check {
    namespace: families[0].clone(),
    key: store_key(b"absent-guard"),
    expected: StoreExpectation::Exact(digest_of(b"no-such-value")),
  });
  let aborted_transaction = transaction(10, initial.revision().clone(), aborted).unwrap();
  assert!(matches!(
    storage.commit(aborted_transaction).await.unwrap(),
    CommitOutcome::Conflict
  ));

  let after_abort = storage.snapshot().await.unwrap();
  for family in &families {
    assert!(
      after_abort
        .get(family, &store_key(b"cross"))
        .await
        .unwrap()
        .is_none()
    );
  }

  let committed: Vec<StoreOperation> = families
    .iter()
    .map(|family| put(family, b"cross", b"applied"))
    .collect();
  let committed_transaction = transaction(11, after_abort.revision().clone(), committed).unwrap();
  let receipt = match storage.commit(committed_transaction).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    outcome => panic!("unexpected outcome: {outcome:?}"),
  };

  let converged = storage.snapshot().await.unwrap();
  for family in &families {
    assert_eq!(
      converged
        .get(family, &store_key(b"cross"))
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      b"applied"
    );
  }
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == receipt
  ));
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), &Digest::from_bytes([7; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::DigestConflict
  ));

  let forget = transaction(
    12,
    converged.revision().clone(),
    vec![
      StoreOperation::ForgetReceipt {
        transaction: receipt.transaction().clone(),
        expected_operation_digest: receipt.operation_digest().clone(),
      },
      put(&families[0], b"cross-after-forget", b"kept"),
    ],
  )
  .unwrap();
  assert!(matches!(
    storage.commit(forget).await.unwrap(),
    CommitOutcome::Committed(_)
  ));
  assert!(matches!(
    storage
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));
}
