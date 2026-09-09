//! All-family metadata contract lane.
//!
//! Drives the backend-neutral storage contract over every entry of the
//! metadata family catalog: provider-owned immutable snapshots, exact
//! lookup, unsigned-byte ordered scan streams, base/per-key conditions,
//! cross-family atomicity, receipts, and reconciliation.

use std::sync::Arc;

use super::helpers::{collect_scan, transaction, transaction_id, value};
use crate::{
  CommitOutcome, Digest, ReconcileOutcome, StoreExpectation, StoreKey, StoreNamespace,
  StoreOperation, StoreRequirements, provider::StorageFactory,
  storage::families::metadata_families,
};

/// One representative key set per family: three keys in unsigned-byte
/// order.
const ROUNDTRIP_KEYS: [&[u8]; 3] = [b"", b"mid", b"\xFF\x00"];

fn family_namespaces() -> Vec<StoreNamespace> {
  metadata_families()
    .iter()
    .map(|family| family.namespace().unwrap())
    .collect()
}

fn digest_of(bytes: &[u8]) -> Digest {
  value(bytes).digest().clone()
}

fn put(namespace: &StoreNamespace, key: &[u8], contents: &[u8]) -> StoreOperation {
  StoreOperation::Put {
    namespace: namespace.clone(),
    key: StoreKey::new(Arc::from(key)),
    expected: StoreExpectation::Absent,
    value: value(contents),
  }
}

fn store_key(key: &[u8]) -> StoreKey {
  StoreKey::new(Arc::from(key))
}

/// Every family round-trips puts, exact lookup, ordered scans, conditional
/// updates, and conditional deletes through one shared contract body.
pub(crate) async fn storage_contract_all_family_roundtrip(factory: Arc<dyn StorageFactory>) {
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
pub(crate) async fn storage_contract_cross_family_atomicity(factory: Arc<dyn StorageFactory>) {
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
