//! The storage-author rails' acceptance, in the external-crate shape:
//! the public contract suite runs the public memory store — a backend
//! that is neither redb nor json — to green, exactly as a third-party
//! backend author would drive it, and the public commit-semantics
//! helpers are nameable and callable from outside the crate.

use std::sync::Arc;

use radiata::{
  Digest, StoreKey, StoreNamespace, StoreOperation, StoreExpectation, QualifiedTag, TransactionId,
  adapters::memory_store, contract::run_storage_contract,
};

/// The full public contract suite over the public memory store: five
/// lanes, one fresh factory per lane, all green.
#[tokio::test]
async fn the_storage_contract_suite_runs_the_memory_store_to_green() {
  run_storage_contract(memory_store).await;
}

/// The public commit-semantics derivation is callable from outside the
/// crate: an absent-record `Absent` expectation holds, an exact-digest
/// expectation holds only over that digest, and a delete expectation
/// only over an exactly matching record — the same clauses the
/// built-in adapters enforce through the shared helpers.
#[test]
fn the_public_commit_semantics_helpers_evaluate_expectations() {
  let namespace = StoreNamespace::new(
    QualifiedTag::parse("radiata.woooo.tech/metadata/v1/resource-record").unwrap(),
  );
  let key = StoreKey::new(Arc::from(b"rail-probe".as_slice()));
  let digest = Digest::from_bytes([7_u8; 32]);

  let entry = |_namespace: &StoreNamespace, _key: &StoreKey| Ok(None);
  let receipt = |_transaction: &TransactionId| Ok(None);

  assert!(radiata::condition_matches(
    entry,
    receipt,
    &StoreOperation::Check {
      namespace: namespace.clone(),
      key: key.clone(),
      expected: StoreExpectation::Absent,
    },
  )
  .unwrap());

  let present = |_namespace: &StoreNamespace, _key: &StoreKey| Ok(Some(digest.clone()));
  assert!(
    !radiata::condition_matches(
      present,
      receipt,
      &StoreOperation::Check {
        namespace: namespace.clone(),
        key,
        expected: StoreExpectation::Absent,
      },
    )
    .unwrap()
  );
}
