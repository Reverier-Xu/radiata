//! Key deletion intents over journaled metadata storage.
//!
//! Deletion first installs a target-bound `KeyDeletionIntent` after a fresh
//! snapshot proves no committed generation references the handle. The intent
//! makes every later transaction that would add a reference conflict (the
//! identity finalization path refuses handles with an intent or tombstone).
//! The provider then deletes under the intent's durable operation ID and the
//! outcome reconciles idempotently. A proven-absent intent is replaced by a
//! `KeyDeleted` tombstone in one journaled transaction. A handle is never
//! reused and a referenced handle is never deleted.

use std::sync::Arc;

use super::{
  lifecycle::{
    CommitWithReconcile, cleanup_pending_exact, commit_with_reconcile, discover_local_identity,
    discovery_corrupt,
  },
  records::{
    KeyDeletedV1, KeyDeletionIntentV1, key_deleted_key, key_deletion_intent_key, local_identity_key,
  },
};
use crate::{
  Error, ErrorKind, KeyDeleteState, KeyHandle, KeyOperationId, Result, StoreExpectation,
  StoreOperation, StoreValue, TransactionId,
  api::Entropy,
  provider::KeyProvider,
  storage::receipt::{ReceiptReferenceChange, ReceiptReferenceToken},
};

/// Deletes one unreferenced provider handle with exact crash recovery.
///
/// The provider delete is driven under the key's own create `operation`:
/// the built-in key stores validate that pairing (the handle names that
/// operation), so a freshly generated id would be rejected as an input
/// error and the key would never leave the provider.
///
/// The call is idempotent: replaying after success performs no provider or
/// storage mutation. A handle referenced by the local identity conflicts
/// without any mutation. Provider `Unknown` outcomes quarantine the intent
/// until `reconcile_delete` proves `Absent`.
pub(crate) async fn delete_unreferenced_key(
  store: &crate::storage::MetadataStore, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
  operation: &KeyOperationId, handle: &KeyHandle,
) -> Result<()> {
  // The whole journaled section holds the writer exclusion: see the
  // same-purpose serialization note on the merge flow.
  let _permit = store.write_permit().await;
  let purpose = deletion_purpose(handle);
  // The deletion path reconciles a frozen store after journal recovery
  // too (a cheap no-op on a non-frozen store), matching its historical
  // unconditional reconcile.
  crate::identity::lifecycle::recover_journal_prologue(
    store,
    entropy,
    &purpose,
    "key deletion pending cleanup",
  )
  .await?;
  store.reconcile_if_frozen().await?;

  let mut attempts = 0_u8;
  loop {
    attempts += 1;
    let snapshot = store.snapshot().await?;
    let (deleted_namespace, deleted_key) = key_deleted_key(handle)?;
    if snapshot
      .get(&deleted_namespace, &deleted_key)
      .await?
      .is_some()
    {
      return Ok(());
    }
    let local_identity = discover_local_identity(snapshot.as_ref()).await?;
    if let Some((_, identity)) = &local_identity
      && identity.handle() == handle
    {
      return Err(Error::conflict("referenced key handle"));
    }
    let (intent_namespace, intent_key) = key_deletion_intent_key(handle)?;
    let existing = snapshot.get(&intent_namespace, &intent_key).await?;
    let (stored_intent, intent, resumed) = match existing {
      Some(stored) => {
        let intent =
          KeyDeletionIntentV1::decode(stored.as_bytes()).map_err(|_| discovery_corrupt())?;
        if intent.handle() != handle || intent.purpose() != purpose {
          return Err(discovery_corrupt());
        }
        (stored, intent, true)
      }
      None => {
        let intent = KeyDeletionIntentV1::new(
          operation.clone(),
          handle.clone(),
          purpose.clone(),
          TransactionId::generate(entropy)?,
          snapshot.revision().clone(),
        )?;
        let token = ReceiptReferenceToken::for_record(&intent_namespace, &intent_key);
        let value = StoreValue::new(Arc::from(intent.encode()?));
        // Transactional guard: pin the exact local-identity record this
        // snapshot proved unreferenced, so a concurrent finalization that
        // changes it aborts the intent install.
        let mut caller_operations = Vec::new();
        if let Some((stored_identity, _)) = &local_identity {
          let (local_namespace, local_key) = local_identity_key()?;
          caller_operations.push(StoreOperation::Check {
            namespace: local_namespace,
            key: local_key,
            expected: StoreExpectation::Exact(stored_identity.digest().clone()),
          });
        }
        caller_operations.push(StoreOperation::Put {
          namespace: intent_namespace.clone(),
          key: intent_key.clone(),
          expected: StoreExpectation::Absent,
          value: value.clone(),
        });
        let prepared = store
          .prepare_transaction_with_receipt_changes(
            snapshot.as_ref(),
            intent.transaction().clone(),
            caller_operations,
            vec![ReceiptReferenceChange::AddSelf(vec![token])],
          )
          .await?;
        drop(snapshot);
        match commit_with_reconcile(store, prepared).await? {
          CommitWithReconcile::Committed => {}
          CommitWithReconcile::Aborted => {
            if attempts >= 2 {
              return Err(Error::conflict("key deletion intent"));
            }
            continue;
          }
        }
        (value, intent, false)
      }
    };
    match delete_provider_step(
      store,
      keys,
      entropy,
      &purpose,
      &stored_intent,
      &intent,
      resumed,
    )
    .await
    {
      Ok(()) => return Ok(()),
      Err(error) if error.kind() == ErrorKind::Conflict && attempts < 2 => continue,
      Err(error) => return Err(error),
    }
  }
}

/// Drives the provider delete/reconcile step and the tombstone finalization
/// for an installed deletion intent.
async fn delete_provider_step(
  store: &crate::storage::MetadataStore, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
  purpose: &str, stored_intent: &StoreValue, intent: &KeyDeletionIntentV1, resumed: bool,
) -> Result<()> {
  let outcome = if resumed {
    keys
      .reconcile_delete(intent.operation(), intent.handle())
      .await?
  } else {
    keys.delete(intent.operation(), intent.handle()).await?
  };
  match outcome {
    // The reconcile reports the removal did not land: issue one fresh
    // delete under the same durable operation id.
    KeyDeleteState::Present if resumed => {
      match keys.delete(intent.operation(), intent.handle()).await? {
        KeyDeleteState::Absent | KeyDeleteState::Present => {}
        KeyDeleteState::Unknown => {
          return Err(Error::provider(
            crate::ProviderErrorKind::CommitUnknown,
            crate::ProviderErrorContext::KeyDelete,
          ));
        }
      }
    }
    // The post-state rule: `Absent` (nothing to remove) and `Present`
    // (existed and was deleted by this call) both prove the key left the
    // provider, and the intent finalizes into the tombstone either way.
    KeyDeleteState::Absent | KeyDeleteState::Present => {}
    KeyDeleteState::Unknown => {
      return Err(Error::provider(
        crate::ProviderErrorKind::CommitUnknown,
        crate::ProviderErrorContext::KeyDelete,
      ));
    }
  }

  let snapshot = store.snapshot().await?;
  let (intent_namespace, intent_key) = key_deletion_intent_key(intent.handle())?;
  let current = snapshot
    .get(&intent_namespace, &intent_key)
    .await?
    .ok_or_else(discovery_corrupt)?;
  if current.digest() != stored_intent.digest() {
    return Err(discovery_corrupt());
  }
  let tombstone = KeyDeletedV1::new(intent.operation().clone(), intent.handle().clone());
  let (deleted_namespace, deleted_key) = key_deleted_key(intent.handle())?;
  let intent_token = ReceiptReferenceToken::for_record(&intent_namespace, &intent_key);
  let tombstone_token = ReceiptReferenceToken::for_record(&deleted_namespace, &deleted_key);
  let target = intent.recovery_identity(stored_intent)?;
  let prepared = store
    .prepare_journaled_transaction(
      snapshot.as_ref(),
      TransactionId::generate(entropy)?,
      purpose,
      vec![
        StoreOperation::Delete {
          namespace: intent_namespace,
          key: intent_key,
          expected: current.digest().clone(),
        },
        StoreOperation::Put {
          namespace: deleted_namespace,
          key: deleted_key,
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(tombstone.encode()?)),
        },
      ],
      vec![
        ReceiptReferenceChange::Remove {
          target,
          tokens: vec![intent_token],
        },
        ReceiptReferenceChange::AddSelf(vec![tombstone_token]),
      ],
    )
    .await?;
  drop(snapshot);
  match commit_with_reconcile(store, prepared).await? {
    CommitWithReconcile::Committed => {}
    CommitWithReconcile::Aborted => return accept_exact_tombstone(store, &tombstone).await,
  }
  cleanup_pending_exact(store, entropy, purpose, "key deletion pending cleanup").await?;
  Ok(())
}

/// Accepts a proven non-commit only when a fresh snapshot shows the exact
/// final tombstone state.
async fn accept_exact_tombstone(
  store: &crate::storage::MetadataStore, tombstone: &KeyDeletedV1,
) -> Result<()> {
  let snapshot = store.snapshot().await?;
  let (intent_namespace, intent_key) = key_deletion_intent_key(tombstone.handle())?;
  let (deleted_namespace, deleted_key) = key_deleted_key(tombstone.handle())?;
  let intent_gone = snapshot
    .get(&intent_namespace, &intent_key)
    .await?
    .is_none();
  let tombstone_value = snapshot.get(&deleted_namespace, &deleted_key).await?;
  drop(snapshot);
  match tombstone_value {
    Some(value) if intent_gone => {
      let stored = KeyDeletedV1::decode(value.as_bytes()).map_err(|_| discovery_corrupt())?;
      if &stored == tombstone {
        return Ok(());
      }
      Err(discovery_corrupt())
    }
    _ => Err(Error::conflict("key deletion tombstone")),
  }
}

fn deletion_purpose(handle: &KeyHandle) -> String {
  crate::identity::records::JournalPurpose::KeyDeletion(handle.clone()).text()
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tokio::sync::Notify;

  use super::delete_unreferenced_key;
  use crate::{
    ErrorKind, KeyOperationId, StoreValue,
    identity::{
      lifecycle::LocalIdentityContext,
      records::{
        KeyDeletedV1, KeyDeletionIntentV1, key_deleted_key, key_deletion_intent_key,
        local_identity_key,
      },
      testing::{
        CommitFault, DeleteScript, FaultingFactory, RETENTION, ScriptedKeys, SequenceEntropy,
        assert_never_deleted, commit_calls, entry, fresh_reference, open_context, pending_keys,
        receipt_ids,
      },
    },
    provider::KeyProvider,
    storage::receipt::internal_namespace,
  };

  struct Fixture {
    reference: Arc<crate::storage::contract::ReferenceFactory>,
    keys: Arc<ScriptedKeys>,
    entropy: Arc<SequenceEntropy>,
    context: LocalIdentityContext,
  }

  async fn fixture() -> Fixture {
    let (reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&factory, &keys, &entropy).await.unwrap();
    Fixture {
      reference,
      keys,
      entropy,
      context,
    }
  }

  fn detached_pair(fixture: &Fixture, index: u64) -> (KeyOperationId, crate::KeyHandle) {
    let operation = KeyOperationId::parse(&format!("keyop-{:021}", 10_000 + index)).unwrap();
    let handle = fixture.keys.create_detached(&operation).handle().clone();
    (operation, handle)
  }

  fn tombstone_present(
    reference: &Arc<crate::storage::contract::ReferenceFactory>, handle: &crate::KeyHandle,
  ) -> bool {
    let (namespace, key) = key_deleted_key(handle).unwrap();
    entry(reference, &namespace, &key).is_some()
  }

  fn intent_present(
    reference: &Arc<crate::storage::contract::ReferenceFactory>, handle: &crate::KeyHandle,
  ) -> bool {
    let (namespace, key) = key_deletion_intent_key(handle).unwrap();
    entry(reference, &namespace, &key).is_some()
  }

  #[tokio::test]
  async fn key_intent_delete_unreferenced_handle_installs_tombstone_atomically() {
    let fixture = fixture().await;
    let (operation, handle) = detached_pair(&fixture, 1);
    assert!(fixture.keys.has_handle(&handle));

    delete_unreferenced_key(
      fixture.context.store(),
      &fixture.keys.as_provider(),
      fixture.entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap();

    assert!(!fixture.keys.has_handle(&handle));
    assert!(!intent_present(&fixture.reference, &handle));
    assert!(tombstone_present(&fixture.reference, &handle));
    assert!(pending_keys(&fixture.reference).is_empty());

    // Idempotent replay performs no mutation.
    let commits_before = commit_calls(&fixture.reference);
    let calls_before = fixture.keys.all_calls().len();
    delete_unreferenced_key(
      fixture.context.store(),
      &fixture.keys.as_provider(),
      fixture.entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap();
    assert_eq!(commit_calls(&fixture.reference), commits_before);
    assert_eq!(fixture.keys.all_calls().len(), calls_before);
  }

  #[tokio::test]
  async fn key_intent_referenced_local_identity_handle_is_never_deleted() {
    let fixture = fixture().await;
    let identity = fixture.context.identity();
    let operation = identity.operation().clone();
    let handle = identity.handle().clone();
    let commits_before = commit_calls(&fixture.reference);
    let calls_before = fixture.keys.all_calls().len();

    let error = delete_unreferenced_key(
      fixture.context.store(),
      &fixture.keys.as_provider(),
      fixture.entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(commit_calls(&fixture.reference), commits_before);
    assert_eq!(fixture.keys.all_calls().len(), calls_before);
    assert!(fixture.keys.has_handle(&handle));
    assert!(!intent_present(&fixture.reference, &handle));
    assert!(!tombstone_present(&fixture.reference, &handle));
  }

  #[tokio::test]
  async fn key_intent_unknown_delete_reconciles_idempotently() {
    let fixture = fixture().await;
    let (operation, handle) = detached_pair(&fixture, 3);
    fixture.keys.push_delete_script(DeleteScript::Unknown);

    let error = delete_unreferenced_key(
      fixture.context.store(),
      &fixture.keys.as_provider(),
      fixture.entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CommitUnknown);
    assert!(intent_present(&fixture.reference, &handle));
    assert!(fixture.keys.has_handle(&handle));

    // Resume: reconcile_delete reports the handle still present, one delete
    // under the same operation completes, and the tombstone commits.
    delete_unreferenced_key(
      fixture.context.store(),
      &fixture.keys.as_provider(),
      fixture.entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap();
    assert!(tombstone_present(&fixture.reference, &handle));
    assert!(!fixture.keys.has_handle(&handle));
    assert!(pending_keys(&fixture.reference).is_empty());
  }

  #[tokio::test]
  async fn key_intent_storage_faults_recover_exactly() {
    for (fault_at_intent, fault_at_tombstone) in [
      (CommitFault::UnknownApplied, CommitFault::Pass),
      (CommitFault::UnknownNotApplied, CommitFault::Pass),
      (CommitFault::Pass, CommitFault::UnknownApplied),
      (CommitFault::Pass, CommitFault::UnknownNotApplied),
    ] {
      let (reference, _factory) = fresh_reference();
      let faulting = FaultingFactory::new(
        &reference,
        vec![
          CommitFault::Pass,
          CommitFault::Pass,
          CommitFault::Pass,
          fault_at_intent,
          CommitFault::Pass,
          fault_at_tombstone,
        ],
      );
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let context = open_context(&faulting.as_factory(), &keys, &entropy)
        .await
        .unwrap();
      let operation = KeyOperationId::parse("keyop-000000000000000000099").unwrap();
      let handle = keys.create_detached(&operation).handle().clone();

      delete_unreferenced_key(
        context.store(),
        &keys.as_provider(),
        entropy.as_ref(),
        &operation,
        &handle,
      )
      .await
      .unwrap();
      assert!(tombstone_present(&reference, &handle));
      assert!(!intent_present(&reference, &handle));
      assert!(pending_keys(&reference).is_empty());
    }
  }

  #[tokio::test]
  async fn key_intent_tombstone_journal_recovers_after_reopen() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(
      &reference,
      vec![
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::Pass,
        CommitFault::HangApplied,
      ],
    );
    faulting.pad_hooks(4);
    let committed = Arc::new(Notify::new());
    {
      let committed = Arc::clone(&committed);
      faulting.push_hook(Box::new(move || committed.notify_one()));
    }
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();
    let operation = KeyOperationId::parse("keyop-000000000000000000098").unwrap();
    let handle = keys.create_detached(&operation).handle().clone();

    let task = tokio::spawn({
      let provider = keys.as_provider();
      let entropy = Arc::clone(&entropy);
      let operation = operation.clone();
      let handle = handle.clone();
      async move {
        delete_unreferenced_key(
          context.store(),
          &provider,
          entropy.as_ref(),
          &operation,
          &handle,
        )
        .await
      }
    });
    committed.notified().await;
    for _ in 0..64 {
      if !pending_keys(&reference).is_empty() {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert_eq!(pending_keys(&reference).len(), 1);
    task.abort();
    let _ = task.await;

    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();
    delete_unreferenced_key(
      context.store(),
      &keys.as_provider(),
      entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap();
    assert!(tombstone_present(&reference, &handle));
    assert!(pending_keys(&reference).is_empty());
  }

  #[tokio::test]
  async fn key_intent_deletion_records_block_identity_reference_reuse() {
    for inject_tombstone in [false, true] {
      let (reference, factory) = fresh_reference();
      let keys = ScriptedKeys::full();
      let entropy = Arc::new(SequenceEntropy::default());
      let expected_handle = {
        // ScriptedKeys allocates scripted-handle-0 for the first operation.
        crate::KeyHandle::from_provider_bytes(Arc::from(b"scripted-handle-0".as_slice())).unwrap()
      };
      if inject_tombstone {
        let (namespace, key) = key_deleted_key(&expected_handle).unwrap();
        let tombstone = KeyDeletedV1::new(
          KeyOperationId::parse("keyop-000000000000000000002").unwrap(),
          expected_handle.clone(),
        );
        let value = StoreValue::new(Arc::from(tombstone.encode().unwrap()));
        reference
          .state
          .lock()
          .unwrap()
          .entries
          .insert((namespace, key), value);
      } else {
        let (namespace, key) = key_deletion_intent_key(&expected_handle).unwrap();
        let revision = crate::StoreRevision::new(Arc::from(0_u64.to_be_bytes())).unwrap();
        let intent = KeyDeletionIntentV1::new(
          KeyOperationId::parse("keyop-000000000000000000002").unwrap(),
          expected_handle.clone(),
          "key-delete-test".to_owned(),
          crate::TransactionId::parse("txn-000000000000000000002").unwrap(),
          revision,
        )
        .unwrap();
        let value = StoreValue::new(Arc::from(intent.encode().unwrap()));
        reference
          .state
          .lock()
          .unwrap()
          .entries
          .insert((namespace, key), value);
      }

      let error = open_context(&factory, &keys, &entropy).await.unwrap_err();
      assert_eq!(
        error.kind(),
        ErrorKind::Conflict,
        "tombstone={inject_tombstone}"
      );
      assert!(fixtureless_local_identity_absent(&reference));
    }
  }

  fn fixtureless_local_identity_absent(
    reference: &Arc<crate::storage::contract::ReferenceFactory>,
  ) -> bool {
    let (namespace, key) = local_identity_key().unwrap();
    entry(reference, &namespace, &key).is_none()
  }

  #[tokio::test]
  async fn key_intent_deletion_receipts_and_references_are_exact() {
    let fixture = fixture().await;
    let (operation, handle) = detached_pair(&fixture, 7);
    let receipts_before = receipt_ids(&fixture.reference).len();
    delete_unreferenced_key(
      fixture.context.store(),
      &fixture.keys.as_provider(),
      fixture.entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap();

    // intent install + tombstone finalize + pending cleanup receipts.
    let receipts_after = receipt_ids(&fixture.reference).len();
    assert_eq!(receipts_before + 3, receipts_after);

    // The tombstone transaction receipt references only the tombstone record;
    // the intent receipt has no remaining references.
    let internal = internal_namespace().unwrap();
    let state = fixture.reference.state.lock().unwrap();
    let heads: Vec<u64> = state
      .entries
      .iter()
      .filter(|((namespace, key), _)| {
        namespace == &internal && key.as_bytes().starts_with(b"\x02reference-head\0")
      })
      .map(|(_, value)| u64::from_be_bytes(value.as_bytes().try_into().unwrap()))
      .collect();
    drop(state);
    assert!(heads.contains(&1));
    assert!(pending_keys(&fixture.reference).is_empty());
    assert_never_deleted_partially(&fixture.keys);
  }

  fn assert_never_deleted_partially(keys: &ScriptedKeys) {
    // The deletion protocol must drive exactly one Delete per handle; no
    // identity lifecycle call may ever issue one implicitly beyond the
    // explicit deletions above.
    let deletes = keys
      .all_calls()
      .into_iter()
      .filter(|call| matches!(call, crate::identity::testing::KeyCall::Delete))
      .count();
    assert_eq!(deletes, 1);
  }

  #[tokio::test]
  async fn key_intent_unused_marker_assert_never_deleted_helper_holds() {
    let fixture = fixture().await;
    // No deletion was requested, so the shared invariant must observe zero
    // provider delete calls.
    assert_never_deleted(&fixture.keys);
  }

  #[tokio::test]
  async fn key_intent_real_file_provider_delete_pairs_with_the_create_operation() {
    // The built-in file key store validates the delete pairing against
    // the key's create operation. This pins the regression where the
    // deletion intent drove the provider delete under a freshly
    // generated operation id: the provider rejected it as an input error
    // and the former identity key never left the provider.
    let (reference, factory) = fresh_reference();
    let directory = tempfile::tempdir().unwrap();
    let keys: Arc<dyn KeyProvider> = Arc::new(crate::keys::file::FileKeyStore::new(
      directory.path().to_path_buf(),
    ));
    let entropy = Arc::new(SequenceEntropy::default());
    let context =
      crate::identity::lifecycle::open_local_identity(&factory, &keys, entropy.as_ref(), RETENTION)
        .await
        .unwrap();

    // A detached key created through the real provider, deleted the way
    // the leave pipeline deletes the former identity key: under the
    // create operation the intent carries.
    let operation = KeyOperationId::parse("keyop-000000000000000000077").unwrap();
    let handle = match keys.create_ed25519(&operation).await.unwrap() {
      crate::KeyCreateState::Present(created) => created.handle().clone(),
      state => panic!("unexpected create state: {state:?}"),
    };

    delete_unreferenced_key(
      context.store(),
      &keys,
      entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap();
    assert!(!intent_present(&reference, &handle));
    assert!(tombstone_present(&reference, &handle));
    assert!(pending_keys(&reference).is_empty());
  }
}

#[cfg(test)]
mod guard_tests {
  use std::sync::Arc;

  use super::*;
  use crate::{
    StoreOperation,
    identity::{
      records::{key_deleted_namespace, key_deletion_intent_namespace, local_identity_key},
      testing::{FaultingFactory, ScriptedKeys, SequenceEntropy, fresh_reference, open_context},
    },
  };

  #[tokio::test]
  async fn key_intent_install_transaction_pins_local_identity_digest() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(&reference, vec![]);
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();
    let operation = KeyOperationId::parse("keyop-000000000000000000055").unwrap();
    let handle = keys.create_detached(&operation).handle().clone();

    delete_unreferenced_key(
      context.store(),
      &keys.as_provider(),
      entropy.as_ref(),
      &operation,
      &handle,
    )
    .await
    .unwrap();

    let committed = faulting.committed_ops();
    let install = &committed[3];
    let (local_namespace, local_key) = local_identity_key().unwrap();
    assert!(
      install.iter().any(|operation| {
        matches!(
          operation,
          StoreOperation::Check {
            namespace,
            key,
            expected: StoreExpectation::Exact(_),
          } if namespace == &local_namespace && key == &local_key
        )
      }),
      "intent install must pin the exact local identity record"
    );
  }

  #[tokio::test]
  async fn key_intent_finalize_transaction_checks_deletion_namespaces_absent() {
    let (reference, _factory) = fresh_reference();
    let faulting = FaultingFactory::new(&reference, vec![]);
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    open_context(&faulting.as_factory(), &keys, &entropy)
      .await
      .unwrap();

    let committed = faulting.committed_ops();
    let finalize = &committed[1];
    let deletion_namespace = key_deletion_intent_namespace().unwrap();
    let deleted_namespace = key_deleted_namespace().unwrap();
    for namespace in [deletion_namespace, deleted_namespace] {
      assert!(
        finalize.iter().any(|operation| {
          matches!(
            operation,
            StoreOperation::Check {
              namespace: actual,
              expected: StoreExpectation::Absent,
              ..
            } if actual == &namespace
          )
        }),
        "finalize must check {namespace:?} absent"
      );
    }
  }
}
