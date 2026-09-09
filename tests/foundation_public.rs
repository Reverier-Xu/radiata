use std::sync::Arc;

use radiata::{
  BoxFuture, CommitOutcome, CommitReceipt, CreatedKey, Digest, DurabilityLevel, Error,
  KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId, ProviderErrorContext,
  ProviderErrorKind, PublicKey, QualifiedTag, ReconcileOutcome, Result, Signature,
  StoreCapabilities, StoreEntry, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
  StoreRequirements, StoreRevision, StoreTransaction, StoreValue, TransactionId,
  extension::{KeyProvider, Storage, StorageFactory, StoreScan, StoreSnapshot},
};

#[derive(Debug)]
struct DummyKeys;

impl KeyProvider for DummyKeys {
  fn capabilities(&self) -> KeyCapabilities {
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async { Ok(KeyCreateState::Absent) })
  }

  fn reconcile_create<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async { Ok(KeyCreateState::Unknown) })
  }

  fn public_key<'a>(&'a self, _handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    Box::pin(async { Ok(PublicKey::from_bytes([3; 32])) })
  }

  fn sign<'a>(
    &'a self, _handle: &'a KeyHandle, _message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async { Ok(Signature::from_bytes([4; 64])) })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async { Ok(KeyDeleteState::Absent) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async { Ok(KeyDeleteState::Unknown) })
  }
}

#[derive(Debug)]
struct DummyScan;

impl StoreScan for DummyScan {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    Box::pin(async { Ok(None) })
  }
}

#[derive(Debug)]
struct DummySnapshot {
  revision: StoreRevision,
}

impl StoreSnapshot for DummySnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, _namespace: &'a StoreNamespace, _key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    Box::pin(async { Ok(None) })
  }

  fn scan<'a>(
    &'a self, _namespace: &'a StoreNamespace, _prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    Box::pin(async { Ok(Box::new(DummyScan) as Box<dyn StoreScan>) })
  }
}

#[derive(Debug)]
struct DummyStorage;

impl Storage for DummyStorage {
  fn capabilities(&self) -> StoreCapabilities {
    complete_store_capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    Box::pin(async {
      let revision = StoreRevision::new(Arc::from([1_u8])).map_err(|_| provider_error())?;
      Ok(Box::new(DummySnapshot { revision }) as Box<dyn StoreSnapshot>)
    })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    Box::pin(async move {
      if transaction.operation_digest() != &transaction.computed_operation_digest() {
        return Ok(CommitOutcome::Conflict);
      }
      Ok(CommitOutcome::Aborted)
    })
  }

  fn reconcile<'a>(
    &'a self, _transaction: &'a TransactionId, _digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    Box::pin(async { Ok(ReconcileOutcome::Unknown) })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

#[derive(Debug)]
struct DummyFactory;

impl StorageFactory for DummyFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    Box::pin(async move {
      inspect_requirements(&requirements);
      Ok(Box::new(DummyStorage) as Box<dyn Storage>)
    })
  }
}

#[test]
fn core_key_boundary_is_constructible_inspectable_and_redacted() {
  let capabilities = KeyCapabilities::new()
    .ed25519(true)
    .reconciliation(true)
    .deletion(true);
  assert!(capabilities.has_ed25519());
  assert!(capabilities.has_reconciliation());
  assert!(capabilities.has_deletion());

  let operation = KeyOperationId::parse("keyop_0123456789abcdefghijk").unwrap();
  assert_eq!(operation.as_str(), "keyop_0123456789abcdefghijk");
  assert_eq!(
    operation.to_string().parse::<KeyOperationId>().unwrap(),
    operation
  );
  assert!(KeyOperationId::parse("keyop_0123456789abcdefghij-").is_err());

  let handle = KeyHandle::from_provider_bytes(Arc::from(b"sensitive-handle".as_slice())).unwrap();
  assert_eq!(handle.expose_provider_handle(), b"sensitive-handle");
  assert_eq!(format!("{handle:?}"), "KeyHandle(..)");
  assert!(KeyHandle::from_provider_bytes(Arc::from([])).is_err());

  let public_key = PublicKey::from_bytes([7; 32]);
  let created = CreatedKey::new(handle.clone(), public_key.clone());
  assert_eq!(created.handle(), &handle);
  assert_eq!(created.public_key(), &public_key);
  assert!(matches!(
    KeyCreateState::Present(created),
    KeyCreateState::Present(_)
  ));
  assert!(matches!(KeyDeleteState::Present, KeyDeleteState::Present));
}

#[test]
fn core_storage_boundary_values_round_trip() {
  let capabilities = complete_store_capabilities();
  assert_eq!(capabilities.durability(), DurabilityLevel::OsCrashDurable);
  assert!(capabilities.has_conditional_batch());
  assert!(capabilities.has_ordered_scan());
  assert!(capabilities.has_reconciliation());
  assert!(capabilities.has_exclusive_lifetime_lock());
  assert!(capabilities.has_transactional_migration());

  let revision = StoreRevision::new(Arc::from([1_u8, 2, 3])).unwrap();
  assert_eq!(revision.as_bytes(), &[1, 2, 3]);
  assert!(StoreRevision::new(Arc::from([])).is_err());

  let namespace =
    StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/metadata/identity").unwrap());
  let key = StoreKey::new(Arc::from(b"node-key".as_slice()));
  let value = StoreValue::new(Arc::from(b"metadata-value".as_slice()));
  assert_eq!(namespace.as_str(), "radiata.woooo.tech/metadata/identity");
  assert_eq!(key.as_bytes(), b"node-key");
  assert_eq!(value.as_bytes(), b"metadata-value");
  assert_eq!(
    value.digest(),
    StoreValue::new(Arc::from(b"metadata-value".as_slice())).digest(),
  );
  assert_ne!(
    value.digest(),
    StoreValue::new(Arc::from(b"different".as_slice())).digest(),
  );

  let entry = StoreEntry::new(namespace.clone(), key.clone(), value.clone());
  assert_eq!(entry.namespace(), &namespace);
  assert_eq!(entry.key(), &key);
  assert_eq!(entry.value(), &value);

  let digest = value.digest().clone();
  let transaction = TransactionId::parse("txn_0123456789abcdefghijk").unwrap();
  let operations = [
    StoreOperation::Check {
      namespace: namespace.clone(),
      key: key.clone(),
      expected: StoreExpectation::Absent,
    },
    StoreOperation::Put {
      namespace: namespace.clone(),
      key: key.clone(),
      expected: StoreExpectation::Exact(digest.clone()),
      value: value.clone(),
    },
    StoreOperation::Delete {
      namespace,
      key,
      expected: digest.clone(),
    },
    StoreOperation::ForgetReceipt {
      transaction: transaction.clone(),
      expected_operation_digest: digest.clone(),
    },
  ];
  assert_eq!(operations.len(), 4);

  let receipt = CommitReceipt::new(transaction.clone(), digest.clone(), revision.clone());
  assert_eq!(receipt.transaction(), &transaction);
  assert_eq!(receipt.operation_digest(), &digest);
  assert_eq!(receipt.committed_revision(), &revision);
  assert!(matches!(
    CommitOutcome::Committed(receipt.clone()),
    CommitOutcome::Committed(_)
  ));
  assert!(matches!(CommitOutcome::Aborted, CommitOutcome::Aborted));
  assert!(matches!(CommitOutcome::Conflict, CommitOutcome::Conflict));
  assert!(matches!(
    CommitOutcome::Unknown {
      transaction,
      operation_digest: digest,
    },
    CommitOutcome::Unknown { .. }
  ));
  assert!(matches!(
    ReconcileOutcome::Committed(receipt),
    ReconcileOutcome::Committed(_)
  ));
  assert!(matches!(
    ReconcileOutcome::DigestConflict,
    ReconcileOutcome::DigestConflict
  ));
}

#[test]
fn core_provider_traits_are_object_safe_and_external() {
  fn accept_traits(
    _keys: Arc<dyn KeyProvider>, _factory: Arc<dyn StorageFactory>, _storage: Box<dyn Storage>,
    _snapshot: Box<dyn StoreSnapshot>, _scan: Box<dyn StoreScan>,
  ) {
  }

  accept_traits(
    Arc::new(DummyKeys),
    Arc::new(DummyFactory),
    Box::new(DummyStorage),
    Box::new(DummySnapshot {
      revision: StoreRevision::new(Arc::from([1_u8])).unwrap(),
    }),
    Box::new(DummyScan),
  );
}

fn complete_store_capabilities() -> StoreCapabilities {
  StoreCapabilities::new(DurabilityLevel::OsCrashDurable)
    .conditional_batch(true)
    .ordered_scan(true)
    .reconciliation(true)
    .exclusive_lifetime_lock(true)
    .transactional_migration(true)
}

fn inspect_requirements(requirements: &StoreRequirements) {
  let _ = requirements.required_durability();
  let _ = requirements.requires_conditional_batch();
  let _ = requirements.requires_ordered_scan();
  let _ = requirements.requires_reconciliation();
  let _ = requirements.requires_exclusive_lifetime_lock();
  let _ = requirements.requires_transactional_migration();
}

fn provider_error() -> Error {
  Error::provider(
    ProviderErrorKind::Internal,
    ProviderErrorContext::StorageSnapshot,
  )
}
