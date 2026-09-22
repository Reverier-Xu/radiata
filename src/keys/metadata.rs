//! The default metadata-store-backed Ed25519 key store: the runtime's
//! built-in custody when the caller does not inject a `KeyProvider`.
//!
//! One reserved metadata family (`key-seed-v1`) holds one seed row per
//! custody operation, in the same store that journals the key-creation
//! and key-deletion intents referring to it. The custody contract maps
//! onto the storage contract directly:
//!
//! - **The row is the evidence.** A seed row exists if and only if the
//!   conditional `Put` that carried it committed; the store's atomic
//!   transactions leave no torn state, so existence is always provable and the
//!   tri-state contract collapses to a snapshot read (`reconcile_create` and
//!   `reconcile_delete` never report `Unknown` from key-level doubt).
//! - **First seed wins.** Create commits one `Put { expected: Absent }`; the
//!   conditional expectation is the idempotency primitive, so across retries
//!   and concurrent creators of one operation id exactly one seed ever reaches
//!   durable storage, and every later call resolves to it. A lost race re-reads
//!   the winner instead of overwriting.
//! - **Deletion is a conditional commit.** Delete removes the row by its exact
//!   content digest, so a concurrent change surfaces as a typed conflict that
//!   re-reads and re-decides, never as a stale overwrite.
//!
//! Signing never touches the store: a seed is loaded once per handle
//! into an in-memory `SigningKey` that zeroizes on drop, and every
//! completed removal evicts the cached key. The durable seed bytes sit
//! next to the metadata they anchor, so custody and metadata share one
//! exclusive lifetime lock, one backup, and one restart story — the
//! provider that can read the identity record can always sign it.

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer as _, SigningKey};

use super::{
  SECRET_LEN, custody_corrupt, fresh_secret, handle_for, operation_from_handle,
  validate_delete_pair,
};
use crate::{
  BoxFuture, CreatedKey, Error, KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle,
  KeyOperationId, ProviderErrorContext, ProviderErrorKind, PublicKey, Result, Signature,
  StoreExpectation, StoreKey, StoreOperation, StoreTransaction, StoreValue,
  api::SystemEntropy,
  provider::{CommitOutcome, KeyProvider, ReconcileOutcome, Storage},
  storage::families,
};

/// The bounded retry budget per create or delete against unrelated store
/// traffic: every competing commit advances the base revision, so a busy
/// store may conflict a conditional write without any key-level race.
/// Each attempt re-snapshots and re-decides from the row itself.
const COMMIT_ATTEMPTS: usize = 8;

/// The durable key store over the node's own metadata storage. The
/// `storage` handle is the same one the metadata store commits through,
/// so custody and metadata share one lifetime lock and one crash domain.
pub(crate) struct MetadataKeyStore {
  storage: Arc<dyn Storage>,
  /// Loaded signing keys by handle bytes. Populated on first use, so
  /// signing never touches the store; evicted on every completed removal
  /// so a deleted key's last in-memory copy zeroizes with the entry.
  loaded: Mutex<BTreeMap<Vec<u8>, SigningKey>>,
}

impl MetadataKeyStore {
  pub(crate) fn new(storage: Arc<dyn Storage>) -> Self {
    Self {
      storage,
      loaded: Mutex::new(BTreeMap::new()),
    }
  }

  /// The seed-row namespace: the reserved `key-seed-v1` catalog family,
  /// parsed through the catalog's single conversion point. The tag is a
  /// compile-time constant; a parse failure is a programming error that
  /// fails closed as a typed provider error instead of a panic.
  fn namespace() -> Result<crate::StoreNamespace> {
    families::namespace(families::KEY_SEED_NAMESPACE)
  }

  /// The row key of one handle: the handle's own bytes, matching the
  /// built-in adapters' discipline (one handle per operation id, named
  /// and validated by it).
  fn row_key(handle: &KeyHandle) -> StoreKey {
    StoreKey::new(handle.expose_provider_handle().into())
  }

  /// Reads one seed row, proving its shape: the row exists only with
  /// exactly `SECRET_LEN` seed bytes, and anything else is custody
  /// corruption that fabricates no key state.
  async fn load_seed(
    &self, handle: &KeyHandle, context: ProviderErrorContext,
  ) -> Result<Option<SigningKey>> {
    let namespace = Self::namespace()?;
    let snapshot = self.storage.snapshot().await?;
    let Some(value) = snapshot.get(&namespace, &Self::row_key(handle)).await? else {
      return Ok(None);
    };
    drop(snapshot);
    Ok(Some(Self::seed_from_row(&value, context)?))
  }

  /// Decodes one seed row into its signing key: exactly `SECRET_LEN`
  /// seed bytes, anything else is custody corruption that fabricates no
  /// key state. The stack copy is scrubbed before returning.
  fn seed_from_row(value: &StoreValue, context: ProviderErrorContext) -> Result<SigningKey> {
    let bytes = value.as_bytes();
    if bytes.len() != SECRET_LEN {
      return Err(custody_corrupt(context));
    }
    let mut seed = [0_u8; SECRET_LEN];
    seed.copy_from_slice(bytes);
    let signing = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(signing)
  }

  /// The loaded signing key for one handle: cache first, then the
  /// durable row. The cache entry lives until eviction, so repeat
  /// signatures and public-key reads are pure memory operations.
  async fn signing(&self, handle: &KeyHandle, context: ProviderErrorContext) -> Result<SigningKey> {
    operation_from_handle(handle)?;
    if let Some(signing) = self
      .loaded
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .get(handle.expose_provider_handle())
    {
      return Ok(signing.clone());
    }
    let Some(signing) = self.load_seed(handle, context).await? else {
      return Err(custody_corrupt(context));
    };
    let shared = signing.clone();
    self
      .loaded
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .insert(handle.expose_provider_handle().to_vec(), shared);
    Ok(signing)
  }

  /// Evicts one handle's cached signing key, zeroizing the last
  /// in-memory copy of a removed or reloaded seed.
  fn evict(&self, handle: &KeyHandle) {
    self
      .loaded
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .remove(handle.expose_provider_handle());
  }

  /// Commits one conditional transaction and classifies an indeterminate
  /// outcome through the storage contract's own reconciliation, so the
  /// key-level verdicts (Committed / Aborted / corrupt / Unknown) cannot
  /// drift from the store's receipt evidence.
  async fn commit_with_reconcile(&self, transaction: StoreTransaction) -> Result<CommitOutcome> {
    let transaction_id = transaction.id().clone();
    let operation_digest = transaction.operation_digest().clone();
    match self.storage.commit(transaction).await? {
      CommitOutcome::Unknown { .. } => {
        match self
          .storage
          .reconcile(&transaction_id, &operation_digest)
          .await?
        {
          ReconcileOutcome::Committed(receipt) => Ok(CommitOutcome::Committed(receipt)),
          ReconcileOutcome::Aborted => Ok(CommitOutcome::Aborted),
          ReconcileOutcome::DigestConflict | ReconcileOutcome::Unknown => Err(Error::provider(
            ProviderErrorKind::StorageCorrupt,
            ProviderErrorContext::StorageReconcile,
          )),
        }
      }
      settled => Ok(settled),
    }
  }

  /// The create core: prove the row from the snapshot, or mint one seed
  /// and land it under the absent expectation. `Some` is the decided
  /// `KeyCreateState`; `None` means the attempt conflicted and the
  /// caller should re-snapshot.
  async fn create_attempt(&self, handle: &KeyHandle) -> Result<Option<KeyCreateState>> {
    let namespace = Self::namespace()?;
    let snapshot = self.storage.snapshot().await?;
    if let Some(value) = snapshot.get(&namespace, &Self::row_key(handle)).await? {
      // The row exists but cannot prove a key: the create state is
      // unknown — fail closed, never overwrite.
      let Some(signing) = Self::seed_from_row(&value, ProviderErrorContext::KeyCreate).ok() else {
        return Ok(Some(KeyCreateState::Unknown));
      };
      return Ok(Some(KeyCreateState::Present(CreatedKey::new(
        handle.clone(),
        PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      ))));
    }
    let secret = fresh_secret()?;
    let signing = SigningKey::from_bytes(&secret);
    let created = CreatedKey::new(
      handle.clone(),
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    );
    let transaction = StoreTransaction::new(
      crate::TransactionId::generate(&SystemEntropy)?,
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace,
        key: Self::row_key(handle),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(&secret[..])),
      }],
    )?;
    drop(snapshot);
    match self.commit_with_reconcile(transaction).await? {
      // This call's seed is durable: warm the cache and report it.
      CommitOutcome::Committed(_) => {
        self
          .loaded
          .lock()
          .unwrap_or_else(std::sync::PoisonError::into_inner)
          .insert(handle.expose_provider_handle().to_vec(), signing);
        Ok(Some(KeyCreateState::Present(created)))
      }
      // A proven non-apply leaves nothing durable under the operation:
      // retry with a fresh snapshot (and a fresh seed, since nothing
      // ever reached storage).
      CommitOutcome::Aborted | CommitOutcome::Conflict => Ok(None),
      // create_ed25519's contract maps an undecided create to Unknown.
      CommitOutcome::Unknown { .. } => Ok(Some(KeyCreateState::Unknown)),
    }
  }
}

impl std::fmt::Debug for MetadataKeyStore {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("MetadataKeyStore")
      .finish_non_exhaustive()
  }
}

impl KeyProvider for MetadataKeyStore {
  fn capabilities(&self) -> KeyCapabilities {
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      let handle = handle_for(operation)?;
      for _ in 0..COMMIT_ATTEMPTS {
        if let Some(decided) = self.create_attempt(&handle).await? {
          return Ok(decided);
        }
      }
      Err(Error::conflict("key seed create"))
    })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      let handle = handle_for(operation)?;
      let namespace = Self::namespace()?;
      let snapshot = self.storage.snapshot().await?;
      let row = snapshot.get(&namespace, &Self::row_key(&handle)).await?;
      drop(snapshot);
      match row {
        // The store's atomic transactions leave no torn state; an
        // undecodable row is foreign corruption that proves nothing,
        // so the state is unknown — fail closed, never overwrite.
        Some(value) => match Self::seed_from_row(&value, ProviderErrorContext::KeyReconcile) {
          Ok(signing) => Ok(KeyCreateState::Present(CreatedKey::new(
            handle,
            PublicKey::from_bytes(signing.verifying_key().to_bytes()),
          ))),
          Err(_) => Ok(KeyCreateState::Unknown),
        },
        // An absent row provably never received a seed under this
        // operation, so the caller may create it.
        None => Ok(KeyCreateState::Absent),
      }
    })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    Box::pin(async move {
      let signing = self
        .signing(handle, ProviderErrorContext::KeyPublicKey)
        .await?;
      Ok(PublicKey::from_bytes(signing.verifying_key().to_bytes()))
    })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async move {
      let signing = self.signing(handle, ProviderErrorContext::KeySign).await?;
      Ok(Signature::from_bytes(signing.sign(message).to_bytes()))
    })
  }

  fn delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      validate_delete_pair(operation, handle)?;
      for _ in 0..COMMIT_ATTEMPTS {
        let namespace = Self::namespace()?;
        let snapshot = self.storage.snapshot().await?;
        let Some(value) = snapshot.get(&namespace, &Self::row_key(handle)).await? else {
          self.evict(handle);
          return Ok(KeyDeleteState::Absent);
        };
        let expected = value.digest().clone();
        let base_revision = snapshot.revision().clone();
        drop(snapshot);
        let transaction = StoreTransaction::new(
          crate::TransactionId::generate(&SystemEntropy)?,
          base_revision,
          vec![StoreOperation::Delete {
            namespace,
            key: Self::row_key(handle),
            expected,
          }],
        )?;
        match self.commit_with_reconcile(transaction).await? {
          CommitOutcome::Committed(_) => {
            self.evict(handle);
            return Ok(KeyDeleteState::Present);
          }
          CommitOutcome::Aborted | CommitOutcome::Conflict => {}
          // delete's contract maps an undecided removal to Unknown.
          CommitOutcome::Unknown { .. } => return Ok(KeyDeleteState::Unknown),
        }
      }
      Err(Error::conflict("key seed delete"))
    })
  }

  fn reconcile_delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      validate_delete_pair(operation, handle)?;
      let namespace = Self::namespace()?;
      let snapshot = self.storage.snapshot().await?;
      match snapshot.get(&namespace, &Self::row_key(handle)).await? {
        // The row survived: the removal did not land and the caller may
        // re-issue it.
        Some(_) => Ok(KeyDeleteState::Present),
        None => {
          self.evict(handle);
          Ok(KeyDeleteState::Absent)
        }
      }
    })
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::{
    KeyCreateState, KeyDeleteState, StoreExpectation, StoreOperation, StoreRequirements,
    StoreValue,
    provider::StorageFactory,
    storage::contract::{ReferenceFactory, required_capabilities},
  };

  fn operation(tag: u128) -> KeyOperationId {
    KeyOperationId::parse(&format!("keyop-{tag:021}")).unwrap()
  }

  async fn fresh_storage() -> Arc<dyn Storage> {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let factory: Arc<dyn StorageFactory> = reference;
    factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap()
      .into()
  }

  async fn store() -> MetadataKeyStore {
    MetadataKeyStore::new(fresh_storage().await)
  }

  /// Creates the same operation twice and through the reconcile path:
  /// one durable seed wins, and every later answer resolves to it.
  #[tokio::test]
  async fn create_is_idempotent_per_operation_id() {
    let keys = store().await;
    let op = operation(1);
    let first = match keys.create_ed25519(&op).await.unwrap() {
      KeyCreateState::Present(created) => created,
      other => panic!("expected Present, got {other:?}"),
    };
    let second = match keys.create_ed25519(&op).await.unwrap() {
      KeyCreateState::Present(created) => created,
      other => panic!("expected Present, got {other:?}"),
    };
    assert_eq!(first, second);
    assert_eq!(
      keys.reconcile_create(&op).await.unwrap(),
      KeyCreateState::Present(first)
    );
    // A different operation id proves absent: nothing was ever stored.
    assert_eq!(
      keys.reconcile_create(&operation(2)).await.unwrap(),
      KeyCreateState::Absent
    );
  }

  /// A concurrent creator that won the race keeps its seed: the losing
  /// create reports the winner's key instead of overwriting the row.
  #[tokio::test]
  async fn lost_create_race_resolves_to_the_winner() {
    let storage = fresh_storage().await;
    let keys = MetadataKeyStore::new(Arc::clone(&storage));
    let op = operation(3);
    // The winner lands a seed out-of-band (any other creator).
    let winner = {
      let rival = MetadataKeyStore::new(storage);
      match rival.create_ed25519(&op).await.unwrap() {
        KeyCreateState::Present(created) => created,
        other => panic!("expected Present, got {other:?}"),
      }
    };
    match keys.create_ed25519(&op).await.unwrap() {
      KeyCreateState::Present(created) => assert_eq!(created, winner),
      other => panic!("expected Present, got {other:?}"),
    }
  }

  /// Delete follows the tri-state contract: absent deletion is a no-op,
  /// present deletion reports Present, and reconcile reads the durable
  /// evidence. A deleted key refuses to sign or expose a public key.
  #[tokio::test]
  async fn delete_follows_the_tri_state_contract() {
    let keys = store().await;
    let op = operation(4);
    let handle = match keys.create_ed25519(&op).await.unwrap() {
      KeyCreateState::Present(created) => created.handle().clone(),
      other => panic!("expected Present, got {other:?}"),
    };
    // Reconcile before any deletion: the removal did not land.
    assert_eq!(
      keys.reconcile_delete(&op, &handle).await.unwrap(),
      KeyDeleteState::Present
    );
    assert_eq!(
      keys.delete(&op, &handle).await.unwrap(),
      KeyDeleteState::Present
    );
    assert_eq!(
      keys.reconcile_delete(&op, &handle).await.unwrap(),
      KeyDeleteState::Absent
    );
    // Deleting again is a proven no-op.
    assert_eq!(
      keys.delete(&op, &handle).await.unwrap(),
      KeyDeleteState::Absent
    );
    // The cached signing key is evicted: every later use fails closed.
    assert!(keys.sign(&handle, b"message").await.is_err());
    assert!(keys.public_key(&handle).await.is_err());
  }

  /// The same storage reopened through a fresh store signs with the same
  /// identity: custody follows the metadata, not the process.
  #[tokio::test]
  async fn signatures_survive_a_store_reopen() {
    let storage = fresh_storage().await;
    let op = operation(5);
    let created = match MetadataKeyStore::new(Arc::clone(&storage))
      .create_ed25519(&op)
      .await
      .unwrap()
    {
      KeyCreateState::Present(created) => created,
      other => panic!("expected Present, got {other:?}"),
    };
    let reopened = MetadataKeyStore::new(storage);
    assert_eq!(
      reopened.public_key(created.handle()).await.unwrap(),
      *created.public_key()
    );
    let signature = reopened.sign(created.handle(), b"message").await.unwrap();
    let verified = ed25519_dalek::VerifyingKey::from_bytes(created.public_key().as_bytes())
      .unwrap()
      .verify_strict(
        b"message",
        &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
      );
    assert!(verified.is_ok());
  }

  /// A handle issued by another provider is a caller error, never a
  /// lookup; a delete against a mismatched operation id never lands.
  #[tokio::test]
  async fn foreign_handles_are_caller_errors() {
    let keys = store().await;
    let foreign = KeyHandle::from_provider_bytes(Arc::from(b"not-a-keyop".as_slice())).unwrap();
    assert!(keys.public_key(&foreign).await.is_err());
    assert!(keys.sign(&foreign, b"message").await.is_err());
    let op = operation(6);
    let handle = match keys.create_ed25519(&op).await.unwrap() {
      KeyCreateState::Present(created) => created.handle().clone(),
      other => panic!("expected Present, got {other:?}"),
    };
    assert_eq!(
      keys
        .delete(&operation(7), &handle)
        .await
        .unwrap_err()
        .kind(),
      crate::ErrorKind::InvalidInput
    );
  }

  /// A row that does not parse as a seed fabricates no key state: the
  /// load fails closed as custody corruption.
  #[tokio::test]
  async fn unparseable_seed_rows_fail_closed() {
    let storage = fresh_storage().await;
    let keys = MetadataKeyStore::new(Arc::clone(&storage));
    let op = operation(8);
    let handle = handle_for(&op).unwrap();
    let namespace = MetadataKeyStore::namespace().unwrap();
    let snapshot = storage.snapshot().await.unwrap();
    let revision = snapshot.revision().clone();
    drop(snapshot);
    let transaction = StoreTransaction::new(
      crate::TransactionId::generate(&SystemEntropy).unwrap(),
      revision,
      vec![StoreOperation::Put {
        namespace,
        key: MetadataKeyStore::row_key(&handle),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(&b"short"[..])),
      }],
    )
    .unwrap();
    match storage.commit(transaction).await.unwrap() {
      CommitOutcome::Committed(_) => {}
      other => panic!("expected Committed, got {other:?}"),
    }
    // Reconcile reports Unknown: the row exists but proves no key, and
    // reads fail closed.
    assert!(matches!(
      keys.reconcile_create(&op).await.unwrap(),
      KeyCreateState::Unknown
    ));
    assert!(matches!(
      keys.create_ed25519(&op).await.unwrap(),
      KeyCreateState::Unknown
    ));
    assert!(keys.public_key(&handle).await.is_err());
    // Deletion still lands: the row is removable by digest.
    assert_eq!(
      keys.delete(&op, &handle).await.unwrap(),
      KeyDeleteState::Present
    );
  }
}
