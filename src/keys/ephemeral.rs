//! The in-memory ephemeral Ed25519 key store behind
//! [`crate::adapters::ephemeral_key_store`].
//!
//! The same operation-id discipline as the file-backed adapter, held
//! entirely in memory: one handle per operation id, tri-state answers
//! from the store's own state, and strict handle validation. There are
//! no torn states to reconcile within a process lifetime — every
//! mutation is atomic under the store lock — so the reconcile methods
//! never report `Unknown` here.
//!
//! Zeroization by construction: a seed exists in exactly one place, an
//! [`ed25519_dalek::SigningKey`], whose drop zeroizes it (the dalek
//! `zeroize` feature); no secret clone ever leaves the store, and a
//! removed or dropped key is zeroized by that drop.

use std::{collections::BTreeMap, fmt, sync::Mutex};

use ed25519_dalek::{Signer as _, SigningKey};

use super::{custody_corrupt, handle_for, operation_from_handle, validate_delete_pair};
use crate::{
  BoxFuture, CreatedKey, Error, KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle,
  KeyOperationId, ProviderErrorContext, ProviderErrorKind, PublicKey, Result, Signature,
  provider::KeyProvider,
};

/// The process-lifetime key store: all custody is lost when the value
/// is dropped, by design and by documentation.
pub(crate) struct EphemeralKeyStore {
  records: Mutex<BTreeMap<Vec<u8>, SigningKey>>,
}

impl EphemeralKeyStore {
  pub(crate) fn new() -> Self {
    Self {
      records: Mutex::new(BTreeMap::new()),
    }
  }

  fn create_sync(&self, operation: &KeyOperationId) -> Result<KeyCreateState> {
    let handle = handle_for(operation)?;
    let mut records = self.lock();
    if let Some(signing) = records.get(handle.expose_provider_handle()) {
      return Ok(KeyCreateState::Present(Self::created(&handle, signing)));
    }
    let secret = fresh_secret()?;
    let signing = SigningKey::from_bytes(&secret);
    let created = Self::created(&handle, &signing);
    records.insert(handle.expose_provider_handle().to_vec(), signing);
    Ok(KeyCreateState::Present(created))
  }

  fn reconcile_create_sync(&self, operation: &KeyOperationId) -> Result<KeyCreateState> {
    let handle = handle_for(operation)?;
    let records = self.lock();
    match records.get(handle.expose_provider_handle()) {
      Some(signing) => Ok(KeyCreateState::Present(Self::created(&handle, signing))),
      // Within one process lifetime an absent record is provable; the
      // file-backed store's torn states do not exist here.
      None => Ok(KeyCreateState::Absent),
    }
  }

  fn load(&self, handle: &KeyHandle, context: ProviderErrorContext) -> Result<SigningKey> {
    operation_from_handle(handle)?;
    self
      .lock()
      .get(handle.expose_provider_handle())
      .cloned()
      .ok_or_else(|| custody_corrupt(context))
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Vec<u8>, SigningKey>> {
    self
      .records
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn created(handle: &KeyHandle, signing: &SigningKey) -> CreatedKey {
    CreatedKey::new(
      handle.clone(),
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    )
  }
}

impl fmt::Debug for EphemeralKeyStore {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("EphemeralKeyStore")
      .finish_non_exhaustive()
  }
}

impl KeyProvider for EphemeralKeyStore {
  fn capabilities(&self) -> KeyCapabilities {
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move { self.create_sync(operation) })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move { self.reconcile_create_sync(operation) })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    Box::pin(async move {
      let signing = self.load(handle, ProviderErrorContext::KeyPublicKey)?;
      Ok(PublicKey::from_bytes(signing.verifying_key().to_bytes()))
    })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async move {
      let signing = self.load(handle, ProviderErrorContext::KeySign)?;
      Ok(Signature::from_bytes(signing.sign(message).to_bytes()))
    })
  }

  /// Removes the key from custody. A returned secret is destroyed, not
  /// archived: the signing key drops and zeroizes here.
  fn delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      validate_delete_pair(operation, handle)?;
      let removed = self.lock().remove(handle.expose_provider_handle());
      // The tri-state reports the post-state, matching the file-backed
      // store: the caller observes absence, presence was pre-state.
      Ok(if removed.is_some() {
        KeyDeleteState::Present
      } else {
        KeyDeleteState::Absent
      })
    })
  }

  fn reconcile_delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async move {
      validate_delete_pair(operation, handle)?;
      let present = self.lock().contains_key(handle.expose_provider_handle());
      Ok(if present {
        KeyDeleteState::Present
      } else {
        KeyDeleteState::Absent
      })
    })
  }
}

fn fresh_secret() -> Result<zeroize::Zeroizing<[u8; 32]>> {
  let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
  getrandom::fill(&mut secret[..])
    .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::Entropy))?;
  Ok(secret)
}

#[cfg(test)]
mod tests {
  use super::EphemeralKeyStore;
  use crate::{
    ErrorKind, KeyCreateState, KeyDeleteState, KeyOperationId, PublicKey, Signature,
    provider::KeyProvider as _,
  };

  fn new_operation(value: u128) -> KeyOperationId {
    KeyOperationId::parse(&format!("keyop-{value:021}")).unwrap()
  }

  fn assert_present(state: KeyCreateState) -> (crate::KeyHandle, PublicKey) {
    match state {
      KeyCreateState::Present(created) => (created.handle().clone(), created.public_key().clone()),
      other => panic!("expected Present, got {other:?}"),
    }
  }

  /// Create, replay, sign, and strictly verify within one process
  /// lifetime; reconciliation answers from the store's own state.
  #[tokio::test]
  async fn lifecycle_and_reconcile_within_one_process() {
    let store = EphemeralKeyStore::new();
    let operation = new_operation(1);
    let message = b"ephemeral message";

    assert!(matches!(
      store.reconcile_create(&operation).await.unwrap(),
      KeyCreateState::Absent
    ));
    let (handle, public_key) = assert_present(store.create_ed25519(&operation).await.unwrap());
    let (replayed, replayed_key) = assert_present(store.create_ed25519(&operation).await.unwrap());
    assert_eq!(&handle, &replayed);
    assert_eq!(&public_key, &replayed_key);
    assert!(matches!(
      store.reconcile_create(&operation).await.unwrap(),
      KeyCreateState::Present(_)
    ));

    let signature: Signature = store.sign(&handle, message).await.unwrap();
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(public_key.as_bytes()).unwrap();
    verifying
      .verify_strict(
        message,
        &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
      )
      .unwrap();

    assert!(matches!(
      store.delete(&operation, &handle).await.unwrap(),
      KeyDeleteState::Present
    ));
    assert!(matches!(
      store.reconcile_delete(&operation, &handle).await.unwrap(),
      KeyDeleteState::Absent
    ));
    assert!(matches!(
      store.delete(&operation, &handle).await.unwrap(),
      KeyDeleteState::Absent
    ));
    let error = store.sign(&handle, message).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::StorageCorrupt);
    // A fresh operation id mints a different key; the deleted key is
    // destroyed, not archived.
    let fresh = new_operation(2);
    let (fresh_handle, fresh_key) = assert_present(store.create_ed25519(&fresh).await.unwrap());
    assert_ne!(&handle, &fresh_handle);
    assert_ne!(&public_key, &fresh_key);
  }

  /// Handles issued elsewhere are caller errors, never lookups.
  #[tokio::test]
  async fn foreign_handles_fail_typed() {
    let store = EphemeralKeyStore::new();
    let foreign =
      crate::KeyHandle::from_provider_bytes(std::sync::Arc::from(b"not-a-keyop".to_vec())).unwrap();
    let error = store.sign(&foreign, b"message").await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    let operation = new_operation(3);
    let (handle, _) = assert_present(store.create_ed25519(&operation).await.unwrap());
    let other = new_operation(4);
    let error = store.delete(&other, &handle).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    store.sign(&handle, b"still held").await.unwrap();
  }
}
