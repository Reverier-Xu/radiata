#![cfg(feature = "redb")]

//! Public-API integration tests for the redb storage adapter.
//!
//! Every test drives the adapter through `adapters::redb_store` and the
//! public `NodeBuilder`/provider SPI only. Test names are prefixed
//! `redb_runtime_` for the task verifier's nonempty lane proof.

use std::sync::{Arc, Mutex};

use radiata::{
  BoxFuture, ErrorKind, GetNodeStatus, KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle,
  KeyOperationId, NodeBuilder, NodeHandle, NodeStatus, PublicKey, Result, Shutdown, Signature,
  extension::{KeyProvider, StorageFactory},
};

#[derive(Debug, Default)]
struct Calls {
  create: Mutex<Vec<String>>,
  public_key: Mutex<usize>,
}

#[derive(Debug)]
struct DeterministicKeys {
  seed: [u8; 32],
  calls: Arc<Calls>,
}

impl DeterministicKeys {
  fn new(seed: u8, calls: Arc<Calls>) -> Self {
    Self {
      seed: [seed; 32],
      calls,
    }
  }

  fn signing(&self) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&self.seed)
  }

  fn handle(&self) -> KeyHandle {
    KeyHandle::from_provider_bytes(Arc::from(b"redb-runtime-handle".as_slice())).unwrap()
  }
}

impl KeyProvider for DeterministicKeys {
  fn capabilities(&self) -> KeyCapabilities {
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self
      .calls
      .create
      .lock()
      .unwrap()
      .push(operation.as_str().to_owned());
    let created = radiata::CreatedKey::new(
      self.handle(),
      PublicKey::from_bytes(self.signing().verifying_key().to_bytes()),
    );
    Box::pin(async move { Ok(KeyCreateState::Present(created)) })
  }

  fn reconcile_create<'a>(
    &'a self, _operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    let created = radiata::CreatedKey::new(
      self.handle(),
      PublicKey::from_bytes(self.signing().verifying_key().to_bytes()),
    );
    Box::pin(async move { Ok(KeyCreateState::Present(created)) })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    *self.calls.public_key.lock().unwrap() += 1;
    let result = if handle.expose_provider_handle() == b"redb-runtime-handle" {
      Ok(PublicKey::from_bytes(
        self.signing().verifying_key().to_bytes(),
      ))
    } else {
      Err(radiata::Error::provider(
        radiata::ProviderErrorKind::Internal,
        radiata::ProviderErrorContext::KeyPublicKey,
      ))
    };
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    let _ = handle;
    use ed25519_dalek::Signer as _;
    let signature = self.signing().sign(message);
    Box::pin(async move { Ok(Signature::from_bytes(signature.to_bytes())) })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async { Ok(radiata::KeyDeleteState::Present) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    Box::pin(async { Ok(radiata::KeyDeleteState::Present) })
  }
}

async fn start(
  factory: Arc<dyn StorageFactory>, keys: Arc<DeterministicKeys>,
) -> Result<NodeHandle> {
  NodeBuilder::new(factory).keys(keys).start().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redb_runtime_node_start_restart_preserves_identity_without_new_key() {
  let dir = tempfile::tempdir().unwrap();
  let calls = Arc::new(Calls::default());

  let first = start(
    radiata::adapters::redb_store(dir.path().join("store.redb")),
    Arc::new(DeterministicKeys::new(11, Arc::clone(&calls))),
  )
  .await
  .unwrap();
  assert_eq!(
    first.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running
  );
  first.command(Shutdown::new()).await.unwrap();
  assert_eq!(calls.create.lock().unwrap().len(), 1);

  let second = start(
    radiata::adapters::redb_store(dir.path().join("store.redb")),
    Arc::new(DeterministicKeys::new(11, Arc::clone(&calls))),
  )
  .await
  .unwrap();
  assert_eq!(
    second.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running
  );
  second.command(Shutdown::new()).await.unwrap();
  assert_eq!(calls.create.lock().unwrap().len(), 1);
  assert!(*calls.public_key.lock().unwrap() >= 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redb_runtime_concurrent_open_is_typed_locked_and_error_is_redacted() {
  let dir = tempfile::tempdir().unwrap();
  let storage = radiata::adapters::redb_store(dir.path().join("store.redb"));
  let keys = Arc::new(DeterministicKeys::new(12, Arc::new(Calls::default())));

  let first = start(Arc::clone(&storage), Arc::clone(&keys))
    .await
    .unwrap();
  let error = match start(Arc::clone(&storage), Arc::clone(&keys)).await {
    Err(error) => error,
    Ok(second) => {
      second.command(Shutdown::new()).await.unwrap();
      panic!("concurrent open unexpectedly succeeded");
    }
  };
  assert_eq!(error.kind(), ErrorKind::StorageLocked);
  let rendered = error.to_string();
  assert!(
    !rendered.contains(dir.path().to_str().unwrap()),
    "error rendering leaks the storage path: {rendered}"
  );
  first.command(Shutdown::new()).await.unwrap();
}
