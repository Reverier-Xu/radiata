//! Public-API integration tests for active leave and identity rotation.
//!
//! Every test drives the facade only: an acknowledged `LeaveCluster`
//! replaces the identity, deletes the old key and the old identity's core
//! metadata, emits one `IdentityReplaced`, and shuts the node down with
//! `ShutdownReason::ActiveLeave`; a restart on either backend shows only
//! the replacement identity and never the old cluster's metadata.

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use radiata::{
  BoxFuture, Endpoint, Error, ErrorKind, EventOptions, EventReceive, IdentityReplaced,
  KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId, LeaveCluster, Listen,
  NodeBuilder, NodeHandle, PageMembers, PageSpec, PublicKey, PutResource,
  ReplaceIdentityAndDeleteOldCoreMetadata, ResourceLabels, ResourceName, ResourceUri,
  ResourceWrite, Result, Shutdown, ShutdownReason, Signature, WaitForShutdown,
  extension::KeyProvider,
};
#[cfg(any(feature = "json", feature = "redb"))]
use radiata::{PageTrust, SelectResources, Selector, extension::StorageFactory};

mod common;

/// A deterministic key provider with working deletion and a call log
/// (the shared scripted providers intentionally fail deletes, so the
/// leave's custody lane needs its own).
#[derive(Debug, Default)]
struct LeaveKeys {
  records: Mutex<BTreeMap<Vec<u8>, ed25519_dalek::SigningKey>>,
  operations: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
  deleted: Mutex<Vec<Vec<u8>>>,
  next: Mutex<u64>,
}

impl LeaveKeys {
  /// A provider whose generated keys start from `base`, so two providers
  /// in one test never collide on an identity.
  fn with_base(base: u64) -> Self {
    let provider = Self::default();
    *provider.next.lock().unwrap() = base;
    provider
  }

  fn seed_for(base: u64) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&base.to_le_bytes().repeat(4)[..32].try_into().unwrap())
  }

  fn create_at(&self, operation: &KeyOperationId) -> KeyCreateState {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation.as_str().as_bytes()) {
      let records = self.records.lock().unwrap();
      let signing = &records[handle];
      return KeyCreateState::Present(radiata::CreatedKey::new(
        KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
        PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      ));
    }
    let mut next = self.next.lock().unwrap();
    let index = *next;
    *next += 1;
    let signing = Self::seed_for(index + 1);
    let handle = format!("leave-handle-{index}").into_bytes();
    let created = radiata::CreatedKey::new(
      KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    );
    operations.insert(operation.as_str().as_bytes().to_vec(), handle.clone());
    self.records.lock().unwrap().insert(handle, signing);
    KeyCreateState::Present(created)
  }

  #[cfg(any(feature = "json", feature = "redb"))]
  fn deleted_count(&self) -> usize {
    self.deleted.lock().unwrap().len()
  }
}

impl KeyProvider for LeaveKeys {
  fn capabilities(&self) -> KeyCapabilities {
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move { Ok(self.create_at(operation)) })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      let operations = self.operations.lock().unwrap();
      let Some(handle) = operations.get(operation.as_str().as_bytes()) else {
        return Ok(KeyCreateState::Absent);
      };
      let records = self.records.lock().unwrap();
      let Some(signing) = records.get(handle) else {
        return Ok(KeyCreateState::Absent);
      };
      Ok(KeyCreateState::Present(radiata::CreatedKey::new(
        KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
        PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      )))
    })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| PublicKey::from_bytes(signing.verifying_key().to_bytes()))
      .ok_or_else(|| {
        Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeyPublicKey,
        )
      });
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    use ed25519_dalek::Signer as _;
    let result = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|signing| Signature::from_bytes(signing.sign(message).to_bytes()))
      .ok_or_else(|| {
        Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeySign,
        )
      });
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    let removed = self
      .records
      .lock()
      .unwrap()
      .remove(handle.expose_provider_handle());
    if removed.is_some() {
      self
        .deleted
        .lock()
        .unwrap()
        .push(handle.expose_provider_handle().to_vec());
    }
    Box::pin(async move { Ok(KeyDeleteState::Absent) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    let present = self
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle());
    Box::pin(async move {
      Ok(if present {
        KeyDeleteState::Present
      } else {
        KeyDeleteState::Absent
      })
    })
  }
}

fn write(name_seed: u8) -> PutResource {
  PutResource::new(ResourceWrite::new(
    ResourceName::parse(&format!(
      "radiata.woooo.tech/resources/leave-{name_seed:03}"
    ))
    .unwrap(),
    ResourceLabels::new(
      radiata::LabelValue::parse("document").unwrap(),
      ResourceUri::parse(&format!("file:///leave/{name_seed:03}")).unwrap(),
    ),
  ))
  .unwrap()
}

/// One resource write with bounded retries: a commit racing the
/// anti-entropy driver's write transiently refuses with NotReady (the
/// harness precedent for admission-sensitive commands).
async fn put_with_retry(handle: &NodeHandle, name_seed: u8) {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    match handle.command(write(name_seed)).await {
      Ok(_) => return,
      Err(error) if error.kind() == ErrorKind::NotReady => {
        assert!(
          deadline.elapsed() < Duration::from_secs(30),
          "put never committed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
      Err(error) => panic!("put failed persistently: {error:?}"),
    }
  }
}

/// An acknowledged active leave binds the exact former and
/// replacement identities, emits one IdentityReplaced, and shuts the node
/// down with the ActiveLeave reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_replaces_identity_and_shuts_down_with_active_leave() {
  let storage = Arc::new(common::MemoryStorageFactory::new(
    common::required_capabilities(),
  ));
  let keys: Arc<dyn KeyProvider> = Arc::new(LeaveKeys::default());
  let handle = NodeBuilder::new(storage, keys).start().await.unwrap();
  handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  put_with_retry(&handle, 1).await;
  let former = handle
    .query(radiata::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();
  let mut events = handle
    .events::<IdentityReplaced>(EventOptions::new())
    .unwrap();

  let outcome = handle
    .command(LeaveCluster::new(
      ReplaceIdentityAndDeleteOldCoreMetadata::new(),
    ))
    .await
    .unwrap();
  assert_eq!(outcome.former_identity(), &former);
  assert_ne!(outcome.former_identity(), outcome.replacement_identity());

  // Exactly one replacement event naming both identities.
  let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .unwrap()
    .unwrap();
  match event {
    EventReceive::Item(replaced) => {
      assert_eq!(replaced.former_identity(), &former);
      assert_eq!(
        replaced.replacement_identity(),
        outcome.replacement_identity()
      );
    }
    _ => panic!("expected the identity replacement event"),
  }
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));

  // The node shuts down with the active-leave reason.
  let reason = handle.query(WaitForShutdown::new()).await.unwrap();
  assert_eq!(reason, ShutdownReason::ActiveLeave);
  assert_eq!(
    handle.query(radiata::GetNodeStatus::new()).await.unwrap(),
    radiata::NodeStatus::Stopped
  );
}

/// The leaver announces its owner-signed leave record to
/// connected sessions before rotating; the peer persists the terminal
/// evidence (one `MemberChanged` for the former identity) and the leaver's
/// bounded first-ack wait completes well before its bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_announces_to_connected_peers_before_rotating() {
  {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
      tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=trace"))
        .with_test_writer()
        .init();
    });
  }
  let listener_storage = Arc::new(common::MemoryStorageFactory::new(
    common::required_capabilities(),
  ));
  let leaver_storage = Arc::new(common::MemoryStorageFactory::new(
    common::required_capabilities(),
  ));
  let listener = NodeBuilder::new(
    listener_storage,
    Arc::new(LeaveKeys::with_base(100)) as Arc<dyn KeyProvider>,
  )
  .start()
  .await
  .unwrap();
  let leaver = NodeBuilder::new(
    leaver_storage,
    Arc::new(LeaveKeys::with_base(200)) as Arc<dyn KeyProvider>,
  )
  .start()
  .await
  .unwrap();
  let endpoint = listener
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap()
    .endpoint()
    .clone();
  common::merge_with_retry(&leaver, &listener, endpoint).await;
  let former = leaver
    .query(radiata::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();
  let mut member_events = listener
    .events::<radiata::MemberChanged>(EventOptions::new())
    .unwrap();

  let started = std::time::Instant::now();
  let outcome = leaver
    .command(LeaveCluster::new(
      ReplaceIdentityAndDeleteOldCoreMetadata::new(),
    ))
    .await
    .unwrap();
  assert_eq!(outcome.former_identity(), &former);
  // The first admission acknowledgement arrived well inside the bound.
  assert!(started.elapsed() < Duration::from_secs(5));

  // The peer observed the leave record for the former identity. The
  // authoritative observation is the member page (the applied leave
  // removes the former descriptor); the event stream is only a fast
  // path, because a loaded runner may lag the subscription and lag
  // drops notifications without replaying them.
  let observed = tokio::time::timeout(Duration::from_secs(60), async {
    loop {
      let present = listener
        .query(PageMembers::new(PageSpec::first(8).unwrap()))
        .await
        .unwrap()
        .items()
        .iter()
        .any(|member| member.node_id() == &former);
      if !present {
        break;
      }
      match tokio::time::timeout(Duration::from_millis(200), member_events.recv()).await {
        Ok(Ok(EventReceive::Item(changed))) if changed.node_id() == &former => break,
        Ok(Ok(_)) => continue,
        Ok(Err(_)) | Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
      }
    }
  })
  .await;
  assert!(observed.is_ok(), "the peer never observed the leave");
  listener.command(Shutdown::new()).await.unwrap();
}

/// With no connected session the announcement has nobody to
/// acknowledge it, so no wait engages and the leave completes immediately
/// (silent leave degrades to the cleanup path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leave_without_peers_completes_without_waiting() {
  let storage = Arc::new(common::MemoryStorageFactory::new(
    common::required_capabilities(),
  ));
  let handle = NodeBuilder::new(storage, Arc::new(LeaveKeys::default()))
    .start()
    .await
    .unwrap();
  let outcome = handle
    .command(LeaveCluster::new(
      ReplaceIdentityAndDeleteOldCoreMetadata::new(),
    ))
    .await
    .unwrap();
  assert_ne!(outcome.former_identity(), outcome.replacement_identity());
  let reason = handle.query(WaitForShutdown::new()).await.unwrap();
  assert_eq!(reason, ShutdownReason::ActiveLeave);
}

/// After the leave and a restart, the store shows no old
/// identity metadata — no cluster, members, trust, or resources — while
/// the replacement identity runs and the old key is provider-deleted.
#[cfg(all(feature = "json", unix))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_leave_restart_shows_only_the_replacement() {
  let directory = tempfile::tempdir().unwrap();
  leave_restart_shows_only_the_replacement(radiata::adapters::json_store(
    directory.path().to_path_buf(),
  ))
  .await;
}

#[cfg(feature = "redb")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redb_leave_restart_shows_only_the_replacement() {
  let directory = tempfile::tempdir().unwrap();
  leave_restart_shows_only_the_replacement(radiata::adapters::redb_store(
    directory.path().join("store.redb"),
  ))
  .await;
}

#[cfg(any(feature = "json", feature = "redb"))]
async fn leave_restart_shows_only_the_replacement(storage: Arc<dyn StorageFactory>) {
  let keys = Arc::new(LeaveKeys::default());
  let provider: Arc<dyn KeyProvider> = keys.clone();
  let former_handle_bytes;
  let replacement;
  {
    let handle = NodeBuilder::new(Arc::clone(&storage), provider.clone())
      .start()
      .await
      .unwrap();
    handle
      .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
      .await
      .unwrap();
    put_with_retry(&handle, 2).await;
    let former = handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone();
    former_handle_bytes = former.clone();
    let outcome = handle
      .command(LeaveCluster::new(
        ReplaceIdentityAndDeleteOldCoreMetadata::new(),
      ))
      .await
      .unwrap();
    assert_eq!(outcome.former_identity(), &former_handle_bytes);
    replacement = outcome.replacement_identity().clone();
    let reason = handle.query(WaitForShutdown::new()).await.unwrap();
    assert_eq!(reason, ShutdownReason::ActiveLeave);
    // The former identity's key passed the custody protocol exactly once.
    assert_eq!(keys.deleted_count(), 1);
  }

  // Restart on the same store: members, trust, and resources are wiped —
  // the replacement identity is born with its own singleton cluster, so
  // the local view resolves to exactly the replacement.
  let handle = NodeBuilder::new(storage, provider).start().await.unwrap();
  let local = handle.query(radiata::GetLocalNode::new()).await.unwrap();
  assert_eq!(local.node_id(), &replacement);
  assert_ne!(local.node_id(), &former_handle_bytes);
  assert!(
    handle
      .query(SelectResources::new(
        Selector::parse("radiata.woooo.tech/resources/type").unwrap(),
        PageSpec::first(8).unwrap(),
      ))
      .await
      .unwrap()
      .items()
      .is_empty()
  );
  // The member page can carry only the restarted node's own descriptor;
  // the old cluster's members (including the former identity) are gone.
  let members = handle
    .query(PageMembers::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(members.items().len() <= 1, "old membership must be wiped");
  assert!(
    members
      .items()
      .iter()
      .all(|member| member.node_id() == &replacement),
    "only the replacement identity may appear"
  );
  assert!(
    handle
      .query(PageTrust::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap()
      .items()
      .is_empty()
  );

  // The old identity never returns: the restarted node is exactly the
  // replacement identity's singleton cluster (asserted above).

  handle.command(Shutdown::new()).await.unwrap();
}
