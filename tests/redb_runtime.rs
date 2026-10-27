#![cfg(feature = "redb")]

//! Public-API integration tests for the redb storage adapter.
//!
//! Every test drives the adapter through `adapters::redb_store` and the
//! public `NodeBuilder`/provider SPI only. Test names are prefixed
//! `redb_runtime_` for the task verifier's nonempty lane proof.

use std::sync::{Arc, Mutex};

use radiata::{
  BoxFuture, ErrorKind, IncomingStream, KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle,
  KeyOperationId, NodeBuilder, NodeConfig, NodeHandle, NodeStatus, PacketConsumer, ProtocolTag,
  PublicKey, Result, RoutingPolicy, Signature, StreamPolicy, StreamTarget,
  extension::{KeyProvider, StorageFactory},
};

mod common;

use common::{MemoryStorageFactory, required_capabilities};

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
  assert_eq!(first.status(), NodeStatus::Running);
  first.shutdown().await.unwrap();
  assert_eq!(calls.create.lock().unwrap().len(), 1);

  let second = start(
    radiata::adapters::redb_store(dir.path().join("store.redb")),
    Arc::new(DeterministicKeys::new(11, Arc::clone(&calls))),
  )
  .await
  .unwrap();
  assert_eq!(second.status(), NodeStatus::Running);
  second.shutdown().await.unwrap();
  assert_eq!(calls.create.lock().unwrap().len(), 1);
  assert!(*calls.public_key.lock().unwrap() >= 2);
}

/// The shutdown reply returns only once the storage execution barrier
/// has drained every execution holding the database — the detached
/// commits (audit 2026-10-23 P1-10) AND the snapshot executions whose
/// blocking reads or live handles used to pin the file lock a few
/// milliseconds past the reply (audit 2026-10-27 B3). The reopen after
/// every round is immediate and un-retried: a single `StorageLocked`
/// here is the regression the barrier's read half exists to prevent.
/// The rounds repeat the exact reproduction shape observed before the
/// fix (durable activity, shutdown, immediate reopen) because the race
/// landed in a minority of rounds under load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redb_runtime_shutdown_releases_the_file_lock_before_the_reply() {
  const ROUNDS: usize = 12;
  let dir = tempfile::tempdir().unwrap();
  let path = dir.path().join("store.redb");
  let keys = Arc::new(DeterministicKeys::new(13, Arc::new(Calls::default())));
  for round in 0..ROUNDS {
    let handle = start(
      radiata::adapters::redb_store(path.clone()),
      Arc::clone(&keys),
    )
    .await
    .unwrap_or_else(|error| panic!("round {round} open failed: {error:?}"));
    handle.shutdown().await.unwrap();
    let reopened = start(
      radiata::adapters::redb_store(path.clone()),
      Arc::clone(&keys),
    )
    .await
    .unwrap_or_else(|error| panic!("round {round} reopen failed: {error:?}"));
    reopened.shutdown().await.unwrap();
  }
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
      second.shutdown().await.unwrap();
      panic!("concurrent open unexpectedly succeeded");
    }
  };
  assert_eq!(error.kind(), ErrorKind::StorageLocked);
  let rendered = error.to_string();
  assert!(
    !rendered.contains(dir.path().to_str().unwrap()),
    "error rendering leaks the storage path: {rendered}"
  );
  first.shutdown().await.unwrap();
}

/// The receiver side of the trace-tail lane below: drains every body so
/// the origin's stream — and with it the origin pump's durable terminal
/// fact — actually completes.
#[derive(Debug, Default)]
struct TraceDrain {
  received: Mutex<usize>,
}

impl PacketConsumer for TraceDrain {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        drop(chunk);
      }
      *self.received.lock().unwrap() += 1;
      Ok(())
    })
  }
}

/// One bounded chunk: the routed bodies below are single-chunk streams,
/// so a burst of them interleaves admission and terminal facts tightly.
fn trace_lane_body(
  index: usize,
) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static {
  let chunk: Arc<[u8]> = Arc::from(
    format!("trace-lane-{index}")
      .into_bytes()
      .into_boxed_slice(),
  );
  futures_util::stream::iter([Ok(chunk)])
}

/// The routed-traffic twin of the lock-release regression above (the
/// audit 2026-10-27 B3 residual, mechanism 2): the trace sink's detached
/// terminal-fact tasks used to hold their identity context — and with it
/// the redb file lock — invisibly to the shutdown barrier, so a
/// shutdown with routed traffic in flight could answer its reply while
/// trace persistence still pinned the file. The sink now holds that
/// context weakly: every task the barrier cannot see (still queued,
/// still parked on the sink's persistence permits, or not yet polled)
/// finds the store released and skips its write instead of re-pinning
/// it. Each round drives a burst of routed streams — the only producer
/// of terminal trace facts — until the first durable fact proves the
/// scenario, shuts the redb node down, and reopens the same file
/// immediately and un-retried. Like the lane above, the race landed in
/// a minority of rounds under load, so the rounds repeat the exact
/// reproduction shape (terminal-fact burst, shutdown, immediate
/// reopen); the skip itself — and its accounting — is pinned
/// deterministically by the lib tests in `routing::trace`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redb_runtime_shutdown_releases_the_file_lock_with_inflight_trace_persistence() {
  const PROTOCOL_TAG: &str = "radiata.woooo.tech/protocols/redb-trace-tail";
  const FEATURE_TAG: &str = "radiata.woooo.tech/features/session-core";
  /// Streams per round: well beyond the sink's sixteen
  /// concurrent-persistence permits, so when the first durable terminal
  /// fact lands the rest of the burst is still admitted, permit-parked,
  /// or mid-commit — the population the shutdown barrier cannot see.
  const STREAMS: usize = 40;
  const ROUNDS: usize = 8;

  fn quiet_config() -> NodeConfig {
    NodeConfig::new()
      .with_anti_entropy_interval(std::time::Duration::from_secs(3_600))
      .unwrap()
  }

  fn registry_with(consumer: Arc<dyn PacketConsumer>) -> radiata::ExtensionRegistry {
    let mut registry = radiata::ExtensionRegistry::new();
    registry
      .register_protocol(
        radiata::ProtocolDefinition::new(
          ProtocolTag::parse(PROTOCOL_TAG).unwrap(),
          radiata::FeatureTag::parse(FEATURE_TAG).unwrap(),
        ),
        consumer,
      )
      .unwrap();
    registry
  }

  let trace_counter = |snapshot: &radiata::ObservabilitySnapshot| {
    snapshot
      .counter(
        &radiata::QualifiedTag::parse(radiata::ObservabilitySnapshot::TRACE_RECORDS).unwrap(),
      )
      .unwrap()
  };

  common::init_tracing();
  let dir = tempfile::tempdir().unwrap();
  let path = dir.path().join("store.redb");
  // One key identity for the redb node across every round: the reopen
  // loads the stored identity instead of creating a new one, the exact
  // restart shape of the first lane above.
  let anchor_keys = Arc::new(DeterministicKeys::new(21, Arc::new(Calls::default())));

  for round in 0..ROUNDS {
    // The redb anchor: quiet driver (nothing but this lane's own writes
    // near the measured window) and the shared drain protocol.
    let anchor = NodeBuilder::new(radiata::adapters::redb_store(path.clone()))
      .keys(Arc::clone(&anchor_keys) as Arc<dyn KeyProvider>)
      .config(quiet_config())
      .extensions(registry_with(Arc::new(TraceDrain::default())))
      .start()
      .await
      .unwrap_or_else(|error| panic!("round {round} open failed: {error:?}"));
    let listener = anchor
      .listeners()
      .create(radiata::Endpoint::parse("wss://127.0.0.1:0").unwrap())
      .await
      .unwrap()
      .wait()
      .await
      .unwrap();

    // The peer on an in-memory store: only its endpoint matters, its
    // storage never touches the measured file.
    let drain = Arc::new(TraceDrain::default());
    let peer = NodeBuilder::new(Arc::new(MemoryStorageFactory::new(required_capabilities())))
      .keys(Arc::new(DeterministicKeys::new(
        22,
        Arc::new(Calls::default()),
      )))
      .config(quiet_config())
      .extensions(registry_with(Arc::clone(&drain) as Arc<dyn PacketConsumer>))
      .start()
      .await
      .unwrap();
    common::merge_with_retry(&peer, &anchor, listener.endpoint().clone()).await;
    let peer_id = peer.local_node().await.unwrap().node_id().clone();

    // The burst: every stream's origin pump lands a durable terminal
    // fact on the anchor's redb store, and the store's commits
    // fsync-serialize, so under load the tail of the burst is still
    // admitted or permit-parked when the shutdown below fires.
    let protocol = ProtocolTag::parse(PROTOCOL_TAG).unwrap();
    let mut sends = tokio::task::JoinSet::new();
    for index in 0..STREAMS {
      let anchor = anchor.clone();
      let target = StreamTarget::Exact(peer_id.clone());
      let protocol = protocol.clone();
      sends.spawn(async move {
        anchor
          .send(
            target,
            protocol.clone(),
            StreamPolicy::new(RoutingPolicy::Direct, 1).unwrap(),
            trace_lane_body(index),
          )
          .await
          .unwrap();
      });
    }
    while sends.join_next().await.is_some() {}

    // The scenario guard: wait only until the FIRST durable terminal
    // fact lands — proof the burst really produces trace persistence —
    // and nothing more. Waiting for the whole burst to drain would wait
    // away the very tail this lane measures: under load the remaining
    // facts are still admitted, permit-parked, or mid-commit when the
    // shutdown below fires.
    let durable_trace = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while trace_counter(&anchor.metrics().await.unwrap()) < 1 {
      assert!(
        std::time::Instant::now() < durable_trace,
        "round {round}: no durable trace fact ever landed"
      );
      tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let received = *drain.received.lock().unwrap();
    assert!(
      received >= 1,
      "round {round}: the routed bodies never flowed ({received}/{STREAMS} received)"
    );

    // The measured window: shutdown reply, then the immediate
    // un-retried reopen of the same file.
    anchor.shutdown().await.unwrap();
    let reopened = NodeBuilder::new(radiata::adapters::redb_store(path.clone()))
      .keys(Arc::clone(&anchor_keys) as Arc<dyn KeyProvider>)
      .config(quiet_config())
      .extensions(registry_with(Arc::new(TraceDrain::default())))
      .start()
      .await
      .unwrap_or_else(|error| {
        panic!("round {round} reopen hit the residual trace lock tail: {error:?}")
      });
    reopened.shutdown().await.unwrap();
    peer.shutdown().await.unwrap();
  }
}
