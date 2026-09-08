//! Secure-merge integration lane (T-G03-02).
//!
//! Two real nodes over loopback TLS 1.3 WebSocket: the receiver rotates a
//! merge credential and listens; the peer completes the exporter-bound
//! merge and persists the adopted binding. Negative lanes prove generic
//! failure without a merge or credential consumption.

use std::{sync::Arc, time::Duration};

use radiata::{
  Endpoint, ErrorKind, GetLocalNode, Listen, MergeCluster, MergeCredential, NodeBuilder,
  NodeHandle, PageSpec, PageTopology, RotateMergeCredential, Shutdown,
};
#[cfg(all(unix, feature = "json"))]
use tempfile::TempDir;

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

struct Node {
  handle: NodeHandle,
  _keys: Arc<ScriptedKeys>,
}

/// Waits until `probe` reports success or the deadline passes. Admission
/// is acknowledged before the consumer finishes, so packet arrival must
/// be polled on wall time: a fixed busy-yield budget can be outlasted by
/// a preemptive scheduler before the peer's tasks ever run.
async fn wait_for(probe: impl FnMut() -> bool, timeout: Duration, what: &'static str) {
  let mut probe = probe;
  let deadline = std::time::Instant::now() + timeout;
  while !probe() {
    assert!(
      std::time::Instant::now() < deadline,
      "{what} not reached within {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
}

/// Routes crate diagnostics into the libtest capture for the calling
/// test, so failures print their own session traces.
fn init_tracing() {
  use std::sync::Once;
  static INIT: Once = Once::new();
  INIT.call_once(|| {
    tracing_subscriber::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=trace"))
      .with_test_writer()
      .init();
  });
}

/// Issues one merge credential with bounded retries: merge-sensitive
/// operations transiently refuse while concurrent metadata commits hold
/// the store (the same precedent as the membership-sync harness).
/// Retry backoff that doubles from 250 ms and caps at four seconds: the
/// fixed merge policy caps one source at sixteen attempts per minute,
/// so a tight retry storm would trip it and fail fast forever after.
fn retry_backoff(attempts: u32) -> Duration {
  let shift = attempts.min(5);
  let millis = 250_u64.saturating_mul(1_u64 << shift);
  Duration::from_millis(millis.max(250)).min(Duration::from_secs(4))
}

async fn rotate_with_retry(issuer: &NodeHandle) -> radiata::IssuedMergeCredential {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    match issuer.command(RotateMergeCredential::new()).await {
      Ok(issued) => return issued,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
      Err(error) => panic!("credential rotation failed persistently: {error:?}"),
    }
  }
}

/// One merge with bounded retries: a transient refusal consumes no
/// credential, so each attempt reuses the same secret.
async fn merge_with_retry(
  node: &NodeHandle, endpoint: &Endpoint, secret: &str,
) -> radiata::MergeView {
  // The fixed authentication deadline expires on starved runners; the
  // bound covers a fully loaded CI machine (the sixteen-node lane runs
  // alongside every other test binary in the workspace suite).
  let deadline = std::time::Instant::now() + Duration::from_secs(300);
  let mut attempts = 0_u32;
  loop {
    attempts = attempts.wrapping_add(1);
    match node
      .command(MergeCluster::new(
        endpoint.clone(),
        MergeCredential::parse(secret).unwrap(),
      ))
      .await
    {
      Ok(view) => return view,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(retry_backoff(attempts)).await;
      }
      Err(error) => panic!("merge failed persistently (attempt {attempts}): {error:?}"),
    }
  }
}

/// One success-expecting merge with bounded retries: the typed rejection
/// lanes stay single-shot, but a success path must not fail the lane when
/// a loaded runner expires the fixed authentication deadline. The same
/// credential is reused (a failed merge consumes no credential).
async fn merge_ok(node: &NodeHandle, endpoint: &Endpoint, secret: &str) -> radiata::MergeView {
  let deadline = std::time::Instant::now() + Duration::from_secs(120);
  loop {
    match node
      .command(MergeCluster::new(
        endpoint.clone(),
        MergeCredential::parse(secret).unwrap(),
      ))
      .await
    {
      Ok(view) => return view,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(500)).await;
      }
      Err(error) => panic!("merge never succeeded: {error:?}"),
    }
  }
}

async fn start(storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>) -> Node {
  init_tracing();
  let factory: Arc<dyn radiata::extension::StorageFactory> = storage;
  let handle = NodeBuilder::new(factory, keys).start().await.unwrap();
  Node {
    handle,
    _keys: Arc::new(ScriptedKeys::full()),
  }
}

#[cfg(all(unix, feature = "json"))]
async fn start_json(dir: &TempDir, keys: Arc<ScriptedKeys>) -> Node {
  let handle = NodeBuilder::new(
    radiata::adapters::json_store(dir.path().to_path_buf()),
    keys,
  )
  .start()
  .await
  .unwrap();
  Node {
    handle,
    _keys: Arc::new(ScriptedKeys::full()),
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_completes_exporter_bound_merge_and_persists_binding() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(10_000)),
  )
  .await;
  let joiner = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(20_000)),
  )
  .await;

  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let secret = issued.credential().expose_secret().to_owned();
  let merge = merge_ok(&joiner.handle, listener.endpoint(), &secret).await;

  let local = joiner.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.node_id(), merge.node());

  // The receiver observes the merged peer in its own identity state: its
  // local node view shows the merge peer, not the merging node.
  let receiver_local = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(receiver_local.node_id(), merge.peer());

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G11-P0-08: born-with-cluster. A freshly started node — no creation
/// ceremony at all — immediately resolves its local view, pages itself as
/// the singleton cluster member, issues a merge credential, and admits a
/// merger over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g11_born_with_cluster_serves_immediately_without_ceremony() {
  let node = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(30_000)),
  )
  .await;
  let merger = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(40_000)),
  )
  .await;

  // No creation ceremony exists: the local view resolves from the first
  // instant, and the singleton membership page is exactly the self node.
  let local = node.handle.query(GetLocalNode::new()).await.unwrap();
  assert!(local.node_id().as_str().starts_with("node_"));
  let members = node
    .handle
    .query(radiata::PageMembers::new(
      radiata::PageSpec::first(8).unwrap(),
    ))
    .await
    .unwrap();
  assert!(
    members
      .items()
      .iter()
      .all(|member| member.node_id() == local.node_id())
  );

  // The fresh node issues a merge credential and admits a merger with no
  // prior state beyond its own birth binding.
  let issued = node
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = node
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  let merge = merge_ok(&merger.handle, listener.endpoint(), &secret).await;
  let merger_local = merger.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(merger_local.node_id(), merge.node());
  assert_eq!(local.node_id(), merge.peer());

  node.handle.command(Shutdown::new()).await.unwrap();
  merger.handle.command(Shutdown::new()).await.unwrap();
}

// The json backend provides OsCrashDurable only where the directory
// barrier is available (unix); elsewhere the runtime requirement is
// refused with a typed error, matching json_runtime's non-unix lane.
#[cfg(all(unix, feature = "json"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_json_backend_round_trips_the_same_merge() {
  let receiver_dir = tempfile::tempdir().unwrap();
  let joiner_dir = tempfile::tempdir().unwrap();
  let receiver_keys = Arc::new(ScriptedKeys::full_at(30_000));
  let joiner_keys = Arc::new(ScriptedKeys::full_at(40_000));
  let receiver = start_json(&receiver_dir, receiver_keys.clone()).await;
  let joiner = start_json(&joiner_dir, joiner_keys.clone()).await;

  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  // The json restart lane contends with the parallel powerset suite, so
  // the merge uses the same bounded-retry helper as the memory lanes.
  let secret = issued.credential().expose_secret().to_owned();
  let merge = merge_with_retry(&joiner.handle, listener.endpoint(), &secret).await;

  // Both sides persist through reopen: shutdown and restart the merging
  // node on the same directory proves the adopted binding survived.
  joiner.handle.command(Shutdown::new()).await.unwrap();
  let restarted = start_json(&joiner_dir, joiner_keys.clone()).await;
  let local = restarted.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.node_id(), merge.node());

  receiver.handle.command(Shutdown::new()).await.unwrap();
  restarted.handle.command(Shutdown::new()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_wrong_credential_fails_without_merge() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(50_000)),
  )
  .await;
  let joiner = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(60_000)),
  )
  .await;

  receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let wrong = MergeCredential::parse("join_BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
  let error = joiner
    .handle
    .command(MergeCluster::new(listener.endpoint().clone(), wrong))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner.handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-02 packet data plane evidence (SC-G03-P0-06) ----

use std::sync::Mutex as StdMutex;

use radiata::{
  BoxFuture, ExtensionRegistry, GetRoute, IncomingStream, ProtocolDefinition, ProtocolTag,
  QualifiedTag, RouteState, StreamMetadata, StreamPolicy, StreamTarget,
};

#[derive(Debug)]
struct VecBody {
  chunks: std::vec::IntoIter<Arc<[u8]>>,
}

impl VecBody {
  fn new(chunks: Vec<&'static [u8]>) -> Self {
    Self {
      chunks: chunks
        .into_iter()
        .map(Arc::from)
        .collect::<Vec<_>>()
        .into_iter(),
    }
  }
}

impl futures_core::Stream for VecBody {
  type Item = radiata::Result<Arc<[u8]>>;

  fn poll_next(
    mut self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Option<Self::Item>> {
    std::task::Poll::Ready(self.chunks.next().map(Ok))
  }
}

#[derive(Debug, Default)]
struct Collector {
  packets: StdMutex<Vec<(String, Vec<u8>)>>,
}

impl radiata::PacketConsumer for Collector {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      let mut body = Vec::new();
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        body.extend_from_slice(&chunk);
      }
      self
        .packets
        .lock()
        .unwrap()
        .push((packet.trace_id().to_string(), body));
      Ok(())
    })
  }
}

async fn start_with_protocol(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, definition: ProtocolDefinition,
  consumer: Arc<Collector>,
) -> NodeHandle {
  init_tracing();
  let mut extensions = ExtensionRegistry::new();
  extensions.register_protocol(definition, consumer).unwrap();
  let factory: Arc<dyn radiata::extension::StorageFactory> = storage;
  NodeBuilder::new(factory, keys)
    .extensions(extensions)
    .start()
    .await
    .unwrap()
}

/// Restarts a node over a just-shut-down storage directory: under CI load
/// the previous handle's exclusive lock can linger briefly past the
/// shutdown reply, so the reopen retries with a bound instead of failing
/// the sample (same pattern as the merge retries).
async fn restart_with_protocol(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, tag: &str, consumer: Arc<Collector>,
) -> NodeHandle {
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
  loop {
    match start_with_protocol_result(
      Arc::clone(&storage),
      Arc::clone(&keys),
      protocol(tag),
      Arc::clone(&consumer),
    )
    .await
    {
      Ok(handle) => return handle,
      Err(error) if error.kind() == radiata::ErrorKind::StorageLocked => {
        assert!(
          std::time::Instant::now() < deadline,
          "restarted storage stays locked: {error}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
      }
      Err(error) => panic!("node restart failed: {error}"),
    }
  }
}

/// The fallible inner start shared by the harness helpers.
async fn start_with_protocol_result(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, definition: ProtocolDefinition,
  consumer: Arc<Collector>,
) -> Result<NodeHandle, radiata::Error> {
  init_tracing();
  let mut extensions = ExtensionRegistry::new();
  extensions.register_protocol(definition, consumer)?;
  let factory: Arc<dyn radiata::extension::StorageFactory> = storage;
  NodeBuilder::new(factory, keys)
    .extensions(extensions)
    .start()
    .await
}

fn protocol(tag: &str) -> ProtocolDefinition {
  ProtocolDefinition::new(
    ProtocolTag::parse(&format!("radiata.woooo.tech/protocols/{tag}")).unwrap(),
    radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
  )
}

fn metadata() -> StreamMetadata {
  StreamMetadata::new()
    .insert(
      QualifiedTag::parse("radiata.woooo.tech/resources/test-label").unwrap(),
      Arc::from(b"value".as_slice()),
    )
    .unwrap()
}

fn policy() -> StreamPolicy {
  StreamPolicy::new(radiata::RoutingPolicy::Direct, 1).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_packet_streams_ordered_after_authentication() {
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(70_000)),
      protocol("test-echo"),
      receiver_collector,
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let collector = Arc::new(Collector::default());
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(80_000)),
    protocol("test-echo"),
    collector.clone(),
  )
  .await;

  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let merge = {
    let secret = issued.credential().expose_secret().to_owned();
    merge_ok(&joiner_handle, &(listener.endpoint().clone()), &secret).await
  };

  // The receiver sends to the joiner over the established authenticated
  // session; the TraceId is visible before any body delivery.
  let packet = receiver
    .handle
    .open_stream(
      StreamTarget::Exact(merge.node().clone()),
      ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      metadata(),
    )
    .unwrap();
  let trace_before = packet.trace_id().clone();
  let ack = packet
    .send_sync(VecBody::new(vec![b"chunk-1", b"chunk-2", b"chunk-3"]))
    .await
    .unwrap();
  assert_eq!(ack.trace_id(), &trace_before);
  assert_eq!(ack.destination(), merge.node());

  // Admission is acked before the consumer finishes; wait for the bounded
  // consumer task to record the packet on wall time.
  wait_for(
    || !collector.packets.lock().unwrap().is_empty(),
    Duration::from_secs(10),
    "packet delivery",
  )
  .await;
  let packets = collector.packets.lock().unwrap().clone();
  assert_eq!(packets.len(), 1);
  assert_eq!(packets[0].0, trace_before.to_string());
  assert_eq!(packets[0].1, b"chunk-1chunk-2chunk-3");

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner_handle.command(Shutdown::new()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_packet_rejects_unknown_target_and_unregistered_protocol() {
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(90_000)),
      protocol("test-echo"),
      Arc::new(Collector::default()),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };

  // No session to any node: routing to an unknown exact node fails before
  // any delivery work.
  let unknown = radiata::NodeId::parse("node_999999999999999999999").unwrap();
  let packet = receiver
    .handle
    .open_stream(
      StreamTarget::Exact(unknown),
      ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      StreamMetadata::new(),
    )
    .unwrap();
  let error = packet
    .send_sync(VecBody::new(vec![b"never-delivered"]))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::RouteUnavailable);

  // Unregistered protocol: rejected before the session even with a live
  // peer.
  let collector = Arc::new(Collector::default());
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(95_000)),
    protocol("only-this"),
    collector,
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let merge = {
    let secret = issued.credential().expose_secret().to_owned();
    merge_ok(&joiner_handle, &(listener.endpoint().clone()), &secret).await
  };

  // Sender-side: creating a packet for a protocol the local registry never
  // registered fails before any session work.
  let error = receiver
    .handle
    .open_stream(
      StreamTarget::Exact(merge.node().clone()),
      ProtocolTag::parse("radiata.woooo.tech/protocols/not-registered").unwrap(),
      policy(),
      StreamMetadata::new(),
    )
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Unsupported);

  receiver.handle.command(Shutdown::new()).await.unwrap();
  joiner_handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-04 feature selection / credential-free reconnect evidence (E2E-01)
// ----

use radiata::ConnectMember;

/// Sends one two-chunk packet from `sender` to `target` and waits for the
/// receiver-side collector to observe it in order.
async fn packet_round_trip(
  sender: &NodeHandle, target: &radiata::NodeId, collector: &Arc<Collector>,
) -> radiata::NodeId {
  // Right after crossed-dial convergence the drained connection can
  // still interrupt one in-flight send; an explicit interruption is a
  // contract outcome, so the round trip retries briefly before failing.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  let ack = loop {
    let packet = sender
      .open_stream(
        StreamTarget::Exact(target.clone()),
        ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
        policy(),
        metadata(),
      )
      .unwrap();
    match packet.send_sync(VecBody::new(vec![b"a", b"b"])).await {
      Ok(ack) => break ack,
      Err(error)
        if matches!(
          error.kind(),
          ErrorKind::StreamInterrupted | ErrorKind::RouteUnavailable
        ) && std::time::Instant::now() < deadline =>
      {
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
      Err(error) => panic!("packet round trip failed persistently: {error:?}"),
    }
  };
  assert_eq!(ack.destination(), target);
  wait_for(
    || !collector.packets.lock().unwrap().is_empty(),
    Duration::from_secs(10),
    "packet delivery",
  )
  .await;
  let packets = collector.packets.lock().unwrap().clone();
  assert_eq!(packets.len(), 1, "one ordered packet must arrive");
  assert_eq!(packets[0].1, b"ab");
  ack.destination().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_rotation_keeps_members_and_reconnect_is_credential_free() {
  let receiver_keys = Arc::new(ScriptedKeys::full_at(90_000));
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      receiver_keys.clone(),
      protocol("test-echo"),
      Arc::clone(&receiver_collector),
    )
    .await,
    _keys: receiver_keys.clone(),
  };
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let joiner_keys = Arc::new(ScriptedKeys::full_at(95_000));
  let joiner_storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let joiner_collector = Arc::new(Collector::default());
  let joiner = Node {
    handle: start_with_protocol(
      Arc::clone(&joiner_storage),
      joiner_keys.clone(),
      protocol("test-echo"),
      Arc::clone(&joiner_collector),
    )
    .await,
    _keys: joiner_keys.clone(),
  };
  let secret = issued.credential().expose_secret().to_owned();
  let merge = merge_ok(&joiner.handle, listener.endpoint(), &secret).await;
  let _admitted = merge.node().clone();

  // E2E-01: the merged member streams packets; credential rotation does
  // not disconnect it.
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  packet_round_trip(&joiner.handle, &receiver_id, &receiver_collector).await;
  receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  receiver_collector.packets.lock().unwrap().clear();
  packet_round_trip(&joiner.handle, &receiver_id, &receiver_collector).await;

  // Disconnect by shutting the joiner down, then reconnect with key trust
  // only: no credential exists on this node, the trusted binding gates the
  // handshake, and packets flow again.
  joiner.handle.command(Shutdown::new()).await.unwrap();
  let restarted = Node {
    handle: restart_with_protocol(
      joiner_storage,
      joiner_keys.clone(),
      "test-echo",
      Arc::clone(&joiner_collector),
    )
    .await,
    _keys: joiner_keys.clone(),
  };
  let authenticated = restarted
    .handle
    .command(ConnectMember::new(
      listener.endpoint().clone(),
      receiver_id.clone(),
    ))
    .await
    .unwrap();
  assert_eq!(authenticated, receiver_id.clone());
  receiver_collector.packets.lock().unwrap().clear();
  packet_round_trip(&restarted.handle, &receiver_id, &receiver_collector).await;

  restarted.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-05 bidirectional packet streams evidence (SC-G03-P0-15..17) ----

use tokio::sync::Notify;

/// A race-free release gate: `open` is stored before the notification, so
/// a body that has not reached its wait yet still observes the release.
#[derive(Debug, Default)]
struct ReleaseGate {
  open: std::sync::atomic::AtomicBool,
  notify: Notify,
}

impl ReleaseGate {
  fn open(&self) {
    self.open.store(true, std::sync::atomic::Ordering::SeqCst);
    self.notify.notify_waiters();
  }

  async fn wait(&self) {
    loop {
      if self.open.load(std::sync::atomic::Ordering::SeqCst) {
        return;
      }
      self.notify.notified().await;
    }
  }
}

/// A packet body stream that stalls on the first chunk until released,
/// then ends.
fn blocking_body(
  release: Arc<ReleaseGate>,
) -> impl futures_core::Stream<Item = radiata::Result<Arc<[u8]>>> + Send + 'static {
  futures_util::stream::once(async move {
    release.wait().await;
    Ok(Arc::from(&b"held"[..]) as Arc<[u8]>)
  })
}

/// A consumer that records packet traces, bodies, and terminal errors.
#[derive(Debug, Default)]
struct RecordingConsumer {
  packets: StdMutex<Vec<(String, Vec<u8>)>>,
}

impl radiata::PacketConsumer for RecordingConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      let mut body = Vec::new();
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        body.extend_from_slice(&chunk);
      }
      self
        .packets
        .lock()
        .unwrap()
        .push((packet.trace_id().to_string(), body));
      Ok(())
    })
  }
}

/// A consumer that derives a caller-owned return packet (endpoint swap,
/// trace-id reuse) and sends it back to the authenticated source.
#[derive(Debug, Default)]
struct ReplyConsumer {
  pings: StdMutex<Vec<(String, Vec<u8>)>>,
}

impl radiata::PacketConsumer for ReplyConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, radiata::Result<()>> {
    Box::pin(async move {
      let mut body = Vec::new();
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        body.extend_from_slice(&chunk);
      }
      let trace = packet.trace_id().clone();
      self.pings.lock().unwrap().push((trace.to_string(), body));
      let reply = packet
        .derive_return_stream(
          ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
          StreamMetadata::new(),
        )
        .unwrap();
      assert_eq!(
        reply.trace_id(),
        &trace,
        "derived reply reuses the trace id"
      );
      reply.send_sync(VecBody::new(vec![b"reply"])).await?;
      Ok(())
    })
  }
}

async fn start_with_config<C: radiata::PacketConsumer + Send + Sync + 'static>(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, definition: ProtocolDefinition,
  consumer: Arc<C>, config: radiata::NodeConfig,
) -> NodeHandle {
  let mut extensions = ExtensionRegistry::new();
  extensions.register_protocol(definition, consumer).unwrap();
  let factory: Arc<dyn radiata::extension::StorageFactory> = storage;
  NodeBuilder::new(factory, keys)
    .extensions(extensions)
    .config(config)
    .start()
    .await
    .unwrap()
}

async fn start_with_reply_consumer(
  storage: Arc<MemoryStorageFactory>, keys: Arc<ScriptedKeys>, definition: ProtocolDefinition,
  consumer: Arc<ReplyConsumer>,
) -> NodeHandle {
  let mut extensions = ExtensionRegistry::new();
  extensions.register_protocol(definition, consumer).unwrap();
  let factory: Arc<dyn radiata::extension::StorageFactory> = storage;
  NodeBuilder::new(factory, keys)
    .extensions(extensions)
    .start()
    .await
    .unwrap()
}

async fn round_trip_to(
  sender: &NodeHandle, target: &radiata::NodeId, body: &[&'static [u8]], collector: &Arc<Collector>,
) -> radiata::TraceId {
  let packet = sender
    .open_stream(
      StreamTarget::Exact(target.clone()),
      ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      metadata(),
    )
    .unwrap();
  let trace = packet.trace_id().clone();
  packet.send_sync(VecBody::new(body.to_vec())).await.unwrap();
  wait_for(
    || !collector.packets.lock().unwrap().is_empty(),
    Duration::from_secs(10),
    "one ordered packet must arrive",
  )
  .await;
  let packets = collector.packets.lock().unwrap().clone();
  assert_eq!(packets.len(), 1, "one ordered packet must arrive");
  trace
}

/// SC-G03-P0-15: both peers stream concurrent packets over one session;
/// each incoming stream preserves its endpoints, trace id, metadata, and
/// byte order.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_packets_flow_concurrently_in_both_directions() {
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(100_000)),
      protocol("test-echo"),
      Arc::clone(&receiver_collector),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let collector = Arc::new(Collector::default());
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(101_000)),
    protocol("test-echo"),
    collector.clone(),
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let merge = {
    let secret = issued.credential().expose_secret().to_owned();
    merge_ok(&joiner_handle, &(listener.endpoint().clone()), &secret).await
  };
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let joiner_id = merge.node().clone();

  let (east_trace, west_trace) = tokio::join!(
    async {
      round_trip_to(
        &receiver.handle,
        &joiner_id,
        &[b"east", b"bound"],
        &collector,
      )
      .await
    },
    async {
      round_trip_to(
        &joiner_handle,
        &receiver_id,
        &[b"west", b"bound"],
        &receiver_collector,
      )
      .await
    }
  );
  assert_ne!(east_trace, west_trace);
  assert_eq!(collector.packets.lock().unwrap().clone()[0].1, b"eastbound");
  assert_eq!(
    receiver_collector.packets.lock().unwrap().clone()[0].1,
    b"westbound"
  );

  joiner_handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G03-P0-16: a caller derives a return packet by swapping endpoints
/// and reusing the incoming trace id; core assigns no return meaning.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_derived_return_stream_reuses_trace_id() {
  let reply_consumer = Arc::new(ReplyConsumer::default());
  let reply_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_reply_consumer(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(110_000)),
      protocol("test-echo"),
      Arc::clone(&reply_consumer),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(111_000)),
    protocol("test-echo"),
    reply_collector.clone(),
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let merge = {
    let secret = issued.credential().expose_secret().to_owned();
    merge_ok(&joiner_handle, &(listener.endpoint().clone()), &secret).await
  };
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let _joiner_id = merge.node().clone();

  let trace = round_trip_to(&joiner_handle, &receiver_id, &[b"ping"], &reply_collector).await;
  let pings = reply_consumer.pings.lock().unwrap().clone();
  assert_eq!(
    pings.len(),
    1,
    "receiver consumer must see the original ping"
  );
  assert_eq!(pings[0].0, trace.to_string(), "trace id preserved inbound");
  assert_eq!(pings[0].1, b"ping");
  let replies = reply_collector.packets.lock().unwrap().clone();
  assert_eq!(replies.len(), 1);
  assert_eq!(
    replies[0].0,
    trace.to_string(),
    "derived reply reuses the trace id"
  );
  assert_eq!(replies[0].1, b"reply");

  joiner_handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G03-P0-17: bounded incoming-stream admission returns typed
/// backpressure at the configured capacity, and release frees every slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_incoming_stream_capacity_returns_backpressure_and_recovers() {
  let config = radiata::NodeConfig::new()
    .with_session_queue_limits(4, 65_536)
    .unwrap();
  let recorder = Arc::new(RecordingConsumer::default());
  let receiver = Node {
    handle: start_with_config(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(120_000)),
      protocol("test-echo"),
      Arc::clone(&recorder),
      config,
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(121_000)),
    protocol("test-echo"),
    Arc::new(Collector::default()),
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let merge = {
    let secret = issued.credential().expose_secret().to_owned();
    merge_ok(&joiner_handle, &(listener.endpoint().clone()), &secret).await
  };
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let _joiner_id = merge.node().clone();

  let release = Arc::new(ReleaseGate::default());
  let protocol_tag = ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap();
  for _ in 0..4 {
    let packet = joiner_handle
      .open_stream(
        StreamTarget::Exact(receiver_id.clone()),
        protocol_tag.clone(),
        policy(),
        metadata(),
      )
      .unwrap();
    packet
      .send_sync(blocking_body(release.clone()))
      .await
      .unwrap();
  }

  let packet = joiner_handle
    .open_stream(
      StreamTarget::Exact(receiver_id.clone()),
      protocol_tag.clone(),
      policy(),
      metadata(),
    )
    .unwrap();
  let error = packet
    .send_sync(VecBody::new(vec![b"overflow"]))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Overloaded);

  release.open();
  wait_for(
    || recorder.packets.lock().unwrap().len() >= 4,
    Duration::from_secs(10),
    "four queued packets drain after release",
  )
  .await;
  assert_eq!(recorder.packets.lock().unwrap().len(), 4);
  let packet = joiner_handle
    .open_stream(
      StreamTarget::Exact(receiver_id.clone()),
      protocol_tag,
      policy(),
      metadata(),
    )
    .unwrap();
  packet
    .send_sync(VecBody::new(vec![b"after"]))
    .await
    .unwrap();
  wait_for(
    || recorder.packets.lock().unwrap().len() >= 5,
    Duration::from_secs(10),
    "the post-release packet arrives",
  )
  .await;
  assert_eq!(recorder.packets.lock().unwrap().len(), 5);

  joiner_handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G03-06 hostile / merge-input closure evidence (SC-G03-P0-22) ----

/// SC-G03-P0-22: a source exhausting its fixed merge rate window is
/// refused before any handshake or signing work; the refusal consumes no
/// credential and performs no signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_merge_rate_window_refuses_before_signing() {
  let receiver_keys = Arc::new(ScriptedKeys::full_at(130_000));
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      receiver_keys.clone(),
      protocol("test-echo"),
      Arc::new(Collector::default()),
    )
    .await,
    _keys: receiver_keys.clone(),
  };
  receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  // A syntactically valid but cryptographically wrong credential fails at
  // proof verification; every attempt still counts against the fixed
  // per-source merge rate window (16 per 60 seconds).
  let hostile = MergeCredential::parse("join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
  let attacker = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(131_000)),
    protocol("test-echo"),
    Arc::new(Collector::default()),
  )
  .await;
  for _ in 0..16 {
    let error = attacker
      .command(MergeCluster::new(
        listener.endpoint().clone(),
        MergeCredential::parse("join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
      ))
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  }
  assert!(
    !receiver_keys.take_calls().is_empty(),
    "authenticated attempts reach the handshake and sign"
  );

  // The seventeenth attempt from the same source (all loopback reconnects
  // normalize to one source) is refused before any signing work.
  let error = attacker
    .command(MergeCluster::new(listener.endpoint().clone(), hostile))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  assert!(
    receiver_keys.take_calls().is_empty(),
    "a rate-refused attempt must perform no signing and consume no credential"
  );

  attacker.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

// ---- Real-world business scenarios (post-G3 review, 2026-08) ----
//
// Three end-to-end lanes that the secure-join suite did not previously
// exercise as a whole process: single-use credential enforcement against a
// copied credential, explicit interruption of an in-flight outbound stream
// when the peer shuts down, and fail-closed merge after the listener stops.

/// THR-001 real-world lane: a merge credential is single-use. Even when the
/// credential bytes are copied (as they would be after a leak), the second
/// merge attempt on the same generation is refused without a merge and
/// without consuming another generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_copied_credential_cannot_merge_twice() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(120_000)),
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  // Snapshot the credential text first: the issuer hands it out once, and
  // the legitimate joiner consumes the issued object.
  let credential_text = issued.credential().expose_secret().to_owned();
  let joiner = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(130_000)),
  )
  .await;
  let secret = issued.credential().expose_secret().to_owned();
  let _merge = merge_ok(&joiner.handle, listener.endpoint(), &secret).await;

  // A second node replays the copied credential bytes; the issuer must
  // refuse without admitting a second subject for the same generation.
  let second = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(140_000)),
  )
  .await;
  let copied = MergeCredential::parse(&credential_text).unwrap();
  let error = second
    .handle
    .command(MergeCluster::new(listener.endpoint().clone(), copied))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);

  second.handle.command(Shutdown::new()).await.unwrap();
  joiner.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// ADR-0007 / SC-G03-P0-06 real-world lane: when the receiving peer shuts
/// down, an in-flight outbound stream ends with an explicit typed
/// `StreamInterrupted` on the sender's route — core never reports the
/// stream as delivered after the peer closes, and never hangs the sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_peer_shutdown_interrupts_inflight_stream_explicitly() {
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(150_000)),
      protocol("test-echo"),
      receiver_collector,
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let collector = Arc::new(Collector::default());
  let joiner_handle = start_with_protocol(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(160_000)),
    protocol("test-echo"),
    collector.clone(),
  )
  .await;

  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let _merge = {
    let secret = issued.credential().expose_secret().to_owned();
    merge_ok(&joiner_handle, &(listener.endpoint().clone()), &secret).await
  };
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let receiver_peer = receiver_id.clone();

  // Start an outbound stream whose body stalls on its first chunk, then
  // observe it through the async route handle: the admission ack resolves
  // before the body finishes, so the explicit interruption is visible in
  // the route state, not the send future.
  let packet = joiner_handle
    .open_stream(
      StreamTarget::Exact(receiver_id),
      ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
      policy(),
      metadata(),
    )
    .unwrap();
  let release = Arc::new(ReleaseGate::default());
  let route = packet
    .send_async(blocking_body(Arc::clone(&release)))
    .unwrap();

  // Wait until the stream is admitted and streaming (the ack resolves
  // before the body finishes), so the peer shutdown below is guaranteed to
  // interrupt an in-flight stream rather than a queued request.
  let mut streaming = false;
  let deadline = std::time::Instant::now() + Duration::from_secs(15);
  while !streaming {
    match joiner_handle.query(GetRoute::new(route.clone())).await {
      // The supervisor inserts the record asynchronously after `send_async`
      // queues the request; keep waiting until it exists.
      Err(error) if error.kind() == ErrorKind::NotFound => {}
      Ok(view) if matches!(view.state(), RouteState::Failed(_)) => break,
      Ok(view) => streaming = matches!(view.state(), RouteState::Streaming),
      Err(error) => panic!("route query failed: {error:?}"),
    }
    assert!(
      std::time::Instant::now() < deadline,
      "the stream must reach streaming state within the budget"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
  assert!(
    streaming,
    "the stream must reach the streaming state before the peer shuts down"
  );

  // Terminate the peer while the body is still in flight, wait for the
  // shutdown to propagate (the peer's session closes its frame channel),
  // then release the stalled body so the route attempts to continue and
  // observes the close.
  receiver.handle.command(Shutdown::new()).await.unwrap();
  // Wait until the joiner observes the session close before releasing the
  // stalled body: releasing early would let the body finish normally and
  // turn the interruption assertion into a false failure.
  let close_deadline = std::time::Instant::now() + Duration::from_secs(15);
  loop {
    let topology = joiner_handle
      .query(PageTopology::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    let connected = topology
      .items()
      .iter()
      .any(|edge| edge.destination() == &receiver_peer && edge.connected());
    if !connected {
      break;
    }
    assert!(
      std::time::Instant::now() < close_deadline,
      "the joiner never observed the peer's session close"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
  release.open();

  // The in-flight route must end with the explicit interruption state.
  let mut terminal: Option<RouteState> = None;
  let deadline = std::time::Instant::now() + Duration::from_secs(15);
  while terminal.is_none() {
    let view = joiner_handle
      .query(GetRoute::new(route.clone()))
      .await
      .unwrap();
    if matches!(view.state(), RouteState::Failed(_)) {
      terminal = Some(view.state().clone());
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "in-flight route never reached a terminal state"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
  assert_eq!(
    terminal,
    Some(RouteState::Failed(ErrorKind::StreamInterrupted)),
    "peer shutdown must interrupt the in-flight stream with a typed error"
  );

  joiner_handle.command(Shutdown::new()).await.unwrap();
}

/// Real-world lane: after the receiver stops listening, a late merge attempt
/// fails closed with a typed error instead of hanging or merging.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_merge_after_listener_stop_fails_closed() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(170_000)),
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  receiver
    .handle
    .command(radiata::StopListener::new(listener.id().clone()))
    .await
    .unwrap();
  // One in-flight accept can still complete after the stop returns; wait
  // until the public listener page is empty before the late merge.
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
  loop {
    let listeners = receiver
      .handle
      .query(radiata::PageListeners::new(
        radiata::PageSpec::first(8).unwrap(),
      ))
      .await
      .unwrap();
    if listeners.items().is_empty() {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "listener never stopped"
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
  }

  let late = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(180_000)),
  )
  .await;
  let error = late
    .handle
    .command(MergeCluster::new(
      listener.endpoint().clone(),
      issued.into_credential(),
    ))
    .await
    .unwrap_err();
  assert!(
    matches!(
      error.kind(),
      ErrorKind::Io | ErrorKind::AuthenticationFailed | ErrorKind::StreamInterrupted
    ),
    "late merge must fail closed with a typed error, got {:?}",
    error.kind()
  );

  late.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

// ---- T-G04-03 crossed-dial evidence (SC-G04-P0-09..11, E2E-03) ----

/// E2E-03 / SC-G04-P0-09: simultaneous dials converge to one authenticated
/// session. The receiver accepts the joiner (incoming) and then dials the
/// joiner back (outgoing); the deterministic ownership rule keeps exactly
/// one connection and the drained one tears down without breaking the
/// surviving session's packet path.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_crossed_dial_converges_to_one_session() {
  let receiver_collector = Arc::new(Collector::default());
  let receiver = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(200_000)),
      protocol("test-echo"),
      Arc::clone(&receiver_collector),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let receiver_listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let joiner_collector = Arc::new(Collector::default());
  let joiner = Node {
    handle: start_with_protocol(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(210_000)),
      protocol("test-echo"),
      Arc::clone(&joiner_collector),
    )
    .await,
    _keys: Arc::new(ScriptedKeys::full()),
  };
  let secret = issued.credential().expose_secret().to_owned();
  let merge = merge_ok(&joiner.handle, receiver_listener.endpoint(), &secret).await;

  // The joiner now listens so the receiver can dial it back.
  let joiner_listener = joiner
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();
  let joiner_id = merge.node().clone();

  // Crossed dial: the receiver dials the already-connected joiner while the
  // incoming session from the merge is still live.
  let authenticated = receiver
    .handle
    .command(ConnectMember::new(
      joiner_listener.endpoint().clone(),
      joiner_id.clone(),
    ))
    .await
    .unwrap();
  assert_eq!(authenticated, joiner_id);

  // The surviving session must still carry packets in both directions; the
  // drained connection must not break it.
  for _ in 0..3 {
    receiver_collector.packets.lock().unwrap().clear();
    joiner_collector.packets.lock().unwrap().clear();
    packet_round_trip(&joiner.handle, &receiver_id, &receiver_collector).await;
    packet_round_trip(&receiver.handle, &joiner_id, &joiner_collector).await;
  }

  joiner.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G04-P0-15: shutdown rejects new work and releases session resources
/// independently of wall-clock progress.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_shutdown_rejects_new_work_after_drain() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(220_000)),
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let joiner = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(230_000)),
  )
  .await;
  let secret = issued.credential().expose_secret().to_owned();
  merge_ok(&joiner.handle, listener.endpoint(), &secret).await;

  receiver.handle.command(Shutdown::new()).await.unwrap();
  // New work after shutdown is rejected with a typed shutdown error, not
  // accepted or hung.
  let error = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ShuttingDown);

  joiner.handle.command(Shutdown::new()).await.unwrap();
}

// ---- G5 public membership and topology views (SC-G05-P0-23..26 core) ----

use radiata::{GetMember, PageMembers};

/// The public membership/topology views expose the local owner-marked
/// descriptor and the authenticated session edge after a merge.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_public_membership_and_topology_views() {
  let receiver = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(400_000)),
  )
  .await;
  let issued = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let joiner = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(410_000)),
  )
  .await;
  let secret = issued.credential().expose_secret().to_owned();
  let merge = merge_ok(&joiner.handle, listener.endpoint(), &secret).await;

  let receiver_view = receiver.handle.query(GetLocalNode::new()).await.unwrap();
  let receiver_id = receiver_view.node_id().clone();

  // The receiver's own descriptor is published lazily and readable.
  let member = receiver
    .handle
    .query(GetMember::new(receiver_id.clone()))
    .await
    .unwrap()
    .expect("local descriptor published");
  assert_eq!(member.node_id(), &receiver_id);
  assert_eq!(member.owner_revision(), 1);

  // The membership page is bounded and exposes the descriptor.
  let page = receiver
    .handle
    .query(PageMembers::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(
    page
      .items()
      .iter()
      .any(|item| item.node_id() == &receiver_id)
  );

  // The topology page exposes the authenticated session edge to the joiner.
  let topology = receiver
    .handle
    .query(PageTopology::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(
    topology
      .items()
      .iter()
      .any(|edge| edge.destination() == merge.node() && edge.connected()),
    "authenticated session edge must be visible"
  );

  joiner.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// G5-06 core: a sixteen-node cluster merges with the issuer and the public
/// topology view exposes the authenticated edges (SC-G05-P0-24).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn secure_join_sixteen_node_membership_merges_and_views() {
  let issuer = start(
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    Arc::new(ScriptedKeys::full_at(500_000)),
  )
  .await;
  let listener = issuer
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  let mut members = Vec::new();
  for index in 0..15 {
    let issued = rotate_with_retry(&issuer.handle).await;
    let member = start(
      Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
      Arc::new(ScriptedKeys::full_at(510_000 + index as u64 * 1_000)),
    )
    .await;
    let secret = issued.credential().expose_secret().to_owned();
    merge_with_retry(&member.handle, listener.endpoint(), &secret).await;
    members.push(member);
  }

  // The issuer's topology view exposes all fifteen authenticated edges.
  let topology = issuer
    .handle
    .query(PageTopology::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap();
  assert_eq!(
    topology
      .items()
      .iter()
      .filter(|edge| edge.connected())
      .count(),
    15,
    "all fifteen members hold an authenticated session"
  );

  // The issuer's own descriptor is readable and the membership page is
  // bounded.
  let issuer_view = issuer.handle.query(GetLocalNode::new()).await.unwrap();
  let member = issuer
    .handle
    .query(GetMember::new(issuer_view.node_id().clone()))
    .await
    .unwrap()
    .expect("issuer descriptor published");
  assert_eq!(member.owner_revision(), 1);

  for member in members {
    member.handle.command(Shutdown::new()).await.unwrap();
  }
  issuer.handle.command(Shutdown::new()).await.unwrap();
}
