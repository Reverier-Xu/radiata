//! Local self-delivery: a packet addressed to the sending node itself is
//! admitted through the same body an inbound open uses and consumed
//! in-process — no session, no first hop, and no route envelope — while a
//! non-local exact target keeps using the session/forward path.

use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

use radiata::{
  ErrorKind, IncomingStream, NodeBuilder, NodeConfig, NodeHandle, NodeId, PacketConsumer, PageSpec,
  ProtocolDefinition, ProtocolTag, RouteHandle, RouteState, RoutingPolicy, StreamMetadata,
  StreamPolicy, StreamTarget,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys, required_capabilities};

const PROTOCOL_TAG: &str = "radiata.woooo.tech/protocols/local-echo";
const FEATURE_TAG: &str = "radiata.woooo.tech/features/session-core";

/// Records every admitted packet's authenticated endpoints and body.
#[derive(Debug, Default)]
struct Collector {
  packets: Mutex<Vec<(NodeId, NodeId, Vec<u8>)>>,
}

impl PacketConsumer for Collector {
  fn accept<'a>(
    &'a self, mut packet: IncomingStream,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = radiata::Result<()>> + Send + 'a>> {
    Box::pin(async move {
      let source = packet.source().clone();
      let destination = packet.destination().clone();
      let mut body = Vec::new();
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx)).await {
        body.extend_from_slice(&chunk?);
      }
      self
        .packets
        .lock()
        .unwrap()
        .push((source, destination, body));
      Ok(())
    })
  }
}

async fn start_node(seed: u64, collector: Arc<Collector>) -> NodeHandle {
  common::init_tracing();
  let storage = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let keys = Arc::new(ScriptedKeys::full_at(1_500_000 + seed * 1_000));
  let mut extensions = radiata::ExtensionRegistry::new();
  let consumer: Arc<dyn PacketConsumer> = Arc::clone(&collector) as Arc<dyn PacketConsumer>;
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse(PROTOCOL_TAG).unwrap(),
        radiata::FeatureTag::parse(FEATURE_TAG).unwrap(),
      ),
      consumer,
    )
    .unwrap();
  NodeBuilder::new(storage)
    .keys(keys)
    .config(NodeConfig::new())
    .extensions(extensions)
    .start()
    .await
    .unwrap()
}

fn body(
  chunk: &'static [u8],
) -> impl futures_core::Stream<Item = radiata::Result<Arc<[u8]>>> + Send + 'static {
  futures_util::stream::once(async move { Ok(Arc::from(chunk) as Arc<[u8]>) })
}

fn protocol() -> ProtocolTag {
  ProtocolTag::parse(PROTOCOL_TAG).unwrap()
}

fn policy() -> StreamPolicy {
  StreamPolicy::new(RoutingPolicy::Direct, 1).unwrap()
}

async fn wait_for<F: FnMut() -> bool>(mut probe: F, what: &'static str) {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  while !probe() {
    assert!(
      std::time::Instant::now() < deadline,
      "{what} not reached within the deadline"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
}

async fn wait_until_terminal(handle: &NodeHandle, route: &RouteHandle) -> RouteState {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    if let Ok(view) = handle.routes().get(route) {
      let state = view.state().clone();
      if matches!(state, RouteState::Failed(_) | RouteState::Delivered) {
        return state;
      }
    }
    assert!(
      std::time::Instant::now() < deadline,
      "the route must reach an explicit terminal state"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
}

/// An isolated node addressing itself delivers in-process: the registered
/// consumer receives the body with the local node as both authenticated
/// endpoints, and the route record reaches `Delivered` — with no session
/// anywhere on the node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_self_delivery_reaches_the_consumer_on_an_isolated_node() {
  let collector = Arc::new(Collector::default());
  let handle = start_node(1, Arc::clone(&collector)).await;
  let local = handle.local_node().await.unwrap().node_id().clone();

  // The node is isolated: nothing but the local pump can carry the stream.
  let sessions = handle
    .sessions()
    .list(PageSpec::first(8).unwrap())
    .await
    .unwrap();
  assert!(
    sessions.items().is_empty(),
    "the node must start with no sessions"
  );

  let packet = handle
    .open_stream(
      StreamTarget::Exact(local.clone()),
      protocol(),
      policy(),
      StreamMetadata::new(),
    )
    .unwrap();
  let trace_id = packet.trace_id().clone();
  let ack = packet.send_sync(body(b"self")).await.unwrap();
  assert_eq!(ack.trace_id(), &trace_id);
  assert_eq!(ack.destination(), &local);

  wait_for(
    || collector.packets.lock().unwrap().len() == 1,
    "the local consumer must receive the body",
  )
  .await;
  {
    let packets = collector.packets.lock().unwrap();
    let (source, destination, received) = &packets[0];
    assert_eq!(source, &local, "the source is the local node");
    assert_eq!(destination, &local, "the destination is the local node");
    assert_eq!(received, b"self");
  }

  // The asynchronous lane observes the same local delivery through the
  // route record: it reaches `Delivered` without a session.
  let packet = handle
    .open_stream(
      StreamTarget::Exact(local.clone()),
      protocol(),
      policy(),
      StreamMetadata::new(),
    )
    .unwrap();
  let route = packet.send_async(body(b"async")).unwrap();
  assert_eq!(
    wait_until_terminal(&handle, &route).await,
    RouteState::Delivered
  );
  wait_for(
    || collector.packets.lock().unwrap().len() == 2,
    "the local consumer must receive the asynchronous body",
  )
  .await;
  assert_eq!(collector.packets.lock().unwrap()[1].2, b"async");

  handle.shutdown().await.unwrap();
}

/// A local body above the wire's chunk bound is re-chunked and reassembled
/// byte-exact: the consumer sees the same chunk boundaries whether the
/// stream arrived locally or over a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_self_delivery_reassembles_a_body_above_the_chunk_bound() {
  let collector = Arc::new(Collector::default());
  let handle = start_node(3, Arc::clone(&collector)).await;
  let local = handle.local_node().await.unwrap().node_id().clone();

  // 300 KiB in one caller chunk: ten wire-sized slices at the 32 KiB bound.
  let expected: Vec<u8> = (0..300 * 1024).map(|i| (i % 251) as u8).collect();
  let chunk: Arc<[u8]> = Arc::from(expected.clone().into_boxed_slice());
  let packet = handle
    .open_stream(
      StreamTarget::Exact(local.clone()),
      protocol(),
      policy(),
      StreamMetadata::new(),
    )
    .unwrap();
  packet
    .send_sync(futures_util::stream::iter([Ok(chunk)]))
    .await
    .unwrap();

  wait_for(
    || collector.packets.lock().unwrap().len() == 1,
    "the local consumer must receive the multi-chunk body",
  )
  .await;
  assert_eq!(
    collector.packets.lock().unwrap()[0].2.as_slice(),
    expected.as_slice()
  );

  handle.shutdown().await.unwrap();
}

/// A non-local exact target keeps using the session/forward path: on an
/// isolated node no session carries the stream, so the send fails with the
/// typed route-unavailable refusal and the local consumer never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_local_exact_target_still_uses_the_session_path() {
  let collector = Arc::new(Collector::default());
  let handle = start_node(2, Arc::clone(&collector)).await;
  let local = handle.local_node().await.unwrap().node_id().clone();
  let remote = NodeId::parse("node-000000000000000000042").unwrap();
  assert_ne!(remote, local);

  let packet = handle
    .open_stream(
      StreamTarget::Exact(remote),
      protocol(),
      policy(),
      StreamMetadata::new(),
    )
    .unwrap();
  let error = packet.send_sync(body(b"remote")).await.unwrap_err();
  assert_eq!(
    error.kind(),
    ErrorKind::RouteUnavailable,
    "a non-local exact target must fail on the session/forward path"
  );
  assert!(
    collector.packets.lock().unwrap().is_empty(),
    "a non-local exact target must never be consumed locally"
  );

  handle.shutdown().await.unwrap();
}
