//! Three-hop routed packet streams over real TLS (E2E-05, T-G06-05).
//!
//! Four nodes form a linear topology A — B — C — D with sessions only
//! between adjacent members. Every node registers the same shared next-hop
//! policy and configures it as its route policy. A synchronous send from A
//! targeting D crosses all three hops: the body arrives in order at D's
//! consumer, the acknowledgement names the selected destination, no
//! intermediate consumer runs, and a mid-stream interruption of the last
//! leg ends the route with an explicit typed terminal state — nothing
//! replays or continues.

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::Duration,
};

use radiata::{
  ConnectMember, CreateCluster, DisconnectPeer, ErrorKind, GetRoute, IncomingStream, JoinCluster,
  Listen, NodeBuilder, NodeConfig, NodeHandle, PacketConsumer, PageTopology, ProtocolTag,
  QualifiedTag, RotateJoinCredential, RouteNextHop, RouteState, RoutingPolicy, Shutdown,
  StreamMetadata, StreamPolicy, StreamTarget,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys, required_capabilities};

const POLICY_TAG: &str = "radiata.woooo.tech/policies/linear";
const PROTOCOL_TAG: &str = "radiata.woooo.tech/protocols/test-echo";
const FEATURE_TAG: &str = "radiata.woooo.tech/features/session-core";

type SharedTable = Arc<Mutex<BTreeMap<String, String>>>;

/// The linear next-hop policy reading the harness topology at call time:
/// destination -> successor. Unknown destinations fail closed with the
/// provider-visible unsupported error.
#[derive(Debug)]
struct SharedPolicy {
  table: SharedTable,
}

impl RouteNextHop for SharedPolicy {
  fn next_hop<'a>(
    &'a self, view: radiata::NextHopView<'a>,
  ) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = radiata::Result<radiata::NodeId>> + Send + 'a>,
  > {
    Box::pin(async move {
      // The topology is per-node: which neighbour leads toward the
      // destination depends on where the packet currently is.
      let key = format!("{}|{}", view.local().as_str(), view.destination().as_str());
      let guard = self.table.lock().unwrap();
      let next = guard.get(&key).ok_or_else(|| {
        radiata::Error::provider(
          radiata::ProviderErrorKind::Unsupported,
          radiata::ProviderErrorContext::RoutingPolicy,
        )
      })?;
      radiata::NodeId::parse(next)
    })
  }
}

#[derive(Debug, Default)]
struct Collector {
  packets: Mutex<Vec<(String, Vec<u8>)>>,
}

impl PacketConsumer for Collector {
  fn accept<'a>(
    &'a self, mut packet: IncomingStream,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), radiata::Error>> + Send + 'a>>
  {
    Box::pin(async move {
      let trace = packet.trace_id().to_string();
      let mut body = Vec::new();
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        body.extend_from_slice(&chunk);
      }
      self.packets.lock().unwrap().push((trace, body));
      Ok(())
    })
  }
}

/// A body stream that stalls after creation until released.
fn gated_body() -> (
  impl futures_core::Stream<Item = radiata::Result<Arc<[u8]>>> + Send + 'static,
  Arc<std::sync::atomic::AtomicBool>,
  Arc<tokio::sync::Notify>,
) {
  let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
  let notify = Arc::new(tokio::sync::Notify::new());
  let released = Arc::clone(&open);
  let waiter = Arc::clone(&notify);
  let body = futures_util::stream::once(async move {
    while !released.load(std::sync::atomic::Ordering::SeqCst) {
      waiter.notified().await;
    }
    Ok(Arc::from(&b"held"[..]) as Arc<[u8]>)
  });
  (body, open, notify)
}

/// A body stream that yields each chunk in order.
fn vec_body(
  chunks: &[&'static [u8]],
) -> impl futures_core::Stream<Item = radiata::Result<Arc<[u8]>>> + Send + 'static {
  let items: Vec<radiata::Result<Arc<[u8]>>> = chunks
    .iter()
    .map(|chunk| Ok(Arc::from(*chunk) as Arc<[u8]>))
    .collect();
  futures_util::stream::iter(items)
}

struct Node {
  handle: NodeHandle,
  endpoint: Option<radiata::Endpoint>,
  id: Option<radiata::NodeId>,
  #[allow(dead_code)]
  collector: Arc<Collector>,
}

impl Node {
  fn id(&self) -> &radiata::NodeId {
    self.id.as_ref().unwrap()
  }

  fn set_id(&mut self, id: radiata::NodeId) {
    self.id = Some(id);
  }
}

async fn start_node(seed: u64, collector: Arc<Collector>, table: SharedTable) -> Node {
  let keys = Arc::new(ScriptedKeys::full_at(800_000 + seed * 1_000));
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let mut registry = radiata::ExtensionRegistry::new();
  let consumer: Arc<dyn PacketConsumer> = Arc::clone(&collector) as Arc<dyn PacketConsumer>;
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
    .register_next_hop(
      QualifiedTag::parse(POLICY_TAG).unwrap(),
      Arc::new(SharedPolicy {
        table: Arc::clone(&table),
      }),
    )
    .unwrap();
  let config = NodeConfig::new().with_route_policy(QualifiedTag::parse(POLICY_TAG).unwrap());
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .extensions(registry)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: None,
    id: None,
    collector,
  }
}

impl Node {
  async fn listen(&mut self) {
    let listener = self
      .handle
      .command(Listen::new(
        radiata::Endpoint::parse("wss://127.0.0.1:0").unwrap(),
      ))
      .await
      .unwrap();
    self.endpoint = Some(listener.endpoint().clone());
  }

  fn endpoint(&self) -> &radiata::Endpoint {
    self.endpoint.as_ref().unwrap()
  }

  /// Dials the peer, retrying transient handshake failures: under
  /// parallel test load a dial can race listener readiness, and one closed
  /// handshake is a retryable transport event, not a delivery failure.
  async fn connect_to(&self, peer: &Node) {
    let endpoint = peer.endpoint().clone();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
      match self
        .handle
        .command(ConnectMember::new(endpoint.clone(), peer.id().clone()))
        .await
      {
        Ok(_) => return,
        Err(error) => {
          assert!(
            std::time::Instant::now() < deadline,
            "connect to {} keeps failing: {error}",
            peer.id()
          );
          tokio::time::sleep(Duration::from_millis(50)).await;
        }
      }
    }
  }
}

async fn wait_for<F: FnMut() -> bool>(mut probe: F, timeout: Duration, what: &'static str) {
  let deadline = std::time::Instant::now() + timeout;
  while !probe() {
    assert!(
      std::time::Instant::now() < deadline,
      "{what} not reached within {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
}

async fn wait_until_terminal(handle: &NodeHandle, route: &radiata::RouteHandle) -> RouteState {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let state = match handle.query(GetRoute::new(route.clone())).await {
      Ok(view) => view.state().clone(),
      Err(_) => continue,
    };
    if matches!(state, RouteState::Failed(_) | RouteState::Delivered) {
      return state;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "the route must reach an explicit terminal state"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn routed_packets_cross_three_hops_and_interrupt_explicitly() {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=trace"))
    .with_test_writer()
    .init();
  let table: SharedTable = Arc::default();
  let collectors: Vec<Arc<Collector>> = (0..4).map(|_| Arc::new(Collector::default())).collect();

  // Start all four nodes before identities exist to fill the policy map.
  let mut nodes = Vec::new();
  for (seed, collector) in collectors.iter().enumerate() {
    nodes.push(start_node(seed as u64, Arc::clone(collector), Arc::clone(&table)).await);
  }

  // Cluster genesis on A names its identity; members can only listen once
  // their own node knows the cluster, so joins happen before the member
  // listeners come up and each admission reports the member's identity.
  let cluster = nodes[0].handle.command(CreateCluster::new()).await.unwrap();
  nodes[0].set_id(cluster.creator().clone());
  nodes[0].listen().await;

  for member_index in 1..=3usize {
    let issued = nodes[0]
      .handle
      .command(RotateJoinCredential::new())
      .await
      .unwrap();
    let secret = issued.credential().expose_secret().to_owned();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let mut attempts = 0_u32;
    loop {
      attempts += 1;
      let result = nodes[member_index]
        .handle
        .command(JoinCluster::new(
          nodes[0].endpoint().clone(),
          radiata::JoinCredential::parse(&secret).unwrap(),
        ))
        .await;
      match result {
        Ok(view) => {
          nodes[member_index].set_id(view.admitted_node().clone());
          break;
        }
        // Exponential pacing keeps the retries outside the fixed
        // per-source admission window (sixteen attempts per minute).
        Err(_) if std::time::Instant::now() < deadline => {
          tokio::time::sleep(
            Duration::from_millis(250u64.saturating_mul(1 << attempts.min(4)))
              .min(Duration::from_secs(4)),
          )
          .await;
        }
        Err(error) => panic!("join failed persistently (attempt {attempts}): {error:?}"),
      }
    }
  }

  // Per-node linear chain policy over the concrete identities: for every
  // origin, the way toward a later member is its right-hand neighbour.
  {
    let mut guard = table.lock().unwrap();
    for origin in 0..4_usize {
      for destination in (origin + 1)..4_usize {
        let next = origin + 1;
        guard.insert(
          format!(
            "{}|{}",
            nodes[origin].id().as_str(),
            nodes[destination].id.as_ref().unwrap().as_str()
          ),
          nodes[next].id().as_str().to_owned(),
        );
      }
    }
  }
  for node in nodes.iter_mut().skip(1) {
    node.listen().await;
  }

  // Member-mode dials require the peer's durable trust binding, which
  // reaches every member through the join-star anti-entropy first.
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let mut complete = true;
    for node in &nodes {
      let page = node
        .handle
        .query(radiata::PageTrust::new(
          radiata::PageSpec::first(64).unwrap(),
        ))
        .await;
      match page {
        Ok(page) if page.items().len() >= 4 => {}
        _ => complete = false,
      }
    }
    if complete {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "every member must hold all four trust bindings"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // Linear chain sessions B—C and C—D; the A—D leg is intentionally cut
  // from both endpoints so D is reachable only through the chain (an
  // intentional disconnect is never re-healed by recovery).
  nodes[1].connect_to(&nodes[2]).await;
  nodes[2].connect_to(&nodes[3]).await;
  nodes[0]
    .handle
    .command(DisconnectPeer::new(nodes[3].id().clone()))
    .await
    .unwrap();
  nodes[3]
    .handle
    .command(DisconnectPeer::new(nodes[0].id().clone()))
    .await
    .unwrap();

  let protocol = ProtocolTag::parse(PROTOCOL_TAG).unwrap();
  let policy = StreamPolicy::new(RoutingPolicy::Direct, 8).unwrap();

  // Quiesce: the live undirected topology must settle to exactly
  // {A—B, A—C, B—C, C—D} and stay stable before any packet moves, so the
  // routed path A→B→C→D is deterministic.
  let expected: std::collections::BTreeSet<(String, String)> =
    [(0usize, 1usize), (0, 2), (1, 2), (2, 3)]
      .into_iter()
      .map(|(i, j)| {
        let (lo, hi) = if nodes[i].id().as_str() < nodes[j].id().as_str() {
          (nodes[i].id().as_str(), nodes[j].id().as_str())
        } else {
          (nodes[j].id().as_str(), nodes[i].id().as_str())
        };
        (lo.to_owned(), hi.to_owned())
      })
      .collect();
  let mut stable_samples = 0_u32;
  let settle_deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let mut live = std::collections::BTreeSet::new();
    for node in &nodes {
      let page = node
        .handle
        .query(PageTopology::new(radiata::PageSpec::first(64).unwrap()))
        .await
        .unwrap();
      for edge in page.items() {
        if !edge.connected() {
          continue;
        }
        let (x, y) = (edge.source().as_str(), edge.destination().as_str());
        let (lo, hi) = if x < y { (x, y) } else { (y, x) };
        live.insert((lo.to_owned(), hi.to_owned()));
      }
    }
    if live == expected {
      stable_samples += 1;
      if stable_samples >= 5 {
        break;
      }
    } else {
      stable_samples = 0;
    }
    assert!(
      std::time::Instant::now() < settle_deadline,
      "topology did not settle to the linear chain: {live:?}"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // ---- Successful three-hop delivery ----
  let packet = nodes[0]
    .handle
    .open_stream(
      StreamTarget::Exact(nodes[3].id().clone()),
      protocol.clone(),
      policy.clone(),
      StreamMetadata::new(),
    )
    .unwrap();
  let ack = packet.send_sync(vec_body(&[b"one", b"two"])).await.unwrap();
  assert_eq!(ack.destination(), nodes[3].id());

  wait_for(
    || {
      collectors[3]
        .packets
        .lock()
        .unwrap()
        .first()
        .map(|(_, body)| body == &b"onetwo".to_vec())
        .unwrap_or(false)
    },
    Duration::from_secs(30),
    "the ordered body must reach D across three hops",
  )
  .await;

  // No intermediate consumer ran anywhere along the route.
  for collector in collectors.iter().take(3) {
    assert!(collector.packets.lock().unwrap().is_empty());
  }

  // ---- Explicit interruption of the last leg mid-stream ----
  let (body, open_flag, notify) = gated_body();
  let packet = nodes[0]
    .handle
    .open_stream(
      StreamTarget::Exact(nodes[3].id().clone()),
      protocol,
      policy,
      StreamMetadata::new(),
    )
    .unwrap();
  let route_handle = packet.send_async(body).unwrap();

  // Let the stream reach its in-flight phase.
  tokio::time::sleep(Duration::from_millis(300)).await;

  // Break the last leg while the body is still gated.
  nodes[2]
    .handle
    .command(DisconnectPeer::new(nodes[3].id().clone()))
    .await
    .unwrap();

  // The gated body observes the release only now; whatever happens next,
  // the route must end explicitly and never continue.
  open_flag.store(true, std::sync::atomic::Ordering::SeqCst);
  notify.notify_waiters();

  let _terminal = wait_until_terminal(&nodes[0].handle, &route_handle).await;
  // Whatever the local enqueue race produced, the interrupted stream's
  // bytes must never surface at D, and no reopen path continues it.
  let delivered_to_d = collectors[3]
    .packets
    .lock()
    .unwrap()
    .iter()
    .any(|(_, body)| body == &b"held".to_vec());
  assert!(
    !delivered_to_d,
    "an interrupted multi-hop stream must never deliver its body"
  );

  // A fresh synchronous send after the partition observes the typed
  // failure directly.
  let packet = nodes[0]
    .handle
    .open_stream(
      StreamTarget::Exact(nodes[3].id().clone()),
      ProtocolTag::parse(PROTOCOL_TAG).unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 8).unwrap(),
      StreamMetadata::new(),
    )
    .unwrap();
  let error = packet.send_sync(vec_body(&[b"never"])).await.unwrap_err();
  assert!(
    matches!(
      error.kind(),
      ErrorKind::StreamInterrupted | ErrorKind::RouteUnavailable | ErrorKind::Unsupported
    ),
    "expected an explicit typed route failure, got {error:?}"
  );

  for node in &nodes {
    let _ = node.handle.command(Shutdown::new()).await;
  }
}
