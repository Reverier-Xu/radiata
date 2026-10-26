//! Convenience routed replies over a relay chain.
//!
//! Four merged members form the linear topology A — B — C — D with
//! sessions only between adjacent members, so the origin of an admitted
//! stream is more than one relay away from the node that receives it.
//! The reply variants of `IncomingStream` are the regression surface:
//!
//! - `derive_return_stream_with_hops` carries an explicit relay budget and
//!   returns a reply that crosses both relays back to the origin;
//! - `derive_return_stream` keeps its single-hop budget, so on the same
//!   two-relay return path its budget runs out and the reply fails observably
//!   at the reply sender instead of reaching the origin.

use std::{
  collections::BTreeSet,
  sync::{Arc, Mutex},
  time::Duration,
};

use radiata::{
  BoxFuture, Endpoint, ErrorKind, IncomingStream, NodeBuilder, NodeConfig, NodeHandle, NodeId,
  PacketConsumer, ProtocolTag, Result, RoutingPolicy, StreamMetadata, StreamPolicy, StreamTarget,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys, required_capabilities};

const PROTOCOL_TAG: &str = "radiata.woooo.tech/protocols/test-reply";
const FEATURE_TAG: &str = "radiata.woooo.tech/features/session-core";
const REQUEST_BODY: &[u8] = b"request";
const REPLY_BODY: &[u8] = b"reply";

/// One bounded chunk: both the request and the reply are single-chunk
/// bodies, so the round trip carries no framing of its own.
fn single_chunk_body(
  bytes: &'static [u8],
) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static {
  let chunk: Arc<[u8]> = Arc::from(bytes);
  futures_util::stream::iter([Ok(chunk)])
}

/// How a receiving node answers an admitted stream, if at all.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ReplyMode {
  /// Record the stream only.
  #[default]
  Silent,
  /// The single-hop convenience reply.
  Direct,
  /// The explicit-budget reply.
  Routed { max_hops: u32 },
}

/// The observed result of one derived reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyOutcome {
  /// The reply's admission acknowledgement reached its sender.
  Delivered,
  /// The reply ended with a typed delivery failure at its sender.
  Failed(ErrorKind),
}

#[derive(Debug, Default)]
struct Collector {
  received: Mutex<Vec<(String, Vec<u8>)>>,
  reply_mode: Mutex<ReplyMode>,
  reply_outcomes: Mutex<Vec<(String, ReplyOutcome)>>,
}

impl Collector {
  fn set_reply(&self, mode: ReplyMode) {
    *self.reply_mode.lock().unwrap() = mode;
  }

  fn received(&self) -> Vec<(String, Vec<u8>)> {
    self.received.lock().unwrap().clone()
  }

  fn received_count(&self) -> usize {
    self.received.lock().unwrap().len()
  }

  fn reply_outcome(&self, trace: &str) -> Option<ReplyOutcome> {
    self
      .reply_outcomes
      .lock()
      .unwrap()
      .iter()
      .find(|(seen, _)| seen == trace)
      .map(|(_, outcome)| *outcome)
  }
}

impl PacketConsumer for Collector {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
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
      self.received.lock().unwrap().push((trace.clone(), body));

      let protocol = packet.protocol().clone();
      let reply = match *self.reply_mode.lock().unwrap() {
        ReplyMode::Silent => return Ok(()),
        ReplyMode::Direct => packet.derive_return_stream(protocol, StreamMetadata::new()),
        ReplyMode::Routed { max_hops } => {
          packet.derive_return_stream_with_hops(protocol, StreamMetadata::new(), max_hops)
        }
      };
      let outcome = match reply {
        Ok(reply) => match reply.send_sync(single_chunk_body(REPLY_BODY)).await {
          Ok(_) => ReplyOutcome::Delivered,
          Err(error) => ReplyOutcome::Failed(error.kind()),
        },
        Err(error) => ReplyOutcome::Failed(error.kind()),
      };
      self.reply_outcomes.lock().unwrap().push((trace, outcome));
      Ok(())
    })
  }
}

struct Node {
  handle: NodeHandle,
  endpoint: Option<Endpoint>,
  id: Option<NodeId>,
  collector: Arc<Collector>,
}

impl Node {
  fn id(&self) -> &NodeId {
    self
      .id
      .as_ref()
      .expect("every booted member learns its identity")
  }

  fn endpoint(&self) -> &Endpoint {
    self.endpoint.as_ref().expect("every booted member listens")
  }

  async fn listen(&mut self) {
    let listener = self
      .handle
      .listeners()
      .create(Endpoint::parse("wss://127.0.0.1:0").unwrap())
      .await
      .unwrap()
      .wait()
      .await
      .unwrap();
    self.endpoint = Some(listener.endpoint().clone());
  }

  /// Dials the peer, retrying transient handshake failures: under
  /// parallel test load a dial can race listener readiness, and one
  /// closed handshake is a retryable transport event.
  async fn connect_to(&self, peer: &Node) {
    let endpoint = peer.endpoint().clone();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
      let connected = match self
        .handle
        .connect(endpoint.clone(), peer.id().clone())
        .await
      {
        Ok(task) => task.wait().await,
        Err(error) => Err(error),
      };
      match connected {
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

async fn start_node(seed: u64, collector: Arc<Collector>) -> Node {
  let keys = Arc::new(ScriptedKeys::full_at(1_200_000 + seed * 1_000));
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
  let handle = NodeBuilder::new(factory)
    .keys(keys)
    .config(NodeConfig::new())
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

async fn wait_for<F: FnMut() -> bool>(mut probe: F, timeout: Duration, what: &str) {
  let deadline = std::time::Instant::now() + timeout;
  while !probe() {
    assert!(
      std::time::Instant::now() < deadline,
      "{what} not reached within {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
}

/// Boots four merged members of one cluster: node 0 is the merge anchor
/// and holds its identity from its local view, members 1..=3 join it and
/// learn theirs from their local view, every member listens, and every
/// member converges to all four trust bindings.
async fn boot_four() -> Vec<Node> {
  let collectors: Vec<Arc<Collector>> = (0..4).map(|_| Arc::new(Collector::default())).collect();
  let mut nodes = Vec::new();
  for (seed, collector) in collectors.iter().enumerate() {
    nodes.push(start_node(seed as u64, Arc::clone(collector)).await);
  }

  let anchor = nodes[0]
    .handle
    .local_node()
    .await
    .unwrap()
    .node_id()
    .clone();
  nodes[0].id = Some(anchor);
  nodes[0].listen().await;

  for index in 1..nodes.len() {
    let endpoint = nodes[0].endpoint().clone();
    common::merge_with_retry(&nodes[index].handle, &nodes[0].handle, endpoint).await;
    let identity = nodes[index]
      .handle
      .local_node()
      .await
      .unwrap()
      .node_id()
      .clone();
    nodes[index].id = Some(identity);
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
      match node
        .handle
        .trust()
        .list(radiata::PageSpec::first(64).unwrap())
        .await
      {
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
    // One deterministic anti-entropy round per node instead of the
    // wall-clock tick.
    for node in &nodes {
      node.handle.sync().await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
  }

  nodes
}

/// Cuts every non-adjacent session and wires B—C and C—D, so A reaches D
/// (and D reaches A) only through the two relays. Waits until the live
/// topology settles to exactly {A—B, B—C, C—D} and stays stable before
/// any packet moves. An intentional disconnect is never re-healed by
/// recovery.
async fn settle_chain(nodes: &[Node]) {
  nodes[1].connect_to(&nodes[2]).await;
  nodes[2].connect_to(&nodes[3]).await;
  for (from, to) in [(0_usize, 2_usize), (0, 3)] {
    for (a, b) in [(from, to), (to, from)] {
      nodes[a]
        .handle
        .disconnect(nodes[b].id().clone())
        .await
        .unwrap()
        .wait()
        .await
        .unwrap();
    }
  }

  let expected: BTreeSet<(String, String)> = [(0usize, 1usize), (1, 2), (2, 3)]
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

  let settle_deadline = std::time::Instant::now() + Duration::from_secs(30);
  let mut stable_samples = 0_u32;
  loop {
    let mut live = BTreeSet::new();
    for node in nodes {
      let page = node
        .handle
        .topology()
        .list(radiata::PageSpec::first(64).unwrap())
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
        return;
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
}

/// Sends one stream from A to D across both relays and returns its trace
/// id, so the caller can observe the reply that reuses it.
async fn send_request(nodes: &[Node]) -> String {
  let protocol = ProtocolTag::parse(PROTOCOL_TAG).unwrap();
  let packet = nodes[0]
    .handle
    .open_stream(
      StreamTarget::Exact(nodes[3].id().clone()),
      protocol,
      StreamPolicy::new(RoutingPolicy::Direct, 8).unwrap(),
      StreamMetadata::new(),
    )
    .unwrap();
  let trace = packet.trace_id().to_string();
  let ack = packet
    .send_sync(single_chunk_body(REQUEST_BODY))
    .await
    .unwrap();
  assert_eq!(ack.destination(), nodes[3].id());
  trace
}

/// A budgeted reply derived from a stream that arrived over two relays
/// reaches the origin: the returned stream targets the authenticated
/// source, reuses the incoming trace id, and the routing plane relays it
/// back through both intermediate nodes without admitting anything there.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_budgeted_reply_crosses_two_relays_back_to_the_origin() {
  common::init_tracing();
  let nodes = boot_four().await;
  settle_chain(&nodes).await;

  // Two relays sit between D and A, so the single-hop budget could not
  // carry this reply at all.
  nodes[3]
    .collector
    .set_reply(ReplyMode::Routed { max_hops: 4 });
  let trace = send_request(&nodes).await;

  wait_for(
    || nodes[3].collector.received_count() == 1,
    Duration::from_secs(30),
    "the request must reach D across two relays",
  )
  .await;
  wait_for(
    || nodes[3].collector.reply_outcome(&trace).is_some(),
    Duration::from_secs(30),
    "D's reply must reach a terminal outcome",
  )
  .await;
  assert_eq!(
    nodes[3].collector.reply_outcome(&trace),
    Some(ReplyOutcome::Delivered),
    "the budgeted reply must be admitted at its origin"
  );

  wait_for(
    || {
      nodes[0]
        .collector
        .received()
        .iter()
        .any(|(seen, body)| seen == &trace && body == REPLY_BODY)
    },
    Duration::from_secs(30),
    "the reply must reach the origin across two relays",
  )
  .await;

  // Only the two endpoints consumed a stream: relays never admit.
  for node in &nodes[1..3] {
    assert_eq!(
      node.collector.received_count(),
      0,
      "an intermediate node must never admit a relayed stream"
    );
  }

  for node in &nodes {
    let _ = node.handle.shutdown().await;
  }
}

/// The single-hop convenience variant is unchanged: a reply whose origin
/// is two relays away runs out of budget and ends with a typed failure at
/// the reply sender — observable to the application — and never reaches
/// the origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_single_hop_reply_fails_observably_when_its_budget_runs_out() {
  common::init_tracing();
  let nodes = boot_four().await;
  settle_chain(&nodes).await;

  nodes[3].collector.set_reply(ReplyMode::Direct);
  let trace = send_request(&nodes).await;

  wait_for(
    || nodes[3].collector.received_count() == 1,
    Duration::from_secs(30),
    "the request must reach D across two relays",
  )
  .await;
  wait_for(
    || nodes[3].collector.reply_outcome(&trace).is_some(),
    Duration::from_secs(30),
    "the exhausted reply must end with a typed failure at its sender",
  )
  .await;
  let outcome = nodes[3].collector.reply_outcome(&trace);
  assert!(
    matches!(outcome, Some(ReplyOutcome::Failed(_))),
    "the exhausted reply must fail observably at its sender, got {outcome:?}"
  );

  // Give the reply every chance to surface late: it must never arrive.
  tokio::time::sleep(Duration::from_millis(500)).await;
  assert!(
    !nodes[0]
      .collector
      .received()
      .iter()
      .any(|(seen, body)| seen == &trace && body == REPLY_BODY),
    "a reply whose hop budget ran out must never reach the origin"
  );

  for node in &nodes {
    let _ = node.handle.shutdown().await;
  }
}
