//! Sparse-topology routing measurement (audit 2026-10-23 item D-6 / R2-D05).
//!
//! Evidence work, not a behavior change: eight real TLS nodes over loopback
//! are reshaped into sparse graphs — ring, tree, dead-end branches, an
//! outbound-dial chain, and a partition — and routed packet streams measure
//! what the next-hop policy can do when it sees only local live peers
//! (`NextHopView::peers`) and the core provides no network-wide
//! reachability knowledge. Forwarding already explores branches on failure;
//! this file measures how far that goes.
//!
//! Two lanes run against every cell:
//!
//! - **default** — the built-in `DefaultNextHop` algorithm unchanged. A
//!   measuring wrapper registered under the built-in policy's own tag
//!   (`DefaultNextHop::TAG`, which a caller may claim per the registry
//!   contract) delegates every decision to `radiata::DefaultNextHop` and only
//!   records `(trace, local, chosen)` cluster-wide. No production code path
//!   changes; the wrapper is a test-side observer.
//! - **oracle** — the same wrapper answers from a precomputed BFS next-hop
//!   table of the enforced shape: what routing with full reachability knowledge
//!   would do. The oracle lane's `decisions == distance − 1` invariant and its
//!   latency anchor the comparison.
//!
//! Recorded per attempt: delivery outcome and typed failure kind,
//! send→admission-ack latency, send→consumer-arrival latency, and the
//! cluster-wide next-hop decision count (search effort: abandoned-branch
//! decisions included, the final destination short-circuit hop excluded, so
//! a delivered branchless walk observes exactly `hops − 1` decisions).
//! Failure cells classify the typed kinds the origin observes and the
//! recovery that exists (forwarder branch search, caller fresh-trace
//! retries) or does not (budget exhaustion below path length, unreachable
//! destinations, the direct-only convenience reply of D-7).
//!
//! Two tests share this harness: `sparse_routing_structural_invariants`
//! runs the lean profile (CI: real nodes, small samples, structural
//! assertions), and the ignored `sparse_routing_full_profile_tables` runs
//! the full statistical profile whose printed tables are the report data:
//!
//! ```text
//! cargo test --release --test routing_sparse_measurement \
//!   sparse_routing_full_profile_tables -- --ignored --exact --nocapture
//! ```
//!
//! Topology control: nodes join one cluster through the anchor, every shape
//! edge is dialed (lower node dials higher — the chain's edges are all
//! outbound from the low end), every non-shape edge is closed from both
//! endpoints, and the exact undirected edge set must hold stably before and
//! after each phase. `with_connection_degree(1)` keeps degree maintenance
//! from re-meshing the sparse shapes (the derived target for eight members
//! is four); the five-minute bridge-probe cadence bounds how long a healthy
//! node leaves unconnected members alone, so each run stays far inside that
//! window and verifies the edge set after every phase.

use std::{
  collections::{BTreeMap, BTreeSet},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use radiata::{
  BoxFuture, DefaultNextHop, Endpoint, Error, ErrorKind, ExtensionRegistry, IncomingStream,
  NextHopView, NodeBuilder, NodeConfig, NodeHandle, NodeId, PacketConsumer, PageSpec,
  ProtocolDefinition, ProtocolTag, Result, RouteNextHop, RoutingPolicy, StreamMetadata,
  StreamPolicy, StreamTarget, TraceId,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys, required_capabilities};

/// Cluster size: one anchor plus seven members.
const NODES: usize = 8;
/// The measurement protocol carrying the routed payloads.
const MEASURE_PROTOCOL: &str = "radiata.woooo.tech/protocols/sparse-measure";
/// The protocol of the derived convenience replies (reply-probe cell).
const REPLY_PROTOCOL: &str = "radiata.woooo.tech/protocols/sparse-reply";
/// The session-core feature both protocols declare.
const FEATURE_TAG: &str = "radiata.woooo.tech/features/session-core";
/// The generous hop budget: every simple path in an eight-node graph (at
/// most seven edges) fits, so budget never masks search behavior. A path
/// of m edges needs m − 1 ≤ budget.
const OPEN_BUDGET: u32 = 8;
/// The admission-ack wait bound for one attempt (typed failures are fast;
/// this only bounds pathological waits).
const ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// The consumer-arrival wait bound for a delivered body.
const ARRIVAL_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------
// Profile

/// One measurement profile: sample counts and settle windows.
#[derive(Clone, Copy, Debug)]
struct Profile {
  /// Attempts per (pair, budget, lane) cell.
  samples: usize,
  /// Bounded caller-retry sequences on the flagged cells.
  retry_sequences: usize,
  /// Fresh-trace attempts one retry sequence may spend.
  retry_cap: u32,
  /// The enforced edge set must hold stably for this window.
  settle_window: Duration,
  /// Convenience-reply probes on the multi-hop chain cell.
  reply_probes: usize,
  /// Attempts per failure cell (partition, budget exhaustion).
  failure_samples: usize,
}

impl Profile {
  /// The lean CI profile: every lane and failure mode exercised once with
  /// small samples; structural assertions, not statistics.
  fn lean() -> Self {
    Self {
      samples: 4,
      retry_sequences: 2,
      retry_cap: 3,
      settle_window: Duration::from_secs(3),
      reply_probes: 1,
      failure_samples: 3,
    }
  }

  /// The full statistical profile behind `--ignored`.
  fn full() -> Self {
    Self {
      samples: 40,
      retry_sequences: 20,
      retry_cap: 6,
      settle_window: Duration::from_secs(4),
      reply_probes: 3,
      failure_samples: 10,
    }
  }

  fn name(&self) -> &'static str {
    if self.samples >= 40 { "full" } else { "lean" }
  }
}

// ---------------------------------------------------------------------
// Shared measurement state

/// Which lane one trace belongs to. `Reply` marks a convenience-reply
/// probe: the main attempt and its derived reply both route through the
/// default algorithm, but their decisions land in a separate bucket so
/// the default-lane statistics stay pure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
  Default,
  Oracle,
  Reply,
}

/// One recorded next-hop decision: where it was made and what it picked
/// (`None` = the policy failed closed, e.g. a dead-end leaf with no
/// loop-free candidate).
#[derive(Clone, Debug)]
struct Decision {
  local: NodeId,
  chosen: Option<NodeId>,
}

/// The cluster-wide measurement state shared by every node's policy and
/// consumer.
#[derive(Debug, Default)]
struct Shared {
  inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
  lanes: BTreeMap<TraceId, Lane>,
  starts: BTreeMap<TraceId, Instant>,
  arrivals: BTreeMap<TraceId, Instant>,
  decisions: BTreeMap<TraceId, Vec<Decision>>,
  reply_decisions: BTreeMap<TraceId, Vec<Decision>>,
  replies: BTreeMap<TraceId, Result<(), ErrorKind>>,
  oracle: BTreeMap<(NodeId, NodeId), NodeId>,
  oracle_drift: usize,
  /// Next-hop decisions for traces the harness never marked: internal
  /// system traffic routed through the same tagged policy.
  foreign_decisions: usize,
}

impl Shared {
  fn lane_of(&self, trace: &TraceId) -> Option<Lane> {
    self.inner.lock().unwrap().lanes.get(trace).copied()
  }

  fn mark(&self, trace: &TraceId, lane: Lane) {
    self.inner.lock().unwrap().lanes.insert(trace.clone(), lane);
  }

  fn begin(&self, trace: &TraceId) {
    self
      .inner
      .lock()
      .unwrap()
      .starts
      .insert(trace.clone(), Instant::now());
  }

  fn record_decision(&self, lane: Lane, trace: &TraceId, decision: Decision) {
    let mut inner = self.inner.lock().unwrap();
    match lane {
      Lane::Reply => inner
        .reply_decisions
        .entry(trace.clone())
        .or_default()
        .push(decision),
      _ => inner
        .decisions
        .entry(trace.clone())
        .or_default()
        .push(decision),
    }
  }

  fn count_foreign(&self) {
    self.inner.lock().unwrap().foreign_decisions += 1;
  }

  fn decisions_of(&self, trace: &TraceId) -> Vec<Decision> {
    self
      .inner
      .lock()
      .unwrap()
      .decisions
      .get(trace)
      .cloned()
      .unwrap_or_default()
  }

  fn reply_decisions_of(&self, trace: &TraceId) -> Vec<Decision> {
    self
      .inner
      .lock()
      .unwrap()
      .reply_decisions
      .get(trace)
      .cloned()
      .unwrap_or_default()
  }

  fn record_arrival(&self, trace: &TraceId, at: Instant) {
    self
      .inner
      .lock()
      .unwrap()
      .arrivals
      .insert(trace.clone(), at);
  }

  fn arrival_of(&self, trace: &TraceId) -> Option<Instant> {
    self.inner.lock().unwrap().arrivals.get(trace).copied()
  }

  /// Waits until the consumer records the full-body arrival for `trace`.
  async fn wait_arrival(&self, trace: &TraceId, timeout: Duration) -> Instant {
    let deadline = Instant::now() + timeout;
    loop {
      if let Some(arrival) = self.arrival_of(trace) {
        return arrival;
      }
      assert!(
        Instant::now() < deadline,
        "the delivered body never reached the consumer within {timeout:?}"
      );
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
  }

  fn set_oracle(&self, table: BTreeMap<(NodeId, NodeId), NodeId>) {
    let mut inner = self.inner.lock().unwrap();
    inner.oracle = table;
    inner.oracle_drift = 0;
  }

  fn oracle_next(&self, local: &NodeId, destination: &NodeId) -> Option<NodeId> {
    self
      .inner
      .lock()
      .unwrap()
      .oracle
      .get(&(local.clone(), destination.clone()))
      .cloned()
  }

  fn bump_oracle_drift(&self) {
    self.inner.lock().unwrap().oracle_drift += 1;
  }

  fn oracle_drift(&self) -> usize {
    self.inner.lock().unwrap().oracle_drift
  }

  fn foreign_decisions(&self) -> usize {
    self.inner.lock().unwrap().foreign_decisions
  }

  fn record_reply(&self, trace: &TraceId, outcome: Result<(), ErrorKind>) {
    self
      .inner
      .lock()
      .unwrap()
      .replies
      .insert(trace.clone(), outcome);
  }

  /// Waits until the destination's consumer derived and pumped the
  /// convenience reply for `trace`.
  async fn wait_reply(&self, trace: &TraceId, timeout: Duration) -> Result<(), ErrorKind> {
    let deadline = Instant::now() + timeout;
    loop {
      if let Some(outcome) = self.inner.lock().unwrap().replies.get(trace).cloned() {
        return outcome;
      }
      assert!(
        Instant::now() < deadline,
        "the derived reply never resolved within {timeout:?}"
      );
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
  }
}

/// The measuring next-hop policy: an observer registered under the
/// built-in policy's own tag on every node. Default and reply lanes
/// delegate to the untouched built-in algorithm; the oracle lane answers
/// from the enforced shape's BFS table (falling back to the built-in pick
/// and counting a drift only if the table ever disagrees with the live
/// peer set, which the shape enforcement should preclude).
#[derive(Debug)]
struct MeasuringPolicy {
  shared: Arc<Shared>,
}

impl RouteNextHop for MeasuringPolicy {
  fn next_hop<'a>(&'a self, view: NextHopView<'a>) -> BoxFuture<'a, Result<NodeId>> {
    Box::pin(async move {
      let trace = view.trace().clone();
      let local = view.local().clone();
      let destination = view.destination().clone();
      let Some(lane) = self.shared.lane_of(&trace) else {
        // Unmarked trace: internal system traffic routed through the same
        // tagged policy. Behave exactly like the built-in default and
        // keep it out of the per-trace measurement log.
        self.shared.count_foreign();
        return DefaultNextHop.next_hop(view).await;
      };
      let oracle_pick = match lane {
        Lane::Oracle => {
          let next = self.shared.oracle_next(&local, &destination);
          match next {
            Some(next) if view.peers().contains(&next) => Some(next),
            _ => {
              self.shared.bump_oracle_drift();
              None
            }
          }
        }
        Lane::Default | Lane::Reply => None,
      };
      let outcome = match oracle_pick {
        Some(next) => Ok(next),
        None => DefaultNextHop.next_hop(view).await,
      };
      self.shared.record_decision(
        lane,
        &trace,
        Decision {
          local,
          chosen: outcome.as_ref().ok().cloned(),
        },
      );
      outcome
    })
  }
}

/// The destination-side consumer: drains the routed body, records the
/// arrival instant, and — for traces marked as reply probes — derives the
/// convenience return stream and pumps one chunk through it.
#[derive(Debug)]
struct Collector {
  shared: Arc<Shared>,
}

impl PacketConsumer for Collector {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, Result<(), Error>> {
    Box::pin(async move {
      let trace = packet.trace_id().clone();
      let reply_probe = self.shared.lane_of(&trace) == Some(Lane::Reply);
      let mut body = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await {
        chunk?;
      }
      self.shared.record_arrival(&trace, Instant::now());
      if reply_probe {
        let outcome = match packet.derive_return_stream(
          ProtocolTag::parse(REPLY_PROTOCOL).unwrap(),
          StreamMetadata::new(),
        ) {
          Ok(stream) => stream
            .send_sync(one_chunk_body())
            .await
            .map(|_| ())
            .map_err(|error| error.kind()),
          Err(error) => Err(error.kind()),
        };
        self.shared.record_reply(&trace, outcome);
      }
      Ok(())
    })
  }
}

/// One single-chunk body.
fn one_chunk_body() -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static {
  futures_util::stream::once(async move { Ok(Arc::from(&b"sparse-probe"[..]) as Arc<[u8]>) })
}

// ---------------------------------------------------------------------
// Cluster harness

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
  id: Option<NodeId>,
}

impl Node {
  fn id(&self) -> &NodeId {
    self.id.as_ref().unwrap()
  }
}

async fn local_id(node: &Node) -> NodeId {
  node.handle.local_node().await.unwrap().node_id().clone()
}

async fn listen(node: &mut Node) {
  let listener = node
    .handle
    .listeners()
    .create(Endpoint::parse("wss://127.0.0.1:0").unwrap())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  node.endpoint = listener.endpoint().clone();
}

/// Starts one measurement node: both protocols consumed by the shared
/// collector, the measuring policy claimed under the built-in default
/// tag, degree maintenance pinned to one session so sparse shapes hold.
async fn start_node(seed: u64, shared: &Arc<Shared>) -> Node {
  let keys = Arc::new(ScriptedKeys::full_at(700_000 + seed * 1_000));
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let collector: Arc<dyn PacketConsumer> = Arc::new(Collector {
    shared: Arc::clone(shared),
  });
  let mut registry = ExtensionRegistry::new();
  for protocol in [MEASURE_PROTOCOL, REPLY_PROTOCOL] {
    registry
      .register_protocol(
        ProtocolDefinition::new(
          ProtocolTag::parse(protocol).unwrap(),
          radiata::FeatureTag::parse(FEATURE_TAG).unwrap(),
        ),
        Arc::clone(&collector),
      )
      .unwrap();
  }
  // Claim the built-in policy's own tag: the builder auto-registers the
  // built-in default only when the tag is free, so every node resolves
  // its default route policy to the measuring wrapper.
  registry
    .register_next_hop(
      radiata::QualifiedTag::parse(DefaultNextHop::TAG).unwrap(),
      Arc::new(MeasuringPolicy {
        shared: Arc::clone(shared),
      }),
    )
    .unwrap();
  let config = NodeConfig::new().with_connection_degree(1);
  let handle = NodeBuilder::new(factory)
    .keys(keys)
    .config(config)
    .extensions(registry)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
    id: None,
  }
}

/// Issues one merge credential with bounded retries (rotation races
/// concurrent metadata commits).
async fn rotate_with_retry(issuer: &Node) -> radiata::IssuedMergeCredential {
  let deadline = Instant::now() + Duration::from_secs(30);
  loop {
    let rotated = match issuer.handle.credentials().rotate().await {
      Ok(task) => task.wait().await,
      Err(error) => Err(error),
    };
    match rotated {
      Ok(issued) => return issued,
      Err(_) if Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
      Err(error) => panic!("merge credential rotation failed persistently: {error:?}"),
    }
  }
}

/// One merge with bounded retries against the anchor's stable credential.
async fn join_with_retry(member: &mut Node, anchor: &Node, endpoint: Endpoint) {
  let issued = rotate_with_retry(anchor).await;
  let secret = issued.credential().expose_secret().to_owned();
  let deadline = Instant::now() + Duration::from_secs(300);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    let joined = match member
      .handle
      .join(
        endpoint.clone(),
        radiata::MergeCredential::parse(&secret).unwrap(),
      )
      .await
    {
      Ok(task) => task.wait().await,
      Err(error) => Err(error),
    };
    match joined {
      Ok(_) => return,
      Err(_) if Instant::now() < deadline => {
        let backoff = Duration::from_millis(250_u64.saturating_mul(1 << attempts.min(4)));
        tokio::time::sleep(backoff.min(Duration::from_secs(4))).await;
      }
      Err(error) => panic!("join failed persistently (attempt {attempts}): {error:?}"),
    }
  }
}

/// Boots the anchor plus `NODES - 1` members joined through it; every
/// node listens.
async fn build_cluster(shared: &Arc<Shared>) -> Vec<Node> {
  let mut nodes = Vec::with_capacity(NODES);
  let mut anchor = start_node(0, shared).await;
  anchor.id = Some(local_id(&anchor).await);
  listen(&mut anchor).await;
  let anchor_endpoint = anchor.endpoint.clone();
  nodes.push(anchor);
  for seed in 1..NODES as u64 {
    let mut member = start_node(seed, shared).await;
    listen(&mut member).await;
    join_with_retry(&mut member, &nodes[0], anchor_endpoint.clone()).await;
    member.id = Some(local_id(&member).await);
    nodes.push(member);
  }
  nodes
}

/// Every node's trust page converges to the full membership.
async fn wait_trust(nodes: &[Node], timeout: Duration) {
  let deadline = Instant::now() + timeout;
  loop {
    for node in nodes {
      node.handle.sync().await.unwrap();
    }
    let mut complete = true;
    for node in nodes {
      let page = node
        .handle
        .trust()
        .list(PageSpec::first(64).unwrap())
        .await
        .unwrap();
      if page.items().len() < NODES {
        complete = false;
        break;
      }
    }
    if complete {
      return;
    }
    assert!(
      Instant::now() < deadline,
      "trust convergence timeout after {timeout:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

// ---------------------------------------------------------------------
// Topology control

fn ids_of(nodes: &[Node]) -> Vec<NodeId> {
  nodes.iter().map(|node| node.id().clone()).collect()
}

/// The canonical undirected form of an edge list: `live_edges` records
/// every pair as `(min, max)`, so targets must use the same form to ever
/// compare equal (the ring's closing edge is written `(7, 0)`).
fn undirected_set(edges: &[(usize, usize)]) -> BTreeSet<(usize, usize)> {
  edges
    .iter()
    .map(|&(left, right)| (left.min(right), left.max(right)))
    .collect()
}

/// The undirected live edge set: an edge is real only when both endpoints
/// report a connected session to the other.
async fn live_edges(nodes: &[Node]) -> BTreeSet<(usize, usize)> {
  let mut directed: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); nodes.len()];
  for (index, node) in nodes.iter().enumerate() {
    let page = node
      .handle
      .topology()
      .list(PageSpec::first(64).unwrap())
      .await
      .unwrap();
    for edge in page.items() {
      if edge.connected()
        && edge.source() == node.id()
        && let Some(peer) = nodes
          .iter()
          .position(|other| other.id() == edge.destination())
      {
        directed[index].insert(peer);
      }
    }
  }
  let mut undirected = BTreeSet::new();
  for left in 0..nodes.len() {
    for right in directed[left].iter().copied() {
      if directed[right].contains(&left) {
        undirected.insert((left.min(right), left.max(right)));
      }
    }
  }
  undirected
}

/// Dials one shape edge: the lower node dials the higher (the chain
/// family's edges are therefore all outbound from the low end), retrying
/// transient handshake failures.
async fn dial_edge(nodes: &[Node], low: usize, high: usize) {
  let endpoint = nodes[high].endpoint.clone();
  let peer = nodes[high].id().clone();
  let deadline = Instant::now() + Duration::from_secs(30);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    let connected = match nodes[low]
      .handle
      .connect(endpoint.clone(), peer.clone())
      .await
    {
      Ok(task) => task.wait().await,
      Err(error) => Err(error),
    };
    match connected {
      Ok(_) => return,
      Err(_) if Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
      Err(error) => {
        panic!("dial {low} -> {high} failed persistently (attempt {attempts}): {error:?}")
      }
    }
  }
}

/// Closes one edge from both endpoints (both must retire the session for
/// the edge to disappear).
async fn close_edge(nodes: &[Node], left: usize, right: usize) {
  for (from, to) in [(left, right), (right, left)] {
    if let Ok(task) = nodes[from].handle.disconnect(nodes[to].id().clone()).await {
      let _ = task.wait().await;
    }
  }
}

/// Enforces the exact undirected edge set: dials missing shape edges,
/// closes everything else, and repeats until the exact set has held
/// stably across `window`. Bridge probes (one dial per healthy node per
/// five minutes) can land a stray edge; the convergent loop closes it
/// again and restarts the stability window.
async fn enforce_topology(
  nodes: &[Node], target: &BTreeSet<(usize, usize)>, window: Duration, timeout: Duration,
) {
  let deadline = Instant::now() + timeout;
  loop {
    let live = live_edges(nodes).await;
    if live == *target {
      tokio::time::sleep(window).await;
      if live_edges(nodes).await == *target {
        return;
      }
      eprintln!("topology drifted inside the settle window; re-enforcing");
    } else {
      let missing: Vec<_> = target.difference(&live).copied().collect();
      let extra: Vec<_> = live.difference(target).copied().collect();
      eprintln!("enforce: missing={missing:?} extra={extra:?}");
      for (low, high) in missing {
        dial_edge(nodes, low, high).await;
        tokio::time::sleep(Duration::from_millis(120)).await;
      }
      for (left, right) in extra {
        close_edge(nodes, left, right).await;
      }
    }
    assert!(
      Instant::now() < deadline,
      "topology enforcement timeout: expected {target:?}, live {:?}",
      live_edges(nodes).await
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
  }
}

// ---------------------------------------------------------------------
// Graph helpers

fn adjacency(edges: &[(usize, usize)]) -> Vec<BTreeSet<usize>> {
  let mut adjacency = vec![BTreeSet::new(); NODES];
  for (left, right) in edges {
    adjacency[*left].insert(*right);
    adjacency[*right].insert(*left);
  }
  adjacency
}

/// BFS distances from `source`; unreachable nodes keep `usize::MAX`.
fn distances_from(adjacency: &[BTreeSet<usize>], source: usize) -> Vec<usize> {
  let mut distance = vec![usize::MAX; adjacency.len()];
  distance[source] = 0;
  let mut queue = std::collections::VecDeque::from([source]);
  while let Some(current) = queue.pop_front() {
    for neighbor in &adjacency[current] {
      if distance[*neighbor] == usize::MAX {
        distance[*neighbor] = distance[current] + 1;
        queue.push_back(*neighbor);
      }
    }
  }
  distance
}

fn graph_distance(edges: &[(usize, usize)], from: usize, to: usize) -> usize {
  distances_from(&adjacency(edges), from)[to]
}

/// The BFS next-hop table of one shape: `(local, destination) -> next`,
/// the neighbor of `local` on a shortest path toward `destination`.
fn oracle_table(nodes: &[Node], edges: &[(usize, usize)]) -> BTreeMap<(NodeId, NodeId), NodeId> {
  let adjacency = adjacency(edges);
  let ids = ids_of(nodes);
  let mut table = BTreeMap::new();
  for destination in 0..NODES {
    let distance = distances_from(&adjacency, destination);
    for local in 0..NODES {
      if local == destination || distance[local] == usize::MAX {
        continue;
      }
      if let Some(next) = adjacency[local]
        .iter()
        .find(|neighbor| distance[**neighbor] == distance[local] - 1)
        .copied()
      {
        table.insert(
          (ids[local].clone(), ids[destination].clone()),
          ids[next].clone(),
        );
      }
    }
  }
  table
}

// ---------------------------------------------------------------------
// Attempt machinery

/// One measured send attempt.
#[derive(Clone, Debug)]
struct Attempt {
  trace: TraceId,
  delivered: bool,
  kind: Option<ErrorKind>,
  ack: Duration,
  e2e: Option<Duration>,
  decisions: usize,
  /// Exact hop count of a delivered branchless walk (ring, chain):
  /// `decisions + 1` — every decision moves the frame one edge and the
  /// final hop into the destination short-circuits without a decision.
  hops: Option<usize>,
}

/// Runs one synchronous send and records its outcome.
async fn send_one(
  nodes: &[Node], shared: &Arc<Shared>, lane: Lane, origin: usize, destination: usize, budget: u32,
) -> Attempt {
  let target = nodes[destination].id().clone();
  let stream = nodes[origin]
    .handle
    .open_stream(
      StreamTarget::Exact(target.clone()),
      ProtocolTag::parse(MEASURE_PROTOCOL).unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, budget).unwrap(),
      StreamMetadata::new(),
    )
    .unwrap();
  let trace = stream.trace_id().clone();
  shared.mark(&trace, lane);
  let started = Instant::now();
  shared.begin(&trace);
  let outcome = tokio::time::timeout(ACK_TIMEOUT, stream.send_sync(one_chunk_body())).await;
  let ack_latency = started.elapsed();
  let decisions = shared.decisions_of(&trace);
  let successful_walk = decisions.iter().all(|decision| decision.chosen.is_some());
  match outcome {
    Ok(Ok(ack)) => {
      assert_eq!(
        ack.destination(),
        &target,
        "the ack must name the destination"
      );
      let arrival = shared.wait_arrival(&trace, ARRIVAL_TIMEOUT).await;
      Attempt {
        trace,
        delivered: true,
        kind: None,
        ack: ack_latency,
        e2e: Some(arrival.duration_since(started)),
        decisions: decisions.len(),
        hops: successful_walk.then_some(decisions.len() + 1),
      }
    }
    Ok(Err(error)) => Attempt {
      trace,
      delivered: false,
      kind: Some(error.kind()),
      ack: ack_latency,
      e2e: None,
      decisions: decisions.len(),
      hops: None,
    },
    Err(_) => Attempt {
      trace,
      delivered: false,
      kind: Some(ErrorKind::StreamInterrupted),
      ack: ack_latency,
      e2e: None,
      decisions: decisions.len(),
      hops: None,
    },
  }
}

/// The hop count a ring walk committed to: the origin's recorded pick of
/// its clockwise or counterclockwise neighbor fixes the direction, and a
/// loop-free ring walk cannot reverse, so the path is exactly the
/// directed arc length.
fn ring_commitment_hops(
  decisions: &[Decision], ids: &[NodeId], origin: usize, destination: usize,
) -> Option<usize> {
  let first = decisions
    .iter()
    .find(|decision| decision.local == ids[origin])?;
  let chosen = first.chosen.as_ref()?;
  let chosen_index = ids.iter().position(|id| id == chosen)?;
  if chosen_index == (origin + 1) % NODES {
    Some((destination + NODES - origin) % NODES)
  } else if chosen_index == (origin + NODES - 1) % NODES {
    Some((origin + NODES - destination) % NODES)
  } else {
    None
  }
}

/// Runs one bounded caller-retry sequence: fresh trace per attempt (the
/// documented recovery for a failed delivery attempt), capped at `cap`
/// attempts. Returns the per-attempt records and the total wall time.
async fn retry_sequence(
  nodes: &[Node], shared: &Arc<Shared>, origin: usize, destination: usize, budget: u32, cap: u32,
) -> (Vec<Attempt>, Duration) {
  let started = Instant::now();
  let mut attempts = Vec::new();
  for _ in 0..cap {
    let attempt = send_one(nodes, shared, Lane::Default, origin, destination, budget).await;
    let delivered = attempt.delivered;
    attempts.push(attempt);
    if delivered {
      break;
    }
  }
  (attempts, started.elapsed())
}

// ---------------------------------------------------------------------
// Shapes and cells

struct PairCell {
  origin: usize,
  destination: usize,
  budgets: Vec<u32>,
  /// Branchless graph between origin and destination (ring arc, chain
  /// segment): a delivered walk's hop count is exactly `decisions + 1`.
  branchless: bool,
  /// Ring-shaped graph: the direction commitment is derivable and the
  /// budget model (`path ≤ budget + 1` edges) is exactly predictable.
  ring: bool,
  /// Run the bounded caller-retry lane on the open budget.
  retry_lane: bool,
}

struct Shape {
  name: &'static str,
  edges: Vec<(usize, usize)>,
  pairs: Vec<PairCell>,
}

fn shapes() -> Vec<Shape> {
  vec![
    // Ring: degree two everywhere, no branches; either direction
    // delivers, so success at a given budget is a pure function of the
    // origin's hash-direction pick.
    Shape {
      name: "ring8",
      edges: vec![
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
        (5, 6),
        (6, 7),
        (7, 0),
      ],
      pairs: vec![
        PairCell {
          origin: 0,
          destination: 3,
          budgets: vec![OPEN_BUDGET, 3],
          branchless: true,
          ring: true,
          retry_lane: true,
        },
        PairCell {
          origin: 1,
          destination: 6,
          budgets: vec![OPEN_BUDGET],
          branchless: true,
          ring: true,
          retry_lane: false,
        },
        PairCell {
          origin: 0,
          destination: 4,
          budgets: vec![OPEN_BUDGET],
          branchless: true,
          ring: true,
          retry_lane: false,
        },
      ],
    },
    // Balanced-ish tree with pendant leaves: the forwarder branch search
    // recovers dead-end subtrees (leaf origins always deliver), while a
    // branching origin that picks a destination-free subtree fails the
    // attempt outright — the origin runs no branch search of its own.
    Shape {
      name: "tree8",
      edges: vec![(3, 1), (3, 5), (1, 0), (1, 2), (5, 4), (5, 6), (4, 7)],
      pairs: vec![
        PairCell {
          origin: 0,
          destination: 6,
          budgets: vec![OPEN_BUDGET],
          branchless: false,
          ring: false,
          retry_lane: false,
        },
        PairCell {
          origin: 1,
          destination: 6,
          budgets: vec![OPEN_BUDGET],
          branchless: false,
          ring: false,
          retry_lane: true,
        },
        PairCell {
          origin: 5,
          destination: 2,
          budgets: vec![OPEN_BUDGET],
          branchless: false,
          ring: false,
          retry_lane: true,
        },
        PairCell {
          origin: 7,
          destination: 2,
          budgets: vec![OPEN_BUDGET],
          branchless: false,
          ring: false,
          retry_lane: false,
        },
      ],
    },
    // Line core with pendant dead ends: random walks enter the dead ends;
    // only the forwarder branch search pulls them back out.
    Shape {
      name: "deadend8",
      edges: vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (1, 6), (4, 7)],
      pairs: vec![
        PairCell {
          origin: 0,
          destination: 5,
          budgets: vec![OPEN_BUDGET],
          branchless: false,
          ring: false,
          retry_lane: false,
        },
        PairCell {
          origin: 6,
          destination: 7,
          budgets: vec![OPEN_BUDGET],
          branchless: false,
          ring: false,
          retry_lane: false,
        },
      ],
    },
    // Chain with every edge dialed by its lower endpoint (all outbound
    // from the low end): node 0 holds only an outbound edge, node 7 only
    // an inbound one — the direction-parity pair — plus the direct
    // baseline (0,1) and the full seven-hop crossing.
    Shape {
      name: "chain8",
      edges: vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)],
      pairs: vec![
        PairCell {
          origin: 0,
          destination: 1,
          budgets: vec![OPEN_BUDGET],
          branchless: true,
          ring: false,
          retry_lane: false,
        },
        PairCell {
          origin: 3,
          destination: 6,
          budgets: vec![OPEN_BUDGET],
          branchless: true,
          ring: false,
          retry_lane: false,
        },
        PairCell {
          origin: 0,
          destination: 7,
          budgets: vec![OPEN_BUDGET, 3],
          branchless: true,
          ring: false,
          retry_lane: true,
        },
        PairCell {
          origin: 7,
          destination: 0,
          budgets: vec![OPEN_BUDGET],
          branchless: true,
          ring: false,
          retry_lane: false,
        },
      ],
    },
  ]
}

// ---------------------------------------------------------------------
// Aggregation and report

/// Percentile helper over a duration slice.
fn percentile(mut samples: Vec<Duration>, fraction: f64) -> Option<Duration> {
  if samples.is_empty() {
    return None;
  }
  samples.sort();
  let index = ((samples.len() as f64) * fraction).ceil() as usize;
  samples
    .get(index.saturating_sub(1).min(samples.len() - 1))
    .copied()
}

fn fmt_duration(value: Option<Duration>) -> String {
  value
    .map(|duration| format!("{duration:.1?}"))
    .unwrap_or_else(|| "—".to_owned())
}

/// One measured (shape, pair, budget, lane) cell.
#[derive(Debug)]
struct Cell {
  shape: &'static str,
  origin: usize,
  destination: usize,
  /// BFS distance, or `None` for cross-partition cells.
  distance: Option<usize>,
  budget: u32,
  lane: &'static str,
  attempts: Vec<Attempt>,
}

impl Cell {
  fn delivered(&self) -> usize {
    self
      .attempts
      .iter()
      .filter(|attempt| attempt.delivered)
      .count()
  }

  fn failures_by_kind(&self) -> BTreeMap<String, usize> {
    let mut kinds = BTreeMap::new();
    for attempt in self.attempts.iter().filter(|attempt| !attempt.delivered) {
      let kind = attempt
        .kind
        .map(|kind| format!("{kind:?}"))
        .unwrap_or_else(|| "unknown".to_owned());
      *kinds.entry(kind).or_default() += 1;
    }
    kinds
  }

  fn print(&self) {
    let delivered = self.delivered();
    let total = self.attempts.len();
    let acks: Vec<Duration> = self.attempts.iter().map(|attempt| attempt.ack).collect();
    let e2es: Vec<Duration> = self
      .attempts
      .iter()
      .filter_map(|attempt| attempt.e2e)
      .collect();
    let delivered_decisions: Vec<usize> = self
      .attempts
      .iter()
      .filter(|attempt| attempt.delivered)
      .map(|attempt| attempt.decisions)
      .collect();
    let hops: Vec<usize> = self
      .attempts
      .iter()
      .filter_map(|attempt| attempt.hops)
      .collect();
    let decisions_mean = (!delivered_decisions.is_empty())
      .then(|| delivered_decisions.iter().sum::<usize>() as f64 / delivered_decisions.len() as f64);
    println!(
      "  {shape}:{origin}->{destination} d={} budget={budget} lane={lane:<7} \
       ok {delivered}/{total} | dec mean {} max {} | hops {hops:?} | \
       ack p50 {} p90 {} max {} | e2e p50 {} p90 {} | fail {:?}",
      self
        .distance
        .map(|distance| distance.to_string())
        .unwrap_or_else(|| "∅".to_owned()),
      decisions_mean
        .map(|mean| format!("{mean:.1}"))
        .unwrap_or_else(|| "—".to_owned()),
      delivered_decisions
        .iter()
        .max()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "—".to_owned()),
      fmt_duration(percentile(acks.clone(), 0.50)),
      fmt_duration(percentile(acks.clone(), 0.90)),
      fmt_duration(acks.iter().max().copied()),
      fmt_duration(percentile(e2es.clone(), 0.50)),
      fmt_duration(percentile(e2es.clone(), 0.90)),
      self.failures_by_kind(),
      shape = self.shape,
      origin = self.origin,
      destination = self.destination,
      budget = self.budget,
      lane = self.lane,
      delivered = delivered,
      total = total,
    );
  }
}

/// One bounded caller-retry sequence outcome.
#[derive(Debug)]
struct RetryOutcome {
  attempts: usize,
  delivered: bool,
  total: Duration,
}

fn print_retries(
  shape: &str, origin: usize, destination: usize, budget: u32, retries: &[RetryOutcome],
) {
  let delivered = retries.iter().filter(|retry| retry.delivered).count();
  let totals: Vec<Duration> = retries.iter().map(|retry| retry.total).collect();
  let attempt_counts: Vec<usize> = retries.iter().map(|retry| retry.attempts).collect();
  println!(
    "  {shape}:{origin}->{destination} budget={budget} lane=retry  ok {delivered}/{} | \
     attempts mean {:.1} max {} | exhausted caps {} | total p50 {} p90 {}",
    retries.len(),
    attempt_counts.iter().sum::<usize>() as f64 / retries.len().max(1) as f64,
    attempt_counts.iter().max().copied().unwrap_or(0),
    retries.iter().filter(|retry| !retry.delivered).count(),
    fmt_duration(percentile(totals.clone(), 0.50)),
    fmt_duration(percentile(totals.clone(), 0.90)),
  );
}

// ---------------------------------------------------------------------
// The measurement run

/// Collected structural-invariant violations; asserted empty at the end.
#[derive(Default)]
struct Invariants {
  violations: Vec<String>,
}

impl Invariants {
  fn check(&mut self, condition: bool, message: String) {
    if !condition {
      self.violations.push(message);
    }
  }

  fn finish(self) {
    assert!(
      self.violations.is_empty(),
      "structural invariant violations:\n  {}",
      self.violations.join("\n  ")
    );
  }
}

/// Measures one shape phase: enforces the exact topology, installs the
/// BFS oracle table, runs the lanes, and prints the cells.
async fn measure_shape(
  nodes: &[Node], shared: &Arc<Shared>, shape: &Shape, profile: Profile,
  invariants: &mut Invariants,
) {
  let target = undirected_set(&shape.edges);
  println!("=== shape {} ({} edges) ===", shape.name, shape.edges.len());
  enforce_topology(
    nodes,
    &target,
    profile.settle_window,
    Duration::from_secs(120),
  )
  .await;
  shared.set_oracle(oracle_table(nodes, &shape.edges));
  let ids = ids_of(nodes);

  // One warmup delivery per shape: the first admission on the fresh
  // topology stays outside the measured samples.
  let warmup = send_one(nodes, shared, Lane::Default, 0, 1, OPEN_BUDGET).await;
  assert!(warmup.delivered, "the warmup delivery must succeed");

  for pair in &shape.pairs {
    let distance = graph_distance(&shape.edges, pair.origin, pair.destination);
    for budget in &pair.budgets {
      // ---- oracle lane: the full-knowledge anchor ----
      let mut oracle = Cell {
        shape: shape.name,
        origin: pair.origin,
        destination: pair.destination,
        distance: Some(distance),
        budget: *budget,
        lane: "oracle",
        attempts: Vec::new(),
      };
      for _ in 0..profile.samples {
        oracle.attempts.push(
          send_one(
            nodes,
            shared,
            Lane::Oracle,
            pair.origin,
            pair.destination,
            *budget,
          )
          .await,
        );
      }
      for attempt in &oracle.attempts {
        // The oracle walks a shortest path of `distance` edges, which a
        // budget below `distance − 1` can never carry — there the oracle
        // must fail like every policy.
        if distance.saturating_sub(1) <= *budget as usize {
          invariants.check(
            attempt.delivered,
            format!(
              "{}:{}->{} budget {}: oracle lane failed ({:?})",
              shape.name, pair.origin, pair.destination, budget, attempt.kind
            ),
          );
          invariants.check(
            attempt.decisions + 1 == distance,
            format!(
              "{}:{}->{} budget {}: oracle decisions {} != distance − 1 = {}",
              shape.name,
              pair.origin,
              pair.destination,
              budget,
              attempt.decisions,
              distance - 1
            ),
          );
        } else {
          invariants.check(
            !attempt.delivered && attempt.kind == Some(ErrorKind::StreamInterrupted),
            format!(
              "{}:{}->{} budget {}: sub-length budget must fail typed StreamInterrupted, got \
               delivered={} ({:?})",
              shape.name, pair.origin, pair.destination, budget, attempt.delivered, attempt.kind
            ),
          );
        }
      }
      oracle.print();

      // ---- default lane: local live peers only ----
      let mut default = Cell {
        shape: shape.name,
        origin: pair.origin,
        destination: pair.destination,
        distance: Some(distance),
        budget: *budget,
        lane: "default",
        attempts: Vec::new(),
      };
      for _ in 0..profile.samples {
        let attempt = send_one(
          nodes,
          shared,
          Lane::Default,
          pair.origin,
          pair.destination,
          *budget,
        )
        .await;
        default.attempts.push(attempt);
      }
      for attempt in &default.attempts {
        let decisions = shared.decisions_of(&attempt.trace);
        if attempt.delivered {
          if pair.branchless {
            // On a ring the origin's direction pick commits the walk to
            // one of the two arcs — the long way around is a valid
            // branchless walk — so the expected hop count is the
            // committed arc, not the BFS distance.
            let expected = if pair.ring {
              ring_commitment_hops(&decisions, &ids, pair.origin, pair.destination)
            } else {
              Some(distance)
            };
            invariants.check(
              attempt.hops == expected,
              format!(
                "{}:{}->{} budget {}: branchless delivered walk took {:?} hops, not {expected:?}",
                shape.name, pair.origin, pair.destination, budget, attempt.hops
              ),
            );
          }
          invariants.check(
            attempt.decisions + 1 >= distance,
            format!(
              "{}:{}->{} budget {}: delivered with {} decisions, below distance − 1",
              shape.name, pair.origin, pair.destination, budget, attempt.decisions
            ),
          );
        } else if let Some(kind) = attempt.kind {
          // The failed attempt's body must never surface (at-most-once
          // data plane): no delivery behind a typed failure.
          invariants.check(
            shared.arrival_of(&attempt.trace).is_none(),
            format!(
              "{}:{}->{} budget {}: body delivered despite the typed failure {kind:?}",
              shape.name, pair.origin, pair.destination, budget
            ),
          );
        }
        if pair.ring {
          // The ring budget model: the origin's direction pick fixes the
          // arc; the attempt succeeds exactly when that arc fits the
          // budget (a path of m edges needs m − 1 ≤ budget).
          if let Some(committed) =
            ring_commitment_hops(&decisions, &ids, pair.origin, pair.destination)
          {
            let predicted = committed <= *budget as usize + 1;
            invariants.check(
              predicted == attempt.delivered,
              format!(
                "{}:{}->{} budget {}: ring model predicted {} for a {}-hop arc, got delivered={}",
                shape.name,
                pair.origin,
                pair.destination,
                budget,
                predicted,
                committed,
                attempt.delivered
              ),
            );
          } else {
            invariants.violations.push(format!(
              "{}:{}->{} budget {}: ring decision log missing the origin's direction pick",
              shape.name, pair.origin, pair.destination, budget
            ));
          }
        }
      }
      default.print();

      // ---- bounded caller-retry lane ----
      if pair.retry_lane {
        let mut retries = Vec::new();
        for _ in 0..profile.retry_sequences {
          let (attempts, total) = retry_sequence(
            nodes,
            shared,
            pair.origin,
            pair.destination,
            *budget,
            profile.retry_cap,
          )
          .await;
          retries.push(RetryOutcome {
            attempts: attempts.len(),
            delivered: attempts.last().map(|attempt| attempt.delivered) == Some(true),
            total,
          });
        }
        print_retries(shape.name, pair.origin, pair.destination, *budget, &retries);
      }
    }
  }
}

/// The full run: boot, shape phases, failure cells, report, invariants.
async fn run_measurement(profile: Profile) {
  init_tracing();
  println!(
    "=== sparse-topology routing measurement | profile {} | build {} ===",
    profile.name(),
    if cfg!(debug_assertions) {
      "debug"
    } else {
      "release"
    },
  );
  let shared = Arc::new(Shared::default());
  let nodes = build_cluster(&shared).await;
  wait_trust(&nodes, Duration::from_secs(180)).await;
  let mut invariants = Invariants::default();

  for shape in shapes() {
    measure_shape(&nodes, &shared, &shape, profile, &mut invariants).await;
    // The topology must have stayed exact through the whole phase; a
    // bridge probe landing mid-phase invalidates the samples.
    let target = undirected_set(&shape.edges);
    let live = live_edges(&nodes).await;
    invariants.check(
      live == target,
      format!("shape {} drifted during measurement: {live:?}", shape.name),
    );
  }

  run_failure_cells(&nodes, &shared, profile, &mut invariants).await;

  println!("=== summary ===");
  println!(
    "oracle drift {} | foreign next-hop decisions (system traffic) {}",
    shared.oracle_drift(),
    shared.foreign_decisions(),
  );
  invariants.finish();
  for node in &nodes {
    let _ = node.handle.shutdown().await;
  }
}

/// The partition, budget-exhaustion, and convenience-reply failure cells.
async fn run_failure_cells(
  nodes: &[Node], shared: &Arc<Shared>, profile: Profile, invariants: &mut Invariants,
) {
  println!("=== shape partition8 (anchor pair + six-node line) ===");
  let target = undirected_set(&[(0, 1), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)]);
  enforce_topology(
    nodes,
    &target,
    profile.settle_window,
    Duration::from_secs(120),
  )
  .await;

  // P1: origin in the isolated pair, destination in the other component.
  // The origin's only forwarder has no loop-free candidate: the typed
  // rejection surfaces at the origin unchanged.
  let mut p1 = Cell {
    shape: "partition8",
    origin: 0,
    destination: 7,
    distance: None,
    budget: OPEN_BUDGET,
    lane: "default",
    attempts: Vec::new(),
  };
  for _ in 0..profile.failure_samples {
    p1.attempts
      .push(send_one(nodes, shared, Lane::Default, 0, 7, OPEN_BUDGET).await);
  }
  for attempt in &p1.attempts {
    invariants.check(
      !attempt.delivered && attempt.kind == Some(ErrorKind::Unsupported),
      format!(
        "partition 0->7 must fail typed Unsupported, got {:?}",
        attempt.kind
      ),
    );
    invariants.check(
      attempt.ack < Duration::from_secs(2),
      format!(
        "partition 0->7 immediate dead-end rejection should be fast, took {:?}",
        attempt.ack
      ),
    );
    invariants.check(
      shared.arrival_of(&attempt.trace).is_none(),
      "no body may surface behind the partition rejection".to_owned(),
    );
  }
  p1.print();

  // P2: origin in the large component, destination in the isolated pair.
  // The forwarder branch search sweeps the whole component before the
  // generic failure surfaces at the origin.
  let mut p2 = Cell {
    shape: "partition8",
    origin: 2,
    destination: 0,
    distance: None,
    budget: OPEN_BUDGET,
    lane: "default",
    attempts: Vec::new(),
  };
  for _ in 0..profile.failure_samples {
    p2.attempts
      .push(send_one(nodes, shared, Lane::Default, 2, 0, OPEN_BUDGET).await);
  }
  for attempt in &p2.attempts {
    invariants.check(
      !attempt.delivered && attempt.kind == Some(ErrorKind::StreamInterrupted),
      format!(
        "partition 2->0 must fail typed StreamInterrupted, got {:?}",
        attempt.kind
      ),
    );
  }
  p2.print();

  // P3: caller retries cannot recover an unreachable destination.
  let mut retries = Vec::new();
  for _ in 0..profile.retry_sequences {
    let (attempts, total) =
      retry_sequence(nodes, shared, 2, 0, OPEN_BUDGET, profile.retry_cap).await;
    retries.push(RetryOutcome {
      attempts: attempts.len(),
      delivered: attempts.last().map(|attempt| attempt.delivered) == Some(true),
      total,
    });
  }
  for retry in &retries {
    invariants.check(
      !retry.delivered,
      "caller retries must never deliver to an unreachable destination".to_owned(),
    );
  }
  print_retries("partition8", 2, 0, OPEN_BUDGET, &retries);

  // P4: isolated origin. The recovery plane re-dials an offline node on
  // its own cadence (seconds), so the send follows the disconnect
  // immediately; a raced round retries the cell.
  for round in 0..3 {
    close_edge(nodes, 0, 1).await;
    let isolated_deadline = Instant::now() + Duration::from_secs(5);
    loop {
      let page = nodes[0]
        .handle
        .topology()
        .list(PageSpec::first(64).unwrap())
        .await
        .unwrap();
      let connected = page
        .items()
        .iter()
        .any(|edge| edge.source() == nodes[0].id() && edge.connected());
      if !connected {
        break;
      }
      assert!(
        Instant::now() < isolated_deadline,
        "node 0 never reached zero live sessions"
      );
      tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let attempt = send_one(nodes, shared, Lane::Default, 0, 7, OPEN_BUDGET).await;
    if !attempt.delivered && attempt.kind == Some(ErrorKind::RouteUnavailable) {
      println!(
        "  isolated-origin 0->7: RouteUnavailable after {:.1?} (round {round})",
        attempt.ack
      );
      break;
    }
    assert!(
      round < 2,
      "isolated-origin cell raced the recovery plane three times: {:?}",
      attempt.kind
    );
  }

  // ---- budget exhaustion and convenience replies on the chain ----
  println!("=== shape chain8 (re-enforced for exhaustion and reply cells) ===");
  let chain = undirected_set(&[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)]);
  enforce_topology(
    nodes,
    &chain,
    profile.settle_window,
    Duration::from_secs(120),
  )
  .await;

  // B1: seven-hop destination under a three-hop budget. Every path is
  // longer than the budget, so no attempt and no fresh trace can deliver.
  let mut b1 = Cell {
    shape: "chain8",
    origin: 0,
    destination: 7,
    distance: Some(7),
    budget: 3,
    lane: "default",
    attempts: Vec::new(),
  };
  for _ in 0..profile.failure_samples {
    b1.attempts
      .push(send_one(nodes, shared, Lane::Default, 0, 7, 3).await);
  }
  for attempt in &b1.attempts {
    invariants.check(
      !attempt.delivered && attempt.kind == Some(ErrorKind::StreamInterrupted),
      format!(
        "chain 0->7 budget 3 must fail typed StreamInterrupted, got {:?}",
        attempt.kind
      ),
    );
  }
  b1.print();

  let mut retries = Vec::new();
  for _ in 0..profile.retry_sequences {
    let (attempts, total) = retry_sequence(nodes, shared, 0, 7, 3, profile.retry_cap).await;
    retries.push(RetryOutcome {
      attempts: attempts.len(),
      delivered: attempts.last().map(|attempt| attempt.delivered) == Some(true),
      total,
    });
  }
  for retry in &retries {
    invariants.check(
      !retry.delivered,
      "retries at a sub-path-length budget must never deliver".to_owned(),
    );
  }
  print_retries("chain8", 0, 7, 3, &retries);

  // R: convenience-reply probes. A delivered multi-hop stream's derived
  // return stream is direct-only (hardcoded one-hop budget, D-7's
  // decided boundary): the reply can never cross the chain back to the
  // source, whatever the caller intends.
  for probe in 0..profile.reply_probes {
    let target = nodes[7].id().clone();
    let stream = nodes[0]
      .handle
      .open_stream(
        StreamTarget::Exact(target),
        ProtocolTag::parse(MEASURE_PROTOCOL).unwrap(),
        StreamPolicy::new(RoutingPolicy::Direct, OPEN_BUDGET).unwrap(),
        StreamMetadata::new(),
      )
      .unwrap();
    let trace = stream.trace_id().clone();
    shared.mark(&trace, Lane::Reply);
    shared.begin(&trace);
    let ack = stream.send_sync(one_chunk_body()).await;
    assert!(
      ack.is_ok(),
      "the probe's main delivery must succeed: {ack:?}"
    );
    let _ = shared.wait_arrival(&trace, ARRIVAL_TIMEOUT).await;
    let reply = shared.wait_reply(&trace, Duration::from_secs(15)).await;
    let reply_decisions = shared.reply_decisions_of(&trace).len();
    println!(
      "  reply-probe 7->0 (derived from the delivered 0->7 stream): \
       outcome {reply:?} after {reply_decisions} reply next-hop decisions (probe {probe})"
    );
    invariants.check(
      reply.is_err(),
      "the direct-only derived reply must fail on a multi-hop route".to_owned(),
    );
  }
}

fn init_tracing() {
  use std::sync::Once;
  static INIT: Once = Once::new();
  INIT.call_once(|| {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
      .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("radiata=warn"));
    let _ = tracing_subscriber::fmt()
      .with_env_filter(filter)
      .with_test_writer()
      .try_init();
  });
}

// ---------------------------------------------------------------------
// Tests

/// The lean CI lane: real nodes on all shape families, every lane and
/// failure mode exercised, structural invariants asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sparse_routing_structural_invariants() {
  run_measurement(Profile::lean()).await;
}

/// The full statistical profile behind `--ignored`; its printed tables
/// are the D-6 measurement report data.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "full statistical profile: cargo test --release --test routing_sparse_measurement sparse_routing_full_profile_tables -- --ignored --exact --nocapture"]
async fn sparse_routing_full_profile_tables() {
  run_measurement(Profile::full()).await;
}
