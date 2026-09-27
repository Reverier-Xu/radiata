//! The connection-degree lanes: the maintenance plane's public contract
//! over real transports.
//!
//! Two scenarios:
//!
//! 1. **Dial back to target.** A five-node star leaves every leaf one session
//!    below the derived target degree k(5) = 3; the maintenance tick dials
//!    uniformly random unconnected members until every node reports `Healthy`
//!    through the status query. The hub, already at four sessions, proves the
//!    healthy path needs no dials at all.
//! 2. **Dial racing the binding spread.** A member dial fired before the
//!    target's trusted binding has spread fails with the typed retryable
//!    `NotFound` — never an authentication failure — and a bounded retry
//!    succeeds once one forced sync round carries the binding. A dial against a
//!    member that can never be known pins the same typed refusal
//!    deterministically.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use radiata::{
  ConnectMember, Endpoint, ErrorKind, GetConnectionDegree, GetLocalNode, GetRecovery, Listen,
  NodeBuilder, NodeConfig, NodeHandle, NodeId, PageMembers, PageSpec, RunSyncRound, Shutdown,
  WaitForShutdown,
};
mod common;

use common::{MemoryStorageFactory, ScriptedKeys, merge_with_retry};

/// The shared cluster gate: the lanes serialize so each cluster owns the
/// process while it runs (the harness runs test files concurrently).
fn cluster_gate() -> &'static tokio::sync::Mutex<()> {
  static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
  GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn init_tracing() {
  use std::sync::Once;
  static INIT: Once = Once::new();
  INIT.call_once(|| {
    tracing_subscriber::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
      .with_test_writer()
      .init();
  });
}

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
  id: NodeId,
}

async fn start_node(seed: u64, storage: Arc<MemoryStorageFactory>, config: NodeConfig) -> Node {
  let factory: Arc<dyn radiata::extension::StorageFactory> = storage.clone();
  let keys = Arc::new(ScriptedKeys::full_at(700_000 + seed * 1_000));
  let handle = NodeBuilder::new(factory)
    .keys(keys)
    .config(config)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
    id: NodeId::parse(&format!("node-{seed:021}")).unwrap(),
  }
}

/// Reads the node's authenticated id from the public facade.
async fn node_id(node: &Node) -> NodeId {
  node
    .handle
    .query(GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone()
}

async fn listen(node: &mut Node) {
  let listener = node
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  node.endpoint = listener.endpoint().clone();
}

async fn connection_degree(node: &Node) -> radiata::ConnectionDegreeView {
  node.handle.query(GetConnectionDegree::new()).await.unwrap()
}

async fn member_count_page(handle: &NodeHandle) -> usize {
  handle
    .query(PageMembers::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap()
    .items()
    .len()
}

async fn degree_view_handle(handle: &NodeHandle) -> radiata::ConnectionDegreeView {
  handle.query(GetConnectionDegree::new()).await.unwrap()
}

/// Polls `probe` until it returns `Some(value)` or the deadline passes.
async fn wait_until<F, T>(mut probe: F, timeout: Duration, what: &str) -> T
where
  F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<T>> + Send>>,
  T: Send, {
  let deadline = std::time::Instant::now() + timeout;
  loop {
    if let Some(value) = probe().await {
      return value;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "convergence timeout after {timeout:?}: {what}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
  }
}

/// The maintenance plane's acceptance lane: a below-target node dials
/// its way back to the derived target degree, visible through the
/// status query, without any operator action and without disturbing the
/// any-one-route contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_unhealthy_node_dials_its_way_back_to_target() {
  init_tracing();
  let _cluster_gate = cluster_gate().lock().await;

  // Five nodes: a hub plus four leaves, each leaf one session below the
  // derived target k(5) = 3 after the star forms. Fast anti-entropy so
  // the member pages (the maintenance universe) converge quickly; the
  // 30-second maintenance cadence is the shipped contract under test.
  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(500))
    .unwrap();
  let mut nodes = Vec::new();
  for seed in 0..5 {
    let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
    nodes.push(start_node(seed, storage, config.clone()).await);
  }
  for node in &mut nodes {
    node.id = node_id(node).await;
    listen(node).await;
  }

  let secret = std::string::String::new();
  let _ = secret;
  for leaf in nodes.iter().skip(1) {
    merge_with_retry(&leaf.handle, &nodes[0].handle, nodes[0].endpoint.clone()).await;
  }

  // The maintenance universe is the member page: wait until every node
  // counts all five members before reading the derived target.
  let members: Vec<(NodeHandle, NodeId)> = nodes
    .iter()
    .map(|node| (node.handle.clone(), node.id.clone()))
    .collect();
  wait_until(
    move || {
      let members = members.clone();
      Box::pin(async move {
        for (handle, _) in &members {
          if member_count_page(handle).await != 5 {
            return None;
          }
        }
        Some(())
      })
    },
    Duration::from_secs(60),
    "member pages converge to five",
  )
  .await;

  // The derived target is k(5) = 3 everywhere (the shipped table), and
  // the hub — four sessions — is healthy without any maintenance work.
  for node in &nodes {
    let view = connection_degree(node).await;
    assert_eq!(view.target(), 3, "k(5) = 3 for {}", node.id);
    assert!(
      view.sessions() >= view.target() || view.state() == radiata::ConnectionDegreeState::Unhealthy,
      "the view must state its own justification"
    );
  }
  let hub_view = connection_degree(&nodes[0]).await;
  assert_eq!(
    hub_view.state(),
    radiata::ConnectionDegreeState::Healthy,
    "the hub holds four sessions against target three"
  );

  // The leaves dial their way to the target on the maintenance cadence.
  // One tick carries the whole deficit; the budget absorbs slow dials
  // and a starved runner.
  let members: Vec<(NodeHandle, NodeId)> = nodes
    .iter()
    .map(|node| (node.handle.clone(), node.id.clone()))
    .collect();
  wait_until(
    move || {
      let members = members.clone();
      Box::pin(async move {
        for (handle, _) in &members {
          let view = degree_view_handle(handle).await;
          if view.state() != radiata::ConnectionDegreeState::Healthy || view.sessions() < 3 {
            return None;
          }
        }
        Some(())
      })
    },
    Duration::from_secs(180),
    "every node reaches the target degree",
  )
  .await;

  // The degree never gates functionality: the any-one-route contract
  // holds everywhere while maintenance runs.
  for node in &nodes {
    let recovery = node.handle.query(GetRecovery::new()).await.unwrap();
    assert!(
      recovery.is_connected(),
      "{} must stay connected throughout",
      node.id
    );
  }

  for node in &nodes {
    let _ = node.handle.command(Shutdown::new()).await;
    let _ = node.handle.query(WaitForShutdown::new()).await;
  }
}

/// The typed dial contract when a member dial races the binding spread:
/// `NotFound` (retryable convergence state), never an authentication
/// failure, and a bounded retry succeeds once the binding arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_member_dial_racing_the_binding_spread_is_typed_retryable() {
  init_tracing();
  let _cluster_gate = cluster_gate().lock().await;

  // Hub H and member B form a cluster; A joins afterwards with a slow
  // anti-entropy cadence, so B's binding cannot have spread when A's
  // first dial fires.
  let mut hub = start_node(
    0,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    NodeConfig::new()
      .with_anti_entropy_interval(Duration::from_millis(200))
      .unwrap(),
  )
  .await;
  hub.id = node_id(&hub).await;
  listen(&mut hub).await;

  let mut member = start_node(
    1,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    NodeConfig::new()
      .with_anti_entropy_interval(Duration::from_millis(200))
      .unwrap(),
  )
  .await;
  member.id = node_id(&member).await;
  listen(&mut member).await;

  merge_with_retry(&member.handle, &hub.handle, hub.endpoint.clone()).await;

  // A stranger that listens but never joined: no cluster member can
  // ever hold its binding, so the typed refusal is deterministic.
  let mut stranger = start_node(
    9,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    NodeConfig::new(),
  )
  .await;
  stranger.id = node_id(&stranger).await;
  listen(&mut stranger).await;

  // A joins with a deliberately slow anti-entropy cadence: no page pull
  // can run between the join and the racing dial.
  let mut dialer = start_node(
    2,
    Arc::new(MemoryStorageFactory::new(common::required_capabilities())),
    NodeConfig::new()
      .with_anti_entropy_interval(Duration::from_secs(30))
      .unwrap(),
  )
  .await;
  dialer.id = node_id(&dialer).await;
  listen(&mut dialer).await;

  merge_with_retry(&dialer.handle, &hub.handle, hub.endpoint.clone()).await;

  // The racing dial against the joined member: whatever the outcome,
  // an authentication failure is a contract violation — an absent
  // binding is the retryable NotFound, never "untrusted".
  let raced = dialer
    .handle
    .command(ConnectMember::new(
      member.endpoint.clone(),
      member.id.clone(),
    ))
    .await;
  if let Err(error) = &raced {
    assert_eq!(
      error.kind(),
      ErrorKind::NotFound,
      "a dial racing the binding spread must be the retryable NotFound, got {error:?}"
    );
  }

  // The same typed refusal, deterministic: the stranger's binding does
  // not exist anywhere in A's reach.
  let unknown = dialer
    .handle
    .command(ConnectMember::new(
      stranger.endpoint.clone(),
      stranger.id.clone(),
    ))
    .await
    .unwrap_err();
  assert_eq!(
    unknown.kind(),
    ErrorKind::NotFound,
    "a dial against an unknowable member must be NotFound, got {unknown:?}"
  );

  // The binding spread: one forced sync round carries the member page
  // and the trust snapshot from the hub, and the bounded retry lands.
  wait_until(
    {
      let dialer_handle = dialer.handle.clone();
      let member_id = member.id.clone();
      move || {
        let dialer_handle = dialer_handle.clone();
        let member_id = member_id.clone();
        Box::pin(async move {
          let _ = dialer_handle.command(RunSyncRound::new()).await;
          if trust_ids_node(&dialer_handle).await.contains(&member_id) {
            return Some(());
          }
          None
        })
      }
    },
    Duration::from_secs(30),
    "the dialer adopts the member's binding",
  )
  .await;

  let deadline = std::time::Instant::now() + Duration::from_secs(60);
  let authenticated = loop {
    match dialer
      .handle
      .command(ConnectMember::new(
        member.endpoint.clone(),
        member.id.clone(),
      ))
      .await
    {
      Ok(peer) => break peer,
      Err(error) => {
        assert_eq!(
          error.kind(),
          ErrorKind::NotFound,
          "only the retryable NotFound may appear while the spread settles: {error:?}"
        );
      }
    }
    assert!(
      std::time::Instant::now() < deadline,
      "the dial must succeed within its budget once the binding spread"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
  };
  assert_eq!(authenticated, member.id);

  for node in [&hub, &member, &stranger, &dialer] {
    let _ = node.handle.command(Shutdown::new()).await;
    let _ = node.handle.query(WaitForShutdown::new()).await;
  }
}

/// Trust-page helper over a bare handle (the closure above cannot
/// borrow the test's `Node`).
async fn trust_ids_node(handle: &NodeHandle) -> BTreeSet<NodeId> {
  handle
    .query(radiata::PageTrust::new(
      radiata::PageSpec::first(64).unwrap(),
    ))
    .await
    .unwrap()
    .items()
    .iter()
    .map(|binding| binding.node_id().clone())
    .collect()
}
