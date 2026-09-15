#![cfg(feature = "redb")]

//! Scale benchmark for the ack-gated anti-entropy planes (P0-2) and
//! the per-key resource watermark (P2-3).
//!
//! Measures convergence time of the resource sync plane at
//! 512–4096 resources × 8–16 members on loopback, the failure
//! shape of a flapping peer (session churn resolving ack verdicts as
//! undelivered), and the P2-3 watermark acceptance sample: exactly one
//! write into a converged mid-size catalog must converge within one
//! detection cadence window plus an amortized scan walk — not the full
//! catalog re-send cycle the previous fingerprint design paid on every
//! quiet window. The matrix quantifies whether the per-page admission
//! ack wait (2s bound) changes convergence or steady-state behavior at
//! scale, replacing the archived loopback baseline.
//!
//! Run: cargo test --release --test sync_scale_benchmark -- --ignored
//! --nocapture

use std::{
  sync::Arc,
  time::{Duration, Instant},
};

use radiata::{
  DisconnectPeer, Endpoint, GetLocalNode, GetObservability, Listen, MergeCluster, NodeBuilder,
  NodeConfig, NodeHandle, NodeId, PageResources, PageSpec, PutResource, RecoveryConfig,
  ResourceLabels, ResourceName, ResourceUri, ResourceWrite, RotateMergeCredential, Shutdown,
  StartRecovery,
};

mod common;

use common::ScriptedKeys;

/// Installs the debug subscriber once (benchmarks observe the sync
/// plane's internal cadence through tracing output).
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

/// The anti-entropy cadence under measurement (the library default;
/// `RADIATA_BENCH_SYNC_MS` overrides it for pacing experiments).
fn sync_interval() -> Duration {
  std::env::var("RADIATA_BENCH_SYNC_MS")
    .ok()
    .and_then(|value| value.parse().ok())
    .map(Duration::from_millis)
    .unwrap_or(Duration::from_millis(250))
}
/// The per-cell convergence bound: generous on shared runners; the
/// benchmark reports the sample, it does not assert tight latency.
const CELL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
  id: NodeId,
  // The node's database directory: held for the node's lifetime so the
  // redb files outlive the handle and drop only at teardown.
  _dir: tempfile::TempDir,
}

async fn start(seed: u64) -> Node {
  let dir = tempfile::tempdir().unwrap();
  let keys = Arc::new(ScriptedKeys::full_at(700_000 + seed * 1_000));
  let storage = radiata::adapters::redb_store(dir.path().join("store.redb"));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(sync_interval())
    .unwrap()
    .with_recovery_policy(
      RecoveryConfig::new(4, 64, Duration::from_secs(2), Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
  let handle = NodeBuilder::new(storage, keys)
    .config(config)
    .start()
    .await
    .unwrap();
  let endpoint = handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap()
    .endpoint()
    .clone();
  let id = handle
    .query(GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();
  Node {
    handle,
    endpoint,
    id,
    _dir: dir,
  }
}

fn resource(seed: u32) -> (ResourceName, ResourceLabels) {
  (
    ResourceName::parse(&format!("radiata.woooo.tech/resources/scale-{seed:05}")).unwrap(),
    ResourceLabels::new(
      radiata::LabelValue::parse("benchmark").unwrap(),
      ResourceUri::parse(&format!("file:///scale/{seed:05}")).unwrap(),
    ),
  )
}

/// Counts the node's locally visible resources by paging the public view.
async fn resource_count(handle: &NodeHandle) -> usize {
  let mut count = 0;
  let mut spec = PageSpec::first(64).unwrap();
  loop {
    let page = handle.query(PageResources::new(spec)).await.unwrap();
    count += page.items().len();
    let Some(cursor) = page.next() else { break };
    spec = PageSpec::after(cursor.clone(), 64).unwrap();
  }
  count
}

/// Polls until every member sees `expected` resources; returns the
/// convergence time from the call instant.
async fn convergence_time(handles: &[NodeHandle], expected: usize) -> Duration {
  let started = Instant::now();
  let deadline = started + CELL_TIMEOUT;
  for handle in handles {
    loop {
      let seen = resource_count(handle).await;
      if seen == expected {
        break;
      }
      if Instant::now() >= deadline {
        panic!("convergence never reached {expected} (stuck at {seen})");
      }
      eprintln!("convergence progress: {seen}/{expected}");
      tokio::time::sleep(Duration::from_secs(2)).await;
    }
  }
  started.elapsed()
}

/// One matrix cell: a star of `peers` members, `resources` writes from
/// the hub, convergence measured on every leaf.
async fn convergence_cell(peers: usize, resources: u32) {
  let mut nodes = vec![start(0).await];
  let secret = nodes[0]
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap()
    .into_credential()
    .expose_secret()
    .to_owned();
  for index in 1..peers as u64 {
    let member = start(index).await;
    merge_with_retry(&mut nodes[0], &member, &secret).await;
    nodes.push(member);
  }

  // The writes are the timed setup; convergence timing starts after the
  // last commit so the sample measures the sync plane, not the writes.
  for seed in 0..resources {
    let (name, labels) = resource(seed);
    nodes[0]
      .handle
      .command(PutResource::new(ResourceWrite::new(name, labels)).unwrap())
      .await
      .unwrap();
  }

  let leaves: Vec<NodeHandle> = nodes[1..].iter().map(|node| node.handle.clone()).collect();
  let elapsed = convergence_time(&leaves, resources as usize).await;

  // Steady-state observations after convergence: queued bytes and
  // pending transactions must be drained on every node.
  let mut queued_bytes = Vec::new();
  for node in &nodes {
    let snapshot = node.handle.query(GetObservability::new()).await.unwrap();
    queued_bytes.push(snapshot.counter(
      &radiata::QualifiedTag::parse(radiata::ObservabilitySnapshot::QUEUED_SESSION_BYTES).unwrap(),
    ));
  }
  println!(
    "cell peers={peers} resources={resources} converge={:.1}s steady_queued_bytes={queued_bytes:?}",
    elapsed.as_secs_f64(),
  );

  for node in nodes {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

/// Joins one member to the hub with bounded retries: a merge racing a
/// loaded store's metadata-commit state machine can be refused with the
/// typed transient `NotReady` (the operator re-issues the join); the
/// sample must measure convergence, not join luck.
async fn merge_with_retry(hub: &mut Node, member: &Node, secret: &str) {
  let deadline = Instant::now() + Duration::from_secs(60);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    let credential = radiata::MergeCredential::parse(secret).unwrap();
    match member
      .handle
      .command(MergeCluster::new(hub.endpoint.clone(), credential))
      .await
    {
      Ok(_) => return,
      Err(_) if Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(
          200u64.saturating_mul(u64::from(attempts.min(5))),
        ))
        .await;
      }
      Err(error) => panic!("the merge never succeeded: {error:?}"),
    }
  }
}

/// One watermark acceptance cell: a full `resources` catalog converges
/// first (untimed), then exactly one new record is written mid-catalog
/// (its key sorts at the midpoint, so the detection pass must walk past
/// unchanged watermarked entries) and the single-write convergence time
/// is sampled on every leaf. Under the per-key watermark design the
/// sample is one detection cadence window plus the amortized scan walk
/// and one page round — not a full catalog re-send.
async fn mid_catalog_single_write_cell(peers: usize, resources: u32) {
  let mut nodes = vec![start(0).await];
  let secret = nodes[0]
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap()
    .into_credential()
    .expose_secret()
    .to_owned();
  for index in 1..peers as u64 {
    let member = start(index).await;
    merge_with_retry(&mut nodes[0], &member, &secret).await;
    nodes.push(member);
  }

  // Untimed setup: converge the full catalog first.
  for seed in 0..resources {
    let (name, labels) = resource(seed);
    nodes[0]
      .handle
      .command(PutResource::new(ResourceWrite::new(name, labels)).unwrap())
      .await
      .unwrap();
  }
  let leaves: Vec<NodeHandle> = nodes[1..].iter().map(|node| node.handle.clone()).collect();
  convergence_time(&leaves, resources as usize).await;

  // The measured write: one new record at the catalog's key midpoint.
  let mid = resources / 2;
  let name =
    ResourceName::parse(&format!("radiata.woooo.tech/resources/scale-{mid:05}-1")).unwrap();
  let started = Instant::now();
  nodes[0]
    .handle
    .command(
      PutResource::new(ResourceWrite::new(
        name,
        ResourceLabels::new(
          radiata::LabelValue::parse("benchmark").unwrap(),
          ResourceUri::parse("file:///scale/mid-write").unwrap(),
        ),
      ))
      .unwrap(),
    )
    .await
    .unwrap();
  convergence_time(&leaves, resources as usize + 1).await;
  let elapsed = started.elapsed();

  // Steady-state observations after the single-write round: queued
  // bytes must be drained on every node.
  let mut queued_bytes = Vec::new();
  for node in &nodes {
    let snapshot = node.handle.query(GetObservability::new()).await.unwrap();
    queued_bytes.push(snapshot.counter(
      &radiata::QualifiedTag::parse(radiata::ObservabilitySnapshot::QUEUED_SESSION_BYTES).unwrap(),
    ));
  }
  println!(
    "cell peers={peers} resources={resources} single_write_converge={:.1}s steady_queued_bytes={queued_bytes:?}",
    elapsed.as_secs_f64(),
  );

  for node in nodes {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

/// The convergence matrix: 512–4096 resources × 8–16 members.
/// `RADIATA_BENCH_CELL=peers,resources` runs one cell only (debugging).
#[ignore = "explicit benchmark: cargo test --release --test sync_scale_benchmark -- --ignored --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn sync_ack_convergence_matrix() {
  init_tracing();
  if let Some(cell) = std::env::var("RADIATA_BENCH_CELL").ok().and_then(|value| {
    let (peers, resources) = value.split_once(',')?;
    Some((peers.parse().ok()?, resources.parse().ok()?))
  }) {
    convergence_cell(cell.0, cell.1).await;
    return;
  }
  for (peers, resources) in [(8, 512), (16, 512), (8, 2048), (16, 4096)] {
    convergence_cell(peers, resources).await;
  }
}

/// The P2-3 watermark acceptance sample: a converged 4096-record
/// catalog receives exactly one mid-catalog write. The sample must be
/// one detection cadence window plus an amortized scan walk (a single
/// changed page) — orders of magnitude below the full-catalog re-send
/// cycle the previous fingerprint design paid on every quiet window.
#[ignore = "explicit benchmark: cargo test --release --test sync_scale_benchmark sync_watermark_single_write_converges_within_one_cadence_window -- --ignored --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn sync_watermark_single_write_converges_within_one_cadence_window() {
  init_tracing();
  mid_catalog_single_write_cell(8, 4096).await;
}

/// A flapping peer (session torn down every two seconds mid-convergence)
/// resolves its ack verdicts as undelivered at the 2s bound; the round
/// must not serialize behind it — the surviving members converge within
/// the same order as the clean cell.
#[ignore = "explicit benchmark: cargo test --release --test sync_scale_benchmark -- --ignored --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn sync_ack_flapping_peer_does_not_stall_the_round() {
  let peers = 8;
  let resources = 512_u32;
  let mut nodes = vec![start(0).await];
  let secret = nodes[0]
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap()
    .into_credential()
    .expose_secret()
    .to_owned();
  for index in 1..peers as u64 {
    let member = start(index).await;
    let credential = radiata::MergeCredential::parse(&secret).unwrap();
    member
      .handle
      .command(MergeCluster::new(nodes[0].endpoint.clone(), credential))
      .await
      .unwrap();
    nodes.push(member);
  }
  for seed in 0..resources {
    let (name, labels) = resource(seed);
    nodes[0]
      .handle
      .command(PutResource::new(ResourceWrite::new(name, labels)).unwrap())
      .await
      .unwrap();
  }

  // Flap the last leaf's session to the hub every two seconds while the
  // survivors converge: every flap resolves in-flight admissions as
  // undelivered and the next tick re-delivers from scratch (D2).
  let flap_id = nodes[0].id.clone();
  let flap = nodes[nodes.len() - 1].handle.clone();
  let flapper = tokio::spawn(async move {
    for _ in 0..8 {
      tokio::time::sleep(Duration::from_secs(2)).await;
      let _ = flap.command(DisconnectPeer::new(flap_id.clone())).await;
      let _ = flap.command(StartRecovery::new()).await;
    }
  });

  let survivors: Vec<NodeHandle> = nodes[1..nodes.len() - 1]
    .iter()
    .map(|node| node.handle.clone())
    .collect();
  let elapsed = convergence_time(&survivors, resources as usize).await;
  println!(
    "cell peers={peers} resources={resources} flapping-leaf converge={:.1}s",
    elapsed.as_secs_f64(),
  );
  flapper.abort();
  for node in nodes {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

/// The trust-binding page limit exercised at scale: 70 members mean the
/// issuer's snapshot holds 70 bindings (one over the 64-binding page
/// limit), so full trust convergence requires two trust pages per peer.
#[ignore = "explicit benchmark: cargo test --release --test sync_scale_benchmark -- --ignored --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn sync_bindings_over_page_limit_converge_through_two_pages() {
  init_tracing();
  let peers = 70_usize;
  let mut nodes = vec![start(0).await];
  let secret = nodes[0]
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap()
    .into_credential()
    .expose_secret()
    .to_owned();
  for index in 1..peers as u64 {
    let member = start(index).await;
    // NotReady (a prior merge's reconcile still in flight) is the
    // documented typed-transient merge failure: bounded retry is the
    // caller contract here, and correctness is asserted after
    // convergence below, not by any single attempt passing.
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
      let credential = radiata::MergeCredential::parse(&secret).unwrap();
      match member
        .handle
        .command(MergeCluster::new(nodes[0].endpoint.clone(), credential))
        .await
      {
        Ok(_) => break,
        Err(error) => {
          assert!(
            Instant::now() < deadline,
            "merge never succeeded for member {index}: {error:?}"
          );
          tokio::time::sleep(Duration::from_millis(200)).await;
        }
      }
    }
    nodes.push(member);
  }

  // Trust convergence: every member's PageTrust shows all `peers`
  // bindings (its own + every other member) — the issuer's snapshot
  // (70 bindings) pages through two wire pages per peer. One poll
  // round over all members, then a single wait between rounds.
  let expected = peers;
  let started = Instant::now();
  let deadline = started + Duration::from_secs(30 * 60);
  loop {
    let mut pending = 0_usize;
    for node in &nodes {
      let trust = node
        .handle
        .query(radiata::PageTrust::new(PageSpec::first(64).unwrap()))
        .await
        .unwrap();
      let mut seen = trust.items().len();
      if let Some(cursor) = trust.next() {
        let second_page = node
          .handle
          .query(radiata::PageTrust::new(
            PageSpec::after(cursor.clone(), 64).unwrap(),
          ))
          .await
          .unwrap();
        seen += second_page.items().len();
      }
      if seen != expected {
        pending += 1;
      }
    }
    if pending == 0 {
      break;
    }
    if started.elapsed().as_secs() % 30 < 1 {
      let mut counts = Vec::new();
      for node in &nodes {
        let trust = node
          .handle
          .query(radiata::PageTrust::new(PageSpec::first(64).unwrap()))
          .await
          .unwrap();
        let mut seen = trust.items().len();
        if let Some(cursor) = trust.next() {
          let second_page = node
            .handle
            .query(radiata::PageTrust::new(
              PageSpec::after(cursor.clone(), 64).unwrap(),
            ))
            .await
            .unwrap();
          seen += second_page.items().len();
        }
        counts.push(seen);
      }
      counts.sort();
      eprintln!("PROBE pending={pending} counts={counts:?}");
    }
    assert!(
      Instant::now() < deadline,
      "trust never converged to {expected} ({pending} members short)"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
  }
  println!(
    "cell peers={peers} bindings={expected} (two pages) converge={:.1}s",
    started.elapsed().as_secs_f64(),
  );

  for node in nodes {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}
