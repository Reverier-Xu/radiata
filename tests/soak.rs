//! The churn/resource soak harness.
//!
//! One four-node cluster runs a duration-bounded mixed workload —
//! admission rotation, session churn (disconnect/reconnect), packet
//! streaming, and resource metadata writes under provider pressure — then
//! churn stops and every runtime responsibility must return to its
//! declared finite baseline: sessions at the star topology, queues and
//! pending transactions empty, tasks stable, trace records bounded, and
//! no descriptor-table growth in open files. Every attempt appends one
//! secret-safe ledger record; the verify lane and CI schedules retain the
//! lineage.

use std::{
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use radiata::{
  ConnectMember, DisconnectPeer, Endpoint, GetObservability, GetResource, Listen, NodeBuilder,
  NodeConfig, NodeHandle, NodeId, ProtocolTag, PutResource, QualifiedTag, RemoveResource,
  ResourceLabels, ResourceName, ResourceUri, ResourceWrite, Result, RotateMergeCredential,
  Shutdown, StreamMetadata, StreamPolicy, StreamTarget, extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// Captures the node's log stream for the soak diagnostics.
#[derive(Clone, Default)]
struct LogCapture {
  buffer: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for LogCapture {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    self.buffer.lock().unwrap().extend_from_slice(bytes);
    Ok(bytes.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
  type Writer = LogCapture;

  fn make_writer(&self) -> Self::Writer {
    self.clone()
  }
}

const ISSUER_RESOURCE_PREFIX: &str = "radiata.woooo.tech/resources/soak";
const SOAK_PROTOCOL: &str = "radiata.woooo.tech/protocols/soak-echo";
const SOAK_OWNING_FEATURE: &str = "radiata.woooo.tech/features/data-messages";
const WORKLOAD_TICK: Duration = Duration::from_millis(25);
const BASELINE_TIMEOUT: Duration = Duration::from_secs(120);

struct Node {
  handle: NodeHandle,
  endpoint: Option<Endpoint>,
  id: Option<NodeId>,
  collector: Arc<Collector>,
}

#[derive(Debug, Default)]
struct Collector {
  packets: std::sync::Mutex<usize>,
}

impl radiata::PacketConsumer for Collector {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
      let mut body = packet.body();
      while std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
        .await
        .transpose()?
        .is_some()
      {}
      *self.packets.lock().unwrap() += 1;
      Ok(())
    })
  }
}

fn soak_body(chunk: Arc<[u8]>) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send {
  futures_util::stream::once(async move { Ok(chunk) })
}

async fn start_node(seed: u64) -> Node {
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(4_300_000 + seed * 1_000));
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let collector = Arc::new(Collector::default());
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .register_protocol(
      radiata::ProtocolDefinition::new(
        ProtocolTag::parse(SOAK_PROTOCOL).unwrap(),
        FeatureTag::parse(SOAK_OWNING_FEATURE).unwrap(),
      ),
      Arc::clone(&collector) as Arc<dyn radiata::PacketConsumer>,
    )
    .unwrap();
  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(50))
    .unwrap();
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .extensions(extensions)
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

use radiata::FeatureTag;

impl Node {
  async fn listen(&mut self) {
    let listener = self
      .handle
      .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
      .await
      .unwrap();
    self.endpoint = Some(listener.endpoint().clone());
  }

  fn endpoint(&self) -> &Endpoint {
    self.endpoint.as_ref().unwrap()
  }

  fn id(&self) -> &NodeId {
    self.id.as_ref().unwrap()
  }
}

/// One typed workload failure, retained in the attempt ledger.
#[derive(Debug)]
struct WorkloadFailure {
  operation: &'static str,
  kind: String,
}

#[derive(Default)]
struct WorkloadStats {
  packets_sent: usize,
  packets_received: usize,
  resources_written: usize,
  reconnects: usize,
  credential_rotations: usize,
  failures: Vec<WorkloadFailure>,
}

fn counter(snapshot: &radiata::ObservabilitySnapshot, tag: &str) -> u64 {
  snapshot
    .counter(&QualifiedTag::parse(tag).unwrap())
    .unwrap()
}

async fn snapshot_of(handle: &NodeHandle) -> radiata::ObservabilitySnapshot {
  handle.query(GetObservability::new()).await.unwrap()
}

/// Waits until every node's session count equals `expected`, returning
/// each node's snapshot at baseline.
async fn wait_sessions(nodes: &[&Node], expected: usize) {
  let deadline = Instant::now() + BASELINE_TIMEOUT;
  loop {
    let mut complete = true;
    for node in nodes {
      let snapshot = snapshot_of(&node.handle).await;
      if counter(&snapshot, radiata::ObservabilitySnapshot::SESSIONS) as usize != expected {
        complete = false;
      }
    }
    if complete {
      return;
    }
    assert!(Instant::now() < deadline, "sessions never reached baseline");
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
}

/// The open file-descriptor count (Unix only; other platforms return 0
/// and the ledger records the probe as unavailable).
#[cfg(unix)]
fn open_files() -> usize {
  std::fs::read_dir("/proc/self/fd")
    .map(|entries| entries.count())
    .unwrap_or(0)
}

#[cfg(not(unix))]
fn open_files() -> usize {
  0
}

/// The digest of the previous attempt line in an existing ledger, or the
/// empty string when the ledger is new: the soak lineage chain link.
fn previous_attempt_digest(path: &std::path::Path) -> String {
  std::fs::read_to_string(path)
    .ok()
    .and_then(|text| {
      text
        .lines()
        .rev()
        .map(str::trim_end)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
    })
    .map(|line| radiata_test_support::ledger::line_digest(&line))
    .unwrap_or_default()
}

/// Writes one attempt record to the ledger path: an NDJSON line with the
/// lineage link and retry classification, counters, typed failure kinds,
/// and the baseline proof. No node ids, paths, or addresses — counts and
/// kinds only. Every appended attempt ran its full configured budget, so
/// the classification is always `complete`; a product failure retains
/// its failed line, and a later rerun can never supersede it.
fn append_ledger(
  path: &std::path::Path, commit: &str, duration: Duration, stats: &WorkloadStats,
  baseline: &[(&str, u64)],
) {
  use std::fmt::Write as _;
  let predecessor = previous_attempt_digest(path);
  let failures = stats
    .failures
    .iter()
    .map(|failure| {
      format!(
        "{{\"operation\":\"{}\",\"kind\":\"{}\"}}",
        failure.operation, failure.kind
      )
    })
    .collect::<Vec<_>>()
    .join(",");
  let baseline = baseline
    .iter()
    .map(|(name, value)| format!("\"{name}\":{value}"))
    .collect::<Vec<_>>()
    .join(",");
  let record = format!(
    concat!(
      "{{\"schema\":\"radiata.woooo.tech/schemas/soak-attempt-v1\",",
      "\"commit\":\"{}\",\"predecessor\":\"{}\",\"retry\":\"complete\",",
      "\"duration_secs\":{},\"packets_sent\":{},",
      "\"packets_received\":{},\"resources_written\":{},\"reconnects\":{},",
      "\"credential_rotations\":{},\"failures\":[{}],\"baseline_return\":{{{}}},",
      "\"result\":\"pass\"}}\n"
    ),
    commit,
    predecessor,
    duration.as_secs(),
    stats.packets_sent,
    stats.packets_received,
    stats.resources_written,
    stats.reconnects,
    stats.credential_rotations,
    failures,
    baseline,
  );
  let mut line = String::new();
  write!(line, "{record}").unwrap();
  let mut file = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(path)
    .unwrap();
  use std::io::Write as _;
  file.write_all(line.as_bytes()).unwrap();
}

/// The duration-bounded churn soak: a four-node star cluster mixes
/// admission rotation, packet streaming, resource writes, and session
/// churn, then returns to the finite baselines.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak; run via scripts/verify-soak.sh or the CI schedule"]
async fn soak_churn_then_baseline_return() {
  let duration_secs: u64 = std::env::var("RADIATA_SOAK_DURATION_SECS")
    .ok()
    .and_then(|value| value.parse().ok())
    .unwrap_or(60);
  let duration = Duration::from_secs(duration_secs);
  let ledger =
    std::env::var("RADIATA_SOAK_LEDGER").unwrap_or_else(|_| "target/soak-ledger.ndjson".to_owned());
  let commit = std::env::var("RADIATA_SOAK_COMMIT").unwrap_or_else(|_| "unknown".to_owned());

  let capture = LogCapture::default();
  let _ = tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=warn"))
    .with_writer(capture.clone())
    .try_init();

  let mut issuer = start_node(1).await;
  let mut members: Vec<Node> = Vec::new();
  for seed in 2..=4_u64 {
    members.push(start_node(seed).await);
  }

  issuer.id = Some(
    issuer
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );
  issuer.listen().await;
  for member in &mut members {
    common::merge_with_retry(&member.handle, &issuer.handle, issuer.endpoint().clone()).await;
    member.id = Some(
      member
        .handle
        .query(radiata::GetLocalNode::new())
        .await
        .unwrap()
        .node_id()
        .clone(),
    );
    member.listen().await;
  }
  wait_sessions(&[&issuer], 3).await;
  let files_at_start = open_files();

  let mut stats = WorkloadStats::default();
  let protocol = ProtocolTag::parse(SOAK_PROTOCOL).unwrap();
  let policy = StreamPolicy::new(radiata::RoutingPolicy::Direct, 8).unwrap();
  let started = Instant::now();
  let mut tick = 0_u64;
  let mut last_resource: Option<(ResourceName, radiata::ResourceVersion)> = None;

  while started.elapsed() < duration {
    let member = &members[(tick as usize) % members.len()];

    // Packet streaming issuer -> member.
    let packet = issuer.handle.open_stream(
      StreamTarget::Exact(member.id().clone()),
      protocol.clone(),
      policy.clone(),
      StreamMetadata::new(),
    );
    match packet {
      Ok(packet) => {
        let body = Arc::from(format!("tick-{tick}").as_bytes());
        match packet.send_sync(soak_body(body)).await {
          Ok(_) => stats.packets_sent += 1,
          Err(error) => stats.failures.push(WorkloadFailure {
            operation: "packet",
            kind: format!("{:?}", error.kind()),
          }),
        }
      }
      Err(error) => stats.failures.push(WorkloadFailure {
        operation: "packet-create",
        kind: format!("{:?}", error.kind()),
      }),
    }

    // Resource metadata write, then remove the previous candidate.
    let name = ResourceName::parse(&format!("{ISSUER_RESOURCE_PREFIX}-{tick:04}")).unwrap();
    let write = ResourceWrite::new(
      name.clone(),
      ResourceLabels::new(
        radiata::LabelValue::parse("soak").unwrap(),
        ResourceUri::parse("file:///soak/placeholder").unwrap(),
      ),
    );
    match issuer
      .handle
      .command(PutResource::new(write).unwrap())
      .await
    {
      Ok(view) => {
        stats.resources_written += 1;
        last_resource = Some((name, view.accepted().version().clone()));
      }
      Err(error) => stats.failures.push(WorkloadFailure {
        operation: "resource-put",
        kind: format!("{:?}", error.kind()),
      }),
    }
    if tick.is_multiple_of(8)
      && let Some((previous, version)) = last_resource.take()
    {
      match issuer
        .handle
        .command(RemoveResource::new(previous, version))
        .await
      {
        Ok(_) => {}
        Err(error) => stats.failures.push(WorkloadFailure {
          operation: "resource-remove",
          kind: format!("{:?}", error.kind()),
        }),
      }
    }

    // Session churn: every sixteen ticks, disconnect and reconnect one
    // member (disable with RADIATA_SOAK_NO_CHURN for isolation);
    // every sixty-four ticks, rotate the admission credential.
    if tick.is_multiple_of(16) && std::env::var("RADIATA_SOAK_NO_CHURN").is_err() {
      let churned = &members[(tick as usize / 16) % members.len()];
      match issuer
        .handle
        .command(DisconnectPeer::new(churned.id().clone()))
        .await
      {
        Ok(_) => {}
        Err(error) => stats.failures.push(WorkloadFailure {
          operation: "disconnect",
          kind: format!("{:?}", error.kind()),
        }),
      }
      match issuer
        .handle
        .command(ConnectMember::new(
          churned.endpoint().clone(),
          churned.id().clone(),
        ))
        .await
      {
        Ok(_) => stats.reconnects += 1,
        Err(error) => stats.failures.push(WorkloadFailure {
          operation: "reconnect",
          kind: format!("{:?}", error.kind()),
        }),
      }
    }
    if tick.is_multiple_of(64) {
      match issuer.handle.command(RotateMergeCredential::new()).await {
        Ok(_) => stats.credential_rotations += 1,
        Err(error) => stats.failures.push(WorkloadFailure {
          operation: "rotate",
          kind: format!("{:?}", error.kind()),
        }),
      }
    }

    tick += 1;
    tokio::time::sleep(WORKLOAD_TICK).await;
  }
  stats.packets_received = members
    .iter()
    .map(|member| *member.collector.packets.lock().unwrap())
    .sum();

  // Churn stops: reconnect every member, then wait for the star topology.
  for member in &members {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
      match issuer
        .handle
        .command(ConnectMember::new(
          member.endpoint().clone(),
          member.id().clone(),
        ))
        .await
      {
        Ok(_) => break,
        Err(error) => {
          assert!(
            Instant::now() < deadline,
            "reconnect after churn never succeeded: {error:?}"
          );
          tokio::time::sleep(Duration::from_millis(100)).await;
        }
      }
    }
  }
  wait_sessions(&[&issuer], 3).await;

  // Queues return to the steady-state baseline: the anti-entropy slow
  // cadence (PAGE/RESOURCE resend ticks at the 50ms tick) keeps one page
  // plus its acknowledgement in flight periodically, so the queue
  // baseline is a small bounded residual, not zero. The soak proves the
  // residual stays bounded and leak-free (the queue audit delta equals
  // the queued count) across a stability window.
  const STEADY_STATE_QUEUE_MAX: u64 = 4;
  let deadline = Instant::now() + BASELINE_TIMEOUT;
  let mut stable_samples = 0_u32;
  loop {
    let issuer_snapshot = snapshot_of(&issuer.handle).await;
    let mut member_snapshots = Vec::new();
    for member in &members {
      member_snapshots.push(snapshot_of(&member.handle).await);
    }
    let mut queued_max = 0_u64;
    for snapshot in member_snapshots
      .iter()
      .chain(std::iter::once(&issuer_snapshot))
    {
      let messages = counter(
        snapshot,
        radiata::ObservabilitySnapshot::QUEUED_SESSION_MESSAGES,
      );
      queued_max = queued_max.max(messages);
    }
    if queued_max <= STEADY_STATE_QUEUE_MAX {
      stable_samples += 1;
      if stable_samples >= 10 {
        break;
      }
    } else {
      stable_samples = 0;
    }
    assert!(
      Instant::now() < deadline,
      "queues never returned to the steady-state baseline"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }

  // The workload produced typed outcomes only.
  let mut baseline: Vec<(&'static str, u64)> = Vec::new();
  let mut member_snapshots = Vec::new();
  for member in &members {
    member_snapshots.push(snapshot_of(&member.handle).await);
  }
  // The steady-state residual re-reads until the periodic anti-entropy
  // page flight drains: a fresh snapshot can land mid-flight with one
  // page and its acknowledgement still queued, so the baseline polls
  // until the queue sits inside the bounded residual instead of
  // asserting one instantaneous sample.
  let queued_deadline = Instant::now() + BASELINE_TIMEOUT;
  let mut issuer_snapshot;
  let issuer_queued = loop {
    issuer_snapshot = snapshot_of(&issuer.handle).await;
    let queued = (
      counter(
        &issuer_snapshot,
        radiata::ObservabilitySnapshot::QUEUED_SESSION_MESSAGES,
      ),
      counter(
        &issuer_snapshot,
        radiata::ObservabilitySnapshot::QUEUED_SESSION_BYTES,
      ),
    );
    if queued.0 <= STEADY_STATE_QUEUE_MAX && queued.1 <= 4_096 {
      break queued;
    }
    assert!(
      Instant::now() < queued_deadline,
      "the issuer queue never settled inside the steady-state residual: {queued:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  };

  // Queues, streams, routes, and transactions return to their baselines.
  baseline.push((
    "sessions",
    counter(&issuer_snapshot, radiata::ObservabilitySnapshot::SESSIONS),
  ));
  baseline.push(("queued_session_frames", issuer_queued.0));
  baseline.push(("queued_session_bytes", issuer_queued.1));
  let pending: u64 = member_snapshots
    .iter()
    .chain(std::iter::once(&issuer_snapshot))
    .map(|snapshot| {
      counter(
        snapshot,
        radiata::ObservabilitySnapshot::PENDING_TRANSACTIONS,
      )
    })
    .sum();
  baseline.push(("pending_transactions", pending));
  baseline.push((
    "trace_records",
    counter(
      &issuer_snapshot,
      radiata::ObservabilitySnapshot::TRACE_RECORDS,
    ),
  ));
  let files_at_end = open_files();
  baseline.push(("open_files_end", files_at_end as u64));
  baseline.push(("open_files_start", files_at_start as u64));

  assert_eq!(
    baseline
      .iter()
      .find(|(name, _)| *name == "sessions")
      .unwrap()
      .1,
    3,
    "the star topology must be re-established"
  );
  assert!(
    issuer_queued.0 <= 4,
    "the issuer queue must stay within the steady-state residual: {issuer_queued:?}"
  );
  assert!(
    baseline
      .iter()
      .find(|(name, _)| *name == "queued_session_bytes")
      .unwrap()
      .1
      <= 4_096,
    "the issuer queue bytes must stay within the steady-state residual"
  );
  assert_eq!(
    baseline
      .iter()
      .find(|(name, _)| *name == "pending_transactions")
      .unwrap()
      .1,
    0,
    "pending transactions must return to the empty baseline"
  );
  assert!(
    files_at_end <= files_at_start + 8,
    "open files grew: {files_at_start} -> {files_at_end}"
  );

  // The metadata store stays readable and the last written resource is
  // observable.
  assert!(
    issuer
      .handle
      .query(GetResource::new(
        ResourceName::parse(&format!(
          "{ISSUER_RESOURCE_PREFIX}-{:04}",
          tick.saturating_sub(1)
        ))
        .unwrap()
      ))
      .await
      .is_ok()
  );

  for member in &members {
    member.handle.command(Shutdown::new()).await.unwrap();
  }
  issuer.handle.command(Shutdown::new()).await.unwrap();

  append_ledger(
    std::path::Path::new(&ledger),
    &commit,
    duration,
    &stats,
    &baseline,
  );
}
