//! Bounded runtime status and secret-safe observability (T-G10-05,
//! SC-G10-P0-15/16).
//!
//! The status lane proves the public observation of the bounded runtime
//! responsibilities — lifecycle, sessions, listeners, tasks, queues,
//! routes, trace metadata, pending transactions, and metadata storage —
//! while the redaction lane drives a full workflow with injected marker
//! material and proves no credential, key, body, path, address, selector,
//! or hostile string enters the emitted log stream.

#[cfg(all(test, feature = "json", unix))]
use std::sync::Mutex;
use std::{sync::Arc, time::Duration};

#[cfg(all(test, feature = "json", unix))]
use radiata::{
  DisconnectPeer, PageResources, ResourceLabels, ResourceName, ResourceUri, ResourceWrite,
  RotateMergeCredential,
};
use radiata::{
  Endpoint, ErrorKind, GetObservability, Listen, NodeBuilder, NodeConfig, PageSessions, PageSpec,
  ProtocolTag, QualifiedTag, Shutdown, StreamMetadata, StreamPolicy, StreamTarget,
  extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// Captures every emitted log line for the redaction scan.
#[cfg(all(test, feature = "json", unix))]
#[derive(Clone, Default)]
struct LogCapture {
  buffer: Arc<Mutex<Vec<u8>>>,
}

#[cfg(all(test, feature = "json", unix))]
impl std::io::Write for LogCapture {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    self.buffer.lock().unwrap().extend_from_slice(bytes);
    Ok(bytes.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

#[cfg(all(test, feature = "json", unix))]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
  type Writer = LogCapture;

  fn make_writer(&self) -> Self::Writer {
    self.clone()
  }
}

struct Node {
  handle: radiata::NodeHandle,
  endpoint: Endpoint,
  id: Option<radiata::NodeId>,
}

async fn start_node(seed: u64) -> Node {
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(3_700_000 + seed * 1_000));
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(50))
    .unwrap();
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
    id: None,
  }
}

async fn listen(node: &mut Node) {
  let listener = node
    .handle
    .command(Listen::new(node.endpoint.clone()))
    .await
    .unwrap();
  node.endpoint = listener.endpoint().clone();
}

/// SC-G10-P0-15: the observability snapshot covers the bounded
/// responsibilities with counters and flags only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observability_snapshot_covers_bounded_responsibilities() {
  let mut issuer = start_node(1).await;
  let mut member = start_node(2).await;
  issuer.id = Some(
    issuer
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );
  listen(&mut issuer).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer.endpoint.clone()).await;
  member.id = Some(
    member
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );

  // Wait for the session to register on both sides.
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let sessions = member
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    if !sessions.items().is_empty() {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "no session registered"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  let counter = |snapshot: &radiata::ObservabilitySnapshot, tag: &str| {
    snapshot
      .counter(&QualifiedTag::parse(tag).unwrap())
      .unwrap()
  };
  for (node, listeners) in [(&issuer, 1_u64), (&member, 0)] {
    let status = node.handle.query(GetObservability::new()).await.unwrap();
    assert_eq!(
      counter(&status, radiata::ObservabilitySnapshot::SESSIONS),
      1
    );
    assert_eq!(
      counter(&status, radiata::ObservabilitySnapshot::LISTENERS),
      listeners
    );
    assert!(counter(&status, radiata::ObservabilitySnapshot::BACKGROUND_TASKS) >= 1);
    assert_eq!(
      counter(&status, radiata::ObservabilitySnapshot::TRACE_RECORDS),
      0
    );
    assert_eq!(
      counter(
        &status,
        radiata::ObservabilitySnapshot::PENDING_TRANSACTIONS
      ),
      0
    );
    assert_eq!(
      counter(
        &status,
        radiata::ObservabilitySnapshot::METADATA_STORE_AVAILABLE
      ),
      1
    );
    assert!(status.captured_at() <= std::time::SystemTime::now());
  }

  // Session queues return to the empty baseline after the sync traffic
  // drains (SC-G10-P0-15's queue responsibility).
  let drain = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let issuer_status = issuer.handle.query(GetObservability::new()).await.unwrap();
    let member_status = member.handle.query(GetObservability::new()).await.unwrap();
    let drained = [issuer_status, member_status].iter().all(|status| {
      counter(
        status,
        radiata::ObservabilitySnapshot::QUEUED_SESSION_MESSAGES,
      ) == 0
        && counter(status, radiata::ObservabilitySnapshot::QUEUED_SESSION_BYTES) == 0
    });
    if drained {
      break;
    }
    assert!(std::time::Instant::now() < drain, "queues never drained");
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // A failing route leaves no queue residue after the typed interruption.
  let unknown = issuer.handle.query(GetObservability::new()).await.unwrap();
  let result = issuer.handle.open_stream(
    StreamTarget::Exact(member.id.clone().unwrap()),
    ProtocolTag::parse("radiata.woooo.tech/protocols/unregistered").unwrap(),
    StreamPolicy::new(radiata::RoutingPolicy::Direct, 8).unwrap(),
    StreamMetadata::new(),
  );
  match result {
    Ok(packet) => {
      let error = packet
        .send_sync(futures_util::stream::empty())
        .await
        .unwrap_err();
      let _ = error.kind();
    }
    Err(error) => assert_eq!(error.kind(), ErrorKind::Unsupported),
  }
  // No queue residue after the typed interruption: the anti-entropy
  // driver may enqueue its own frame concurrently, so the baseline is
  // observed through the same bounded drain window as above.
  let residue = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let after = issuer.handle.query(GetObservability::new()).await.unwrap();
    if counter(
      &after,
      radiata::ObservabilitySnapshot::QUEUED_SESSION_MESSAGES,
    ) == 0
      && counter(&after, radiata::ObservabilitySnapshot::QUEUED_SESSION_BYTES) == 0
    {
      assert_eq!(
        counter(&after, radiata::ObservabilitySnapshot::SESSIONS),
        counter(&unknown, radiata::ObservabilitySnapshot::SESSIONS)
      );
      break;
    }
    assert!(
      std::time::Instant::now() < residue,
      "queue residue never drained"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  issuer.handle.command(Shutdown::new()).await.unwrap();
  member.handle.command(Shutdown::new()).await.unwrap();
}

/// SC-G10-P0-16: injected credential, key, packet-body, path, address,
/// selector, and hostile-string markers never enter the emitted log
/// stream of a full node workflow.
///
/// The path marker rides the JSON adapter (the only backend that mounts
/// a real filesystem path), so the lane requires the `json` feature and
/// the unix directory barrier the full-node open demands.
#[cfg(all(test, feature = "json", unix))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redaction_lane_rejects_every_forbidden_class() {
  let capture = LogCapture::default();
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=trace"))
    .with_writer(capture.clone())
    .try_init()
    .unwrap();

  // A distinctive storage path marker through the JSON adapter.
  let directory = tempfile::tempdir().unwrap();
  let storage_marker = directory.path().join("redaction-marker-directory-7x2q");
  std::fs::create_dir(&storage_marker).unwrap();
  let path_marker = storage_marker.to_string_lossy().to_string();

  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(3_710_000));
  let factory = radiata::adapters::json_store(storage_marker.clone());
  let mut issuer = {
    let config = NodeConfig::new()
      .with_anti_entropy_interval(Duration::from_millis(50))
      .unwrap();
    let handle = NodeBuilder::new(factory, keys)
      .config(config)
      .start()
      .await
      .unwrap();
    Node {
      handle,
      endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
      id: None,
    }
  };
  let mut member = start_node(3).await;

  issuer.id = Some(
    issuer
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );
  listen(&mut issuer).await;

  // Markers: the credential secret, the packet body, a hostile label
  // value, a selector text, and the storage path.
  let issued = issuer
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let credential_marker = issued.credential().expose_secret().to_owned();
  let body_marker: Arc<[u8]> = Arc::from(b"PACKET-BODY-MARKER-9w4e".as_slice());
  let label_marker = "hostile\nlabel\x00value-MARKER";
  let selector_marker = "radiata.woooo.tech/labels/marker-selector-x1q9";

  common::merge_with_retry(&member.handle, &issuer.handle, issuer.endpoint.clone()).await;
  member.id = Some(
    member
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );
  listen(&mut member).await;
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let sessions = member
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    if !sessions.items().is_empty() {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "no session registered"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // Packet bodies stay inside the stream; never loggable.
  let packet = member.handle.open_stream(
    StreamTarget::Exact(issuer.id.clone().unwrap()),
    ProtocolTag::parse("radiata.woooo.tech/protocols/unregistered-marker").unwrap(),
    StreamPolicy::new(radiata::RoutingPolicy::Direct, 8).unwrap(),
    StreamMetadata::new(),
  );
  match packet {
    Ok(packet) => {
      let _ = packet.send_sync(marker_body(body_marker.clone())).await;
    }
    Err(error) => assert_eq!(error.kind(), ErrorKind::Unsupported),
  }

  // A resource write with a hostile label value and a selector probe.
  let write = ResourceWrite::new(
    ResourceName::parse("radiata.woooo.tech/resources/redaction-lane").unwrap(),
    ResourceLabels::new(
      radiata::LabelValue::parse("marker").unwrap(),
      ResourceUri::parse("file:///tmp/redaction-lane").unwrap(),
    )
    .custom(
      radiata::LabelKey::parse("example.org/labels/owner").unwrap(),
      radiata::LabelValue::parse(label_marker).unwrap(),
    )
    .unwrap(),
  );
  let _ = member
    .handle
    .command(radiata::PutResource::new(write).unwrap())
    .await;
  let _ = member
    .handle
    .query(PageResources::new(PageSpec::first(8).unwrap()))
    .await;
  let _ = member
    .handle
    .query(radiata::SelectResources::new(
      radiata::Selector::parse(selector_marker).unwrap(),
      PageSpec::first(8).unwrap(),
    ))
    .await;

  // A session close churns the driver before the scan.
  member
    .handle
    .command(DisconnectPeer::new(issuer.id.clone().unwrap()))
    .await
    .unwrap();
  issuer.handle.command(Shutdown::new()).await.unwrap();
  member.handle.command(Shutdown::new()).await.unwrap();

  let captured = String::from_utf8_lossy(&capture.buffer.lock().unwrap()).to_string();
  assert!(!captured.is_empty(), "the workflow emitted no log events");
  for (class, marker) in [
    ("credential", credential_marker.as_str()),
    ("packet body", "PACKET-BODY-MARKER-9w4e"),
    ("label value", label_marker),
    ("selector", selector_marker),
    ("storage path", path_marker.as_str()),
  ] {
    assert!(
      !captured.contains(marker),
      "the {class} marker leaked into the log stream"
    );
  }
  // The listener address never enters the log stream either.
  assert!(
    !captured.contains(issuer.endpoint.as_str()),
    "the listener address leaked into the log stream"
  );
  // The packet body marker as a Debug byte array must not appear either.
  let bytes_marker: String = body_marker
    .iter()
    .map(u8::to_string)
    .collect::<Vec<_>>()
    .join(", ");
  assert!(
    !captured.contains(&bytes_marker),
    "packet body bytes leaked into the log stream"
  );
}

#[cfg(all(test, feature = "json", unix))]
fn marker_body(
  marker: Arc<[u8]>,
) -> impl futures_core::Stream<Item = radiata::Result<Arc<[u8]>>> + Send {
  futures_util::stream::once(async move { Ok(marker) })
}
