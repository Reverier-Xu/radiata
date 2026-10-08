//! Starvation regression: reads and packet sends keep flowing while a
//! join effect is wedged on a silent peer.
//!
//! Before the declarative refactor every mutating verb ran inline in
//! the supervisor's select loop, so one slow join dial (the transport
//! deadline alone) froze reads, commands, and packet routing for the
//! whole dial. The join now runs as a task-manager effect off the
//! loop; this test pins that the loop's own lanes (control reads and
//! the outbound packet pump) answer promptly mid-dial.

use std::{sync::Arc, time::Duration};

use radiata::{
  Endpoint, EventOptions, MergeCredential, NodeBuilder, NodeConfig, NodeHandle, PacketConsumer,
  ProtocolDefinition, ProtocolTag, Result, RoutingPolicy, StreamPolicy, StreamTarget,
  extension::{KeyProvider, StorageFactory},
};
use tokio::time::Instant;

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

/// The dial deadline the wedged join pays: long enough that a read or
/// packet queued behind the dial would blow the probe boxes below, and
/// short enough that the retry ladder stays observable.
const DIAL_DEADLINE: Duration = Duration::from_secs(5);
/// The box every read probe must fit in while the dial is wedged.
const READ_BOX: Duration = Duration::from_secs(1);
/// The box the packet admission must fit in while the dial is wedged.
const PACKET_BOX: Duration = Duration::from_secs(2);

const ECHO_PROTOCOL: &str = "radiata.woooo.tech/protocols/starvation-echo";

/// A packet consumer that drains and counts echo bodies.
#[derive(Debug, Default)]
struct EchoCollector {
  packets: std::sync::Mutex<usize>,
}

impl PacketConsumer for EchoCollector {
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

fn echo_body(
  chunk: &'static [u8],
) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static {
  futures_util::stream::once(async move { Ok(Arc::from(chunk) as Arc<[u8]>) })
}

async fn start(seed: u64) -> NodeHandle {
  let storage: Arc<dyn StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(6_000_000 + seed * 1_000));
  let mut extensions = radiata::ExtensionRegistry::new();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
        radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      Arc::new(EchoCollector::default()),
    )
    .unwrap();
  NodeBuilder::new(storage)
    .keys(keys)
    .extensions(extensions)
    .config(NodeConfig::new().with_dial_deadline(DIAL_DEADLINE).unwrap())
    .start()
    .await
    .unwrap()
}

/// The silent-peer fixture from the supervisor's dial-deadline tests:
/// accepts the TCP connection and then never speaks, so the TLS
/// handshake stalls until the configured deadline.
async fn silent_peer() -> (u16, tokio::task::JoinHandle<()>) {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let port = listener.local_addr().unwrap().port();
  let holder = tokio::spawn(async move {
    let (_held, _) = listener.accept().await.unwrap();
    // Hold the socket open without ever speaking TLS: an early drop
    // would reset the connection and fail the dial fast, bypassing the
    // wedge this test needs.
    tokio::time::sleep(Duration::from_secs(60)).await;
  });
  (port, holder)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_and_packets_flow_while_a_join_is_wedged_on_a_silent_peer() {
  common::init_tracing();
  let issuer = start(1).await;
  let member = start(2).await;

  let issued = issuer
    .credentials()
    .rotate()
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  let credential = MergeCredential::parse(issued.credential().expose_secret()).unwrap();
  let listener = issuer
    .listeners()
    .create(Endpoint::parse("wss://127.0.0.1:0").unwrap())
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  common::merge_with_retry(&member, &issuer, listener.endpoint().clone()).await;
  let issuer_id = issuer.local_node().await.unwrap().node_id().clone();

  // The wedge: a join against a peer that accepts TCP and never speaks.
  let (port, holder) = silent_peer().await;
  let wedged_endpoint = Endpoint::parse(&format!("wss://127.0.0.1:{port}")).unwrap();
  let mut join_events = member
    .watch::<radiata::TaskChanged>(EventOptions::new())
    .unwrap();
  let join = member.join(wedged_endpoint, credential).await.unwrap();

  // Drive to Running through the task event (value-based and exact,
  // no polling race): the dial is now wedged for the full deadline, and
  // every probe below must answer from the loop's own lanes — the
  // pre-refactor shape queued reads and packets behind the inline join
  // for the whole deadline.
  let admission = tokio::time::timeout(READ_BOX, join_events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(
    matches!(admission, radiata::EventReceive::Item(ref event) if event.phase() == radiata::TaskPhase::Pending),
    "the admission transition must publish first"
  );
  let running = tokio::time::timeout(READ_BOX, join_events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(
    matches!(running, radiata::EventReceive::Item(ref event) if event.phase() == radiata::TaskPhase::Running),
    "the first reconcile spawn must publish running"
  );

  let started = Instant::now();
  let members = tokio::time::timeout(
    READ_BOX,
    member.members().list(radiata::PageSpec::first(8).unwrap()),
  )
  .await
  .expect("a member read must not queue behind the wedged join dial")
  .unwrap();
  assert!(!members.items().is_empty());
  let read_elapsed = started.elapsed();
  assert!(
    read_elapsed < READ_BOX,
    "the member read took {read_elapsed:?} while the dial was wedged"
  );

  // The packet plane keeps admitting too: the same loop's packet arm
  // routes the stream to the issuer while the dial holds.
  let started = Instant::now();
  let ack = tokio::time::timeout(
    PACKET_BOX,
    member.send(
      StreamTarget::Exact(issuer_id.clone()),
      ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 1).unwrap(),
      echo_body(b"still-flowing"),
    ),
  )
  .await
  .expect("packet admission must not queue behind the wedged join dial")
  .unwrap();
  assert_eq!(ack.destination(), &issuer_id);
  let packet_elapsed = started.elapsed();
  assert!(
    packet_elapsed < PACKET_BOX,
    "packet admission took {packet_elapsed:?} while the dial was wedged"
  );

  // The wedge really was a wedge: the dial spends its whole deadline
  // before the retry ladder advances (the first attempt failing fast
  // would mean no dial stall at all).
  let deadline = Instant::now() + DIAL_DEADLINE + Duration::from_secs(10);
  let attempts = loop {
    let view = member
      .tasks()
      .get(join.id().clone())
      .await
      .unwrap()
      .unwrap();
    if view.attempts() >= 2 {
      break view.attempts();
    }
    assert!(
      Instant::now() < deadline,
      "the wedged dial never spent its deadline"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  };
  assert!(
    attempts >= 2,
    "the retry ladder advanced past the first dial"
  );

  // Shutdown cancels the wedged join promptly instead of draining it.
  let started = Instant::now();
  member.shutdown().await.unwrap();
  assert!(
    started.elapsed() < Duration::from_secs(10),
    "shutdown drained the cancellable wedged join too slowly"
  );
  issuer.shutdown().await.unwrap();
  holder.abort();
}
