//! Starvation regressions: reads and packet sends keep flowing while a
//! join effect is wedged on a silent peer, and reads, packet sends, and
//! local resource writes keep flowing while four wedged dials hold
//! every network execution slot.
//!
//! Before the declarative refactor every mutating verb ran inline in
//! the supervisor's select loop, so one slow join dial (the transport
//! deadline alone) froze reads, commands, and packet routing for the
//! whole dial. The join now runs as a task-manager effect off the loop.
//! Before the slot split, all effects shared one four-permit pool, so
//! four wedged dials also froze every local write (the resource write
//! queued behind the dials): the dials now draw from their own channel
//! ([`NodeConfig::with_task_reconcile_slots`]) while local work keeps
//! its own. These tests pin that the loop's own lanes (control reads
//! and the outbound packet pump) and the local channel answer promptly
//! mid-dial.

use std::{sync::Arc, time::Duration};

use radiata::{
  Endpoint, EventOptions, LabelValue, MergeCredential, NodeBuilder, NodeConfig, NodeHandle,
  PacketConsumer, ProtocolDefinition, ProtocolTag, ResourceLabels, ResourceName, ResourceUri,
  ResourceWrite, Result, RoutingPolicy, StreamPolicy, StreamTarget,
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
/// The box the local resource write must fit in while every network
/// slot sits inside a wedged dial: under the old shared pool the write
/// queued until the first dial's deadline elapsed (seconds), so a tight
/// box is the discriminator.
const LOCAL_WRITE_BOX: Duration = Duration::from_secs(2);
/// The network slot budget for the saturation scenario: four wedged
/// dials fill the whole channel deterministically (the same shape the
/// old shared pool offered every effect).
const NETWORK_SLOTS: usize = 4;
/// The box the saturation drive (every dial reaching `Running`) and the
/// shutdown must fit in.
const DRIVE_BOX: Duration = Duration::from_secs(10);

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

async fn start_with(seed: u64, config: NodeConfig) -> NodeHandle {
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
    .config(config)
    .start()
    .await
    .unwrap()
}

async fn start(seed: u64) -> NodeHandle {
  start_with(
    seed,
    NodeConfig::new().with_dial_deadline(DIAL_DEADLINE).unwrap(),
  )
  .await
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

/// One fabricated dial subject for the saturation scenario: a valid id
/// shape that never matches a real peer, so every wedged connect dials a
/// distinct subject (no coalescing) and the handshake never runs (the
/// dial wedges on the silent peer first).
fn dial_subject(index: usize) -> radiata::NodeId {
  radiata::NodeId::parse(&format!("node-0000000000000000000{index:02x}")).unwrap()
}

/// The full saturation shape the shared pool froze: four wedged network
/// dials holding every network slot at once. Reads, packet admission,
/// and a local resource write must all still answer inside their boxes
/// — under the old single pool the write queued behind the dials for a
/// whole dial deadline (the audit's finding), and before the
/// declarative refactor even the reads and packets froze.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_packets_and_local_writes_flow_while_four_dials_hold_every_network_slot() {
  common::init_tracing();
  let issuer = start_with(
    3,
    NodeConfig::new().with_dial_deadline(DIAL_DEADLINE).unwrap(),
  )
  .await;
  // Two local slots and exactly four network slots: the four wedged
  // dials below saturate the network channel deterministically.
  let member = start_with(
    4,
    NodeConfig::new()
      .with_dial_deadline(DIAL_DEADLINE)
      .unwrap()
      .with_task_reconcile_slots(2, NETWORK_SLOTS)
      .unwrap(),
  )
  .await;

  let issued = issuer
    .credentials()
    .rotate()
    .await
    .unwrap()
    .wait()
    .await
    .unwrap();
  let _credential = MergeCredential::parse(issued.credential().expose_secret()).unwrap();
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

  // The wedge, fourfold: four silent peers, four distinct dial
  // subjects, so four connect tasks each hold a network slot for the
  // whole dial deadline.
  let mut holders = Vec::new();
  let mut wedged = Vec::new();
  for index in 0..NETWORK_SLOTS {
    let (port, holder) = silent_peer().await;
    holders.push(holder);
    let endpoint = Endpoint::parse(&format!("wss://127.0.0.1:{port}")).unwrap();
    wedged.push(member.connect(endpoint, dial_subject(index)).await.unwrap());
  }
  // Drive every dial to `Running`: the task view is the exact signal
  // that the dial holds a network slot (the attempt publishes `Running`
  // only after its permit draw).
  let deadline = Instant::now() + DRIVE_BOX;
  for task in &wedged {
    loop {
      let view = member
        .tasks()
        .get(task.id().clone())
        .await
        .unwrap()
        .unwrap();
      if view.phase() == radiata::TaskPhase::Running {
        break;
      }
      assert!(
        Instant::now() < deadline,
        "a wedged dial never reached running"
      );
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
  }

  // The read plane: a member read answers from the loop's own lane.
  let started = Instant::now();
  let members = tokio::time::timeout(
    READ_BOX,
    member.members().list(radiata::PageSpec::first(8).unwrap()),
  )
  .await
  .expect("a member read must not queue behind the wedged dials")
  .unwrap();
  assert!(!members.items().is_empty());
  assert!(
    started.elapsed() < READ_BOX,
    "the member read took {:?} while every network slot was wedged",
    started.elapsed()
  );

  // The packet plane: the same loop's packet arm routes the stream to
  // the issuer while the dials hold.
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
  .expect("packet admission must not queue behind the wedged dials")
  .unwrap();
  assert_eq!(ack.destination(), &issuer_id);
  assert!(
    started.elapsed() < PACKET_BOX,
    "packet admission took {:?} while every network slot was wedged",
    started.elapsed()
  );

  // The local plane: a resource write runs on the local channel,
  // inside the box — this is the probe the old shared pool queued
  // behind the dials.
  let write = ResourceWrite::new(
    ResourceName::parse("radiata.woooo.tech/resources/starvation-local-write").unwrap(),
    ResourceLabels::new(
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse("file:///starvation/local-write").unwrap(),
    ),
  );
  let put = member.resources().put(write).await.unwrap();
  let started = Instant::now();
  tokio::time::timeout(LOCAL_WRITE_BOX, put.wait())
    .await
    .expect("the local write must not queue behind the wedged dials")
    .unwrap();
  assert!(
    started.elapsed() < LOCAL_WRITE_BOX,
    "the local write took {:?} while every network slot was wedged",
    started.elapsed()
  );

  // The saturation really held: every dial is still mid-flight, holding
  // its slot inside the deadline (none of them settled early).
  for task in &wedged {
    let view = member
      .tasks()
      .get(task.id().clone())
      .await
      .unwrap()
      .unwrap();
    assert!(
      !view.phase().is_terminal(),
      "the wedged dials must still hold their network slots"
    );
  }

  // Shutdown cancels the wedged dials promptly instead of draining
  // them (boxed: a regression must fail here, not hang the harness).
  let started = Instant::now();
  tokio::time::timeout(DRIVE_BOX, member.shutdown())
    .await
    .expect("shutdown must cancel the wedged dials inside the box")
    .unwrap();
  assert!(
    started.elapsed() < DRIVE_BOX,
    "shutdown drained the cancellable wedged dials too slowly"
  );
  issuer.shutdown().await.unwrap();
  for holder in holders {
    holder.abort();
  }
}
