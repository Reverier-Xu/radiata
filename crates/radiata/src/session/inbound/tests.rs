//! The inbound read-loop test suites, split out of `inbound.rs` so the
//! production read loop stays readable (the `connection`/`connection/tests`
//! file layout).

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use tokio::sync::mpsc;

use super::SessionPacketContext;
use crate::{NodeId, TraceId, identity::testing::SequenceEntropy};

fn node(value: u8) -> NodeId {
  NodeId::parse(&format!("node-{value:021}")).unwrap()
}

fn trace(seed: u32) -> TraceId {
  TraceId::parse(&format!("trace-{seed:021}")).unwrap()
}

/// Builds one read-loop packet context from the collaborators the suites
/// share: the session-owned defaults (the bounded queue policy, the
/// routing-only runtime client, the sequence entropy, the empty tracked
/// task vec) and the caller's overrides — the registry under test, the
/// injected clock, the route table, and the durable trace sink. The
/// routing plane keeps the built-in default next-hop policy tag and the
/// capacities the production context derives from the trace metadata
/// budget.
fn test_context(
  registry: crate::ExtensionRegistry, clock: Arc<dyn crate::time::WallClock>,
  routes: crate::routing::RouteTable, trace_sink: Option<crate::routing::trace::TraceSink>,
) -> SessionPacketContext {
  let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SequenceEntropy::default());
  SessionPacketContext::new(
    node(1),
    Arc::new(registry),
    crate::session::stream::SessionPolicy::new(
      8,
      1 << 20,
      Duration::from_secs(30),
      None,
      Duration::from_secs(15),
    ),
    crate::runtime::RuntimeClient::routing_only(
      mpsc::channel(4).0,
      Arc::new(std::sync::Mutex::new(BTreeMap::new())),
    ),
    clock,
    entropy,
    Arc::new(crate::node::EventHub::new()),
    Arc::new(std::sync::Mutex::new(BTreeMap::new())),
    crate::session::stream::RoutingPlaneContext::new(
      crate::routing::DefaultNextHop::tag().unwrap(),
      routes,
      trace_sink,
      8,
      16,
      Duration::from_secs(5),
    ),
    Arc::new(std::sync::Mutex::new(Vec::new())),
    crate::protocol::CONTROL_CBOR_LIMITS,
    crate::session::stream::AuthorizationBoundary::default(),
  )
}

mod admission_tests {
  use std::{collections::BTreeMap, sync::Arc};

  use minicbor::bytes::ByteVec;

  use super::{node, trace};
  use crate::{
    ProtocolTag, QualifiedTag, StreamMetadata,
    identity::signature::body_digest,
    routing::{RouteTable, table::record_terminal_failure},
    session::inbound::opening_context_digest,
  };

  fn protocol(name: &str) -> ProtocolTag {
    ProtocolTag::parse(&format!("radiata.woooo.tech/protocols/{name}")).unwrap()
  }

  fn metadata(entries: &[(&str, &[u8])]) -> StreamMetadata {
    let mut md = StreamMetadata::new();
    for (name, value) in entries {
      let key: QualifiedTag = format!("radiata.woooo.tech/labels/{name}").parse().unwrap();
      md = md.insert(key, Arc::from(*value)).unwrap();
    }
    md
  }

  // ---- Identical duplicates report status; conflicts fail ----

  /// The immutable context digest is stable across identical retransmissions
  /// and changes with any mutation of source, destination, protocol, or
  /// canonical metadata.
  #[test]
  fn opening_context_digest_binds_every_immutable_field() {
    let base = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("zone", b"edge")]),
    );

    let same = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("zone", b"edge")]),
    );
    assert_eq!(base, same, "identical contexts share one digest");

    let mutated_source = opening_context_digest(
      &node(3),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("zone", b"edge")]),
    );
    let mutated_destination = opening_context_digest(
      &node(1),
      &node(4),
      &protocol("test-echo"),
      &metadata(&[("zone", b"edge")]),
    );
    let mutated_protocol = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-other"),
      &metadata(&[("zone", b"edge")]),
    );
    let mutated_metadata = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("zone", b"core")]),
    );
    for (what, digest) in [
      ("source", mutated_source),
      ("destination", mutated_destination),
      ("protocol", mutated_protocol),
      ("metadata", mutated_metadata),
    ] {
      assert_ne!(base, digest, "mutating the {what} must change the context");
    }
  }

  /// The digest covers canonical metadata ordering: two maps with the same
  /// entries in different insertion orders produce one digest, and an
  /// entry-value change is visible.
  #[test]
  fn metadata_ordering_is_canonical_in_the_digest() {
    let a = StreamMetadata::new()
      .insert(
        "radiata.woooo.tech/labels/alpha".parse().unwrap(),
        Arc::from(&b"1"[..]),
      )
      .unwrap()
      .insert(
        "radiata.woooo.tech/labels/zeta".parse().unwrap(),
        Arc::from(&b"2"[..]),
      )
      .unwrap();
    let b = StreamMetadata::new()
      .insert(
        "radiata.woooo.tech/labels/zeta".parse().unwrap(),
        Arc::from(&b"2"[..]),
      )
      .unwrap()
      .insert(
        "radiata.woooo.tech/labels/alpha".parse().unwrap(),
        Arc::from(&b"1"[..]),
      )
      .unwrap();
    assert_eq!(a.entries().len(), b.entries().len());
    let da = body_digest(
      &a.entries()
        .flat_map(|(key, value)| {
          let mut bytes = key.as_str().as_bytes().to_vec();
          bytes.extend_from_slice(value);
          bytes
        })
        .collect::<Vec<u8>>(),
    );
    let db = body_digest(
      &b.entries()
        .flat_map(|(key, value)| {
          let mut bytes = key.as_str().as_bytes().to_vec();
          bytes.extend_from_slice(value);
          bytes
        })
        .collect::<Vec<u8>>(),
    );
    assert_eq!(da, db);
  }

  /// The bounded metadata map rejects duplicate keys, so two openings whose
  /// metadata differs in any entry always carry different contexts.
  #[test]
  fn conflicting_metadata_yields_different_contexts() {
    let first = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("role", b"a"), ("role2", b"b")]),
    );
    let second = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("role", b"b"), ("role2", b"a")]),
    );
    assert_ne!(first, second);
    let _ = BTreeMap::<String, ByteVec>::new();
  }

  /// Metadata values are arbitrary wire bytes that may contain the
  /// separator bytes and the text of a later key: a value that spells
  /// out the next entry must not collide with the genuine two-entry
  /// context it imitates (collision regression for the length-prefixed
  /// preimage).
  #[test]
  fn crafted_value_bytes_cannot_impersonate_the_next_entry() {
    let original = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("alpha", b"x"), ("beta", b"y")]),
    );
    let crafted = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("alpha", b"x\x02radiata.woooo.tech/labels/beta\x01y")]),
    );
    assert_ne!(
      original, crafted,
      "a value spelling out the next entry must not collide with it"
    );
  }

  /// A value that ends with the entry separator never aliases a further
  /// entry: the entry count and the fixed-width length prefixes delimit
  /// the map unambiguously even when values are empty.
  #[test]
  fn separator_bytes_inside_values_do_not_alias_entry_boundaries() {
    let with_suffix_value = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("alpha", b"x\x02")]),
    );
    let with_second_entry = opening_context_digest(
      &node(1),
      &node(2),
      &protocol("test-echo"),
      &metadata(&[("alpha", b"x"), ("beta", b"")]),
    );
    assert_ne!(
      with_suffix_value, with_second_entry,
      "a trailing separator byte must not open an entry boundary"
    );
  }

  // ---- Rejection records stay bounded terminal facts ----

  /// A rejected open records exactly one bounded terminal route fact; a
  /// second rejection for the same trace never grows the table.
  #[tokio::test]
  async fn rejections_record_one_terminal_fact() {
    let routes: RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    record_terminal_failure(&routes, 8, &trace(9), crate::ErrorKind::Unsupported);
    record_terminal_failure(&routes, 8, &trace(9), crate::ErrorKind::Unsupported);

    let table = routes.lock().unwrap();
    assert_eq!(table.len(), 1);
    let record = table.get(&trace(9)).unwrap();
    assert!(matches!(
      record.state,
      crate::RouteState::Failed(crate::ErrorKind::Unsupported)
    ));
    assert!(record.selected_node.is_none());
  }

  /// A rejection never grows the table past the node's configured route
  /// capacity: the oldest terminal record is evicted to make room.
  #[tokio::test]
  async fn rejections_stay_within_the_route_capacity() {
    let routes: RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    for seed in 1..=4 {
      record_terminal_failure(&routes, 3, &trace(seed), crate::ErrorKind::Unsupported);
    }

    let table = routes.lock().unwrap();
    assert_eq!(table.len(), 3);
    assert!(
      !table.contains_key(&trace(1)),
      "the oldest rejection is evicted once the table is full"
    );
    assert!(table.contains_key(&trace(4)));
  }
}

#[cfg(test)]
mod read_loop_liveness_tests {
  use std::{
    collections::BTreeMap,
    sync::{
      Arc, Mutex,
      atomic::{AtomicU64, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
  };

  use futures_util::future::BoxFuture;
  use tokio::{sync::oneshot, task::JoinSet};

  use super::{node, test_context};
  use crate::{
    routing::forward::SessionIdentity,
    session::{
      inbound::{ConsumerDrainGuard, FrameSource, SessionGrant, read_loop, read_loop_frames},
      pending::PendingAdmissions,
      stream::{SessionPacketContext, test_queue},
    },
    storage::contract::helpers::ManualClock,
    transport::Received,
  };

  /// The authenticated grant of one test session, derived exactly as the
  /// session loop derives it: the established session summary plus the
  /// incarnation the session table registered.
  fn grant() -> SessionGrant {
    SessionGrant::for_session(
      &crate::session::driver::EstablishedSession::test_session(node(2)),
      SessionIdentity::new(
        node(2),
        crate::SessionId::parse("session-000000000000000000002").unwrap(),
      ),
    )
  }

  /// A frame source that answers every wake with a keepalive pong (the
  /// wire shape of a responsive but application-silent peer), advancing
  /// the injected clock before each wake, and then ends the session
  /// orderly.
  struct PongSource {
    remaining: u32,
    clock: Arc<ManualClock>,
    second: u64,
  }

  impl FrameSource for PongSource {
    fn receive_event(&mut self) -> BoxFuture<'_, crate::Result<Option<Received>>> {
      let pong = self.remaining > 0;
      if pong {
        self.remaining -= 1;
        self.second += 1;
        self
          .clock
          .set(UNIX_EPOCH + Duration::from_secs(self.second));
      }
      Box::pin(async move {
        if pong {
          Ok(Some(Received::Pong))
        } else {
          Ok(None)
        }
      })
    }
  }

  fn context(clock: Arc<dyn crate::time::WallClock>) -> SessionPacketContext {
    let mut registry = crate::ExtensionRegistry::new();
    registry.register_default().unwrap();
    test_context(registry, clock, Arc::new(Mutex::new(BTreeMap::new())), None)
  }

  /// A frame-silent peer that answers keepalive pings must stay alive:
  /// every pong wake stamps the session's activity mark from the
  /// injected clock, so the liveness observer (pinned separately) never
  /// sees the idle deadline lapse. A pong swallowed inside the transport
  /// receive would leave the activity mark unadvanced.
  #[tokio::test]
  async fn pong_wakes_reflect_activity_for_frame_silent_peers() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    // A stale activity mark: the peer has been silent since second 1.
    let last_activity = Arc::new(AtomicU64::new(1));
    let mut source = PongSource {
      remaining: 3,
      clock: Arc::clone(&clock),
      second: 1_000,
    };
    let grant = grant();
    let context = context(Arc::clone(&clock) as Arc<dyn crate::time::WallClock>);
    let (frames, _receiver) = test_queue(8, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);

    read_loop(
      &mut source,
      &grant,
      &context,
      &frames,
      &pending_acks,
      &last_activity,
    )
    .await;

    // Each pong wake stamped the activity mark from the injected clock,
    // which the source advanced before every wake.
    assert_eq!(
      last_activity.load(Ordering::SeqCst),
      1_003,
      "the pong wakes must stamp the session activity mark from the injected clock"
    );
  }

  /// A frame source that never resolves: the read loop stays parked on
  /// its receive wake until it is cancelled.
  struct SilentSource;

  impl FrameSource for SilentSource {
    fn receive_event(&mut self) -> BoxFuture<'_, crate::Result<Option<Received>>> {
      Box::pin(std::future::pending())
    }
  }

  /// A read loop cancelled mid-frame (a deterministic replacement, a
  /// shutdown signal, a liveness failure, a writer death) still hands its
  /// consumer `JoinSet` to the node-scoped drain task: the cancellation
  /// path must not abort the session's in-flight consumer tasks.
  #[tokio::test]
  async fn cancelled_read_loop_still_registers_the_consumer_drain() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    let mut source = SilentSource;
    let grant = grant();
    let context = context(Arc::clone(&clock) as Arc<dyn crate::time::WallClock>);
    let (frames, _receiver) = test_queue(8, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(AtomicU64::new(1));

    // The silent source parks the loop; the bounded timeout cancels it.
    let cancelled = tokio::time::timeout(
      Duration::from_millis(100),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await;
    assert!(
      cancelled.is_err(),
      "the silent source must keep the read loop pending until cancelled"
    );

    // The cancellation path registered the consumer drain exactly once.
    assert_eq!(
      context.task_drains.lock().unwrap().len(),
      1,
      "a cancelled read loop must still own its consumer tasks"
    );
  }

  /// The orderly exit registers exactly one drain — never two — so the
  /// guard covers both paths without double-registering.
  #[tokio::test]
  async fn orderly_read_loop_registers_exactly_one_consumer_drain() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    let mut source = PongSource {
      remaining: 0,
      clock: Arc::clone(&clock),
      second: 1_000,
    };
    let grant = grant();
    let context = context(Arc::clone(&clock) as Arc<dyn crate::time::WallClock>);
    let (frames, _receiver) = test_queue(8, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(AtomicU64::new(1));

    read_loop(
      &mut source,
      &grant,
      &context,
      &frames,
      &pending_acks,
      &last_activity,
    )
    .await;

    assert_eq!(
      context.task_drains.lock().unwrap().len(),
      1,
      "the orderly exit registers the consumer drain exactly once"
    );
  }

  /// The long-lived read loop reaps completed consumer entries on its
  /// receive wakes instead of accumulating finished `JoinSet` entries for
  /// the whole session's life. Several short-lived
  /// consumers plus one still in flight are driven through the real frame
  /// loop with a test-owned guard (the admission path itself cannot run
  /// here without a negotiated feature set, so the guard receives exactly
  /// the task shape `admit_open` spawns): after the loop's in-life reap
  /// point, exactly the still-running entry remains, the reap registered no
  /// drain, and the guard's drop still hands that remainder to the
  /// node-scoped drain exactly once — teardown semantics unchanged.
  #[tokio::test]
  async fn read_loop_reaps_completed_consumer_entries_before_teardown() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    let grant = grant();
    let context = context(Arc::clone(&clock) as Arc<dyn crate::time::WallClock>);
    let (frames, _receiver) = test_queue(8, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(AtomicU64::new(1));

    // The loop borrows the guard, so the set stays observable between the
    // in-life reap point and the teardown drop.
    let mut consumers = ConsumerDrainGuard {
      consumers: JoinSet::new(),
      drains: Arc::clone(&context.task_drains),
    };

    // Three short-lived consumers and one still in flight. Each
    // short-lived task reports its completion, so the set's state is
    // deterministic at the loop's reap point (the sender's poll resolves
    // the task before the receiver's await can resume).
    let mut finished = Vec::new();
    for _ in 0..3 {
      let (done, wait) = oneshot::channel::<()>();
      finished.push(wait);
      consumers.consumers.spawn(async move {
        let _ = done.send(());
      });
    }
    let (release, wait) = oneshot::channel::<()>();
    consumers.consumers.spawn(async move {
      let _ = wait.await;
    });
    for wait in finished {
      wait.await.unwrap();
    }

    // The loop's first wake reaps the three completed entries in-life, then
    // the source ends the session orderly.
    let mut source = PongSource {
      remaining: 0,
      clock: Arc::clone(&clock),
      second: 1_000,
    };
    read_loop_frames(
      &mut source,
      &grant,
      &context,
      &frames,
      &pending_acks,
      &last_activity,
      &mut consumers,
    )
    .await;

    // Exactly the still-running entry remains pending; a reap that only
    // ran at teardown would accumulate all four. The in-life reap registers no
    // teardown drain of its own.
    assert_eq!(
      consumers.consumers.len(),
      1,
      "completed consumer entries must be reaped during the session's life"
    );
    assert!(
      context.task_drains.lock().unwrap().is_empty(),
      "the in-life reap must not register a teardown drain"
    );

    // Teardown semantics unchanged: the drop hands the remaining set to the
    // node-scoped drain exactly once, and that drain owns the in-flight
    // consumer until it finishes.
    drop(consumers);
    assert_eq!(
      context.task_drains.lock().unwrap().len(),
      1,
      "the orderly exit registers the consumer drain exactly once"
    );
    let _ = release.send(());
    let drain = context.task_drains.lock().unwrap().pop().unwrap();
    drain.await.unwrap();
  }
}

#[cfg(test)]
mod ack_attribution_tests {
  use std::{
    sync::{Arc, Mutex},
    time::Duration,
  };

  use futures_util::future::BoxFuture;

  use super::{node, test_context, trace};
  use crate::{
    packet::wire::{AckFrame, AckStatus, OpenFrame},
    protocol::wire::{BASE_SCHEMA_ID, PacketKind},
    routing::{
      RouteContext,
      forward::{ForwardingHop, HopPhase, PendingAck, RetryState, SessionIdentity, register},
    },
    session::{
      inbound::{FrameSource, SessionGrant, read_loop},
      pending::PendingAdmissions,
      stream::{SessionPacketContext, test_queue},
    },
    transport::{Received, connection::Message},
  };

  /// A frame source yielding one acknowledgement message for `trace`,
  /// then ending the session orderly.
  struct AckSource {
    body: Vec<u8>,
  }

  impl FrameSource for AckSource {
    fn receive_event(&mut self) -> BoxFuture<'_, crate::Result<Option<Received>>> {
      let body = std::mem::take(&mut self.body);
      Box::pin(async move {
        if body.is_empty() {
          Ok(None)
        } else {
          Ok(Some(Received::Message(Message {
            schema_id: BASE_SCHEMA_ID,
            kind_id: PacketKind::Ack.kind_id(),
            flags: 0,
            body,
          })))
        }
      })
    }
  }

  fn context() -> SessionPacketContext {
    let mut registry = crate::ExtensionRegistry::new();
    registry.register_default().unwrap();
    test_context(
      registry,
      Arc::new(crate::time::HostWallClock),
      Arc::new(Mutex::new(std::collections::BTreeMap::new())),
      None,
    )
  }

  /// The authenticated grant of one test session, derived exactly as the
  /// session loop derives it: the established session summary plus the
  /// incarnation the session table registered.
  fn grant() -> SessionGrant {
    SessionGrant::for_session(
      &crate::session::driver::EstablishedSession::test_session(node(2)),
      SessionIdentity::new(
        node(2),
        crate::SessionId::parse("session-000000000000000000002").unwrap(),
      ),
    )
  }

  /// The session identity of another incarnation of the same peer: a hop
  /// bound to it is not the receiving session's own downstream.
  fn other_session(peer: u8, incarnation: u32) -> SessionIdentity {
    SessionIdentity::new(
      node(peer),
      crate::SessionId::parse(&format!("session-{incarnation:021}")).unwrap(),
    )
  }

  fn hop_on(
    upstream: crate::session::stream::BoundedSender,
    downstream: crate::session::stream::BoundedSender, downstream_acks: PendingAdmissions,
    downstream_session: SessionIdentity,
  ) -> ForwardingHop {
    let trace_id = trace(9);
    ForwardingHop {
      upstream,
      downstream,
      downstream_acks: downstream_acks.clone(),
      upstream_session: other_session(3, 1),
      downstream_session,
      relay_lock: Arc::new(tokio::sync::Mutex::new(())),
      deadline: None,
      phase: HopPhase::Discovering(Box::new(RetryState {
        open: OpenFrame {
          trace_id: trace_id.clone(),
          source: node(3),
          destination: node(9),
          protocol: crate::ProtocolTag::parse("radiata.woooo.tech/protocols/test-echo").unwrap(),
          metadata: crate::StreamMetadata::new(),
          route: None,
        },
        context: RouteContext::new(trace_id, node(3), node(9), Vec::new(), 8),
        candidates: Vec::new(),
        downstream_acks,
      })),
    }
  }

  /// The same hop once the destination admitted the stream: a pure relay
  /// bound to `downstream_session`, whose one-shot admission waiter the
  /// admission acknowledgement already consumed from the pending map.
  fn admitted_hop_on(
    upstream: crate::session::stream::BoundedSender,
    downstream: crate::session::stream::BoundedSender, downstream_acks: PendingAdmissions,
    downstream_session: SessionIdentity,
  ) -> ForwardingHop {
    let mut hop = hop_on(upstream, downstream, downstream_acks, downstream_session);
    hop.phase = HopPhase::Admitted;
    hop
  }

  /// Reads one acknowledgement frame from a fresh session frame source and
  /// returns the peer-facing queue of the read loop: the sender stays with
  /// the caller so "no frame was queued" is distinguishable from "the loop
  /// dropped the queue". The source ends the session orderly after the
  /// acknowledgement, so the loop always terminates within the timeout.
  async fn deliver_ack(
    grant: &SessionGrant, context: &SessionPacketContext, pending_acks: &PendingAdmissions,
    body: Vec<u8>,
  ) -> (
    crate::session::stream::BoundedSender,
    crate::session::stream::BoundedReceiver,
  ) {
    let mut source = AckSource { body };
    let (frames, frames_rx) = test_queue(8, 1 << 20);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));
    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        grant,
        context,
        &frames,
        pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the acknowledgement source ends the read loop orderly");
    (frames, frames_rx)
  }

  /// A late failure acknowledgement from a superseded branch must not
  /// steer the live hop: this node's discovering retry for the trace
  /// switched to a new downstream (the first branch's deadline expired),
  /// and the stale branch's session now delivers its late failure. The
  /// live hop keeps its retry armed, the live attempt's pending entry
  /// survives, nothing fails upstream, and no acknowledgement resolves on
  /// the stale session's map.
  #[tokio::test]
  async fn late_ack_from_a_superseded_branch_leaves_the_live_hop_untouched() {
    let trace_id = trace(9);
    let grant = grant();
    let context = context();

    // The hop's current downstream attempt: a live relay entry on its
    // pending map, discovering retry armed with no candidates left to
    // try (any bogus failure handling would exhaust it and fail the
    // route upstream immediately).
    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let live_acks: PendingAdmissions =
      PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    live_acks
      .try_reserve_admission(
        &trace_id,
        PendingAck::Relay {
          upstream: upstream_tx.clone(),
        },
      )
      .unwrap();
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    register(
      &context.routing.forwarding,
      trace_id.clone(),
      hop_on(
        upstream_tx,
        downstream_tx,
        live_acks.clone(),
        // A different session than the one delivering the late ack: the
        // hop already re-dispatched to another branch.
        other_session(7, 5),
      ),
    )
    .unwrap();

    // The superseded branch's session map: its entry was already
    // consumed when the hop re-dispatched.
    let stale_acks: PendingAdmissions =
      PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let body = crate::packet::wire::encode_ack(&AckFrame {
      trace_id: trace_id.clone(),
      status: AckStatus::Failed,
      admitted_at_millis: 0,
    })
    .unwrap();
    let (_session_frames, mut frames_rx) = deliver_ack(&grant, &context, &stale_acks, body).await;

    // The live hop is untouched: still registered, still discovering.
    assert!(crate::routing::forward::contains(
      &context.routing.forwarding,
      &trace_id
    ));
    assert!(crate::routing::forward::owns_discovering(
      &context.routing.forwarding,
      &trace_id
    ));
    // The live attempt's pending entry survived.
    assert!(live_acks.contains(&trace_id));
    // Nothing failed upstream and no frame left the stale session.
    use futures_util::FutureExt;
    assert!(upstream_rx.recv().now_or_never().is_none());
    assert!(frames_rx.recv().now_or_never().is_none());
  }

  /// A mid-stream failure arriving after the destination admitted the
  /// stream belongs to the hop that owns it, even though its one-shot
  /// admission waiter was consumed by the admission acknowledgement: the
  /// admitted phase carries the ownership, so the report still travels
  /// upstream instead of being dropped as a superseded branch's
  /// latecomer.
  #[tokio::test]
  async fn post_admission_failure_from_the_bound_session_relays_upstream() {
    let trace_id = trace(9);
    let grant = grant();
    let context = context();

    // The admission acknowledgement already resolved the one-shot waiter:
    // the session's pending map is empty and the hop alone represents the
    // stream from here on.
    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let session_acks: PendingAdmissions =
      PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    register(
      &context.routing.forwarding,
      trace_id.clone(),
      admitted_hop_on(
        upstream_tx,
        downstream_tx,
        session_acks.clone(),
        grant.identity().clone(),
      ),
    )
    .unwrap();

    let body = crate::packet::wire::encode_ack(&AckFrame {
      trace_id: trace_id.clone(),
      status: AckStatus::Failed,
      admitted_at_millis: 0,
    })
    .unwrap();
    let (_session_frames, mut frames_rx) = deliver_ack(&grant, &context, &session_acks, body).await;

    // The bound session's failure reached the previous hop with its typed
    // status preserved.
    use futures_util::FutureExt;
    let relayed = upstream_rx
      .recv()
      .now_or_never()
      .flatten()
      .expect("the admitted hop relays the failure upstream");
    assert_eq!(relayed.kind, PacketKind::Ack);
    let relayed = crate::packet::wire::decode_ack(&relayed.body, context.parser_limits()).unwrap();
    assert_eq!(relayed.trace_id, trace_id);
    assert_eq!(relayed.status, AckStatus::Failed);
    // The hop stays the stream's owner for its whole life: still
    // registered, never re-searching, and nothing sent back downstream.
    assert!(crate::routing::forward::contains(
      &context.routing.forwarding,
      &trace_id
    ));
    assert!(!crate::routing::forward::owns_discovering(
      &context.routing.forwarding,
      &trace_id
    ));
    assert!(frames_rx.recv().now_or_never().is_none());
  }

  /// The admitted hop's ownership is the exact downstream incarnation, not
  /// the peer: a post-admission failure from a replacement session of the
  /// same peer is another generation's traffic and is dropped rather than
  /// steered through the live stream.
  #[tokio::test]
  async fn post_admission_failure_from_another_incarnation_is_dropped() {
    let trace_id = trace(9);
    let grant = grant();
    let context = context();

    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    // The hop's bound attempt is another incarnation of the delivering
    // peer, so its pending map is not the one this session acknowledges on.
    let bound_acks: PendingAdmissions =
      PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    register(
      &context.routing.forwarding,
      trace_id.clone(),
      admitted_hop_on(
        upstream_tx,
        downstream_tx,
        bound_acks.clone(),
        other_session(2, 7),
      ),
    )
    .unwrap();

    let session_acks: PendingAdmissions =
      PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let body = crate::packet::wire::encode_ack(&AckFrame {
      trace_id: trace_id.clone(),
      status: AckStatus::Failed,
      admitted_at_millis: 0,
    })
    .unwrap();
    let (_session_frames, mut frames_rx) = deliver_ack(&grant, &context, &session_acks, body).await;

    use futures_util::FutureExt;
    assert!(upstream_rx.recv().now_or_never().is_none());
    assert!(frames_rx.recv().now_or_never().is_none());
    // The hop still owns its own stream: nothing about it changed.
    assert!(crate::routing::forward::contains(
      &context.routing.forwarding,
      &trace_id
    ));
    assert!(!crate::routing::forward::owns_discovering(
      &context.routing.forwarding,
      &trace_id
    ));
  }

  /// A repeated admission from the bound session carries nothing new: the
  /// admission was relayed upstream when it resolved the one-shot waiter,
  /// so the admitted hop does not echo it a second time.
  #[tokio::test]
  async fn a_repeated_admission_is_not_relayed_again() {
    let trace_id = trace(9);
    let grant = grant();
    let context = context();

    let (upstream_tx, mut upstream_rx) = test_queue(16, usize::MAX);
    let session_acks: PendingAdmissions =
      PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let (downstream_tx, _downstream_rx) = test_queue(16, usize::MAX);
    register(
      &context.routing.forwarding,
      trace_id.clone(),
      admitted_hop_on(
        upstream_tx,
        downstream_tx,
        session_acks.clone(),
        grant.identity().clone(),
      ),
    )
    .unwrap();

    let body = crate::packet::wire::encode_ack(&AckFrame {
      trace_id: trace_id.clone(),
      status: AckStatus::Admitted,
      admitted_at_millis: 1,
    })
    .unwrap();
    let (_session_frames, mut frames_rx) = deliver_ack(&grant, &context, &session_acks, body).await;

    use futures_util::FutureExt;
    assert!(upstream_rx.recv().now_or_never().is_none());
    assert!(frames_rx.recv().now_or_never().is_none());
  }
}

#[cfg(test)]
mod durable_mirror_tests {
  use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
  };

  use futures_util::future::BoxFuture;

  use super::{node, test_context, trace};
  use crate::{
    ErrorKind, RouteState, TraceId,
    packet::{
      RouteRecord,
      wire::{AckFrame, AckStatus},
    },
    routing::{
      forward::SessionIdentity,
      trace::{TraceRecord, TraceSink},
    },
    session::{
      inbound::{FrameSource, SessionGrant, read_loop},
      pending::PendingAdmissions,
      stream::{SessionPacketContext, test_queue},
    },
    transport::{Received, connection::Message},
  };

  /// A frame source yielding one acknowledgement message, then ending
  /// the session orderly (the read loop processes the ack before its
  /// final receive).
  struct AckSource {
    body: Vec<u8>,
  }

  impl FrameSource for AckSource {
    fn receive_event(&mut self) -> BoxFuture<'_, crate::Result<Option<Received>>> {
      let body = std::mem::take(&mut self.body);
      Box::pin(async move {
        if body.is_empty() {
          Ok(None)
        } else {
          Ok(Some(Received::Message(Message {
            schema_id: crate::protocol::wire::BASE_SCHEMA_ID,
            kind_id: crate::protocol::wire::PacketKind::Ack.kind_id(),
            flags: 0,
            body,
          })))
        }
      })
    }
  }

  /// A packet context carrying a real durable trace sink and the given
  /// in-memory route table, so the read loop's late-failure handling can
  /// be observed on both planes at once.
  fn context_with(sink: TraceSink, routes: crate::routing::RouteTable) -> SessionPacketContext {
    let mut registry = crate::ExtensionRegistry::new();
    registry.register_default().unwrap();
    test_context(
      registry,
      Arc::new(crate::time::HostWallClock),
      routes,
      Some(sink),
    )
  }

  /// Feeds one failed acknowledgement through the read loop and returns
  /// the durable rows once the sink's bounded queue drained (wall-clock
  /// deadline bounded).
  async fn deliver_failed_ack(
    sink: &TraceSink, routes: &crate::routing::RouteTable, trace_id: &TraceId,
  ) -> Vec<TraceRecord> {
    let context = context_with(sink.clone(), routes.clone());
    let grant = SessionGrant::for_session(
      &crate::session::driver::EstablishedSession::test_session(node(2)),
      SessionIdentity::new(
        node(2),
        crate::SessionId::parse("session-000000000000000000002").unwrap(),
      ),
    );
    let body = crate::packet::wire::encode_ack(&AckFrame {
      trace_id: trace_id.clone(),
      status: AckStatus::Failed,
      admitted_at_millis: 0,
    })
    .unwrap();
    let mut source = AckSource { body };
    let (frames, _frames_rx) = test_queue(8, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the acknowledgement source ends the read loop orderly");

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while sink.queued() != 0 {
      assert!(
        std::time::Instant::now() < deadline,
        "the admitted queue never drained"
      );
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    sink.persisted_records().await
  }

  /// Internal control traffic is excluded from durable trace persistence
  /// on every path: its pump holds no sink, and a late failure flips the
  /// in-memory record without writing any durable revision.
  #[tokio::test]
  async fn internal_traffic_flips_in_memory_but_never_reaches_the_durable_twin() {
    let sink = TraceSink::test_sink().await;
    let trace_id = trace(43);
    let routes: crate::routing::RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    crate::routing::insert_route(
      &routes,
      8,
      RouteRecord::new(trace_id.clone(), node(9)).with_internal(true),
    )
    .unwrap();
    crate::routing::table::update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Streaming);
    });

    let records = deliver_failed_ack(&sink, &routes, &trace_id).await;

    // The in-memory flip still happens (routing correctness is identical
    // for internal traffic)…
    let memory = routes.lock().unwrap().get(&trace_id).cloned().unwrap();
    assert_eq!(
      memory.state,
      RouteState::Failed(ErrorKind::StreamInterrupted)
    );
    // …but the durable twin stays untouched: no row, no revision.
    assert!(
      records.is_empty(),
      "internal traffic must never persist a durable trace row"
    );
  }

  /// The durable twin's mirror of the in-memory flip: a late failed
  /// acknowledgement that flips the origin's in-memory record to
  /// `Failed(StreamInterrupted)` also revises the durable terminal that already
  /// recorded `Delivered` — the realistic ordering, since the failure report
  /// trails the pump tail — so the durable trace ends failed exactly like the
  /// in-memory record instead of keeping `Delivered` for the whole retention
  /// window.
  #[tokio::test]
  async fn late_failure_revises_the_durable_delivered_twin() {
    let sink = TraceSink::test_sink().await;
    let trace_id = trace(41);
    let routes: crate::routing::RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    crate::routing::insert_route(&routes, 8, RouteRecord::new(trace_id.clone(), node(9))).unwrap();
    // The pump tail already landed on both planes.
    crate::routing::table::update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Delivered);
    });
    sink
      .record(
        TraceRecord::new(trace_id.clone(), node(1), node(9), sink.clock_now())
          .with_transition(RouteState::Delivered, sink.clock_now()),
      )
      .await;

    let records = deliver_failed_ack(&sink, &routes, &trace_id).await;

    // The in-memory record ends failed (the terminal contract, unchanged).
    let memory = routes.lock().unwrap().get(&trace_id).cloned().unwrap();
    assert_eq!(
      memory.state,
      RouteState::Failed(ErrorKind::StreamInterrupted)
    );
    // The durable twin converged with it: revised in place, identity
    // preserved, terminal answer the same explicit failure.
    assert_eq!(records.len(), 1, "one revised row, not two");
    assert_eq!(records[0].trace_id(), &trace_id);
    assert_eq!(records[0].source(), &node(1));
    assert_eq!(records[0].destination(), &node(9));
    assert_eq!(
      records[0].phase(),
      &RouteState::Failed(ErrorKind::StreamInterrupted)
    );
  }

  /// The other ordering: when the failure report lands before the pump
  /// tail's durable write (the write still in flight), the revision
  /// writes the fresh durable terminal itself, so the durable twin ends
  /// failed even though no durable row existed at the moment of the
  /// flip.
  #[tokio::test]
  async fn late_failure_writes_the_twin_when_no_durable_row_landed_yet() {
    let sink = TraceSink::test_sink().await;
    let trace_id = trace(42);
    let routes: crate::routing::RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    crate::routing::insert_route(&routes, 8, RouteRecord::new(trace_id.clone(), node(9))).unwrap();
    // Still streaming: no durable terminal row exists yet.
    crate::routing::table::update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Streaming);
    });
    assert!(sink.persisted_records().await.is_empty());

    let records = deliver_failed_ack(&sink, &routes, &trace_id).await;

    let memory = routes.lock().unwrap().get(&trace_id).cloned().unwrap();
    assert_eq!(
      memory.state,
      RouteState::Failed(ErrorKind::StreamInterrupted)
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].trace_id(), &trace_id);
    assert_eq!(records[0].source(), &node(1));
    assert_eq!(records[0].destination(), &node(9));
    assert_eq!(
      records[0].phase(),
      &RouteState::Failed(ErrorKind::StreamInterrupted)
    );
  }

  /// Containment: the revision fires only for a record this node's route
  /// table actually flipped. A failed acknowledgement for an untracked
  /// trace (this node is a relay hop, or the record was evicted) leaves
  /// the durable store untouched — no fabricated origin-side identity,
  /// no `StreamInterrupted` row for a route this node never pumped.
  #[tokio::test]
  async fn untracked_failure_leaves_the_durable_twin_untouched() {
    let sink = TraceSink::test_sink().await;
    let routes: crate::routing::RouteTable = Arc::new(Mutex::new(BTreeMap::new()));

    let records = deliver_failed_ack(&sink, &routes, &trace(43)).await;

    assert!(records.is_empty(), "no durable row may be fabricated");
  }
}

#[cfg(test)]
mod slow_consumer_tests {
  use std::{
    sync::{Arc, Mutex},
    time::Duration,
  };

  use futures_util::{StreamExt as _, future::BoxFuture};
  use minicbor::bytes::ByteVec;

  use super::{node, test_context, trace};
  use crate::{
    ExtensionRegistry, FeatureTag, IncomingStream, ProtocolTag, TraceId,
    extension_registry::{PacketConsumer, ProtocolDefinition},
    packet::wire::{AckStatus, ChunkFrame, OpenFrame},
    protocol::{
      CONTROL_CBOR_LIMITS,
      wire::{BASE_SCHEMA_ID, PacketKind},
    },
    routing::forward::SessionIdentity,
    session::{
      inbound::{
        FrameSource, INCOMING_STREAM_CHUNKS, INCOMING_STREAM_TERMINAL_SLOTS, LocalLeg,
        SessionGrant, read_loop,
      },
      pending::PendingAdmissions,
      stream::{SessionPacketContext, test_queue},
    },
    transport::{Received, connection::Message},
  };

  const FEATURE: &str = "radiata.woooo.tech/features/data-messages";
  const PROTOCOL: &str = "example.org/protocols/test-echo";

  /// The authenticated grant of a session that selected the test
  /// protocol's owning feature: admission requires the negotiated
  /// selection, so the test grant carries it exactly like a real
  /// handshake would.
  fn grant() -> SessionGrant {
    SessionGrant::new(
      SessionIdentity::new(
        node(2),
        crate::SessionId::parse("session-000000000000000000002").unwrap(),
      ),
      vec![FeatureTag::parse(FEATURE).unwrap()],
    )
  }

  /// A consumer that holds the admitted stream without draining it until
  /// the level-triggered gate opens, then records the body's terminal:
  /// `None` for a completed body, `Some(kind)` for exactly one typed
  /// interruption.
  #[derive(Debug)]
  struct GatedConsumer {
    gate: tokio::sync::watch::Receiver<bool>,
    terminal: Arc<Mutex<Option<Option<crate::ErrorKind>>>>,
  }

  impl PacketConsumer for GatedConsumer {
    fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, crate::Result<()>> {
      let mut gate = self.gate.clone();
      let terminal = Arc::clone(&self.terminal);
      Box::pin(async move {
        while !*gate.borrow_and_update() {
          let _ = gate.changed().await;
        }
        let mut body = packet.body();
        let outcome = loop {
          match body.next().await {
            Some(Ok(_)) => continue,
            Some(Err(error)) => break Some(error.kind()),
            None => break None,
          }
        };
        terminal.lock().unwrap().replace(outcome);
        Ok(())
      })
    }
  }

  /// Yields the queued wire messages in order, then ends the session
  /// orderly.
  struct FramesSource {
    messages: std::collections::VecDeque<Message>,
  }

  impl FrameSource for FramesSource {
    fn receive_event(&mut self) -> BoxFuture<'_, crate::Result<Option<Received>>> {
      let message = self.messages.pop_front();
      Box::pin(async move { Ok(message.map(Received::Message)) })
    }
  }

  fn open_frame(seed: u32) -> Message {
    Message {
      schema_id: BASE_SCHEMA_ID,
      kind_id: PacketKind::Open.kind_id(),
      flags: 0,
      body: crate::packet::wire::encode_open(&OpenFrame {
        trace_id: trace(seed),
        source: node(2),
        destination: node(1),
        protocol: ProtocolTag::parse(PROTOCOL).unwrap(),
        metadata: crate::StreamMetadata::new(),
        route: None,
      })
      .unwrap(),
    }
  }

  fn chunk_frame(seed: u32, sequence: u64) -> Message {
    chunk_frame_with(seed, sequence, &[7; 8])
  }

  fn chunk_frame_with(seed: u32, sequence: u64, bytes: &[u8]) -> Message {
    Message {
      schema_id: BASE_SCHEMA_ID,
      kind_id: PacketKind::Chunk.kind_id(),
      flags: 0,
      body: crate::packet::wire::encode_chunk(&ChunkFrame {
        trace_id: trace(seed),
        sequence,
        bytes: ByteVec::from(bytes.to_vec()),
      })
      .unwrap(),
    }
  }

  fn end_frame(seed: u32) -> Message {
    Message {
      schema_id: BASE_SCHEMA_ID,
      kind_id: PacketKind::End.kind_id(),
      flags: 0,
      body: crate::packet::wire::encode_end(&crate::packet::wire::EndFrame {
        trace_id: trace(seed),
        reason: crate::packet::wire::EndReason::Completed,
      })
      .unwrap(),
    }
  }

  /// Every body the draining consumer finished: its trace and the
  /// concatenated payload.
  type RecordedBodies = Arc<Mutex<Vec<(TraceId, Vec<u8>)>>>;

  /// Every terminal the draining consumer observed: its trace and `None`
  /// for a completed body or the typed interruption kind.
  type RecordedTerminals = Arc<Mutex<Vec<(TraceId, Option<crate::ErrorKind>)>>>;

  /// A consumer that drains immediately — the healthy side of a burst —
  /// and records each body and its terminal. The trace it is told to stall
  /// is instead held forever without a single read: a consumer whose task
  /// and admission slot are alive but that never frees its window.
  #[derive(Debug)]
  struct DrainingConsumer {
    stalled: Option<TraceId>,
    bodies: RecordedBodies,
    terminals: RecordedTerminals,
  }

  impl DrainingConsumer {
    fn new(stalled: Option<TraceId>) -> Self {
      Self {
        stalled,
        bodies: Arc::default(),
        terminals: Arc::default(),
      }
    }

    /// Waits (bounded) for the recorded body of `trace` and returns its
    /// bytes together with its terminal: `None` for a completed body,
    /// `Some(kind)` for exactly one typed interruption.
    async fn body_of(&self, trace: &TraceId) -> (Vec<u8>, Option<crate::ErrorKind>) {
      let deadline = std::time::Instant::now() + Duration::from_secs(10);
      loop {
        let terminal = self
          .terminals
          .lock()
          .unwrap()
          .iter()
          .find(|(recorded, _)| recorded == trace)
          .map(|(_, terminal)| *terminal);
        if let Some(terminal) = terminal {
          let body = self
            .bodies
            .lock()
            .unwrap()
            .iter()
            .find(|(recorded, _)| recorded == trace)
            .map(|(_, body)| body.clone())
            .unwrap_or_default();
          return (body, terminal);
        }
        assert!(
          std::time::Instant::now() < deadline,
          "the draining consumer must finish its body"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
      }
    }
  }

  impl PacketConsumer for DrainingConsumer {
    fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, crate::Result<()>> {
      let stalled = self.stalled.clone();
      let bodies = Arc::clone(&self.bodies);
      let terminals = Arc::clone(&self.terminals);
      Box::pin(async move {
        let trace = packet.trace_id().clone();
        if stalled.as_ref() == Some(&trace) {
          // Never read a byte: the window fills and only the reader's
          // bounded drain grace stands between it and the overload policy.
          std::future::pending::<()>().await;
        }
        let mut bytes = Vec::new();
        let mut body = packet.body();
        let terminal = loop {
          match body.next().await {
            Some(Ok(chunk)) => bytes.extend_from_slice(&chunk),
            Some(Err(error)) => break Some(error.kind()),
            None => break None,
          }
        };
        bodies.lock().unwrap().push((trace.clone(), bytes));
        terminals.lock().unwrap().push((trace, terminal));
        Ok(())
      })
    }
  }

  /// Builds the registry + read loop plumbing around one consumer.
  fn session_for(consumer: Arc<DrainingConsumer>) -> SessionPacketContext {
    let mut registry = ExtensionRegistry::new();
    registry.register_default().unwrap();
    registry
      .register_protocol(
        ProtocolDefinition::new(
          ProtocolTag::parse(PROTOCOL).unwrap(),
          FeatureTag::parse(FEATURE).unwrap(),
        ),
        Arc::clone(&consumer) as Arc<dyn PacketConsumer>,
      )
      .unwrap();
    context(registry)
  }

  fn context(registry: ExtensionRegistry) -> SessionPacketContext {
    test_context(
      registry,
      Arc::new(crate::time::HostWallClock),
      Arc::new(Mutex::new(std::collections::BTreeMap::new())),
      None,
    )
  }

  /// Regression: the local leg's terminal must reach a consumer whose
  /// body channel is completely full. The pump is the channel's only
  /// sender and its chunk sends respect the channel's full capacity
  /// (`INCOMING_STREAM_CHUNKS` plus the terminal slot), so every slot can
  /// hold a chunk when the end arrives — a `try_send` terminal would race
  /// the consumer's drain and drop the completion, surfacing a delivered
  /// body as a typed interruption (the failure the Windows runner caught
  /// on a ten-chunk body). The terminal therefore awaits the window like
  /// a chunk.
  #[tokio::test]
  async fn the_local_terminal_reaches_a_consumer_with_a_full_window() {
    let consumer = Arc::new(DrainingConsumer::new(None));
    let context = Arc::new(session_for(Arc::clone(&consumer)));
    let seed = 21_u32;
    let mut leg = LocalLeg::new(&context, trace(seed));

    // Admit the stream through the local leg, then fill the body channel
    // to its full capacity before the consumer task ever runs: on a
    // single-threaded test runtime the chunk sends into a non-full channel
    // complete without yielding, so the terminal faces a genuinely full
    // window.
    leg
      .deliver_open(OpenFrame {
        trace_id: trace(seed),
        source: node(2),
        destination: node(1),
        protocol: ProtocolTag::parse(PROTOCOL).unwrap(),
        metadata: crate::StreamMetadata::new(),
        route: None,
      })
      .await
      .unwrap();
    let chunk_bytes = 64_u32;
    let chunks = (INCOMING_STREAM_CHUNKS + INCOMING_STREAM_TERMINAL_SLOTS) as u64;
    for sequence in 0..chunks {
      leg
        .deliver_chunk(ChunkFrame {
          trace_id: trace(seed),
          sequence,
          bytes: ByteVec::from(vec![7_u8; chunk_bytes as usize]),
        })
        .await
        .unwrap();
    }

    // The terminal waits for the consumer to free a slot and reaches it:
    // the consumer observes the full body and a clean end, never a
    // truncation.
    assert!(
      leg
        .deliver_end(crate::packet::wire::EndReason::Completed)
        .await
    );
    let (body, terminal) = consumer.body_of(&trace(seed)).await;
    assert_eq!(terminal, None, "the completed end must reach the consumer");
    assert_eq!(body.len(), chunks as usize * chunk_bytes as usize);
  }

  /// Regression: a consumer that never drains its bounded
  /// window must not stall the session's shared read loop. The window
  /// (`INCOMING_STREAM_CHUNKS`) fills, the overflowing chunk spends the
  /// stream's single drain grace, the grace expires, and the explicit
  /// overload policy terminates the stream — the origin learns it through
  /// a typed failed acknowledgement, the consumer later observes exactly
  /// one typed interruption — and the reader keeps processing frames after
  /// the overload until the orderly end. A reader parked
  /// on the full channel would leave the session mute.
  #[tokio::test]
  async fn an_undrained_window_terminates_the_stream_without_stalling_the_reader() {
    let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
    let consumer = Arc::new(GatedConsumer {
      gate: gate_rx,
      terminal: Arc::new(Mutex::new(None)),
    });
    let mut registry = ExtensionRegistry::new();
    registry.register_default().unwrap();
    registry
      .register_protocol(
        ProtocolDefinition::new(
          ProtocolTag::parse(PROTOCOL).unwrap(),
          FeatureTag::parse(FEATURE).unwrap(),
        ),
        Arc::clone(&consumer) as Arc<dyn PacketConsumer>,
      )
      .unwrap();
    let context = context(registry);
    let grant = grant();
    let (frames, mut frames_rx) = test_queue(16, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // The window fills, then the next chunk overflows it and spends the
    // stream's one drain grace, which expires against this gated consumer.
    let mut messages = Vec::new();
    messages.push(open_frame(9));
    for sequence in 0..(INCOMING_STREAM_CHUNKS as u64 + 1) {
      messages.push(chunk_frame(9, sequence));
    }
    // Frames after the overload still get processed: the terminal end for
    // the terminated trace (now unknown — dropped with a warning) and the
    // orderly session end both prove the loop kept running.
    messages.push(Message {
      schema_id: BASE_SCHEMA_ID,
      kind_id: PacketKind::End.kind_id(),
      flags: 0,
      body: crate::packet::wire::encode_end(&crate::packet::wire::EndFrame {
        trace_id: trace(9),
        reason: crate::packet::wire::EndReason::Completed,
      })
      .unwrap(),
    });
    let mut source = FramesSource {
      messages: messages.into(),
    };

    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the read loop must not stall on an undrained consumer window");

    // The origin saw the admission, then the typed failure from the
    // overload policy.
    let ack = frames_rx.recv().await.unwrap();
    assert_eq!(ack.kind, PacketKind::Ack);
    let ack = crate::packet::wire::decode_ack(&ack.body, CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.trace_id, trace(9));
    assert_eq!(ack.status, AckStatus::Admitted);
    let ack = frames_rx.recv().await.unwrap();
    assert_eq!(ack.kind, PacketKind::Ack);
    let ack = crate::packet::wire::decode_ack(&ack.body, CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.trace_id, trace(9));
    assert_eq!(ack.status, AckStatus::Failed);

    // Opening the gate surfaces exactly one typed interruption: the
    // buffered chunks drain, then the dropped sender ends the prefix as
    // interrupted — never a silent truncation.
    gate_tx.send(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
      if let Some(terminal) = consumer.terminal.lock().unwrap().take() {
        assert_eq!(terminal, Some(crate::ErrorKind::StreamInterrupted));
        break;
      }
      assert!(
        std::time::Instant::now() < deadline,
        "the gated consumer must finish after its gate opens"
      );
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  }

  /// The same bounded window with a stream that completes within it still
  /// delivers a clean terminal: exactly one completed end, no failure.
  #[tokio::test]
  async fn a_stream_within_the_window_receives_the_completed_terminal() {
    let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
    let consumer = Arc::new(GatedConsumer {
      gate: gate_rx,
      terminal: Arc::new(Mutex::new(None)),
    });
    let mut registry = ExtensionRegistry::new();
    registry.register_default().unwrap();
    registry
      .register_protocol(
        ProtocolDefinition::new(
          ProtocolTag::parse(PROTOCOL).unwrap(),
          FeatureTag::parse(FEATURE).unwrap(),
        ),
        Arc::clone(&consumer) as Arc<dyn PacketConsumer>,
      )
      .unwrap();
    let context = context(registry);
    let grant = grant();
    let (frames, mut frames_rx) = test_queue(16, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // A body that fits the window: the wire end queues as the terminal
    // even while the consumer stays gated shut.
    let mut messages = Vec::new();
    messages.push(open_frame(10));
    for sequence in 0..(INCOMING_STREAM_CHUNKS as u64) {
      messages.push(chunk_frame(10, sequence));
    }
    messages.push(Message {
      schema_id: BASE_SCHEMA_ID,
      kind_id: PacketKind::End.kind_id(),
      flags: 0,
      body: crate::packet::wire::encode_end(&crate::packet::wire::EndFrame {
        trace_id: trace(10),
        reason: crate::packet::wire::EndReason::Completed,
      })
      .unwrap(),
    });
    let mut source = FramesSource {
      messages: messages.into(),
    };

    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the read loop ends orderly");

    let ack = frames_rx.recv().await.unwrap();
    let ack = crate::packet::wire::decode_ack(&ack.body, CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.status, AckStatus::Admitted);

    gate_tx.send(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
      if let Some(terminal) = consumer.terminal.lock().unwrap().take() {
        assert_eq!(terminal, None, "a completed end is a clean terminal");
        break;
      }
      assert!(
        std::time::Instant::now() < deadline,
        "the gated consumer must finish after its gate opens"
      );
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  }

  /// Regression: a burst of wire slices above the
  /// window can reach the shared reader before the consumer task is first
  /// scheduled — the transport already buffered every slice. The bounded
  /// drain grace keeps that legitimate burst from being misread as
  /// overload: the live consumer frees slots inside its patience, the body
  /// arrives byte-exact, and the stream keeps its clean completed terminal.
  #[tokio::test]
  async fn a_burst_above_the_window_with_a_live_consumer_stays_byte_exact() {
    let consumer = Arc::new(DrainingConsumer::new(None));
    let context = session_for(Arc::clone(&consumer));
    let grant = grant();
    let (frames, mut frames_rx) = test_queue(16, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // Two slices above the window: the overflowing slice spends the
    // stream's one drain grace, which a live consumer answers immediately.
    let mut expected = Vec::new();
    let mut messages = Vec::new();
    messages.push(open_frame(11));
    for sequence in 0..(INCOMING_STREAM_CHUNKS as u64 + 2) {
      let bytes = [sequence as u8; 8];
      expected.extend_from_slice(&bytes);
      messages.push(chunk_frame_with(11, sequence, &bytes));
    }
    messages.push(end_frame(11));
    let mut source = FramesSource {
      messages: messages.into(),
    };

    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the read loop must not stall on a live consumer's burst");

    // Admission is the only acknowledgement: the burst never reached the
    // overload policy.
    let ack = frames_rx.recv().await.unwrap();
    assert_eq!(ack.kind, PacketKind::Ack);
    let ack = crate::packet::wire::decode_ack(&ack.body, CONTROL_CBOR_LIMITS).unwrap();
    assert_eq!(ack.trace_id, trace(11));
    assert_eq!(ack.status, AckStatus::Admitted);
    // A live consumer's burst must not surface a failed acknowledgement:
    // the read loop already queued every frame it will ever send, so an
    // empty queue after a short wait is the whole assertion.
    assert!(
      tokio::time::timeout(Duration::from_millis(100), frames_rx.recv())
        .await
        .is_err(),
      "a live consumer's burst must not surface a failed acknowledgement"
    );

    let (body, terminal) = consumer.body_of(&trace(11)).await;
    assert_eq!(terminal, None, "the burst must keep its completed terminal");
    assert_eq!(body, expected, "the burst must arrive byte-exact");
  }

  /// The other half of the policy: a consumer that stays stalled past its
  /// grace is still terminated. The shared reader spends one bounded
  /// patience per stalled stream, surfaces the typed failed acknowledgement
  /// and the consumer's single typed interruption, and keeps serving the
  /// session — a second stream opened after the overload completes
  /// byte-exact.
  #[tokio::test]
  async fn a_stalled_consumer_overloads_after_its_grace_without_holding_the_session() {
    let stalled = trace(20);
    let consumer = Arc::new(DrainingConsumer::new(Some(stalled.clone())));
    let context = session_for(Arc::clone(&consumer));
    let grant = grant();
    let (frames, mut frames_rx) = test_queue(16, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // The stalled stream fills its window and spends its grace on the next
    // slice; the live stream is opened after that overload and must be
    // served to completion by the same read loop.
    let mut live_expected = Vec::new();
    let mut messages = Vec::new();
    messages.push(open_frame(20));
    for sequence in 0..(INCOMING_STREAM_CHUNKS as u64 + 1) {
      messages.push(chunk_frame(20, sequence));
    }
    messages.push(open_frame(21));
    for sequence in 0..(INCOMING_STREAM_CHUNKS as u64) {
      let bytes = [sequence as u8; 8];
      live_expected.extend_from_slice(&bytes);
      messages.push(chunk_frame_with(21, sequence, &bytes));
    }
    messages.push(end_frame(21));
    let mut source = FramesSource {
      messages: messages.into(),
    };

    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the read loop must not stall on a consumer that never drains");

    // The stalled stream: admission, then the typed failure from the
    // overload policy once its grace expired. The live stream is still
    // admitted afterwards.
    let mut statuses = Vec::new();
    for _ in 0..3 {
      let ack = frames_rx.recv().await.unwrap();
      assert_eq!(ack.kind, PacketKind::Ack);
      let ack = crate::packet::wire::decode_ack(&ack.body, CONTROL_CBOR_LIMITS).unwrap();
      statuses.push((ack.trace_id, ack.status));
    }
    assert_eq!(
      statuses,
      vec![
        (stalled.clone(), AckStatus::Admitted),
        (stalled, AckStatus::Failed),
        (trace(21), AckStatus::Admitted),
      ],
      "the stalled stream is overloaded and the live stream is still admitted"
    );

    let (body, terminal) = consumer.body_of(&trace(21)).await;
    assert_eq!(terminal, None, "the live stream completes cleanly");
    assert_eq!(body, live_expected, "the live body arrives byte-exact");
    assert!(
      consumer
        .bodies
        .lock()
        .unwrap()
        .iter()
        .all(|(recorded, _)| recorded != &trace(20)),
      "the stalled consumer never completed a body"
    );
  }
}

#[cfg(test)]
mod consumer_lifecycle_tests {
  use std::{
    sync::{Arc, Mutex},
    time::Duration,
  };

  use futures_util::{StreamExt as _, future::BoxFuture};

  use super::{node, test_context, trace};
  use crate::{
    ExtensionRegistry, FeatureTag, IncomingStream, ProtocolTag, TraceId,
    extension_registry::{PacketConsumer, ProtocolDefinition},
    packet::wire::{AckStatus, OpenFrame},
    protocol::{
      CONTROL_CBOR_LIMITS,
      wire::{BASE_SCHEMA_ID, PacketKind},
    },
    routing::forward::SessionIdentity,
    session::{
      inbound::{FrameSource, SessionGrant, read_loop},
      pending::PendingAdmissions,
      stream::{SessionPacketContext, test_queue},
    },
    transport::{Received, connection::Message},
  };

  const FEATURE: &str = "radiata.woooo.tech/features/data-messages";
  const PROTOCOL: &str = "example.org/protocols/test-echo";

  /// The authenticated grant of one test session: a distinct incarnation
  /// per `peer`, carrying the feature set a real handshake would negotiate
  /// for the test protocol.
  fn grant(peer: u8, incarnation: u32) -> SessionGrant {
    SessionGrant::new(
      SessionIdentity::new(
        node(peer),
        crate::SessionId::parse(&format!("session-{incarnation:021}")).unwrap(),
      ),
      vec![FeatureTag::parse(FEATURE).unwrap()],
    )
  }

  /// A consumer that waits for its level-triggered gate before finishing —
  /// the post-wire-EOF work the lifecycle budget must carry — and records
  /// every trace it accepted.
  #[derive(Debug)]
  struct GatedConsumer {
    gate: tokio::sync::watch::Receiver<bool>,
    accepted: Arc<Mutex<Vec<TraceId>>>,
  }

  impl PacketConsumer for GatedConsumer {
    fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, crate::Result<()>> {
      let mut gate = self.gate.clone();
      let trace_id = packet.trace_id().clone();
      let accepted = Arc::clone(&self.accepted);
      Box::pin(async move {
        while !*gate.borrow_and_update() {
          let _ = gate.changed().await;
        }
        // Drain whatever terminal the body carries; the lifecycle budget
        // observes the accept future, not the body itself.
        let mut body = packet.body();
        while body.next().await.is_some() {}
        accepted.lock().unwrap().push(trace_id);
        Ok(())
      })
    }
  }

  /// Yields the queued wire messages in order, then ends the session
  /// orderly.
  struct FramesSource {
    messages: std::collections::VecDeque<Message>,
  }

  impl FrameSource for FramesSource {
    fn receive_event(&mut self) -> BoxFuture<'_, crate::Result<Option<Received>>> {
      let message = self.messages.pop_front();
      Box::pin(async move { Ok(message.map(Received::Message)) })
    }
  }

  fn open_message(seed: u32, peer: u8) -> Message {
    Message {
      schema_id: BASE_SCHEMA_ID,
      kind_id: PacketKind::Open.kind_id(),
      flags: 0,
      body: crate::packet::wire::encode_open(&OpenFrame {
        trace_id: trace(seed),
        source: node(peer),
        destination: node(1),
        protocol: ProtocolTag::parse(PROTOCOL).unwrap(),
        metadata: crate::StreamMetadata::new(),
        route: None,
      })
      .unwrap(),
    }
  }

  fn end_message(seed: u32) -> Message {
    Message {
      schema_id: BASE_SCHEMA_ID,
      kind_id: PacketKind::End.kind_id(),
      flags: 0,
      body: crate::packet::wire::encode_end(&crate::packet::wire::EndFrame {
        trace_id: trace(seed),
        reason: crate::packet::wire::EndReason::Completed,
      })
      .unwrap(),
    }
  }

  /// The node context of a session-serving runtime: the node-wide consumer
  /// budget shrunk to `budget` so the lifecycle is observable without the
  /// production-scale population.
  fn context(consumer: Arc<GatedConsumer>, budget: usize) -> Arc<SessionPacketContext> {
    let mut registry = ExtensionRegistry::new();
    registry.register_default().unwrap();
    registry
      .register_protocol(
        ProtocolDefinition::new(
          ProtocolTag::parse(PROTOCOL).unwrap(),
          FeatureTag::parse(FEATURE).unwrap(),
        ),
        consumer as Arc<dyn PacketConsumer>,
      )
      .unwrap();
    Arc::new(
      test_context(
        registry,
        Arc::new(crate::time::HostWallClock),
        Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        None,
      )
      .with_live_consumer_budget(budget),
    )
  }

  /// Waits until every gated consumer of `count` finished, bounded by a
  /// wall-clock deadline.
  async fn consumers_finish(consumer: &GatedConsumer, count: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
      if consumer.accepted.lock().unwrap().len() >= count {
        return;
      }
      assert!(
        std::time::Instant::now() < deadline,
        "the gated consumers must finish after their gate opens"
      );
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
  }

  /// Regression: the wire stream's end frees the per-session
  /// table slot, but the consumer's lifecycle slot is held until the accept
  /// future finishes — the post-EOF work is legitimate and is never
  /// cancelled at the wire end. Repeated complete streams accumulate their
  /// reservations, and the budget releases each one exactly when its
  /// consumer terminates.
  #[tokio::test]
  async fn complete_wire_streams_keep_their_consumer_slots_after_eof() {
    let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
    let consumer = Arc::new(GatedConsumer {
      gate: gate_rx,
      accepted: Arc::new(Mutex::new(Vec::new())),
    });
    let context = context(Arc::clone(&consumer), 8);
    let grant = grant(2, 1);
    let (frames, _frames_rx) = test_queue(16, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // Four complete wire streams: every End frees the table entry, so the
    // per-session bound would admit a fifth — the node budget must still
    // see the four live consumers.
    let mut messages = Vec::new();
    for seed in 1_u32..=4 {
      messages.push(open_message(seed, 2));
      messages.push(end_message(seed));
    }
    let mut source = FramesSource {
      messages: messages.into(),
    };

    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the gated consumers never block the read loop");

    assert_eq!(
      context.live_consumers.in_use(),
      4,
      "every post-EOF consumer still holds its lifecycle slot"
    );

    gate_tx.send(true).unwrap();
    consumers_finish(&consumer, 4).await;
    assert_eq!(
      context.live_consumers.in_use(),
      0,
      "a finished consumer releases its lifecycle slot"
    );
  }

  /// Regression: past the node-wide budget, a new open is
  /// refused with the typed `Overloaded` backpressure — never admitted
  /// beyond the running-consumer bound — and no consumer runs for the
  /// refused stream. The slots return once the stalled consumers finish.
  #[tokio::test]
  async fn an_exhausted_consumer_budget_refuses_new_opens_with_typed_overload() {
    let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
    let consumer = Arc::new(GatedConsumer {
      gate: gate_rx,
      accepted: Arc::new(Mutex::new(Vec::new())),
    });
    let context = context(Arc::clone(&consumer), 2);
    let grant = grant(2, 1);
    let (frames, mut frames_rx) = test_queue(16, 1 << 20);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // Two complete wire streams whose consumers stay parked past EOF; the
    // third open finds the node budget exhausted even though the per-session
    // table is empty again.
    let mut messages = Vec::new();
    for seed in 1_u32..=2 {
      messages.push(open_message(seed, 2));
      messages.push(end_message(seed));
    }
    messages.push(open_message(3, 2));
    messages.push(end_message(3));
    let mut source = FramesSource {
      messages: messages.into(),
    };

    tokio::time::timeout(
      Duration::from_secs(10),
      read_loop(
        &mut source,
        &grant,
        &context,
        &frames,
        &pending_acks,
        &last_activity,
      ),
    )
    .await
    .expect("the gated consumers never block the read loop");

    // Every outcome is on the wire: dropping the session queue's last
    // sender ends the ack stream so the statuses collect exhaustively
    // instead of waiting on a channel that never closes.
    drop(frames);
    let mut statuses = Vec::new();
    while let Some(frame) = frames_rx.recv().await {
      let ack = crate::packet::wire::decode_ack(&frame.body, CONTROL_CBOR_LIMITS).unwrap();
      statuses.push((ack.trace_id, ack.status));
    }
    assert_eq!(
      statuses,
      vec![
        (trace(1), AckStatus::Admitted),
        (trace(2), AckStatus::Admitted),
        (trace(3), AckStatus::Overloaded),
      ],
      "the exhausted budget is typed backpressure, not silent growth"
    );
    assert_eq!(context.live_consumers.in_use(), 2);

    gate_tx.send(true).unwrap();
    consumers_finish(&consumer, 2).await;
    assert_eq!(context.live_consumers.in_use(), 0);
  }

  /// Regression: a retired session hands its consumers to the
  /// node-scoped drain, and their lifecycle reservations survive that
  /// transfer — and across sessions: the next session's admissions count
  /// against the same node-wide budget, and every reservation returns when
  /// the drained consumers finish.
  #[tokio::test]
  async fn retired_sessions_keep_their_reservations_through_the_node_drain() {
    let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
    let consumer = Arc::new(GatedConsumer {
      gate: gate_rx,
      accepted: Arc::new(Mutex::new(Vec::new())),
    });
    let context = context(Arc::clone(&consumer), 8);
    let pending_acks = PendingAdmissions::new(crate::session::stream::MAX_PENDING_ADMISSIONS);
    let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(1));

    // Session A: one complete stream, then the session ends orderly — the
    // consumer keeps running under the node drain.
    let (frames_a, _frames_a_rx) = test_queue(16, 1 << 20);
    let mut source = FramesSource {
      messages: vec![open_message(1, 2), end_message(1)].into(),
    };
    let grant_a = grant(2, 1);
    read_loop(
      &mut source,
      &grant_a,
      &context,
      &frames_a,
      &pending_acks,
      &last_activity,
    )
    .await;
    assert_eq!(
      context.live_consumers.in_use(),
      1,
      "the retired session's consumer still holds its slot through the drain"
    );

    // Session B (a different peer incarnation) counts against the same
    // node-wide budget while A's consumer is still running.
    let (frames_b, _frames_b_rx) = test_queue(16, 1 << 20);
    let mut source = FramesSource {
      messages: vec![open_message(2, 3), end_message(2)].into(),
    };
    let grant_b = grant(3, 7);
    read_loop(
      &mut source,
      &grant_b,
      &context,
      &frames_b,
      &pending_acks,
      &last_activity,
    )
    .await;
    assert_eq!(
      context.live_consumers.in_use(),
      2,
      "the node budget accumulates across retired sessions"
    );
    assert_eq!(
      context.task_drains.lock().unwrap().len(),
      2,
      "each retired session handed its consumers to the node drain"
    );

    // The drained consumers finish and release their reservations.
    gate_tx.send(true).unwrap();
    consumers_finish(&consumer, 2).await;
    let drains: Vec<_> = context.task_drains.lock().unwrap().drain(..).collect();
    for drain in drains {
      drain.await.unwrap();
    }
    assert_eq!(
      context.live_consumers.in_use(),
      0,
      "every reservation returns when the drained consumers finish"
    );
  }
}
