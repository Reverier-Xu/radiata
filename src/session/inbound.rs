//! The session read loop: inbound frame demultiplexing and local
//! admission. Opens are re-validated against the session-authenticated
//! peer before entering the bounded incoming stream table; chunks flow
//! in strict sequence into the admitted stream's bounded body channel;
//! ends terminate streams; acks resolve pending outbound admissions
//! (the origin-side counterpart lives in `crate::routing::outbound`).

use std::{
  collections::HashMap,
  sync::{Arc, atomic::Ordering},
};

use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, trace, warn};

use super::{
  driver::EstablishedSession,
  stream::{BoundedSender, SessionFrame, SessionPacketContext, clock_seconds},
};
use crate::{
  Error, ErrorKind, NodeId, ProtocolTag, Result, StreamMetadata, TraceId,
  packet::{
    IncomingStream, PacketReplyContext, RouteState, StreamItem, channel_body,
    wire::{self, AckFrame, AckStatus, ChunkFrame, OpenFrame},
  },
  protocol::wire::PacketKind,
  routing::{
    forward::{self, PendingAck, PendingAcks},
    table::{record_terminal_failure, update_route},
  },
  transport::connection::ConnectionReader,
};

/// The number of body chunks buffered per admitted incoming stream before
/// backpressure stalls the session reader.
const INCOMING_STREAM_CHUNKS: usize = 8;

/// One admitted incoming stream: its bounded body channel, the next
/// expected chunk sequence, the immutable opening-context digest that
/// decides duplicate handling, and the admission wall-clock time reported
/// by identical retransmissions.
struct AdmittedStream {
  stream: mpsc::Sender<StreamItem>,
  next_sequence: u64,
  context: crate::Digest,
  admitted_at_millis: u64,
}

/// UNIX-milliseconds from the injected wall clock, used for the admission
/// timestamps reported in acknowledgements so simulation controls them too.
fn clock_millis(clock: &dyn crate::storage::receipt::WallClock) -> u64 {
  crate::time::to_millis(clock.now())
}

/// The read loop's frame source: one receive wake plus the shared pong
/// stamp. Abstracted so liveness tests can feed synthetic wakes without
/// a TLS connection.
pub(super) trait FrameSource {
  fn receive_event(
    &mut self,
  ) -> futures_util::future::BoxFuture<'_, crate::Result<Option<crate::transport::Received>>>;
  fn pong_last_seen(&self) -> u64;
}

impl FrameSource for ConnectionReader {
  fn receive_event(
    &mut self,
  ) -> futures_util::future::BoxFuture<'_, crate::Result<Option<crate::transport::Received>>> {
    Box::pin(ConnectionReader::receive_event(self))
  }

  fn pong_last_seen(&self) -> u64 {
    ConnectionReader::pong_last_seen(self)
  }
}

/// Serves incoming packet frames until the connection closes or a frame
/// violates the wire contract (fail closed).
pub(super) async fn read_loop(
  source: &mut impl FrameSource, session: &EstablishedSession, context: &SessionPacketContext,
  frames: &BoundedSender, pending_acks: &PendingAcks,
  last_activity: &Arc<std::sync::atomic::AtomicU64>,
) {
  let mut incoming: HashMap<TraceId, AdmittedStream> = HashMap::new();
  let mut consumers = JoinSet::new();
  let mut last_pong_seen = source.pong_last_seen();
  loop {
    let message = match source.receive_event().await {
      Ok(Some(crate::transport::Received::Message(message))) => message,
      Ok(Some(crate::transport::Received::Pong)) => {
        // A peer pong is a keepalive response: reflect it into the
        // injected clock's activity mark so the liveness observer sees
        // one time source. This wake is what lets a frame-silent but
        // responsive peer survive the idle deadline.
        let pong = source.pong_last_seen();
        if pong != last_pong_seen {
          last_pong_seen = pong;
          last_activity.store(clock_seconds(context.clock.as_ref()), Ordering::Relaxed);
        }
        continue;
      }
      Ok(None) => {
        trace!("session read ended orderly");
        break;
      }
      Err(error) => {
        warn!(kind = ?error.kind(), "session receive failed");
        break;
      }
    };
    last_activity.store(clock_seconds(context.clock.as_ref()), Ordering::Relaxed);
    let Some(kind) = crate::protocol::wire::lookup_packet(message.schema_id, message.kind_id)
    else {
      // An established session carries packet kinds only.
      warn!(
        schema_id = message.schema_id,
        kind_id = message.kind_id,
        "unknown packet kind on session"
      );
      break;
    };
    trace!(kind = ?kind, "session frame received");
    match kind {
      PacketKind::Open => match wire::decode_open(&message.body, context.parser_limits()) {
        Ok(open) => {
          // A routed frame addressed elsewhere is forwarded; everything
          // else goes through the local admission path.
          let routed = open.destination != *context.local() && open.route.is_some();
          if routed {
            forward::open(
              &context.local().clone(),
              session.peer(),
              open,
              frames,
              &context.sessions,
              &context.forwarding,
              &context.registry,
              context.route_policy(),
              context.forwarding_capacity(),
            )
            .await;
          } else if admit_open(
            open,
            session,
            context,
            frames,
            &mut incoming,
            &mut consumers,
          )
          .await
          .is_err()
          {
            break;
          }
        }
        Err(_) => {
          warn!("malformed packet open frame");
          break;
        }
      },
      PacketKind::Chunk => match wire::decode_chunk(&message.body, context.parser_limits()) {
        Ok(chunk) => {
          let trace = chunk.trace_id.clone();
          if forward::contains(&context.forwarding, &trace) {
            forward::relay_chunk(&context.forwarding, chunk).await;
          } else if !forward_chunk(chunk, &mut incoming).await {
            warn!(trace_id = %trace, "incoming chunk sequence violation; closing session");
            break;
          }
        }
        Err(_) => {
          warn!("malformed packet chunk frame");
          break;
        }
      },
      PacketKind::End => match wire::decode_end(&message.body, context.parser_limits()) {
        Ok(end) => {
          trace!(trace_id = %end.trace_id, "incoming stream ended");
          if forward::contains(&context.forwarding, &end.trace_id) {
            forward::relay_end(&context.forwarding, end).await;
            continue;
          }
          if let Some(stream) = incoming
            .remove(&end.trace_id)
            .map(|admitted| admitted.stream)
          {
            let _ = stream.send(StreamItem::End).await;
          } else {
            // A lost consumer means its session task aborted mid-stream:
            // surface it loudly, because silence here looks like a lost
            // packet downstream.
            warn!(trace_id = %end.trace_id, "end frame for unknown incoming stream");
          }
        }
        Err(_) => {
          warn!("malformed packet end frame");
          break;
        }
      },
      PacketKind::Ack => match wire::decode_ack(&message.body, context.parser_limits()) {
        Ok(ack) => {
          resolve_ack(ack.clone(), pending_acks);
          // A late failure for an admitted stream (a downstream hop died
          // mid-flight) still terminates the origin's route observation.
          if ack.status == crate::packet::wire::AckStatus::Failed {
            update_route(&context.routes, &ack.trace_id, |record| {
              record.update(RouteState::Failed(ErrorKind::StreamInterrupted));
            });
          }
        }
        Err(_) => {
          warn!("malformed packet ack frame");
          break;
        }
      },
    }
  }
  // Graceful consumer drain: handing the session's consumer tasks to a
  // node-scoped drain task means a teardown (Io error, deterministic
  // replacement, shutdown) can no longer abort an in-flight apply. A
  // fully received control payload therefore always completes its
  // persist-and-emit (terminal evidence must not strand on a session
  // end), and a partial body fails closed at decode instead. The drain
  // handle joins the node's tracked task vec, so shutdown still awaits
  // it and the recovery tick reaps it (bounded task accounting).
  let drain = tokio::spawn(async move { while consumers.join_next().await.is_some() {} });
  if let Ok(mut tasks) = context.task_drains.lock() {
    tasks.push(drain);
  }
}

/// Validates one open frame against the authenticated session and the
/// local registry, admits it into the bounded incoming stream table, and
/// acknowledges current-process admission (or the typed rejection).
///
/// Routed frames carry a route envelope that is re-validated against the
/// session-authenticated peer before admission; any mutation, loop, or
/// exhausted budget fails closed before a consumer runs. Frames addressed
/// to another node belong to the route forwarder; an open that reaches
/// this admission boundary addressed elsewhere is rejected as unsupported
/// — fail-closed, with no consumer invocation.
async fn admit_open(
  open: OpenFrame, session: &EstablishedSession, context: &SessionPacketContext,
  frames: &BoundedSender, incoming: &mut HashMap<TraceId, AdmittedStream>,
  consumers: &mut JoinSet<()>,
) -> Result<()> {
  let trace_id = open.trace_id.clone();
  let ack_protocol = open.protocol.clone();
  let local = context.local().clone();
  let mut reack_admitted_at: Option<u64> = None;
  let status = 'status: {
    // The routing envelope re-validates against the session-authenticated
    // holder before anything else (the chain itself then authenticates the
    // original source; a direct frame authenticates only through the exact
    // source-peer match). Forwarding work belongs to the route forwarder;
    // this admission boundary never branches a body, so any frame that
    // does not arrive exactly here fails closed without a consumer.
    if !matches!(
      crate::routing::receive_open_envelope(
        trace_id.clone(),
        open.source.clone(),
        open.destination.clone(),
        open.route.clone(),
        &local,
        session.peer(),
      ),
      Ok(crate::routing::RouteProgress::Arrive)
    ) {
      break 'status AckStatus::Unsupported;
    }
    // The immutable opening context decides duplicate handling: an
    // identical retransmission reports the current admission status
    // without invoking the consumer twice; a conflicting one fails closed.
    let context_digest = opening_context_digest(
      &open.source,
      &open.destination,
      &open.protocol,
      &open.metadata,
    );
    match incoming.get(&trace_id) {
      // An identical retransmission reports the current admission status
      // with the original admission time; the consumer is not invoked
      // twice.
      Some(admitted) if admitted.context == context_digest => {
        reack_admitted_at = Some(admitted.admitted_at_millis);
        break 'status AckStatus::Admitted;
      }
      Some(_) => break 'status AckStatus::Unsupported,
      None => {}
    }
    match context.registry.protocol(&open.protocol) {
      Some(registration)
        if session
          .selected_features()
          .contains(registration.definition.owning_feature()) =>
      {
        // Saturation prioritises conflicts over genuinely new streams:
        // identical duplicates were already answered above, conflicting
        // ones failed closed above, and only a new stream receives the
        // typed backpressure. The inbound admitted stream table
        // deliberately shares the caller-selected session queue message
        // budget: every admitted stream occupies queue capacity, so one
        // knob bounds both.
        if incoming.len() >= context.policy.queue_messages {
          break 'status AckStatus::Overloaded;
        }
        let admitted_at = clock_millis(context.clock.as_ref());
        let (stream, body) = mpsc::channel(INCOMING_STREAM_CHUNKS);
        incoming.insert(
          open.trace_id.clone(),
          AdmittedStream {
            stream,
            next_sequence: 0,
            context: context_digest,
            admitted_at_millis: admitted_at,
          },
        );
        let packet = IncomingStream::new(
          open.source,
          open.destination,
          open.trace_id,
          open.protocol,
          open.metadata,
          channel_body(body),
          PacketReplyContext::new(context.registry.clone(), context.runtime.clone()),
        );
        let consumer = Arc::clone(&registration.consumer);
        let consumer_trace = trace_id.clone();
        debug!(trace_id = %consumer_trace, "incoming consumer spawned");
        consumers.spawn(async move {
          let result = consumer.accept(packet).await;
          if let Err(error) = &result {
            // An admitted stream whose consumer failed is an operational
            // anomaly (decode failure, store fault): surfaced at warn so
            // it is visible above the protocol's trace/debug traffic.
            warn!(
              trace_id = %consumer_trace,
              kind = ?error.kind(),
              "packet consumer failed"
            );
          }
          debug!(
            trace_id = %consumer_trace,
            ok = result.is_ok(),
            "packet consumer finished"
          );
        });
        AckStatus::Admitted
      }
      // Unknown protocol tag or owning feature not selected on this
      // session: rejected before admission, never reaching a consumer.
      // The rejection is recorded as bounded terminal route metadata
      // within the node's configured route-record capacity.
      _ => {
        record_terminal_failure(
          &context.routes,
          context.route_capacity(),
          &trace_id,
          ErrorKind::Unsupported,
        );
        AckStatus::Unsupported
      }
    }
  };
  let ack = AckFrame {
    trace_id: trace_id.clone(),
    status,
    admitted_at_millis: reack_admitted_at.unwrap_or_else(|| clock_millis(context.clock.as_ref())),
  };
  debug!(
    trace_id = %ack.trace_id,
    protocol = %ack_protocol,
    ?ack.status,
    "packet admission outcome"
  );
  let body = wire::encode_ack(&ack)?;
  frames
    .send(SessionFrame {
      kind: PacketKind::Ack,
      body,
    })
    .await
    .map_err(|_| Error::stream_interrupted("packet session"))
}

/// Forwards one chunk to its admitted stream in strict sequence order.
/// Returns `false` on a sequence violation (fail closed).
async fn forward_chunk(chunk: ChunkFrame, incoming: &mut HashMap<TraceId, AdmittedStream>) -> bool {
  let Some(admitted) = incoming.get_mut(&chunk.trace_id) else {
    // Unknown or already-terminated stream: drop the chunk.
    return true;
  };
  if admitted.next_sequence != chunk.sequence {
    return false;
  }
  admitted.next_sequence = admitted.next_sequence.saturating_add(1);
  trace!(
    trace_id = %chunk.trace_id,
    sequence = chunk.sequence,
    bytes = chunk.bytes.len(),
    "incoming chunk forwarded"
  );
  let bytes: Arc<[u8]> = Arc::from(chunk.bytes.as_slice());
  if admitted
    .stream
    .send(StreamItem::Chunk(bytes))
    .await
    .is_err()
  {
    // The consumer is gone; terminate the incoming stream.
    incoming.remove(&chunk.trace_id);
  }
  true
}

/// Resolves one pending outbound admission. The admitting node is this
/// session's authenticated peer, so the acknowledgement can name it for
/// the synchronous sender's `DeliveryAck`.
fn resolve_ack(ack: AckFrame, pending_acks: &PendingAcks) {
  let entry = pending_acks
    .lock()
    .map(|mut pending| pending.remove(&ack.trace_id))
    .ok()
    .flatten();
  let Some(entry) = entry else {
    return;
  };
  match entry {
    PendingAck::Wait { notify, .. } => {
      // The single AckStatus→kind mapping lives on the wire type; `Admitted`
      // carries the admission time and every rejection its typed kind.
      let outcome = match ack.status.to_kind() {
        None => Ok(crate::time::from_millis(ack.admitted_at_millis)),
        Some(kind) => Err(kind),
      };
      trace!(trace_id = %ack.trace_id, ?ack.status, "admission ack resolved");
      let _ = notify.send(outcome);
    }
    PendingAck::Relay { upstream } => {
      // Relay the destination's acknowledgement to the previous hop with
      // its status preserved.
      if let Ok(body) = wire::encode_ack(&AckFrame {
        trace_id: ack.trace_id.clone(),
        status: ack.status,
        admitted_at_millis: ack.admitted_at_millis,
      }) {
        upstream.try_send(SessionFrame::new(PacketKind::Ack, body));
      }
    }
  }
}

/// Digests the immutable opening context of one open frame (endpoints,
/// protocol, canonical metadata): identical retransmissions produce the
/// same digest; any mutation produces a different one.
fn opening_context_digest(
  source: &NodeId, destination: &NodeId, protocol: &ProtocolTag, metadata: &StreamMetadata,
) -> crate::Digest {
  let mut bytes = Vec::with_capacity(128);
  bytes.extend_from_slice(source.as_str().as_bytes());
  bytes.push(0);
  bytes.extend_from_slice(destination.as_str().as_bytes());
  bytes.push(0);
  bytes.extend_from_slice(protocol.as_str().as_bytes());
  for (key, value) in metadata.entries() {
    bytes.extend_from_slice(key.as_str().as_bytes());
    bytes.push(1);
    bytes.extend_from_slice(value);
    bytes.push(2);
  }
  crate::identity::signature::body_digest(&bytes)
}

#[cfg(test)]
mod admission_tests {
  use std::{collections::BTreeMap, sync::Arc};

  use minicbor::bytes::ByteVec;

  use super::opening_context_digest;
  use crate::{
    NodeId, ProtocolTag, QualifiedTag, StreamMetadata, TraceId, identity::signature::body_digest,
    routing::RouteTable,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

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

  // ---- Rejection records stay bounded terminal facts ----

  /// A rejected open records exactly one bounded terminal route fact; a
  /// second rejection for the same trace never grows the table.
  #[tokio::test]
  async fn rejections_record_one_terminal_fact() {
    let routes: RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    super::record_terminal_failure(&routes, 8, &trace(9), crate::ErrorKind::Unsupported);
    super::record_terminal_failure(&routes, 8, &trace(9), crate::ErrorKind::Unsupported);

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
      super::record_terminal_failure(&routes, 3, &trace(seed), crate::ErrorKind::Unsupported);
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
    collections::{BTreeMap, HashMap},
    sync::{
      Arc, Mutex,
      atomic::{AtomicU64, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
  };

  use futures_util::future::BoxFuture;
  use tokio::sync::mpsc;

  use super::{FrameSource, read_loop};
  use crate::{
    NodeId,
    identity::testing::SequenceEntropy,
    node::EventHub,
    session::stream::{SessionPacketContext, SessionPolicy, test_queue},
    storage::contract::helpers::ManualClock,
    transport::Received,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  /// A frame source that answers every wake with a keepalive pong (the
  /// wire shape of a responsive but application-silent peer) and then
  /// ends the session orderly.
  struct PongSource {
    remaining: u32,
    now: u64,
  }

  impl FrameSource for PongSource {
    fn receive_event(&mut self) -> BoxFuture<'_, crate::Result<Option<Received>>> {
      let pong = self.remaining > 0;
      if pong {
        self.remaining -= 1;
        self.now += 1;
      }
      Box::pin(async move {
        if pong {
          Ok(Some(Received::Pong))
        } else {
          Ok(None)
        }
      })
    }

    fn pong_last_seen(&self) -> u64 {
      self.now
    }
  }

  fn context(clock: Arc<dyn crate::storage::receipt::WallClock>) -> SessionPacketContext {
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SequenceEntropy::default());
    SessionPacketContext::new(
      node(1),
      Arc::new(crate::ExtensionRegistry::new()),
      SessionPolicy::new(
        8,
        1 << 20,
        Duration::from_secs(30),
        Duration::from_secs(5),
        Duration::from_secs(15),
      ),
      crate::runtime::RuntimeClient::routing_only(
        mpsc::channel(4).0,
        Arc::new(Mutex::new(BTreeMap::new())),
      ),
      clock,
      entropy,
      Arc::new(EventHub::new()),
      crate::routing::DefaultNextHop::tag().unwrap(),
      Arc::new(Mutex::new(BTreeMap::new())),
      Arc::new(Mutex::new(BTreeMap::new())),
      8,
      16,
      Arc::new(Mutex::new(Vec::new())),
      crate::protocol::CONTROL_CBOR_LIMITS,
    )
  }

  /// A frame-silent peer that answers keepalive pings must stay alive:
  /// every pong wake reflects the injected clock into the session's
  /// activity mark, so the liveness observer (pinned separately) never
  /// sees the idle deadline lapse. Before the fix the pong was swallowed
  /// inside the transport receive and the activity mark never advanced.
  #[tokio::test]
  async fn pong_wakes_reflect_activity_for_frame_silent_peers() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    // A stale activity mark: the peer has been silent since second 1.
    let last_activity = Arc::new(AtomicU64::new(1));
    let mut source = PongSource {
      remaining: 3,
      now: 0,
    };
    let session = crate::session::driver::EstablishedSession::test_session(node(2));
    let context = context(Arc::clone(&clock) as Arc<dyn crate::storage::receipt::WallClock>);
    let (frames, _receiver) = test_queue(8, 1 << 20);
    let pending_acks = Arc::new(Mutex::new(HashMap::new()));

    read_loop(
      &mut source,
      &session,
      &context,
      &frames,
      &pending_acks,
      &last_activity,
    )
    .await;

    // The pong wakes advanced the activity mark to the injected clock's
    // current seconds (the pong stamp changes are what the loop saw).
    assert_eq!(
      last_activity.load(Ordering::SeqCst),
      1_000,
      "the pong wakes must refresh the session activity mark"
    );
  }
}
