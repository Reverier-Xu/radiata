//! The session read loop: inbound frame demultiplexing and local
//! admission. Opens are re-validated against the session-authenticated
//! peer before entering the bounded incoming stream table; chunks flow
//! in strict sequence into the admitted stream's bounded body channel;
//! ends terminate streams; acks resolve pending outbound admissions
//! (the origin-side counterpart lives in `crate::routing::outbound`).
//! The origin-side delivery legs live here too: [`DeliveryLeg`] is the
//! outbound pump's next hop — a live session's frame queue, or the node
//! itself admitting and consuming the stream in-process — so local
//! self-delivery is one hop of the same pump, sharing the admission body
//! and the pending-admission model, with only the `deliver_*` trio
//! diverging.

use std::{
  collections::HashMap,
  sync::{Arc, Mutex, atomic::Ordering},
  time::Duration,
};

use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, trace, warn};

use super::{
  driver::EstablishedSession,
  stream::{BoundedSender, SessionEntry, SessionFrame, SessionPacketContext, clock_seconds},
};
use crate::{
  Error, ErrorKind, NodeId, ProtocolTag, Result, StreamMetadata, TraceId,
  packet::{
    IncomingStream, PacketReplyContext, StreamItem, channel_body,
    wire::{self, AckFrame, AckStatus, ChunkFrame, EndFrame, EndReason, OpenFrame},
  },
  protocol::wire::PacketKind,
  routing::{
    forward::{self, PendingAck, SessionIdentity},
    table::record_terminal_failure,
  },
  session::pending::PendingAdmissions,
  transport::connection::ConnectionReader,
};

/// The number of body chunks buffered per admitted incoming stream: the
/// stream's whole flow-control window. A consumer that lets it fill stalls
/// nothing but its own stream — the session reader applies the explicit
/// overload policy in [`deliver_chunk_local`] instead.
const INCOMING_STREAM_CHUNKS: usize = 8;

/// The terminal slot reserved on top of the chunk window: a completed or
/// interrupted end always queues without waiting for the consumer, so a
/// body that fits its window always surfaces its exact terminal — and the
/// bounded channel still never grows beyond window plus terminal.
const INCOMING_STREAM_TERMINAL_SLOTS: usize = 1;

/// How long the shared session reader waits for a live consumer to free a
/// slot in its chunk window before it applies the overload policy, on the
/// same scale as the session queue's `WAIT_BACKSTOP`. A burst above the
/// window can reach the reader before the consumer task is first scheduled
/// — the frames were already in the connection's receive buffer — so
/// terminating on the spot would misread a healthy consumer as a stalled
/// one. Each admitted stream spends this grace once: a consumer that frees
/// a slot proves it is alive and the burst continues, while a consumer that
/// never drains costs the shared reader one bounded patience and then ends
/// through the explicit overload policy.
const INCOMING_STREAM_DRAIN_PATIENCE: Duration = Duration::from_millis(50);

/// The authenticated grant one established session confers on its read
/// loop: the exact session incarnation (the identity forwarded hops bind
/// their ownership to), the peer, and the negotiated feature set that gates
/// packet-protocol admission.
pub(super) struct SessionGrant {
  identity: SessionIdentity,
  selected_features: Vec<crate::FeatureTag>,
}

impl SessionGrant {
  pub(super) const fn new(
    identity: SessionIdentity, selected_features: Vec<crate::FeatureTag>,
  ) -> Self {
    Self {
      identity,
      selected_features,
    }
  }

  /// The grant one authenticated session confers on its read loop: the
  /// peer identity, the negotiated feature selection, and the exact
  /// incarnation the session table registered.
  pub(super) fn for_session(session: &EstablishedSession, identity: SessionIdentity) -> Self {
    Self::new(identity, session.selected_features().to_vec())
  }

  pub(super) const fn identity(&self) -> &SessionIdentity {
    &self.identity
  }

  pub(super) const fn peer(&self) -> &NodeId {
    self.identity.peer()
  }

  pub(super) fn selected_features(&self) -> &[crate::FeatureTag] {
    &self.selected_features
  }
}

/// One admitted incoming stream: its bounded body channel, the next
/// expected chunk sequence, the immutable opening-context digest that
/// decides duplicate handling, and the admission wall-clock time reported
/// by identical retransmissions. The entry deliberately holds no consumer
/// budget: the consumer task owns its reserved slot for its whole life,
/// which outlives this table entry's wire stream.
struct AdmittedStream {
  stream: mpsc::Sender<StreamItem>,
  next_sequence: u64,
  context: crate::Digest,
  admitted_at_millis: i64,
  /// Whether this stream already spent its single bounded drain grace. One
  /// grace per stream is what keeps the shared reader's stall bounded by
  /// [`INCOMING_STREAM_DRAIN_PATIENCE`] independently of the stream's
  /// length: after it, a full window is overload, not backpressure.
  drain_grace_spent: bool,
}

/// UNIX-milliseconds from the injected wall clock, used for the admission
/// timestamps reported in acknowledgements so simulation controls them too.
fn clock_millis(clock: &dyn crate::time::WallClock) -> i64 {
  crate::time::to_millis(clock.now())
}

/// The read loop's frame source: one receive wake. Abstracted so
/// liveness tests can feed synthetic wakes without a TLS connection.
pub(super) trait FrameSource {
  fn receive_event(
    &mut self,
  ) -> futures_util::future::BoxFuture<'_, crate::Result<Option<crate::transport::Received>>>;
}

impl FrameSource for ConnectionReader {
  fn receive_event(
    &mut self,
  ) -> futures_util::future::BoxFuture<'_, crate::Result<Option<crate::transport::Received>>> {
    Box::pin(ConnectionReader::receive_event(self))
  }
}

/// Owns the read loop's consumer `JoinSet` and hands it to a node-scoped
/// drain task when dropped — on the orderly exit AND the cancellation
/// path. In this tokio version, dropping a `JoinSet` ABORTS its
/// children, so a read loop dropped mid-frame (deterministic
/// replacement, shutdown, liveness failure, writer death) would cut an
/// in-flight apply short and leave the surviving consumer tasks with no
/// owner: nothing would join them, shutdown would not wait for them,
/// and the recovery tick's reaper could not see them. The guard instead
/// MOVES the set into the drain task on every path — an ownership
/// transfer, not a drop — so the children keep running until the drain
/// task joins them. The guard drops inside the session task's runtime
/// context, so the spawn is always legal.
struct ConsumerDrainGuard {
  consumers: JoinSet<()>,
  drains: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Drop for ConsumerDrainGuard {
  fn drop(&mut self) {
    let mut consumers = std::mem::take(&mut self.consumers);
    // Graceful consumer drain: handing the session's consumer tasks to a
    // node-scoped drain task means a teardown (Io error, deterministic
    // replacement, shutdown, or the read loop's own cancellation) can no
    // longer abort an in-flight apply. A fully received control payload
    // therefore always completes its persist-and-emit (terminal evidence
    // must not strand on a session end), and a partial body fails closed
    // at decode instead. The drain handle joins the node's tracked task
    // vec, so shutdown still awaits it and the recovery tick reaps it
    // (bounded task accounting).
    let drain = tokio::spawn(async move { while consumers.join_next().await.is_some() {} });
    if let Ok(mut tasks) = self.drains.lock() {
      tasks.push(drain);
    }
  }
}

/// Serves incoming packet frames until the connection closes or a frame
/// violates the wire contract (fail closed). Owns the consumer drain guard:
/// it is created here so the cancellation path (the future being dropped)
/// still hands the consumer set to the node-scoped drain exactly like the
/// orderly exit below.
pub(super) async fn read_loop(
  source: &mut impl FrameSource, grant: &SessionGrant, context: &SessionPacketContext,
  frames: &BoundedSender, pending_acks: &PendingAdmissions,
  last_activity: &Arc<std::sync::atomic::AtomicU64>,
) {
  // Registered at entry: the cancellation path must drain consumers too.
  let mut consumers = ConsumerDrainGuard {
    consumers: JoinSet::new(),
    drains: Arc::clone(&context.task_drains),
  };
  read_loop_frames(
    source,
    grant,
    context,
    frames,
    pending_acks,
    last_activity,
    &mut consumers,
  )
  .await;
  // The guard drops here on the orderly exit: its `Drop` hands whatever
  // remains (in-life completed entries were already reaped) to the
  // node-scoped drain task, unchanged from the pre-reap teardown contract.
}

/// The frame loop proper, over a caller-owned consumer guard so liveness
/// tests can hold the guard and observe the set between the loop's in-life
/// reap and the guard's teardown.
async fn read_loop_frames(
  source: &mut impl FrameSource, grant: &SessionGrant, context: &SessionPacketContext,
  frames: &BoundedSender, pending_acks: &PendingAdmissions,
  last_activity: &Arc<std::sync::atomic::AtomicU64>, consumers: &mut ConsumerDrainGuard,
) {
  let mut incoming: HashMap<TraceId, AdmittedStream> = HashMap::new();
  loop {
    // Completed consumer entries are reaped on every
    // receive wake, so finished tasks never accumulate for the whole
    // session's life. Non-blocking on purpose: still-running consumers are
    // left untouched for the guard's `Drop`, which keeps handing the full
    // remaining set to the node-scoped drain on every exit path.
    while consumers.consumers.try_join_next().is_some() {}
    let message = match source.receive_event().await {
      Ok(Some(crate::transport::Received::Message(message))) => message,
      Ok(Some(crate::transport::Received::Pong)) => {
        // A peer pong is a keepalive response: stamp the session's
        // activity mark from the injected clock so the liveness observer
        // sees one time source. This wake is what lets a frame-silent but
        // responsive peer survive the idle deadline.
        last_activity.store(clock_seconds(context.clock.as_ref()), Ordering::Relaxed);
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
    let open_session = match kind {
      PacketKind::Open => {
        handle_open(
          &message.body,
          grant,
          context,
          frames,
          &mut incoming,
          &mut consumers.consumers,
        )
        .await
      }
      PacketKind::Chunk => handle_chunk(&message.body, context, &mut incoming, frames).await,
      PacketKind::End => handle_end(&message.body, context, &mut incoming).await,
      PacketKind::Ack => handle_ack(&message.body, context, pending_acks).await,
    };
    if !open_session {
      break;
    }
  }
  // The frame loop exits without dropping the guard: `read_loop` owns it
  // and its `Drop` hands the JoinSet to the node-scoped drain task on this
  // orderly exit and on every cancellation path alike.
}

/// One frame-kind handler's verdict for the session: `true` keeps the
/// read loop open, `false` closes it (a malformed frame, or an admission
/// or sequence violation).
type FrameVerdict = bool;

/// The `Open` handler: a routed frame addressed elsewhere is forwarded;
/// everything else goes through the local admission path. A malformed
/// open closes the session.
async fn handle_open(
  body: &[u8], grant: &SessionGrant, context: &SessionPacketContext, frames: &BoundedSender,
  incoming: &mut HashMap<TraceId, AdmittedStream>, consumers: &mut JoinSet<()>,
) -> FrameVerdict {
  let Ok(open) = wire::decode_open(body, context.parser_limits()) else {
    warn!("malformed packet open frame");
    return false;
  };
  let routed = open.destination != *context.local() && open.route.is_some();
  if routed {
    forward::open(
      &context.local().clone(),
      grant.peer(),
      grant.identity(),
      open,
      frames,
      &context.sessions,
      &context.routing.forwarding,
      context.registry.routing(),
      context.routing.route_policy(),
      context.routing.forwarding_capacity(),
      context.routing.relay_hop_deadline(),
    )
    .await;
  } else if admit_open(open, grant, context, frames, incoming, consumers)
    .await
    .is_err()
  {
    return false;
  }
  true
}

/// The `Chunk` handler: a chunk for a trace this node forwards is
/// relayed downstream; otherwise it flows in sequence into the admitted
/// incoming stream. A malformed chunk, or a sequence violation, closes
/// the session.
async fn handle_chunk(
  body: &[u8], context: &SessionPacketContext, incoming: &mut HashMap<TraceId, AdmittedStream>,
  frames: &BoundedSender,
) -> FrameVerdict {
  let Ok(chunk) = wire::decode_chunk(body, context.parser_limits()) else {
    warn!("malformed packet chunk frame");
    return false;
  };
  let trace = chunk.trace_id.clone();
  if forward::contains(&context.routing.forwarding, &trace) {
    forward::relay_chunk(&context.routing.forwarding, chunk).await;
  } else if !deliver_chunk_local(chunk, incoming, frames).await {
    warn!(trace_id = %trace, "incoming chunk sequence violation; closing session");
    return false;
  }
  true
}

/// The `End` handler: an end for a forwarded trace is relayed
/// downstream; otherwise it terminates the admitted incoming stream with
/// its typed terminal. A malformed end closes the session.
async fn handle_end(
  body: &[u8], context: &SessionPacketContext, incoming: &mut HashMap<TraceId, AdmittedStream>,
) -> FrameVerdict {
  let Ok(end) = wire::decode_end(body, context.parser_limits()) else {
    warn!("malformed packet end frame");
    return false;
  };
  trace!(trace_id = %end.trace_id, reason = ?end.reason, "incoming stream ended");
  if forward::contains(&context.routing.forwarding, &end.trace_id) {
    forward::relay_end(&context.routing.forwarding, end).await;
    return true;
  }
  if let Some(admitted) = incoming.remove(&end.trace_id) {
    let terminal = terminal_item(end.reason);
    // The terminal is queued without waiting for the consumer: a
    // consumer that never drains its window is the stream's own
    // overload condition, not a reason to stall every other frame
    // of the session (acks, pongs, other streams). The reserved
    // terminal slot guarantees the queue succeeds for a live
    // consumer; a failure means the consumer is gone, and dropping
    // the sender still ends the body prefix with exactly one typed
    // `StreamInterrupted`.
    if admitted.stream.try_send(terminal).is_err() {
      warn!(
        trace_id = %end.trace_id,
        "incoming consumer did not drain its terminal; stream interrupted"
      );
    }
  } else {
    // A lost consumer means its session task aborted mid-stream:
    // surface it loudly, because silence here looks like a lost
    // packet downstream.
    warn!(trace_id = %end.trace_id, "end frame for unknown incoming stream");
  }
  true
}

/// The `Ack` handler: the whole routing-plane acknowledgement decision
/// lives in [`forward::on_session_ack`]; this shell decodes the frame and
/// closes the session on a malformed one.
async fn handle_ack(
  body: &[u8], context: &SessionPacketContext, pending_acks: &PendingAdmissions,
) -> FrameVerdict {
  let Ok(ack) = wire::decode_ack(body, context.parser_limits()) else {
    warn!("malformed packet ack frame");
    return false;
  };
  forward::on_session_ack(
    &forward::SessionAckContext {
      forwarding: &context.routing.forwarding,
      sessions: &context.sessions,
      routes: &context.routing.routes,
      events: &context.events,
      trace: context.routing.trace.as_ref(),
      local: &context.local,
      relay_hop_deadline: context.routing.relay_hop_deadline(),
    },
    ack,
    pending_acks,
  )
  .await;
  true
}

/// The typed terminal one wire end reason surfaces to a consumer — the
/// single mapping both delivery paths (the session read loop and the
/// local delivery leg) share: a completed end closes the body normally;
/// an interrupted end (the sending leg died mid-stream) surfaces exactly
/// one typed `StreamInterrupted` instead of a silent truncation.
fn terminal_item(reason: EndReason) -> StreamItem {
  match reason {
    EndReason::Completed => StreamItem::End,
    EndReason::Interrupted => StreamItem::Interrupted,
  }
}

/// The admission decision one open resolves to: the wire status and the
/// admission wall-clock time reported for it (the original admission time
/// for an identical retransmission).
struct StreamAdmission {
  status: AckStatus,
  admitted_at_millis: i64,
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
  open: OpenFrame, grant: &SessionGrant, context: &SessionPacketContext, frames: &BoundedSender,
  incoming: &mut HashMap<TraceId, AdmittedStream>, consumers: &mut JoinSet<()>,
) -> Result<()> {
  let trace_id = open.trace_id.clone();
  let ack_protocol = open.protocol.clone();
  let local = context.local().clone();
  // The routing envelope re-validates against the session-authenticated
  // holder before anything else (the chain itself then authenticates the
  // original source; a direct frame authenticates only through the exact
  // source-peer match). Forwarding work belongs to the route forwarder;
  // this admission boundary never branches a body, so any frame that does
  // not arrive exactly here fails closed without a consumer.
  let admission = if matches!(
    crate::routing::receive_open_envelope(
      trace_id.clone(),
      open.source.clone(),
      open.destination.clone(),
      open.route.clone(),
      &local,
      grant.peer(),
    ),
    Ok(crate::routing::RouteProgress::Arrive)
  ) {
    admit_stream(
      open,
      |feature| grant.selected_features().contains(feature),
      context,
      incoming,
      consumers,
    )?
  } else {
    StreamAdmission {
      status: AckStatus::Unsupported,
      admitted_at_millis: clock_millis(context.clock.as_ref()),
    }
  };
  let ack = AckFrame {
    trace_id: trace_id.clone(),
    status: admission.status,
    admitted_at_millis: admission.admitted_at_millis,
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

/// The one admission body shared by the inbound open path and local
/// self-delivery: the immutable opening context's duplicate handling, the
/// protocol registration and owning-feature gate, the bounded incoming
/// stream table, the consumer lifecycle permit, and the consumer spawn.
/// `owns_feature` is the caller's gate — the negotiated session selection
/// for an inbound open, the node's own implemented features for a local
/// stream — so the two admission paths cannot drift. The body awaits
/// nothing: the table lock the local delivery leg holds across it is
/// never held across a suspension.
fn admit_stream(
  open: OpenFrame, owns_feature: impl Fn(&crate::FeatureTag) -> bool,
  context: &SessionPacketContext, incoming: &mut HashMap<TraceId, AdmittedStream>,
  consumers: &mut JoinSet<()>,
) -> Result<StreamAdmission> {
  let trace_id = open.trace_id.clone();
  let mut reack_admitted_at: Option<i64> = None;
  let status = 'status: {
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
    match context.registry.protocol(&open.protocol)? {
      Some(registration) if owns_feature(registration.definition.owning_feature()) => {
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
        // The consumer's lifecycle slot is reserved BEFORE admission and
        // handed to the consumer task: a stream whose wire stream ends still
        // holds its slot until the accept future finishes, so the node-wide
        // budget — not the per-session table — bounds the running consumer
        // population.
        let Some(permit) = context.live_consumers.reserve() else {
          debug!(
            trace_id = %trace_id,
            budget = context.live_consumers.limit(),
            "node consumer lifecycle budget exhausted; open refused"
          );
          break 'status AckStatus::Overloaded;
        };
        let admitted_at = clock_millis(context.clock.as_ref());
        let (stream, body) = mpsc::channel(INCOMING_STREAM_CHUNKS + INCOMING_STREAM_TERMINAL_SLOTS);
        incoming.insert(
          open.trace_id.clone(),
          AdmittedStream {
            stream,
            next_sequence: 0,
            context: context_digest,
            admitted_at_millis: admitted_at,
            drain_grace_spent: false,
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
          // The admission slot is held for the consumer's whole life —
          // including its post-wire-EOF work and the node-scoped drain that
          // joins it after a session teardown — and released here.
          let _permit = permit;
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
          &context.routing.routes,
          context.routing.route_capacity(),
          &trace_id,
          ErrorKind::Unsupported,
        );
        AckStatus::Unsupported
      }
    }
  };
  Ok(StreamAdmission {
    status,
    admitted_at_millis: reack_admitted_at.unwrap_or_else(|| clock_millis(context.clock.as_ref())),
  })
}

/// The node-level local-delivery plane: the admitted-stream table and the
/// pending-admission map every local delivery leg of this node shares —
/// the local counterpart of one session's read loop (one table, one queue
/// bound, one duplicate detector, one pending map). Because the table is
/// shared instead of per-pump, duplicate detection and the session queue's
/// message budget bound the local path exactly like the session path.
pub(crate) struct LocalDelivery {
  incoming: Mutex<HashMap<TraceId, AdmittedStream>>,
  pending_acks: PendingAdmissions,
}

impl LocalDelivery {
  /// One plane per node incarnation; `bound` mirrors the per-session
  /// pending-admission bound the wire path uses.
  pub(crate) fn new(bound: usize) -> Self {
    Self {
      incoming: Mutex::new(HashMap::new()),
      pending_acks: PendingAdmissions::new(bound),
    }
  }
}

/// The local node as one delivery leg of the outbound pump: the stream is
/// admitted through the node-level [`LocalDelivery`] table — the same
/// admission body an inbound open runs — and consumed in-process. The leg
/// owns its delivery's consumer drain guard (its drop hands spawned
/// consumers to the node-scoped drain) and removes its table entry on
/// drop, so an interrupted pump cannot strand its admission in the shared
/// table.
pub(crate) struct LocalLeg {
  plane: Arc<LocalDelivery>,
  packet: Arc<SessionPacketContext>,
  consumers: ConsumerDrainGuard,
  trace_id: TraceId,
}

impl LocalLeg {
  /// Builds one leg for one locally addressed stream. Born in the
  /// admission task, moved through the pump handoff, and dropped when the
  /// pump task ends — every drop point runs inside a runtime context, so
  /// the guard's drain spawn is always legal.
  pub(crate) fn new(packet: &Arc<SessionPacketContext>, trace_id: TraceId) -> Self {
    Self {
      plane: Arc::clone(&packet.local_delivery),
      consumers: ConsumerDrainGuard {
        consumers: JoinSet::new(),
        drains: Arc::clone(&packet.task_drains),
      },
      packet: Arc::clone(packet),
      trace_id,
    }
  }

  /// The local leg's open: the same admission body an inbound open runs,
  /// with the node's own registry as the owning-feature gate (the node
  /// offer supports exactly its registry's features — the same gate the
  /// negotiated session selection applies to an inbound open). The pump's
  /// pending waiter resolves on the spot with the admission outcome, the
  /// local counterpart of a destination's acknowledgement frame.
  async fn deliver_open(&mut self, open: OpenFrame) -> Result<(), ErrorKind> {
    let admission = {
      let mut incoming = self
        .plane
        .incoming
        .lock()
        .map_err(|_| ErrorKind::Internal)?;
      admit_stream(
        open,
        |feature| self.packet.registry.feature_digest(feature).is_some(),
        &self.packet,
        &mut incoming,
        &mut self.consumers.consumers,
      )
      .map_err(|error| error.kind())?
    };
    if let Some(PendingAck::Wait { notify, .. }) = self.plane.pending_acks.take(&self.trace_id) {
      let _ = notify.send(match admission.status.to_kind() {
        Some(kind) => Err(kind),
        None => Ok(crate::time::from_millis(admission.admitted_at_millis)),
      });
    }
    Ok(())
  }

  /// The local leg's chunk: one `StreamItem` into the admitted stream's
  /// bounded body channel. This pump feeds one stream, so the consumer's
  /// window is plain backpressure — the session reader's bounded overload
  /// policy exists to keep a shared connection responsive, which does not
  /// apply here. A closed channel means the consumer is gone.
  async fn deliver_chunk(&self, chunk: ChunkFrame) -> Result<(), ErrorKind> {
    let stream = {
      let incoming = self
        .plane
        .incoming
        .lock()
        .map_err(|_| ErrorKind::Internal)?;
      incoming
        .get(&chunk.trace_id)
        .map(|admitted| admitted.stream.clone())
        .ok_or(ErrorKind::StreamInterrupted)?
    };
    stream
      .send(StreamItem::Chunk(Arc::from(chunk.bytes.as_slice())))
      .await
      .map_err(|_| ErrorKind::StreamInterrupted)
  }

  /// The local leg's typed terminal: awaits the consumer's window like a
  /// chunk — the pump feeds one stream, so the window is plain
  /// backpressure — and removes the table entry. `false` means the
  /// terminal did not reach a consumer: the consumer is gone.
  ///
  /// The terminal cannot rely on the reserved terminal slot the session
  /// read loop keeps: the session reader bounds its own chunk sends to
  /// the window, while this pump's chunk sends only respect the channel's
  /// full capacity, so every slot can be holding a chunk when the end
  /// arrives.
  async fn deliver_end(&self, reason: EndReason) -> bool {
    let terminal = terminal_item(reason);
    let admitted = self
      .plane
      .incoming
      .lock()
      .ok()
      .and_then(|mut incoming| incoming.remove(&self.trace_id));
    match admitted {
      Some(admitted) => admitted.stream.send(terminal).await.is_ok(),
      None => false,
    }
  }
}

impl Drop for LocalLeg {
  fn drop(&mut self) {
    // The shared node-level table outlives this pump: a leg whose pump
    // ended before its typed terminal (an aborted task, a shutdown) must
    // not strand its admission in the table and its slot in the queue
    // bound. A completed stream already removed its entry; the removal is
    // then a no-op.
    if let Ok(mut incoming) = self.plane.incoming.lock() {
      incoming.remove(&self.trace_id);
    }
  }
}

/// Delivers one chunk to its admitted stream in strict sequence order.
/// Returns `false` on a sequence violation (fail closed).
///
/// Delivery never awaits the consumer's window unboundedly: the shared
/// session reader must stay responsive to the pongs, acknowledgements, and
/// other streams of the same session, so one stalled consumer cannot park
/// the whole connection. The per-stream window is the
/// flow-control bound. A full window first spends the stream's single
/// [`INCOMING_STREAM_DRAIN_PATIENCE`] grace — a burst whose frames were
/// already buffered by the transport can reach the reader before the
/// consumer task is first scheduled, and a live consumer frees a slot well
/// inside that patience. A window still full on expiry is the stream's own
/// overload: the stream is terminated — its consumer observes exactly one
/// typed `StreamInterrupted` through the closed body channel — and the
/// origin learns the interruption through a best-effort failed
/// acknowledgement, exactly the status a destination-side mid-stream
/// failure reports. The terminal slot stays reserved for the typed end, so
/// a body that fits its window still completes cleanly.
async fn deliver_chunk_local(
  chunk: ChunkFrame, incoming: &mut HashMap<TraceId, AdmittedStream>, frames: &BoundedSender,
) -> bool {
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
  // The chunk window is the flow-control bound: a chunk never takes the
  // reserved terminal slot. The read loop is the channel's only sender, so
  // the check and the send are one decision — no racing sender can steal
  // the slot between them.
  let window_full = admitted.stream.capacity() <= INCOMING_STREAM_TERMINAL_SLOTS;
  let chunk_item = StreamItem::Chunk(bytes);
  let delivered = if !window_full {
    admitted.stream.try_send(chunk_item)
  } else if admitted.drain_grace_spent {
    Err(mpsc::error::TrySendError::Full(chunk_item))
  } else {
    admitted.drain_grace_spent = true;
    // Spend the stream's one grace on the first full window: wait, bounded
    // by the patience, until the consumer frees a chunk slot *and* the
    // terminal slot the window keeps in reserve. Reserving both is what
    // keeps the policy honest — waiting for one slot alone would spend the
    // terminal reservation and turn a live consumer's burst into a false
    // overload.
    match tokio::time::timeout(
      INCOMING_STREAM_DRAIN_PATIENCE,
      admitted
        .stream
        .reserve_many(INCOMING_STREAM_TERMINAL_SLOTS + 1),
    )
    .await
    {
      Ok(Ok(mut permits)) => {
        // The iterator holds the reserved slots; the chunk takes one and
        // dropping the iterator returns the terminal reservation.
        if let Some(permit) = permits.next() {
          permit.send(chunk_item);
          Ok(())
        } else {
          Err(mpsc::error::TrySendError::Full(chunk_item))
        }
      }
      Ok(Err(_)) => Err(mpsc::error::TrySendError::Closed(chunk_item)),
      Err(_elapsed) => Err(mpsc::error::TrySendError::Full(chunk_item)),
    }
  };
  match delivered {
    Ok(()) => true,
    Err(error) => {
      // The consumer is gone (closed) or stayed stalled through its grace
      // (full). Either way this stream ends here, explicitly: dropping the
      // sender closes the body channel, which the consumer surfaces as one
      // typed `StreamInterrupted`, and the failed status tells the origin
      // to stop the stream too.
      let full = matches!(error, mpsc::error::TrySendError::Full(_));
      warn!(
        trace_id = %chunk.trace_id,
        overloaded = full,
        "incoming stream terminated instead of stalling the session reader"
      );
      incoming.remove(&chunk.trace_id);
      frames.try_send_status(&chunk.trace_id, AckStatus::Failed);
      true
    }
  }
}

/// Digests the immutable opening context of one open frame (endpoints,
/// protocol, canonical metadata): identical retransmissions produce the
/// same digest; any mutation produces a different one. Metadata values
/// are arbitrary wire bytes that may contain any separator byte, so the
/// entry preimage is length-prefixed — the entry count, then a `u32`
/// big-endian length before every key and value (the style of the
/// receipt reference domain) — making the encoding injective: a
/// crafted value can never impersonate an entry boundary. The digest is
/// process-local (never serialized), so the preimage carries no
/// compatibility weight.
fn opening_context_digest(
  source: &NodeId, destination: &NodeId, protocol: &ProtocolTag, metadata: &StreamMetadata,
) -> crate::Digest {
  let mut bytes = Vec::with_capacity(128);
  bytes.extend_from_slice(source.as_str().as_bytes());
  bytes.push(0);
  bytes.extend_from_slice(destination.as_str().as_bytes());
  bytes.push(0);
  bytes.extend_from_slice(protocol.as_str().as_bytes());
  let entries = metadata.entries();
  bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
  for (key, value) in entries {
    bytes.extend_from_slice(&(key.as_str().len() as u32).to_be_bytes());
    bytes.extend_from_slice(key.as_str().as_bytes());
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
  }
  crate::identity::signature::body_digest(&bytes)
}

/// One delivery leg of the origin-side outbound pump: the stream's next
/// hop. The session leg carries the wire frames over a live session's
/// bounded frame queue; the local leg admits and consumes the stream
/// in-process. The legs share the pending-admission map, the clock, and
/// aliveness — the pump registers its admission wait and withdraws a
/// never-queued open through either one — and only the `deliver_*` trio
/// diverges: where the open, the chunks, and the typed terminal go.
pub(crate) enum DeliveryLeg {
  Session(SessionEntry),
  Local(LocalLeg),
}

impl DeliveryLeg {
  /// The leg's pending-admission map: the origin's one-shot admission
  /// waiters (and, on a forwarded session, the hops' relays) register
  /// here.
  pub(crate) fn pending_acks(&self) -> &PendingAdmissions {
    match self {
      Self::Session(entry) => &entry.pending_acks,
      Self::Local(leg) => &leg.plane.pending_acks,
    }
  }

  /// The leg's wall clock: the pending waiters' queue stamps come from
  /// the same clock the liveness observer reads.
  pub(crate) fn clock(&self) -> &Arc<dyn crate::time::WallClock> {
    match self {
      Self::Session(entry) => &entry.clock,
      Self::Local(leg) => &leg.packet.clock,
    }
  }

  /// Whether the leg can carry the stream's open: a session whose reader
  /// loop is gone cannot; the local node always can.
  pub(crate) fn alive(&self) -> bool {
    match self {
      Self::Session(entry) => entry.alive(),
      Self::Local(_) => true,
    }
  }

  /// Delivers the open frame: the session leg encodes it and queues it on
  /// the session's bounded frame queue; the local leg admits the stream
  /// and resolves the pump's pending waiter on the spot. The pump awaits
  /// the leg's pending-admission resolution before streaming any body
  /// chunk.
  pub(crate) async fn deliver_open(&mut self, open: OpenFrame) -> Result<(), ErrorKind> {
    match self {
      Self::Session(entry) => {
        let body = wire::encode_open(&open).map_err(|error| error.kind())?;
        entry
          .frames
          .send(SessionFrame {
            kind: PacketKind::Open,
            body,
          })
          .await
          .map_err(|_| ErrorKind::StreamInterrupted)
      }
      Self::Local(leg) => leg.deliver_open(open).await,
    }
  }

  /// Delivers one ordered body chunk (already re-chunked to the wire
  /// bound by the pump): the session leg encodes it and queues it on the
  /// session's bounded frame queue; the local leg feeds the admitted
  /// stream's body channel.
  pub(crate) async fn deliver_chunk(&self, chunk: ChunkFrame) -> Result<(), ErrorKind> {
    match self {
      Self::Session(entry) => {
        let encoded = wire::encode_chunk(&chunk).map_err(|error| error.kind())?;
        entry
          .frames
          .send(SessionFrame {
            kind: PacketKind::Chunk,
            body: encoded,
          })
          .await
          .map_err(|_| ErrorKind::StreamInterrupted)
      }
      Self::Local(leg) => leg.deliver_chunk(chunk).await,
    }
  }

  /// Delivers the stream's typed terminal. Returns whether the terminal
  /// reached the leg: the session leg encodes it and waits for queue
  /// capacity — the terminal is the last frame the stream contributes, so
  /// the writer either drains it or the connection dies and the queue
  /// closes; the local leg likewise awaits the consumer's window, because
  /// its pump's chunk sends fill the channel's full capacity and no
  /// terminal slot stays reserved.
  pub(crate) async fn deliver_end(&self, trace_id: &TraceId, reason: EndReason) -> bool {
    match self {
      Self::Session(entry) => {
        let Ok(body) = wire::encode_end(&EndFrame {
          trace_id: trace_id.clone(),
          reason,
        }) else {
          return false;
        };
        entry
          .frames
          .send_waiting(SessionFrame::new(PacketKind::End, body))
          .await
          .is_ok()
      }
      Self::Local(leg) => leg.deliver_end(reason).await,
    }
  }

  /// Removes a pending admission that never reached the leg.
  pub(crate) fn withdraw_pending(&self, trace_id: &TraceId) {
    self.pending_acks().withdraw(trace_id);
  }
}

#[cfg(test)]
mod tests;
