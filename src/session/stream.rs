//! Established-session keep-alive and packet-stream multiplexing.
//!
//! After the authentication exchange completes, the connection splits into
//! a writer half driven by a bounded frame channel (the session queue) and
//! a reader loop that demultiplexes the four packet kinds: opens are
//! validated and admitted into the bounded incoming stream table before
//! the current-process acknowledgement is returned; chunks flow in order
//! into the admitted stream's bounded body channel; ends terminate
//! streams; acks resolve pending outbound admissions.
//!
//! Interruption is explicit everywhere: a closed session fails pending
//! admissions and in-flight bodies with `StreamInterrupted`, and core
//! never persists or replays payload bytes.

use std::{
  collections::{BTreeMap, HashMap},
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
  },
  time::Duration,
};

use minicbor::bytes::ByteVec;
use tokio::{
  sync::{mpsc, oneshot, watch},
  task::JoinSet,
};
use tracing::{debug, instrument, trace, warn};

use super::driver::EstablishedSession;
use crate::{
  Error, ErrorKind, NodeId, ProtocolTag, QualifiedTag, Result, StreamMetadata, TraceId,
  api::BoxFuture,
  extension_registry::ExtensionRegistry,
  packet::{
    AckOutcome, IncomingStream, MAX_CHUNK_BYTES, OutboundRequest, PacketReplyContext, RouteState,
    StreamItem, StreamTarget, channel_body,
    wire::{self, AckFrame, AckStatus, ChunkFrame, EndFrame, OpenFrame},
  },
  protocol::wire::PacketKind,
  routing::{
    forward,
    table::{RouteTable, record_rejection, update_route},
  },
  transport::connection::{Connection, ConnectionReader, ConnectionWriter},
};

/// The number of body chunks buffered per admitted incoming stream before
/// backpressure stalls the session reader.
const INCOMING_STREAM_CHUNKS: usize = 8;

/// The shared node-local session table: authenticated peer to live (or
/// dead, pending replacement) session entry.
pub(crate) type SessionTable = Arc<Mutex<BTreeMap<NodeId, SessionEntry>>>;

/// One pending outbound admission: a synchronous waiter, or a forwarding
/// hop whose acknowledgement must be relayed upstream. The
/// map holding these is bounded per session by
/// [`SessionPolicy::pending_admissions`]: a peer that accepts opens
/// without acknowledging them cannot grow origin memory without limit.
pub(crate) enum PendingAck {
  Wait {
    notify: oneshot::Sender<AckOutcome>,
    /// Host wall-clock seconds at insertion; the liveness policy lets the
    /// idle deadline close a session whose oldest waiting admission has
    /// been outstanding for a full idle deadline, so a silent peer cannot
    /// hold a session open forever through the owned-work exemption.
    queued_at: u64,
  },
  Relay {
    upstream: BoundedSender,
  },
}

pub(crate) type PendingAcks = Arc<Mutex<HashMap<TraceId, PendingAck>>>;

/// The packet-handling context shared by every session of one node.
/// The caller-selected session bounds: outbound queue count and
/// encoded-byte budgets, plus the wall-clock liveness deadlines.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionPolicy {
  pub(crate) queue_messages: usize,
  pub(crate) queue_bytes: usize,
  /// Concurrent outbound admissions awaiting their peer's ack per
  /// session (the pending-acknowledgement map). An internal protection
  /// bound (like the trace persistence semaphore), not a caller knob: it
  /// caps origin-side memory against a peer that accepts opens without
  /// acknowledging them. The inbound admitted-stream table instead shares
  /// the caller-selected `queue_messages` budget (see `admit_open`).
  pub(crate) pending_admissions: usize,
  pub(crate) idle_timeout: Duration,
  pub(crate) keepalive_interval: Duration,
  pub(crate) keepalive_timeout: Duration,
}

/// The fixed per-session bound on concurrent admissions awaiting their
/// peer: beyond it, new opens fail closed with typed
/// `Overloaded` backpressure instead of growing memory.
pub(crate) const MAX_PENDING_ADMISSIONS: usize = 256;

impl SessionPolicy {
  pub(crate) fn new(
    queue_messages: usize, queue_bytes: usize, idle_timeout: Duration,
    keepalive_interval: Duration, keepalive_timeout: Duration,
  ) -> Self {
    Self {
      queue_messages,
      queue_bytes,
      pending_admissions: MAX_PENDING_ADMISSIONS,
      idle_timeout,
      keepalive_interval,
      keepalive_timeout,
    }
  }

  /// Builds the session bounds from the node configuration, so a session
  /// knob is declared once in `NodeConfig` and not copied field-by-field.
  pub(crate) fn from_config(config: &crate::NodeConfig) -> Self {
    Self::new(
      config.session_queue_messages(),
      config.session_queue_bytes(),
      config.session_idle_timeout(),
      config.keepalive_interval(),
      config.keepalive_timeout(),
    )
  }
}

pub(crate) struct SessionPacketContext {
  local: NodeId,
  registry: Arc<ExtensionRegistry>,
  policy: SessionPolicy,
  runtime: crate::runtime::RuntimeClient,
  clock: Arc<dyn crate::storage::receipt::WallClock>,
  /// Injected entropy for per-session identifiers.
  entropy: Arc<dyn crate::api::Entropy>,
  /// The typed event hub: session and route transitions emit through it.
  events: Arc<crate::node::EventHub>,
  forwarding: crate::routing::forward::ForwardingTable,
  route_policy: Option<QualifiedTag>,
  sessions: SessionTable,
  routes: RouteTable,
  forwarding_capacity: usize,
  /// The node's configured bound on in-memory terminal route records;
  /// admission rejections must respect it like every other writer.
  route_capacity: usize,
  /// The node-scoped tracked task vec: session-exit consumer drains join
  /// it so a teardown cannot abort an in-flight apply unnoticed.
  task_drains: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
  parser_limits: crate::protocol::CborLimits,
}

impl SessionPacketContext {
  /// The argument list mirrors the context's node-shared collaborators; no
  /// subset forms a meaningful grouping.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    local: NodeId, registry: Arc<ExtensionRegistry>, policy: SessionPolicy,
    runtime: crate::runtime::RuntimeClient, clock: Arc<dyn crate::storage::receipt::WallClock>,
    entropy: Arc<dyn crate::api::Entropy>, events: Arc<crate::node::EventHub>,
    route_policy: Option<QualifiedTag>, sessions: SessionTable, routes_clone: RouteTable,
    forwarding_capacity: usize, route_capacity: usize,
    task_drains: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    parser_limits: crate::protocol::CborLimits,
  ) -> Self {
    Self {
      local,
      registry,
      policy,
      runtime,
      clock,
      entropy,
      events,
      forwarding: crate::routing::forward::new_table(),
      route_policy,
      sessions,
      routes: routes_clone,
      forwarding_capacity,
      route_capacity,
      task_drains,
      parser_limits,
    }
  }

  /// The node's configured next-hop routing policy tag, if any.
  pub(crate) const fn route_policy(&self) -> Option<&QualifiedTag> {
    self.route_policy.as_ref()
  }

  pub(crate) const fn local(&self) -> &NodeId {
    &self.local
  }

  /// The caller-selected bound on concurrently forwarded routes.
  pub(crate) const fn forwarding_capacity(&self) -> usize {
    self.forwarding_capacity
  }

  /// The caller-selected bound on in-memory terminal route records.
  pub(crate) const fn route_capacity(&self) -> usize {
    self.route_capacity
  }

  /// The caller-selected packet parser limits.
  pub(crate) const fn parser_limits(&self) -> crate::protocol::CborLimits {
    self.parser_limits
  }
}

/// One admitted incoming stream: its bounded body channel, the next
/// expected chunk sequence, the immutable opening-context digest that
/// decides duplicate handling, and the admission wall-clock time reported
/// by identical retransmissions.
pub(crate) struct AdmittedStream {
  stream: mpsc::Sender<StreamItem>,
  next_sequence: u64,
  context: crate::Digest,
  admitted_at_millis: u64,
}

/// One framed outbound session message.
pub(crate) struct SessionFrame {
  pub(crate) kind: PacketKind,
  pub(crate) body: Vec<u8>,
}

impl SessionFrame {
  pub(crate) const fn new(kind: PacketKind, body: Vec<u8>) -> Self {
    Self { kind, body }
  }
}

/// Which side initiated an established session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DialDirection {
  /// This node dialed the peer.
  Outgoing,
  /// The peer dialed this node.
  Incoming,
}

/// The deterministic crossed-dial ownership rule: the
/// connection initiated by the smaller node id wins, so both sides of a
/// simultaneous dial converge to the same authenticated session. Each side
/// keeps the entry whose direction matches the rule and drops the other.
pub(crate) fn keep_connection(local: &NodeId, peer: &NodeId, direction: DialDirection) -> bool {
  match direction {
    DialDirection::Outgoing => local < peer,
    DialDirection::Incoming => local > peer,
  }
}

/// The shared admission state of one outbound session queue: the count of
/// queued frames and their summed encoded bytes. Both bounds are checked
/// atomically (under `admit`) before enqueue, and a rejected frame is never
/// partially enqueued.
#[derive(Debug, Default)]
struct QueueState {
  count: AtomicUsize,
  bytes: AtomicUsize,
  admit: std::sync::Mutex<()>,
  /// Signalled by [`BoundedReceiver::recv`] after every reservation
  /// release, so waiting relays wake on progress instead of spinning.
  released: tokio::sync::Notify,
  /// Soak diagnostic: admissions granted and removals (drains
  /// plus error-path releases). reserved - removed = frames sitting in
  /// the channel.
  audit_reserved: AtomicUsize,
  audit_removed: AtomicUsize,
}

/// The admission overhead of one queued frame beyond its body bytes.
const FRAME_OVERHEAD: usize = 16;

/// Upper bound on one wait for a queue release when the receiver is gone
/// or silent; each wake re-checks capacity and closure, so this bounds
/// staleness without busy-spinning.
const WAIT_BACKSTOP: Duration = Duration::from_millis(50);

/// A bounded outbound frame sender. `send` atomically checks message count
/// and summed encoded bytes against the caller-selected limits and returns
/// a typed overload error at either boundary without partial enqueue.
#[derive(Clone)]
pub(crate) struct BoundedSender {
  inner: mpsc::Sender<SessionFrame>,
  state: Arc<QueueState>,
  max_count: usize,
  max_bytes: usize,
}

impl BoundedSender {
  /// The current queued frame count (runtime status view).
  pub(crate) fn queued_messages(&self) -> usize {
    self.state.count.load(Ordering::Relaxed)
  }

  /// The current queued frame bytes (runtime status view).
  pub(crate) fn queued_bytes(&self) -> u64 {
    u64::try_from(self.state.bytes.load(Ordering::Relaxed)).unwrap_or(u64::MAX)
  }

  /// The reservation audit delta: reserved minus removed. Zero means
  /// every admission was matched by a drain or release; positive means
  /// frames are sitting in the channel (soak diagnostic).
  pub(crate) fn audit_delta(&self) -> usize {
    self
      .state
      .audit_reserved
      .load(Ordering::Relaxed)
      .saturating_sub(self.state.audit_removed.load(Ordering::Relaxed))
  }

  /// Best-effort admission-status relay (single construction site): the
  /// encoded ack is enqueued when the bounded queue has room; a saturated
  /// queue drops the status and the upstream liveness policy bounds the
  /// wait regardless.
  pub(crate) fn try_send_status(&self, trace_id: &TraceId, status: crate::packet::wire::AckStatus) {
    if let Ok(body) = wire::encode_ack(&crate::packet::wire::AckFrame {
      trace_id: trace_id.clone(),
      status,
      admitted_at_millis: 0,
    }) {
      self.try_send(SessionFrame::new(PacketKind::Ack, body));
    }
  }

  /// Awaiting variant of [`Self::try_send_status`] used when tearing a
  /// session down: the drained queue has room and the interruption status
  /// must reach the upstream hop before the connection closes.
  pub(crate) async fn send_status(
    &self, trace_id: &TraceId, status: crate::packet::wire::AckStatus,
  ) {
    if let Ok(body) = wire::encode_ack(&crate::packet::wire::AckFrame {
      trace_id: trace_id.clone(),
      status,
      admitted_at_millis: 0,
    }) {
      let _ = self.send(SessionFrame::new(PacketKind::Ack, body)).await;
    }
  }

  /// The non-blocking variant used for best-effort control frames (relay
  /// acknowledgements): saturation drops the frame instead of awaiting.
  pub(crate) fn try_send(&self, frame: SessionFrame) {
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    let Some(bytes) = self.try_reserve(bytes) else {
      return;
    };
    if self.inner.try_send(frame).is_err() {
      // The queue closed after admission; release the reservation.
      self.release(bytes);
    }
  }

  /// The admission check and reservation are one atomic critical section:
  /// concurrent senders cannot both pass the count/byte check and exceed
  /// the budget (the check-then-act is synchronous, no await inside).
  /// `Ok(None)` means saturated; an error means poisoned state.
  fn reserve(&self, bytes: usize) -> Result<Option<usize>> {
    match self.state.admit.lock() {
      Ok(_guard) => {
        let count = self.state.count.load(Ordering::Relaxed);
        let queued_bytes = self.state.bytes.load(Ordering::Relaxed);
        if count >= self.max_count || queued_bytes.saturating_add(bytes) > self.max_bytes {
          Ok(None)
        } else {
          self.state.count.fetch_add(1, Ordering::Relaxed);
          self.state.bytes.fetch_add(bytes, Ordering::Relaxed);
          self.state.audit_reserved.fetch_add(1, Ordering::Relaxed);
          Ok(Some(bytes))
        }
      }
      Err(_) => Err(Error::internal("session queue")),
    }
  }

  fn try_reserve(&self, bytes: usize) -> Option<usize> {
    self.reserve(bytes).ok().flatten()
  }

  fn release(&self, bytes: usize) {
    self.state.count.fetch_sub(1, Ordering::Relaxed);
    self.state.bytes.fetch_sub(bytes, Ordering::Relaxed);
    self.state.audit_removed.fetch_add(1, Ordering::Relaxed);
  }

  /// The forwarding variant: waits for downstream capacity instead of
  /// rejecting, so a slow destination stops the relay's reads until it
  /// progresses. Order is preserved by the FIFO queue.
  /// Wakeups come from [`BoundedReceiver::recv`] releases; the bounded
  /// backstop covers a closed queue that will never release again.
  pub(crate) async fn send_waiting(&self, frame: SessionFrame) -> Result<()> {
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    loop {
      match self.reserve(bytes)? {
        Some(reserved) => {
          if self.inner.send(frame).await.is_err() {
            // The queue closed after admission; release the reservation.
            self.release(reserved);
            return Err(Error::shutting_down("session queue"));
          }
          return Ok(());
        }
        None => {
          if self.inner.is_closed() {
            return Err(Error::shutting_down("session queue"));
          }
          tokio::select! {
            _ = self.state.released.notified() => {}
            _ = tokio::time::sleep(WAIT_BACKSTOP) => {}
          }
        }
      }
    }
  }

  /// The blocking admission path used by payload frames.
  pub(crate) fn send(&self, frame: SessionFrame) -> BoxFuture<'_, Result<()>> {
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    let inner = self.inner.clone();
    Box::pin(async move {
      let Some(reserved) = self.reserve(bytes)? else {
        return Err(Error::overloaded("session queue"));
      };
      if inner.send(frame).await.is_err() {
        // The queue closed after admission; release the reservation.
        self.release(reserved);
        return Err(Error::shutting_down("session queue"));
      }
      Ok(())
    })
  }
}

/// The receiving half that releases queue reservations as frames drain.
pub(crate) struct BoundedReceiver {
  inner: mpsc::Receiver<SessionFrame>,
  state: Arc<QueueState>,
}

impl BoundedReceiver {
  pub(crate) async fn recv(&mut self) -> Option<SessionFrame> {
    let frame = self.inner.recv().await?;
    let bytes = FRAME_OVERHEAD.saturating_add(frame.body.len());
    self.state.count.fetch_sub(1, Ordering::Relaxed);
    self.state.bytes.fetch_sub(bytes, Ordering::Relaxed);
    self.state.audit_removed.fetch_add(1, Ordering::Relaxed);
    self.state.released.notify_one();
    Some(frame)
  }
}

/// The public session metadata allocated at registration: the
/// server-allocated id, the per-peer replacement generation, the
/// attachment endpoint (dial target for outbound, accepting listener for
/// inbound), and the session-scoped selected features.
#[derive(Clone)]
pub(crate) struct SessionMeta {
  pub(crate) id: crate::SessionId,
  pub(crate) generation: u64,
  pub(crate) endpoint: crate::Endpoint,
  pub(crate) features: Vec<crate::FeatureTag>,
}

/// One established session's send-side handle in the session table.
#[derive(Clone)]
pub(crate) struct SessionEntry {
  pub(crate) frames: BoundedSender,
  pub(crate) pending_acks: PendingAcks,
  /// Per-session concurrent admission bound from the session policy,
  /// carried here so the outbound pump (which runs without the session
  /// context) can enforce typed backpressure.
  pub(super) pending_admissions: usize,
  pub(super) clock: Arc<dyn crate::storage::receipt::WallClock>,
  /// The public session metadata.
  pub(crate) meta: Arc<SessionMeta>,
  alive: Arc<AtomicBool>,
  direction: DialDirection,
  retire: watch::Sender<()>,
}

impl SessionEntry {
  /// Whether the session's reader loop is still serving the connection.
  pub(crate) fn alive(&self) -> bool {
    self.alive.load(Ordering::SeqCst)
  }

  /// The queued outbound frame count (runtime status view).
  pub(crate) fn queued_messages(&self) -> usize {
    self.frames.queued_messages()
  }

  /// The queued outbound frame bytes (runtime status view).
  pub(crate) fn queued_bytes(&self) -> u64 {
    self.frames.queued_bytes()
  }

  /// Frames admitted into the channel but not drained (soak diagnostic).
  pub(crate) fn queue_audit_delta(&self) -> usize {
    self.frames.audit_delta()
  }
}

/// Runs one established session until the connection closes or the node
/// shuts down: spawns the writer task, registers the session in the table
/// (retiring any previous session to the same peer), and serves incoming
/// packet frames.
///
/// The argument list mirrors one session's node-shared collaborators; no
/// subset forms a meaningful grouping.
#[allow(clippy::too_many_arguments)]
#[instrument(name = "session", skip_all, fields(peer = %session.peer()))]
pub(crate) async fn run_session(
  connection: Connection, session: EstablishedSession, context: Arc<SessionPacketContext>,
  table: SessionTable, shutdown: watch::Receiver<()>, direction: DialDirection,
  attachment: crate::Endpoint, registered: Option<oneshot::Sender<()>>,
) {
  let peer = session.peer().clone();
  let (writer, mut reader) = connection.into_split();
  let (frames_tx, frames_rx) = mpsc::channel(context.policy.queue_messages);
  let queue_state = Arc::new(QueueState::default());
  let frames = BoundedSender {
    inner: frames_tx,
    state: Arc::clone(&queue_state),
    max_count: context.policy.queue_messages,
    max_bytes: context.policy.queue_bytes,
  };
  let frames_rx = BoundedReceiver {
    inner: frames_rx,
    state: Arc::clone(&queue_state),
  };
  let pending_acks = Arc::new(Mutex::new(HashMap::new()));
  let alive = Arc::new(AtomicBool::new(true));
  let (retire_tx, retire_rx) = watch::channel(());
  let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(clock_seconds(
    context.clock.as_ref(),
  )));
  let (ping_tx, ping_rx) = watch::channel(());
  let session_id = match crate::SessionId::generate(context.entropy.as_ref()) {
    Ok(id) => id,
    Err(_) => {
      alive.store(false, Ordering::SeqCst);
      if let Some(registered) = registered {
        let _ = registered.send(());
      }
      return;
    }
  };
  let entry = SessionEntry {
    frames: frames.clone(),
    pending_acks: Arc::clone(&pending_acks),
    pending_admissions: context.policy.pending_admissions,
    clock: context.clock.clone(),
    meta: Arc::new(SessionMeta {
      id: session_id,
      generation: 0, // resolved against the previous entry at insert
      endpoint: attachment,
      features: session.selected_features().to_vec(),
    }),
    alive: Arc::clone(&alive),
    direction,
    retire: retire_tx,
  };
  {
    let local = context.local().clone();
    let mut guard = match table.lock() {
      Ok(guard) => guard,
      Err(_) => {
        alive.store(false, Ordering::SeqCst);
        if let Some(registered) = registered {
          let _ = registered.send(());
        }
        return;
      }
    };
    let replace = match guard.get(&peer) {
      None => true,
      Some(previous) => {
        // A dead entry must never block reconnection: only a live previous
        // session competes under the crossed-dial ownership rule.
        if !previous.alive() {
          true
        } else {
          let keep_existing = keep_connection(&local, &peer, previous.direction);
          let keep_new = keep_connection(&local, &peer, direction);
          // Crossed dial: the deterministic rule prefers exactly one of the
          // two directions; keep that one and drop the other. Same
          // direction (reconnect, restart) always replaces with the newest
          // entry.
          if keep_existing != keep_new {
            keep_new
          } else {
            true
          }
        }
      }
    };
    if replace {
      let generation = guard
        .get(&peer)
        .map(|previous| previous.meta.generation.saturating_add(1))
        .unwrap_or(1);
      let entry = SessionEntry {
        meta: Arc::new(SessionMeta {
          generation,
          ..(*entry.meta).clone()
        }),
        ..entry
      };
      let previous = guard.insert(peer.clone(), entry);
      drop(guard);
      // The dialing caller waits on this signal, so its first packet
      // cannot race the session-table registration.
      if let Some(registered) = registered {
        let _ = registered.send(());
      }
      context
        .events
        .emit(crate::SessionChanged::new(peer.clone()));
      if let Some(previous) = previous {
        debug!("session replaced; draining the previous connection");
        retire(&previous);
      }
    } else {
      drop(guard);
      debug!("crossed dial: keeping the deterministic owner, closing this connection");
      alive.store(false, Ordering::SeqCst);
      if let Some(registered) = registered {
        let _ = registered.send(());
      }
      return;
    }
  }

  debug!("session established; serving packet streams");
  let mut writer_task = tokio::spawn(run_writer(writer, frames_rx, ping_rx));
  tokio::select! {
    () = read_loop(
      &mut reader,
      &session,
      &context,
      &frames,
      &pending_acks,
      &last_activity,
    ) => {
      trace!("session reader ended");
    }
    () = shutdown_observer(shutdown) => {
      trace!("session ended by shutdown signal");
    }
    () = retire_observer(retire_rx) => {
      trace!("session ended by deterministic replacement");
    }
    () = liveness_observer(
      &last_activity,
      &pending_acks,
      context.clock.clone(),
      context.policy.idle_timeout,
      context.policy.keepalive_interval,
      context.policy.keepalive_timeout,
      &ping_tx,
    ) => {
      debug!("session closed by the liveness policy");
    }
    _ = &mut writer_task => {
      // A writer that ends (send/ping failure) must tear the session down;
      // otherwise a half-open connection would keep its table entry and
      // every outbound packet would fail forever.
      trace!("session writer ended");
    }
  }

  alive.store(false, Ordering::SeqCst);
  // Remove this session's entry when it is still the registered one, so a
  // dead entry cannot block a later reconnection from either direction.
  let mut removed = false;
  if let Ok(mut sessions) = table.lock()
    && let Some(current) = sessions.get(&peer)
    && !current.alive()
  {
    sessions.remove(&peer);
    removed = true;
  }
  if removed {
    context
      .events
      .emit(crate::SessionChanged::new(peer.clone()));
  }
  writer_task.abort();
  // Pending admissions and in-flight incoming bodies observe the
  // interruption explicitly: pending acks fail with StreamInterrupted,
  // forwarded hops relay a failed acknowledgement upstream, and dropped
  // body channels close without an end marker. Every hop fed by this
  // session's peer terminates downstream explicitly.
  let relays: Vec<(TraceId, BoundedSender)> = if let Ok(mut pending) = pending_acks.lock() {
    let interrupted = pending.len();
    let mut relays = Vec::new();
    for (trace_id, entry) in pending.drain() {
      match entry {
        PendingAck::Wait { notify, .. } => {
          let _ = notify.send(Err(ErrorKind::StreamInterrupted));
        }
        PendingAck::Relay { upstream } => relays.push((trace_id, upstream)),
      }
    }
    if interrupted > 0 {
      debug!(interrupted, "session closed pending admissions");
    }
    relays
  } else {
    Vec::new()
  };
  for (trace_id, upstream) in relays {
    upstream
      .send_status(&trace_id, crate::packet::wire::AckStatus::Failed)
      .await;
  }
  forward::close_for_peer(&context.forwarding, &peer).await;
}

/// Resolves when the runtime signals or drops the shutdown channel.
async fn shutdown_observer(mut signal: watch::Receiver<()>) {
  let _ = signal.changed().await;
}

/// Resolves when this session is deterministically replaced (crossed dial
/// or a newer same-direction connection).
async fn retire_observer(mut signal: watch::Receiver<()>) {
  let _ = signal.changed().await;
}

/// UNIX-seconds from the injected wall clock.
fn clock_seconds(clock: &dyn crate::storage::receipt::WallClock) -> u64 {
  crate::time::to_seconds(clock.now())
}

/// UNIX-milliseconds from the injected wall clock, used for the admission
/// timestamps reported in acknowledgements so simulation controls them too.
fn clock_millis(clock: &dyn crate::storage::receipt::WallClock) -> u64 {
  crate::time::to_millis(clock.now())
}

/// Enforces the session liveness policy on host wall time:
/// a session with no authenticated traffic or owned in-flight work for the
/// idle deadline closes; a peer missing a keepalive result for the
/// keepalive deadline closes. Wall-clock rollback or freeze delays both
/// deadlines and a forward jump makes them immediately due.
async fn liveness_observer(
  last_activity: &Arc<std::sync::atomic::AtomicU64>, pending_acks: &PendingAcks,
  clock: Arc<dyn crate::storage::receipt::WallClock>, idle_timeout: Duration,
  keepalive_interval: Duration, keepalive_timeout: Duration, ping_tx: &watch::Sender<()>,
) {
  if idle_timeout.is_zero() && keepalive_interval.is_zero() {
    // No liveness policy configured; never resolves.
    std::future::pending::<()>().await;
    return;
  }
  let tick = std::cmp::min(
    if idle_timeout.is_zero() {
      Duration::MAX
    } else {
      idle_timeout
    },
    if keepalive_interval.is_zero() {
      Duration::MAX
    } else {
      keepalive_interval
    },
  )
  .min(Duration::from_secs(1))
  .max(Duration::from_millis(10));
  let mut last_ping = 0_u64;
  loop {
    tokio::time::sleep(tick).await;
    let now = clock_seconds(clock.as_ref());
    let last = last_activity.load(Ordering::Relaxed);
    // Owned in-flight work holds the session open, but the hold-off is
    // itself deadline-bounded: once the oldest waiting admission has been
    // outstanding for a full idle deadline, a silent peer no longer
    // exempts the session from the idle close (which then fails every
    // pending admission explicitly with StreamInterrupted).
    let holds_session = pending_acks
      .lock()
      .map(|pending| {
        if pending.is_empty() {
          return false;
        }
        let oldest_wait = pending
          .values()
          .filter_map(|entry| match entry {
            PendingAck::Wait { queued_at, .. } => Some(*queued_at),
            PendingAck::Relay { .. } => None,
          })
          .min();
        match oldest_wait {
          Some(oldest) => now.saturating_sub(oldest) < idle_timeout.as_secs(),
          // Pure forwarding hops are bounded transitively by the liveness
          // policies of the sessions on both ends of the relay.
          None => true,
        }
      })
      .unwrap_or(false);
    // Idle close only when no owned in-flight work remains (or it went stale).
    if !idle_timeout.is_zero()
      && !holds_session
      && now.saturating_sub(last) >= idle_timeout.as_secs()
    {
      return;
    }
    if !keepalive_interval.is_zero()
      && last_ping != 0
      && now.saturating_sub(last_ping) >= keepalive_timeout.as_secs()
      && now.saturating_sub(last) >= keepalive_timeout.as_secs()
    {
      // The peer missed the keepalive result (no pong or traffic since the
      // ping was sent); close.
      return;
    }
    if !keepalive_interval.is_zero()
      && now.saturating_sub(last_ping) >= keepalive_interval.as_secs()
    {
      last_ping = now;
      let _ = ping_tx.send(());
    }
  }
}

/// Closes the authenticated session to `peer` from the node side: removes
/// the entry so no further routing occurs and retires it so its reader and
/// writer loops end (DisconnectPeer, partition simulation).
/// A missing or already-dead entry is a no-op.
pub(crate) fn retire_session(table: &SessionTable, peer: &NodeId) -> Result<()> {
  let entry = table
    .lock()
    .map_err(crate::Error::session_table)?
    .remove(peer);
  if let Some(entry) = entry {
    retire(&entry);
  }
  Ok(())
}

/// Drains one replaced session: it stops accepting new work, its pending
/// admissions fail exactly once with `StreamInterrupted`, and the retire
/// signal closes its reader so the connection tears down after the winner
/// is registered.
fn retire(entry: &SessionEntry) {
  entry.alive.store(false, Ordering::SeqCst);
  if let Ok(mut pending) = entry.pending_acks.lock() {
    for (trace_id, ack) in pending.drain() {
      match ack {
        PendingAck::Wait { notify, .. } => {
          let _ = notify.send(Err(ErrorKind::StreamInterrupted));
        }
        PendingAck::Relay { upstream } => {
          // Best-effort relay of the interruption; a saturated queue
          // cannot be repaired here and the upstream liveness policy
          // bounds the wait regardless.
          upstream.try_send_status(&trace_id, crate::packet::wire::AckStatus::Failed);
        }
      }
    }
  }
  let _ = entry.retire.send(());
}

/// Writes queued session frames in order until the queue closes or the
/// connection fails.
async fn run_writer(
  mut writer: ConnectionWriter, mut frames: BoundedReceiver, mut ping: watch::Receiver<()>,
) {
  debug!("session writer started");
  loop {
    tokio::select! {
      frame = frames.recv() => {
        let Some(frame) = frame else {
          trace!("session writer channel closed");
          return;
        };
        if writer
          .send(frame.kind.kind_id(), &frame.body)
          .await
          .is_err()
        {
          warn!(kind = ?frame.kind, "session writer send failed");
          return;
        }
        trace!(kind = ?frame.kind, "session frame sent");
      }
      () = async { let _ = ping.changed().await; } => {
        if writer.ping().await.is_err() {
          warn!("session keepalive ping failed");
          return;
        }
      }
    }
  }
}

/// Serves incoming packet frames until the connection closes or a frame
/// violates the wire contract (fail closed).
async fn read_loop(
  reader: &mut ConnectionReader, session: &EstablishedSession, context: &SessionPacketContext,
  frames: &BoundedSender, pending_acks: &PendingAcks,
  last_activity: &Arc<std::sync::atomic::AtomicU64>,
) {
  let mut incoming: HashMap<TraceId, AdmittedStream> = HashMap::new();
  let mut consumers = JoinSet::new();
  let mut last_pong_seen = reader.pong_last_seen();
  loop {
    // A peer pong is a keepalive response: reflect it into the injected
    // clock's activity mark so the liveness observer sees one time source.
    let pong = reader.pong_last_seen();
    if pong != last_pong_seen {
      last_pong_seen = pong;
      last_activity.store(clock_seconds(context.clock.as_ref()), Ordering::Relaxed);
    }
    let message = match reader.receive().await {
      Ok(Some(message)) => message,
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
    // A routed frame re-validates its envelope against the
    // session-authenticated holder before anything else;
    // the chain itself then authenticates the original source.
    if let Some(route) = open.route.clone() {
      let envelope = crate::routing::RouteContext::from_frame(
        trace_id.clone(),
        open.source.clone(),
        open.destination.clone(),
        Some(route),
      );
      // Forwarding work belongs to the route forwarder; this
      // admission boundary never branches a body, so any frame that does
      // not arrive exactly here fails closed without a consumer.
      if !matches!(
        envelope.receive(&local, session.peer(), |_| {
          Err(Error::unsupported("route forwarding"))
        }),
        Ok(crate::routing::RouteProgress::Arrive)
      ) {
        break 'status AckStatus::Unsupported;
      }
    } else if open.source != *session.peer() {
      // Direct frames: endpoints must match the session-authenticated
      // identities exactly.
      break 'status AckStatus::Unsupported;
    }
    if open.destination != local {
      break 'status AckStatus::Unsupported;
    }
    // The immutable opening context decides duplicate handling: an
    // identical retransmission reports the current admission status
    // without invoking the consumer twice; a conflicting one fails closed.
    let context_digest = crate::session::stream::opening_context_digest(
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
        record_rejection(
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

/// Pumps one outbound packet over its session: open, admission wait,
/// ordered chunks, end. Updates the in-memory route record and notifies
/// the synchronous waiter of the admission outcome (the ack
/// proves current-process admission only).
#[instrument(name = "packet", skip_all, fields(
  trace_id = %request.trace_id,
  target = ?request.target,
  local = %local,
))]
pub(crate) async fn run_outbound(
  entry: SessionEntry, local: NodeId, request: OutboundRequest, routes: RouteTable,
  force_routed: bool, trace: Option<crate::routing::trace::TraceSink>,
  events: Arc<crate::node::EventHub>,
) {
  // The supervisor resolves selector targets before spawning the pump; a
  // matching-node request that reaches this point is an internal error.
  let destination = match request.target.clone() {
    StreamTarget::Exact(destination) => destination,
    StreamTarget::MatchingNodes(_) => {
      request.reject(ErrorKind::Internal);
      return;
    }
  };
  let trace_id = request.trace_id.clone();
  let source = local.clone();
  // Fire-and-forget persistence of one durable terminal fact per packet;
  // the data plane never waits on metadata storage and intermediate
  // progress stays an in-memory observation.
  macro_rules! terminal {
    ($kind:expr) => {{
      update_route(&routes, &trace_id, |record| {
        record.update(RouteState::Failed($kind));
      });
      events.emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
      record_terminal_trace(
        &trace,
        &trace_id,
        &source,
        &destination,
        crate::routing::trace::TraceTransition::Failed($kind),
      );
    }};
  }
  trace!(force_routed, "pumping outbound packet");
  let (ack_tx, ack_rx) = oneshot::channel();
  if !entry.alive() {
    debug!("packet rejected: session not alive");
    request.reject(ErrorKind::StreamInterrupted);
    terminal!(ErrorKind::StreamInterrupted);
    return;
  }
  {
    let queued_at = clock_seconds(entry.clock.as_ref());
    let registered = entry.pending_acks.lock().map(|mut pending| {
      // Typed backpressure instead of unbounded growth: beyond the
      // per-session admission bound the open fails closed.
      if pending.len() >= entry.pending_admissions {
        return Err(());
      }
      pending.insert(
        trace_id.clone(),
        PendingAck::Wait {
          notify: ack_tx,
          queued_at,
        },
      );
      Ok(())
    });
    match registered {
      Ok(Ok(())) => {}
      Ok(Err(())) => {
        request.reject(ErrorKind::Overloaded);
        terminal!(ErrorKind::Overloaded);
        return;
      }
      Err(_) => {
        request.reject(ErrorKind::Internal);
        terminal!(ErrorKind::Internal);
        return;
      }
    }
  }

  // Selector-selected and multi-hop-routed deliveries carry the route
  // envelope: every hop re-validates the chain before admission. Direct
  // exact-node sends carry no envelope.
  let route = if force_routed || matches!(request.target, StreamTarget::MatchingNodes(_)) {
    Some(
      crate::routing::RouteContext::new(
        trace_id.clone(),
        local.clone(),
        destination.clone(),
        request.max_hops,
      )
      .hop_state(),
    )
  } else {
    None
  };
  let open = OpenFrame {
    trace_id: trace_id.clone(),
    source: local,
    destination: destination.clone(),
    protocol: request.protocol.clone(),
    metadata: request.metadata.clone(),
    route,
  };
  let body = match wire::encode_open(&open) {
    Ok(body) => body,
    Err(error) => {
      withdraw_pending(&entry, &trace_id);
      request.reject(error.kind());
      terminal!(error.kind());
      return;
    }
  };
  if entry
    .frames
    .send(SessionFrame {
      kind: PacketKind::Open,
      body,
    })
    .await
    .is_err()
  {
    withdraw_pending(&entry, &trace_id);
    request.reject(ErrorKind::StreamInterrupted);
    terminal!(ErrorKind::StreamInterrupted);
    return;
  }
  trace!("packet open queued");

  // Wait for the destination's current-process admission before streaming
  // body chunks; a dead session resolves the wait with StreamInterrupted.
  let outcome: AckOutcome = ack_rx.await.unwrap_or(Err(ErrorKind::StreamInterrupted));
  let failure = outcome.as_ref().err().copied();
  let routed_ack: crate::packet::RoutedAckOutcome =
    outcome.map(|admitted_at| crate::packet::RoutedAck {
      by: destination.clone(),
      admitted_at,
    });
  let _ = request.ack_notify.send(routed_ack);
  debug!(
    admitted = failure.is_none(),
    "packet admission acknowledged"
  );
  if let Some(kind) = failure {
    terminal!(kind);
    return;
  }
  update_route(&routes, &trace_id, |record| {
    record.update(RouteState::Streaming);
  });
  events.emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
    trace_id.clone(),
  )));

  let mut sequence = 0_u64;
  let mut body = request.body;
  loop {
    match std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await {
      Some(Ok(bytes)) => {
        if bytes.len() > MAX_CHUNK_BYTES {
          terminal!(ErrorKind::InvalidInput);
          return;
        }
        let forwarded = bytes.len() as u64;
        let chunk = ChunkFrame {
          trace_id: trace_id.clone(),
          sequence,
          bytes: ByteVec::from(bytes.to_vec()),
        };
        sequence = sequence.saturating_add(1);
        let encoded = match wire::encode_chunk(&chunk) {
          Ok(encoded) => encoded,
          Err(error) => {
            terminal!(error.kind());
            return;
          }
        };
        if entry
          .frames
          .send(SessionFrame {
            kind: PacketKind::Chunk,
            body: encoded,
          })
          .await
          .is_err()
        {
          terminal!(ErrorKind::StreamInterrupted);
          return;
        }
        trace!(sequence, bytes = forwarded, "packet chunk queued");
        update_route(&routes, &trace_id, |record| {
          record.forward(forwarded);
        });
      }
      None => break,
      Some(Err(error)) => {
        terminal!(error.kind());
        return;
      }
    }
  }

  let end = match wire::encode_end(&EndFrame {
    trace_id: trace_id.clone(),
  }) {
    Ok(end) => end,
    Err(error) => {
      terminal!(error.kind());
      return;
    }
  };
  let interrupted = entry
    .frames
    .send(SessionFrame {
      kind: PacketKind::End,
      body: end,
    })
    .await
    .is_err();
  if interrupted {
    terminal!(ErrorKind::StreamInterrupted);
  } else {
    update_route(&routes, &trace_id, |record| {
      record.update(RouteState::Delivered);
    });
    events.emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
      trace_id.clone(),
    )));
    record_terminal_trace(
      &trace,
      &trace_id,
      &source,
      &destination,
      crate::routing::trace::TraceTransition::Delivered,
    );
  }
  debug!(interrupted, "packet stream finished");
}

/// Fire-and-forget persistence of one durable terminal fact per packet:
/// the data plane never waits on metadata storage and intermediate
/// progress stays an in-memory observation.
fn record_terminal_trace(
  trace: &Option<crate::routing::trace::TraceSink>, trace_id: &TraceId, source: &NodeId,
  destination: &NodeId, transition: crate::routing::trace::TraceTransition,
) {
  if let Some(trace) = trace {
    let updated = crate::routing::trace::TraceRecord::new(
      trace_id.clone(),
      source.clone(),
      destination.clone(),
      trace.clock_now(),
    )
    .with_transition(transition, trace.clock_now());
    let trace = trace.clone();
    tokio::spawn(async move { trace.record(updated).await });
  }
}

#[cfg(test)]
pub(crate) fn test_queue(max_count: usize, max_bytes: usize) -> (BoundedSender, BoundedReceiver) {
  let (tx, rx) = mpsc::channel(max_count);
  let state = Arc::new(QueueState::default());
  (
    BoundedSender {
      inner: tx,
      state: Arc::clone(&state),
      max_count,
      max_bytes,
    },
    BoundedReceiver { inner: rx, state },
  )
}

/// Removes a pending admission that never reached the wire.
fn withdraw_pending(entry: &SessionEntry, trace_id: &TraceId) {
  if let Ok(mut pending) = entry.pending_acks.lock() {
    pending.remove(trace_id);
  }
}

/// Digests the immutable opening context of one open frame (endpoints,
/// protocol, canonical metadata): identical retransmissions produce the
/// same digest; any mutation produces a different one.
pub(crate) fn opening_context_digest(
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
mod replacement_tests {
  use super::{DialDirection, keep_connection};
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  /// Every completion ordering picks the same single session owner from
  /// durable identities.
  #[test]
  fn crossed_dial_converges_to_the_smaller_initiator_connection() {
    let smaller = node(1);
    let larger = node(2);

    // Smaller node keeps its outgoing dial; larger keeps its incoming one —
    // both sides converge to the smaller's connection.
    assert!(keep_connection(&smaller, &larger, DialDirection::Outgoing));
    assert!(!keep_connection(&smaller, &larger, DialDirection::Incoming));
    assert!(!keep_connection(&larger, &smaller, DialDirection::Outgoing));
    assert!(keep_connection(&larger, &smaller, DialDirection::Incoming));

    // The rule is total for every ordering: exactly one direction wins per
    // side, and the winning pair is the same connection.
    for (local, peer) in [
      (smaller.clone(), larger.clone()),
      (larger.clone(), smaller.clone()),
    ] {
      let keep_outgoing = keep_connection(&local, &peer, DialDirection::Outgoing);
      let keep_incoming = keep_connection(&local, &peer, DialDirection::Incoming);
      assert_ne!(keep_outgoing, keep_incoming);
    }
  }
}

#[cfg(test)]
mod queue_tests {
  use std::sync::Arc;

  use futures_util::FutureExt;
  use tokio::sync::mpsc;

  use super::{BoundedReceiver, BoundedSender, FRAME_OVERHEAD, QueueState, SessionFrame};
  use crate::{ErrorKind, protocol::wire::PacketKind};

  fn frame(bytes: usize) -> SessionFrame {
    SessionFrame {
      kind: PacketKind::Chunk,
      body: vec![0_u8; bytes],
    }
  }

  fn queue(max_count: usize, max_bytes: usize) -> (BoundedSender, BoundedReceiver) {
    let (tx, rx) = mpsc::channel(max_count);
    let state = Arc::new(QueueState::default());
    (
      BoundedSender {
        inner: tx,
        state: Arc::clone(&state),
        max_count,
        max_bytes,
      },
      BoundedReceiver { inner: rx, state },
    )
  }

  /// Count and byte bounds are checked atomically and a rejected frame is
  /// never partially enqueued.
  #[tokio::test]
  async fn bounded_queue_rejects_at_either_boundary_without_partial_enqueue() {
    let (sender, mut receiver) = queue(2, 1_000);

    // Two frames fit the count bound.
    sender.send(frame(10)).await.unwrap();
    sender.send(frame(20)).await.unwrap();
    // Third exceeds the count bound.
    let error = sender.send(frame(5)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Overloaded);
    assert_eq!(error.context(), "session queue");

    // Drain one; the queue admits again at the count boundary.
    let _ = receiver.recv().await.unwrap();
    sender.send(frame(5)).await.unwrap();

    // Byte bound: a single oversized frame is rejected outright.
    let (byte_sender, mut byte_receiver) = queue(16, FRAME_OVERHEAD + 32);
    let error = byte_sender.send(frame(64)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Overloaded);
    // Nothing was enqueued by the rejected frame (a recv would hang).
    assert!(byte_receiver.recv().now_or_never().is_none());
  }

  #[tokio::test]
  async fn bounded_queue_recovers_after_drain() {
    let (sender, mut receiver) = queue(1, 1_000);
    sender.send(frame(10)).await.unwrap();
    assert_eq!(
      sender.send(frame(10)).await.unwrap_err().kind(),
      ErrorKind::Overloaded
    );
    let _ = receiver.recv().await.unwrap();
    sender.send(frame(10)).await.unwrap();
    let _ = receiver.recv().await.unwrap();
  }
}

#[cfg(test)]
mod liveness_tests {
  use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::AtomicU64},
    time::{Duration, UNIX_EPOCH},
  };

  use tokio::sync::{oneshot, watch};

  use super::{PendingAcks, liveness_observer};
  use crate::storage::contract::helpers::ManualClock;

  fn no_pending() -> PendingAcks {
    Arc::new(Mutex::new(HashMap::new()))
  }

  /// While host wall time advances normally, only sessions without
  /// authenticated traffic or owned in-flight work close after the
  /// configured idle deadline.
  #[tokio::test(start_paused = true)]
  async fn idle_closes_at_the_deadline_only_without_owned_work() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let pending = no_pending();
    let (ping_tx, _) = watch::channel(());
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Before the deadline the observer stays alive.
    clock.set(UNIX_EPOCH + Duration::from_secs(109));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // Owned in-flight work holds the session past the deadline.
    let held = no_pending();
    let held_handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let held = Arc::clone(&held);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &held,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });
    clock.set(UNIX_EPOCH + Duration::from_secs(200));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!held_handle.is_finished());

    // At the deadline with no work the observer resolves.
    clock.set(UNIX_EPOCH + Duration::from_secs(110));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// Clock rollback or freeze delays closure and a forward jump makes it
  /// immediately due.
  #[tokio::test(start_paused = true)]
  async fn idle_respects_clock_rollback_and_forward_jumps() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let (ping_tx, _) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Rollback keeps the session alive (deadline recedes).
    clock.set(UNIX_EPOCH + Duration::from_secs(50));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // A forward jump makes the deadline immediately due.
    clock.set(UNIX_EPOCH + Duration::from_secs(500));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// A peer missing the keepalive result is closed after the keepalive
  /// deadline.
  #[tokio::test(start_paused = true)]
  async fn keepalive_closes_a_peer_missing_the_result() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000)));
    let last_activity = Arc::new(AtomicU64::new(1_000));
    let (ping_tx, mut ping_rx) = watch::channel(());
    let pending = no_pending();
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::ZERO,
          Duration::from_secs(5),
          Duration::from_secs(10),
          &ping_tx,
        )
        .await
      }
    });

    // After the keepalive interval a ping fires.
    clock.set(UNIX_EPOCH + Duration::from_secs(1_005));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(ping_rx.changed().await.is_ok());

    // The peer never answers: after the keepalive timeout the observer
    // resolves (session closes).
    clock.set(UNIX_EPOCH + Duration::from_secs(1_015));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }

  /// The owned-work hold-off is itself deadline-bounded — a waiting
  /// admission older than the idle deadline no longer exempts the
  /// session, so a peer that never acknowledges cannot hold it open
  /// forever.
  #[tokio::test(start_paused = true)]
  async fn stale_owned_work_no_longer_blocks_the_idle_close() {
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(100)));
    let last_activity = Arc::new(AtomicU64::new(100));
    let pending = no_pending();
    {
      let (notify, _wait) = oneshot::channel();
      pending.lock().unwrap().insert(
        crate::TraceId::parse("trace_000000000000000000001").unwrap(),
        super::PendingAck::Wait {
          notify,
          queued_at: 100,
        },
      );
    }
    let (ping_tx, _) = watch::channel(());
    let handle = tokio::spawn({
      let last_activity = Arc::clone(&last_activity);
      let pending = Arc::clone(&pending);
      let clock = clock.clone();
      let ping_tx = ping_tx.clone();
      async move {
        liveness_observer(
          &last_activity,
          &pending,
          clock,
          Duration::from_secs(10),
          Duration::ZERO,
          Duration::ZERO,
          &ping_tx,
        )
        .await
      }
    });

    // Fresh owned work still holds the session open.
    clock.set(UNIX_EPOCH + Duration::from_secs(109));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!handle.is_finished());

    // Once the oldest waiting admission is a full idle deadline old, the
    // hold-off expires and the idle close proceeds.
    clock.set(UNIX_EPOCH + Duration::from_secs(110));
    tokio::time::advance(Duration::from_secs(2)).await;
    handle.await.unwrap();
  }
}

#[cfg(test)]
mod pending_admission_tests {
  use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, UNIX_EPOCH},
  };

  use tokio::sync::{mpsc, oneshot, watch};

  use super::{
    BoundedSender, DialDirection, PendingAck, PendingAcks, QueueState, RouteTable, SessionEntry,
    SessionMeta, run_outbound,
  };
  use crate::{
    ErrorKind, NodeId, ProtocolTag, StreamMetadata, StreamTarget, TraceId, packet::StaticBody,
    storage::contract::helpers::ManualClock,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  /// A session entry whose pending map is pre-filled with relayed
  /// admissions, ready for one more outbound pump.
  fn saturated_entry(pending_admissions: usize) -> SessionEntry {
    let (frames_tx, _frames_rx) = mpsc::channel(8);
    let frames = BoundedSender {
      inner: frames_tx,
      state: Arc::new(QueueState::default()),
      max_count: 8,
      max_bytes: 1 << 20,
    };
    let pending_acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
    for seed in 0..pending_admissions {
      let trace_id = TraceId::parse(&format!("trace_{seed:021}")).unwrap();
      pending_acks.lock().unwrap().insert(
        trace_id,
        PendingAck::Relay {
          upstream: frames.clone(),
        },
      );
    }
    let (retire, _) = watch::channel(());
    SessionEntry {
      frames,
      pending_acks,
      pending_admissions,
      clock: Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1))),
      meta: Arc::new(SessionMeta {
        id: crate::SessionId::parse("session_000000000000000000001").unwrap(),
        generation: 1,
        endpoint: crate::Endpoint::parse("wss://saturated:9000").unwrap(),
        features: Vec::new(),
      }),
      alive: Arc::new(AtomicBool::new(true)),
      direction: DialDirection::Outgoing,
      retire,
    }
  }

  /// A session at its concurrent-admission bound rejects a new outbound
  /// open with typed `Overloaded` backpressure instead of growing the
  /// pending map without limit.
  #[tokio::test]
  async fn admission_bound_rejects_new_opens_with_overloaded() {
    let entry = saturated_entry(4);
    let (ack_tx, ack_rx) = oneshot::channel();
    let request = crate::packet::OutboundRequest {
      trace_id: TraceId::parse("trace_000000000000000000099").unwrap(),
      target: StreamTarget::Exact(node(2)),
      load_balancer: None,
      max_hops: 1,
      protocol: ProtocolTag::parse("radiata.woooo.tech/protocols/test").unwrap(),
      metadata: StreamMetadata::new(),
      body: Box::pin(StaticBody::new(Arc::from(&b"x"[..]))),
      internal: true,
      ack_notify: ack_tx,
    };
    let routes: RouteTable = Arc::new(Mutex::new(BTreeMap::new()));
    run_outbound(
      entry,
      node(1),
      request,
      routes,
      false,
      None,
      Arc::new(crate::node::EventHub::new()),
    )
    .await;
    assert_eq!(
      ack_rx.await.ok().and_then(|outcome| outcome.err()),
      Some(ErrorKind::Overloaded)
    );
  }
}

#[cfg(test)]
mod admission_tests {
  use std::{collections::BTreeMap, sync::Arc};

  use minicbor::bytes::ByteVec;

  use super::opening_context_digest;
  use crate::{
    NodeId, ProtocolTag, QualifiedTag, StreamMetadata, TraceId, identity::signature::body_digest,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace_{seed:021}")).unwrap()
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
    let routes: super::RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    super::record_rejection(&routes, 8, &trace(9), crate::ErrorKind::Unsupported);
    super::record_rejection(&routes, 8, &trace(9), crate::ErrorKind::Unsupported);

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
    let routes: super::RouteTable = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    for seed in 1..=4 {
      super::record_rejection(&routes, 3, &trace(seed), crate::ErrorKind::Unsupported);
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
