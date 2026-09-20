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
//!
//! Module boundary: routing-domain concepts (the forwarding table,
//! relayed acknowledgements, envelope validation) live in
//! `crate::routing`; this module owns only the session infrastructure
//! they attach to.

use std::{
  collections::{BTreeMap, HashMap},
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use tokio::sync::{oneshot, watch};
use tracing::{debug, instrument, trace, warn};

#[cfg(test)]
pub(crate) use super::queue::test_queue;
pub(crate) use super::queue::{BoundedReceiver, BoundedSender, SessionFrame};
use super::{driver::EstablishedSession, inbound::read_loop, liveness::liveness_observer};
use crate::{
  ErrorKind, NodeId, QualifiedTag, Result, TraceId,
  extension_registry::ExtensionRegistry,
  routing::{
    forward::{self, PendingAck, PendingAcks},
    table::RouteTable,
  },
  transport::connection::{Connection, ConnectionWriter},
};

/// The shared node-local session table: authenticated peer to live (or
/// dead, pending replacement) session entry.
pub(crate) type SessionTable = Arc<Mutex<BTreeMap<NodeId, SessionEntry>>>;

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
  pub(super) local: NodeId,
  pub(super) registry: Arc<ExtensionRegistry>,
  pub(super) policy: SessionPolicy,
  pub(super) runtime: crate::runtime::RuntimeClient,
  pub(super) clock: Arc<dyn crate::time::WallClock>,
  /// Injected entropy for per-session identifiers.
  pub(super) entropy: Arc<dyn crate::api::Entropy>,
  /// The typed event hub: session and route transitions emit through it.
  pub(super) events: Arc<crate::node::EventHub>,
  pub(super) forwarding: crate::routing::forward::ForwardingTable,
  pub(super) route_policy: QualifiedTag,
  pub(super) sessions: SessionTable,
  pub(super) routes: RouteTable,
  pub(super) forwarding_capacity: usize,
  /// The node's configured bound on in-memory terminal route records;
  /// admission rejections must respect it like every other writer.
  pub(super) route_capacity: usize,
  /// The node-scoped tracked task vec: session-exit consumer drains join
  /// it so a teardown cannot abort an in-flight apply unnoticed.
  pub(super) task_drains: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
  pub(super) parser_limits: crate::protocol::CborLimits,
}

impl SessionPacketContext {
  /// The argument list mirrors the context's node-shared collaborators; no
  /// subset forms a meaningful grouping.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    local: NodeId, registry: Arc<ExtensionRegistry>, policy: SessionPolicy,
    runtime: crate::runtime::RuntimeClient, clock: Arc<dyn crate::time::WallClock>,
    entropy: Arc<dyn crate::api::Entropy>, events: Arc<crate::node::EventHub>,
    route_policy: QualifiedTag, sessions: SessionTable, routes_clone: RouteTable,
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

  /// The node's effective next-hop routing policy tag (the caller
  /// selection, or the built-in default policy's tag).
  pub(crate) const fn route_policy(&self) -> &QualifiedTag {
    &self.route_policy
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
  pub(crate) pending_admissions: usize,
  pub(crate) clock: Arc<dyn crate::time::WallClock>,
  /// The public session metadata.
  pub(crate) meta: Arc<SessionMeta>,
  alive: Arc<AtomicBool>,
  direction: DialDirection,
  /// Whether the recovery plane (not the caller) dialed this session:
  /// pruning only ever retires recovery-dialed edges — caller-configured
  /// and inbound sessions are never reclaimed by the pruning pass.
  recovery_dialed: bool,
  retire: watch::Sender<()>,
}

impl SessionEntry {
  /// Whether the session's reader loop is still serving the connection.
  pub(crate) fn alive(&self) -> bool {
    self.alive.load(Ordering::SeqCst)
  }

  /// Whether the recovery plane dialed this session (prunable on
  /// redundancy; see the bounded pruning pass in the recovery tick).
  pub(crate) fn recovery_dialed(&self) -> bool {
    self.recovery_dialed
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
  attachment: crate::Endpoint, registered: Option<oneshot::Sender<()>>, recovery_dialed: bool,
) {
  let peer = session.peer().clone();
  let (writer, mut reader) = connection.into_split();
  let (frames, frames_rx) =
    BoundedSender::channel(context.policy.queue_messages, context.policy.queue_bytes);
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
    recovery_dialed,
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
  let (interrupted, relays) = fail_pending_waits(&pending_acks);
  if interrupted > 0 {
    debug!(interrupted, "session closed pending admissions");
  }
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
pub(crate) fn clock_seconds(clock: &dyn crate::time::WallClock) -> u64 {
  crate::time::to_seconds(clock.now())
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

/// Tears down every registered session at node shutdown: each entry's
/// pending admissions fail exactly once and its frame sender drops, so
/// even a session task whose abort landed before the graceful shutdown
/// signal (skipping its exit cleanup) still closes its writer and
/// connection — a peer observes the teardown either way.
pub(crate) fn retire_all_sessions(table: &SessionTable) -> Result<()> {
  let entries: Vec<SessionEntry> = {
    let mut guard = table.lock().map_err(crate::Error::session_table)?;
    std::mem::take(&mut *guard).into_values().collect()
  };
  for entry in &entries {
    retire(entry);
  }
  Ok(())
}

/// Drains one replaced session: it stops accepting new work, its pending
/// admissions fail exactly once with `StreamInterrupted`, and the retire
/// signal closes its reader so the connection tears down after the winner
/// is registered.
fn retire(entry: &SessionEntry) {
  entry.alive.store(false, Ordering::SeqCst);
  let (_, relays) = fail_pending_waits(&entry.pending_acks);
  for (trace_id, upstream) in relays {
    // Best-effort relay of the interruption; a saturated queue
    // cannot be repaired here and the upstream liveness policy
    // bounds the wait regardless.
    upstream.try_send_status(&trace_id, crate::packet::wire::AckStatus::Failed);
  }
  let _ = entry.retire.send(());
}

/// Drains one session's pending admission acks, failing every local
/// waiter with the typed interruption, and returns the count plus the
/// forwarded hops' upstream senders for the caller's relay handling.
fn fail_pending_waits(pending_acks: &PendingAcks) -> (usize, Vec<(TraceId, BoundedSender)>) {
  let mut relays = Vec::new();
  let mut interrupted = 0_usize;
  if let Ok(mut pending) = pending_acks.lock() {
    interrupted = pending.len();
    for (trace_id, ack) in pending.drain() {
      match ack {
        PendingAck::Wait { notify, .. } => {
          let _ = notify.send(Err(ErrorKind::StreamInterrupted));
        }
        PendingAck::Relay { upstream } => relays.push((trace_id, upstream)),
      }
    }
  }
  (interrupted, relays)
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

/// Test-only: a live session entry around a test queue, so sync-layer
/// tests can drive per-peer dispatch without a real connection.
#[cfg(test)]
pub(crate) fn test_entry(entropy: &dyn crate::api::Entropy) -> (SessionEntry, BoundedReceiver) {
  let (frames, receiver) = test_queue(256, 8 * 1_024 * 1_024);
  let entry = SessionEntry {
    frames,
    pending_acks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    pending_admissions: MAX_PENDING_ADMISSIONS,
    clock: Arc::new(crate::time::HostWallClock),
    meta: Arc::new(SessionMeta {
      id: crate::SessionId::generate(entropy).unwrap(),
      generation: 0,
      endpoint: crate::Endpoint::parse("wss://127.0.0.1:9").unwrap(),
      features: Vec::new(),
    }),
    alive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    direction: DialDirection::Outgoing,
    recovery_dialed: false,
    retire: watch::channel(()).0,
  };
  (entry, receiver)
}

#[cfg(test)]
mod replacement_tests {
  use super::{DialDirection, keep_connection};
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
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
mod pending_admission_tests {
  use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, UNIX_EPOCH},
  };

  use tokio::sync::{oneshot, watch};

  use super::{
    BoundedSender, DialDirection, PendingAck, PendingAcks, RouteTable, SessionEntry, SessionMeta,
  };
  use crate::{
    ErrorKind, NodeId, ProtocolTag, StreamMetadata, StreamTarget, TraceId, packet::StaticBody,
    routing::outbound::run_outbound, storage::contract::helpers::ManualClock,
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  /// A session entry whose pending map is pre-filled with relayed
  /// admissions, ready for one more outbound pump.
  fn saturated_entry(pending_admissions: usize) -> SessionEntry {
    let (frames, _frames_rx) = BoundedSender::channel(8, 1 << 20);
    let pending_acks: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
    for seed in 0..pending_admissions {
      let trace_id = TraceId::parse(&format!("trace-{seed:021}")).unwrap();
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
        id: crate::SessionId::parse("session-000000000000000000001").unwrap(),
        generation: 1,
        endpoint: crate::Endpoint::parse("wss://saturated:9000").unwrap(),
        features: Vec::new(),
      }),
      alive: Arc::new(AtomicBool::new(true)),
      direction: DialDirection::Outgoing,
      recovery_dialed: false,
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
      trace_id: TraceId::parse("trace-000000000000000000099").unwrap(),
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
