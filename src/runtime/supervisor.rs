use std::{collections::BTreeMap, sync::Arc};

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};

use super::{
  anti_entropy::spawn_sync_driver,
  task_manager::{TaskManagerHandle, spawn_task_manager},
};
use crate::{
  Endpoint, Error, NodeConfig, NodeId, Result, ShutdownOutcome, ShutdownReason,
  api::Entropy,
  extension_registry::ExtensionRegistry,
  identity::{
    credential::MergeCredentialIssuer,
    lifecycle::{LocalIdentityContext, ensure_self_binding, open_local_identity},
  },
  protocol::offer::node_offer,
  provider::{KeyProvider, StorageFactory},
  routing::RouteTable,
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
  session::{
    SessionDriver,
    stream::{SessionPacketContext, SessionTable, run_session},
  },
  transport::registry::{Transport, TransportListener, TransportTrust},
};

const CONTROL_CAPACITY: usize = 32;

/// Capacity of the node's outbound packet command channel:
/// `PACKET_CHANNEL_CAPACITY` derives from it so one bound governs both
/// control ends.
///
/// The bounded channel for immediate sync-round requests forwarded to
/// the sync driver (the cursor owner; the `SyncRound` task effect holds
/// a sender): rounds are self-limiting (one page per session per
/// round), so a small queue with typed backpressure matches the work.
pub(crate) const SYNC_ROUND_CHANNEL_CAPACITY: usize = 8;

pub(crate) const PACKET_CHANNEL_CAPACITY: usize = CONTROL_CAPACITY;

/// One bound listener's supervisor-side entry: the published endpoint,
/// the listener handle, and the abort handle of its accept loop.
pub(crate) type ListenerEntry = (Endpoint, std::sync::Arc<dyn TransportListener>, AbortHandle);

/// The node's bound listeners, shared by the supervisor's pages, the
/// leave teardown, and the task manager's listen/stop effects: one
/// registry, mutated under one lock.
pub(crate) type ListenerRegistry =
  Arc<std::sync::Mutex<BTreeMap<crate::identity::ListenerId, ListenerEntry>>>;

struct LifecyclePublisher {
  state: watch::Sender<LifecycleSnapshot>,
  terminal: bool,
}

impl LifecyclePublisher {
  fn new(state: watch::Sender<LifecycleSnapshot>) -> Self {
    Self {
      state,
      terminal: false,
    }
  }

  fn publish(&self, snapshot: LifecycleSnapshot) {
    self.state.send_replace(snapshot);
  }

  fn stop(&mut self, reason: ShutdownReason) {
    self.publish(LifecycleSnapshot::stopped(reason));
    self.terminal = true;
  }
}

impl Drop for LifecyclePublisher {
  fn drop(&mut self) {
    if !self.terminal {
      self.state.send_replace(LifecycleSnapshot::failed());
    }
  }
}

pub(crate) struct RuntimeDependencies {
  pub(crate) storage_factory: Arc<dyn StorageFactory>,
  pub(crate) context: Option<Arc<LocalIdentityContext>>,
  /// The caller's custody injection, if any. `open_local_identity`
  /// resolves `None` to the default store-backed provider, and the
  /// resolved provider lives on the identity context; this field is only
  /// the pre-open injection.
  pub(crate) keys: Option<Arc<dyn KeyProvider>>,
  pub(crate) config: NodeConfig,
  pub(crate) entropy: Arc<dyn Entropy>,
  pub(crate) extensions: Arc<ExtensionRegistry>,
  pub(crate) sessions: SessionTable,
  pub(crate) routes: RouteTable,
  /// The typed event hub shared with every node handle.
  pub(crate) events: Arc<crate::node::EventHub>,
  /// The node's member-set revision signal: bumped one-to-one with the
  /// MemberChanged emissions so observers await changes instead of
  /// polling pages.
  pub(crate) member_revision: crate::node::MemberRevisionSignal,
  /// The leave-plane applied-receipt signal: the membership sync
  /// consumer bumps it when this node durably installs a peer's leave
  /// applied receipt addressed to this node.
  pub(crate) leave_applied: crate::membership::sync::LeaveAppliedSignal,
  /// The reconciliation plane shared by the registered consumer and the
  /// anti-entropy driver: created in `spawn_runtime` when the
  /// reconcile v1 protocol registers, consumed by `supervise` when the
  /// sync driver spawns.
  pub(crate) reconcile: Option<crate::reconcile::plane::ReconcilePlane>,
  /// Requests for one immediate anti-entropy round, forwarded to the
  /// sync driver (the cursor owner) by the RunSyncRound command.
  pub(crate) sync_round_requests: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<()>>,
  /// Node-scoped task handles: connection tasks plus the graceful
  /// consumer-drain tasks. Shutdown awaits them and the recovery tick
  /// reaps finished ones (bounded task accounting).
  pub(crate) connection_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
  /// The node's bound listeners: the supervisor's pages and leave teardown
  /// read the same registry the task manager's listen/stop effects mutate.
  pub(crate) listeners: ListenerRegistry,
  /// The task manager's teardown handle: the shutdown path closes its
  /// admission, broadcasts its cancel watch, and drains it before the
  /// node's own task set is shut down.
  pub(crate) task_manager: Option<TaskManagerHandle>,
  /// The node-shared operation handles: the session driver, packet
  /// context, shutdown signal, and the effect-side collaborators every
  /// migrated mutating verb reads. Built here (one construction site)
  /// and read by the supervisor, the verb effects, and every node
  /// handle.
  pub(crate) operations: Option<Arc<super::task_effects::OperationDeps>>,
  /// The 32-byte runtime seed drawn once at startup, before identity
  /// provisioning. Deliberately reserved and pinned by the lifecycle
  /// entropy-sequence test.
  pub(crate) runtime_seed: Option<[u8; 32]>,
}

pub(crate) async fn spawn_runtime(
  mut dependencies: RuntimeDependencies,
  packets: (
    mpsc::Sender<crate::packet::OutboundRequest>,
    mpsc::Receiver<crate::packet::OutboundRequest>,
  ),
  sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
) -> Result<RuntimeClient> {
  let runtime = Handle::try_current().map_err(|_| Error::not_ready("Tokio runtime"))?;
  // The runtime seed is drawn before anything else so the startup entropy
  // budget stays exactly the sequence the lifecycle test pins.
  let mut runtime_seed = [0; 32];
  dependencies.entropy.fill(&mut runtime_seed)?;
  dependencies.runtime_seed = Some(runtime_seed);
  // Every dial and listen resolves its transport from the endpoint's
  // selector through the extension registry at call time (the built-in
  // tags merged with caller registrations), so configured attempts stay
  // observable at one boundary per transport.
  let receipt_retention = dependencies.config.receipt_retention();
  let context = open_local_identity(
    &dependencies.storage_factory,
    dependencies.keys.as_ref(),
    dependencies.entropy.as_ref(),
    receipt_retention,
  )
  .await?;
  let context = {
    // Born-with-cluster: every started node holds
    // its own immutable identity binding, so it is a singleton cluster of
    // one and merge union needs no genesis ceremony.
    ensure_self_binding(&context, dependencies.entropy.as_ref()).await?;
    Arc::new(context)
  };
  dependencies.context = Some(context);
  // The core membership sync protocol is registered before the runtime is
  // marked ready: a caller that registered the same tag fails `start`
  // with a typed conflict instead of a spawned-task panic.
  let sync_definition = crate::membership::sync::sync_protocol_definition()?;
  let runtime_context = Arc::clone(
    dependencies
      .context
      .as_ref()
      .ok_or_else(|| Error::internal("runtime context"))?,
  );
  let sync_consumer = Arc::new(crate::membership::sync::MembershipSyncConsumer::new(
    Arc::clone(&runtime_context),
    dependencies.entropy.clone(),
    dependencies.events.clone(),
    dependencies.member_revision.clone(),
    dependencies.leave_applied.clone(),
  ));
  dependencies
    .extensions
    .register_core_protocol(sync_definition, sync_consumer)?;
  // The core reconciliation plane rides the same authenticated sessions
  // as the sync lanes: one consumer for the reconcile v1 protocol, one
  // shared plane behind it (the anti-entropy driver ticks the same
  // plane once the supervisor spawns it).
  let reconcile_plane = crate::reconcile::plane::ReconcilePlane::new(
    Arc::clone(&runtime_context),
    dependencies.entropy.clone(),
    dependencies.events.clone(),
    dependencies.member_revision.clone(),
    dependencies.sessions.clone(),
  );
  let reconcile_consumer = Arc::new(crate::reconcile::plane::ReconcileConsumer::new(
    reconcile_plane.shared(),
  ));
  dependencies.extensions.register_core_protocol(
    crate::reconcile::plane::ReconcilePlane::protocol_definition()?,
    reconcile_consumer,
  )?;
  dependencies.reconcile = Some(reconcile_plane);
  // The negotiation registry and the node offer are built before the
  // runtime is marked ready (the core protocols above joined the feature
  // set): a provisioning failure (a caller-required feature outside the
  // registry) is a typed start() error, never a running node that
  // silently stopped.
  let mut definitions = crate::protocol::feature::builtin_definitions()?;
  definitions.extend(dependencies.extensions.feature_definitions());
  // The merged registry is shared with the session driver (Arc): the same
  // set that built the node offer drives every handshake selection, so
  // caller-registered features survive into the negotiated intersection.
  let registry = Arc::new(crate::protocol::feature::FeatureRegistry::build(
    definitions,
  )?);
  let offer = node_offer(&registry, dependencies.config.required_features())?;
  let routes = dependencies.routes.clone();
  let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();
  let (packet_tx, packet_rx) = packets;
  // The node-shared operation handles are built here rather than inside
  // the supervisor: the supervisor's own fields, the verb effects, and
  // every node handle must read the same session driver (one credential
  // issuer, one SPKI anchor table), the same packet context, and the same
  // shutdown signal.
  let operations = operation_deps(&dependencies, packet_tx.clone(), offer, registry)?;
  dependencies.operations = Some(Arc::clone(&operations));
  // The task manager is spawned here, beside the supervisor and before the
  // node is marked running: the client side rides the node handle (so an
  // admitted task always has a live manager) and the teardown handle rides
  // the runtime dependencies (so the shutdown path drains it in order).
  let (leave_complete, leave_signals) = mpsc::channel(1);
  let (task_client, task_manager) = spawn_task_manager(super::task_manager::TaskManagerDeps {
    entropy: dependencies.entropy.clone(),
    clock: Arc::new(crate::time::HostWallClock),
    operations,
    leave_complete,
  })?;
  dependencies.task_manager = Some(task_manager);
  let client = RuntimeClient::new(
    control_tx,
    state_rx,
    routes,
    packet_tx.clone(),
    Some(task_client),
  );

  runtime.spawn(supervise(
    dependencies,
    (packet_tx, packet_rx),
    sync_rounds,
    RuntimeSignals {
      control: control_rx,
      leave_complete: leave_signals,
      state: state_tx,
      ready: ready_tx,
    },
  ));

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(client)
}

/// The runtime's signal ends, grouped so the start-up call cannot
/// transpose two same-typed channels.
struct RuntimeSignals {
  control: mpsc::Receiver<Control>,
  /// The task manager's leave-completion signal (see `finish_shutdown`).
  leave_complete: mpsc::Receiver<()>,
  state: watch::Sender<LifecycleSnapshot>,
  ready: oneshot::Sender<()>,
}

async fn supervise(
  dependencies: RuntimeDependencies,
  packets: (
    mpsc::Sender<crate::packet::OutboundRequest>,
    mpsc::Receiver<crate::packet::OutboundRequest>,
  ),
  sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>, signals: RuntimeSignals,
) {
  let RuntimeSignals {
    mut control,
    mut leave_complete,
    state,
    ready,
  } = signals;
  let (packet_tx, mut packet_rx) = packets;
  let mut tasks = JoinSet::<()>::new();
  let mut lifecycle = LifecyclePublisher::new(state);
  lifecycle.publish(LifecycleSnapshot::running());
  if ready.send(()).is_err() {
    finish_shutdown(
      control,
      tasks,
      dependencies,
      Vec::new(),
      &mut lifecycle,
      None,
      ShutdownReason::Explicit,
    )
    .await;
    return;
  }

  let mut supervisor = match Supervisor::new(dependencies, packet_tx, sync_rounds) {
    Ok(supervisor) => supervisor,
    Err(failure) => {
      // Unreachable today: the offer was built in spawn_runtime before
      // the runtime was marked ready, so the only remaining failure is
      // the internal context invariant. Publish Fatal anyway — a
      // provisioning failure can never mask as an explicit shutdown.
      let (error, dependencies) = *failure;
      tracing::error!(kind = ?error.kind(), "supervisor provisioning failed");
      lifecycle.publish(LifecycleSnapshot::failed());
      finish_shutdown(
        control,
        tasks,
        dependencies,
        Vec::new(),
        &mut lifecycle,
        None,
        ShutdownReason::Fatal(error.kind()),
      )
      .await;
      return;
    }
  };
  // Any trace records still non-terminal from a previous incarnation
  // terminate explicitly at startup: a restart never continues a body.
  if let Some(context) = supervisor.dependencies.context.as_ref()
    && let Err(error) = crate::routing::trace::terminate_stale(
      context.store(),
      supervisor.dependencies.entropy.as_ref(),
      &crate::time::HostWallClock,
    )
    .await
  {
    tracing::warn!(kind = ?error.kind(), "stale trace termination failed");
  }
  // The periodic planes run OFF the select loop (audit 2026-10-09
  // item 3): one long-lived recovery-observation worker (recovery tick
  // plus the three retention sweeps) and one degree-maintenance worker,
  // each owning its own timer, so slow storage or a slow policy no
  // longer parks control-plane reads and packet admission behind a
  // tick. Bounded accounting (audit item 4's lesson): exactly two tasks
  // for the node's lifetime, aborted and awaited by the shutdown path —
  // never one spawned task per tick.
  let tick_workers = match supervisor.tick_state() {
    Ok(ticks) => {
      let ticks = std::sync::Arc::new(ticks);
      vec![
        tokio::spawn(super::recovery::run_recovery_worker(std::sync::Arc::clone(
          &ticks,
        ))),
        tokio::spawn(super::degree::run_maintenance_worker(ticks)),
      ]
    }
    Err(error) => {
      // Unreachable today: `Supervisor::new` already validated the
      // operation handles `tick_state` reads. A provisioning failure
      // still tears down with the fatal reason, never a silent
      // half-running node.
      tracing::error!(kind = ?error.kind(), "tick worker provisioning failed");
      let (dependencies, drained) = supervisor.into_dependencies();
      finish_shutdown(
        control,
        tasks,
        dependencies,
        drained,
        &mut lifecycle,
        None,
        ShutdownReason::Fatal(error.kind()),
      )
      .await;
      return;
    }
  };
  supervisor.tick_workers = tick_workers;
  // The leave effect's completion signal: once it lands, the caller has
  // already observed the task's terminal outcome (the publication precedes
  // the signal) and the node tears down with the active-leave reason. A
  // closed channel means the manager (the sender's only owner) is gone, so
  // the arm is disabled rather than polled again.
  let mut leave_signals_open = true;
  loop {
    tokio::select! {
      message = control.recv() => {
        let Some(message) = message else {
          break;
        };
        match message {
      Control::Shutdown { reply } => {
        let (dependencies, drained) = supervisor.into_dependencies();
        finish_shutdown(
          control,
          tasks,
          dependencies,
          drained,
          &mut lifecycle,
          Some(reply),
          ShutdownReason::Explicit,
        )
        .await;
        return;
      }
      Control::GetLocalNode { reply } => {
        let result = supervisor.local_node().await;
        let _ = reply.send(result);
      }
      Control::GetMember { node, reply } => {
        let result = supervisor.member(node).await;
        let _ = reply.send(result);
      }
      Control::GetRecovery { reply } => {
        let _ = reply.send(Ok(supervisor.recovery_view()));
      }
      Control::GetConnectionDegree { reply } => {
        let result = supervisor.connection_degree_view().await;
        let _ = reply.send(result);
      }
      Control::PageMembers { cursor, limit, reply } => {
        let result = supervisor.page_members(cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::SelectResources {
        selector,
        cursor,
        limit,
        reply,
      } => {
        let result = supervisor.select_resources(&selector, cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::GetResource { name, reply } => {
        let result = supervisor.get_resource(&name).await;
        let _ = reply.send(result);
      }
      Control::PageResources { cursor, limit, reply } => {
        let result = supervisor.page_resources(cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::PageListeners { cursor, limit, reply } => {
        let result = supervisor.page_listeners(cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::PageSessions { cursor, limit, reply } => {
        let result = supervisor.page_sessions(cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::PageTopology { cursor, limit, reply } => {
        let result = supervisor.page_topology(cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::PageTrust { cursor, limit, reply } => {
        let result = supervisor.page_trust(cursor, limit).await;
        let _ = reply.send(result);
      }
      Control::Observability { reply } => {
        let result = supervisor.observability_snapshot(&tasks).await;
        let _ = reply.send(result);
      }
        }
      }
      request = packet_rx.recv() => {
        let Some(request) = request else {
          continue;
        };
        // Deliberately INLINE (audit 2026-10-09 item 3, partial): the
        // packet arm is the node's admission backpressure point — the
        // bounded command channel plus this await is what paces the
        // outbound pump population. The storage IO it awaits is
        // per-request bounded (one descriptor snapshot plus one
        // authoritative descriptor read for matching-node targets; one
        // policy resolution plus one session-table lock for forwarded
        // targets), and the route record must land before the pump
        // starts so asynchronous senders observe the admission
        // decision. Externalizing that resolution would relocate the
        // same serialization into a bounded admission worker while
        // breaking the record-before-pump ordering, so the structural
        // cost exceeds the win; the periodic ticks (the unbounded
        // latency source) are the ones that moved off-loop.
        let _ = supervisor.send_packet(request, &mut tasks).await;
      }
      finished = tasks.join_next(), if !tasks.is_empty() => {
        // Reap finished packet tasks as they complete instead of
        // letting their handles accumulate in the JoinSet until
        // shutdown (audit 2026-10-09, item 4): the set stays bounded
        // by the live pump count. A join error (a panicked or aborted
        // pump) stays visible as a diagnostic.
        if let Some(Err(error)) = finished {
          tracing::warn!(%error, "packet task exited abnormally");
        }
      }
      signal = leave_complete.recv(), if leave_signals_open => {
        match signal {
          Some(()) => {
            let (dependencies, drained) = supervisor.into_dependencies();
            finish_shutdown(
              control,
              tasks,
              dependencies,
              drained,
              &mut lifecycle,
              None,
              ShutdownReason::ActiveLeave,
            )
            .await;
            return;
          }
          None => leave_signals_open = false,
        }
      }
    }
  }
  let (dependencies, drained) = supervisor.into_dependencies();
  finish_shutdown(
    control,
    tasks,
    dependencies,
    drained,
    &mut lifecycle,
    None,
    ShutdownReason::Explicit,
  )
  .await;
}

/// The shutdown sequence shared by the explicit, fatal, and active-leave
/// exits: the control channel closes, the task manager drains (the
/// journaled kinds run to their terminal phase), the runtime's own task
/// set tears down, and every queued shutdown reply answers with the one
/// reason.
async fn finish_shutdown(
  mut control: mpsc::Receiver<Control>, mut tasks: JoinSet<()>,
  mut dependencies: RuntimeDependencies, drained: Vec<tokio::task::JoinHandle<()>>,
  lifecycle: &mut LifecyclePublisher, first_reply: Option<oneshot::Sender<ShutdownOutcome>>,
  reason: ShutdownReason,
) {
  lifecycle.publish(LifecycleSnapshot::shutting_down());
  control.close();

  // The task manager goes first: it stops admitting, releases every
  // cancellable effect, and awaits the journaled kinds (leave,
  // frozen-journal resolution) to their terminal phase. Only then does the
  // node's own task set shut down — the effects still need the storage and
  // session machinery this teardown releases.
  if let Some(manager) = dependencies.task_manager.take() {
    manager.begin_shutdown();
    manager.drain().await;
  }

  let mut queued_replies = Vec::with_capacity(CONTROL_CAPACITY);
  while let Ok(Control::Shutdown { reply }) = control.try_recv() {
    queued_replies.push(reply);
  }
  tasks.shutdown().await;
  // Await the aborted accept-side and anti-entropy driver tasks so their
  // storage captures are dropped before the shutdown reply returns (a
  // restarted node on the same factory must not race the release).
  for handle in drained {
    let _ = handle.await;
  }
  drop(control);
  drop(dependencies);

  lifecycle.stop(reason);
  if let Some(reply) = first_reply {
    let _ = reply.send(ShutdownOutcome::new(reason));
  }
  for reply in queued_replies {
    let _ = reply.send(ShutdownOutcome::new(reason));
  }
}

pub(super) struct Supervisor {
  pub(super) dependencies: RuntimeDependencies,
  pub(super) shutdown_tx: watch::Sender<()>,
  pub(super) packet: Arc<SessionPacketContext>,
  pub(super) route_capacity: usize,
  /// The recovery controller, shared with the start-recovery effect's
  /// plane and the tick workers: one controller truth per incarnation,
  /// briefly locked (never across an await) by the read view, the
  /// recovery worker's tick, and the effect alike.
  pub(super) recovery:
    std::sync::Arc<std::sync::Mutex<crate::membership::recovery::RecoveryController>>,
  /// Memoized departed-members exclusion set, keyed by the store
  /// revision it was computed at: the set only changes when a leave or
  /// cleanup tombstone lands or gets GC'd, and every such change commits
  /// (advancing the revision). A tick or member view over an unchanged
  /// revision reuses the cached set instead of rescanning and decoding
  /// every accumulated tombstone; any other commit also invalidates,
  /// which merely recomputes once (commit-writes are rare metadata
  /// events). The cache is the one shared with the task effects' plane
  /// and the tick workers, so the checkpoint guard memoizes with the
  /// same truth.
  pub(super) exclusion_cache: super::recovery::ExclusionCache,
  // The anti-entropy driver task: aborted on shutdown so the node's
  // storage handle is released promptly (a restarted node reopening the
  // same factory must not race a lingering driver).
  pub(super) sync_driver: Option<tokio::task::JoinHandle<()>>,
  // The two periodic-plane workers (recovery observation with the
  // retention sweeps, degree maintenance): spawned once by `supervise`,
  // aborted and awaited by `into_dependencies` — a fixed two-handle
  // population, never one task per tick (audit 2026-10-09 items 3–4).
  pub(super) tick_workers: Vec<tokio::task::JoinHandle<()>>,
  pub(super) trace_sink: crate::routing::trace::TraceSink,
  // Approximate live durable trace-record population, shared with the
  // sink (incremented per successful persistence) and decremented by the
  // retention sweep's removals; zero means sweeps can stay skipped.
  pub(super) trace_records: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// The periodic planes' shared state: everything the recovery-observation
/// worker (`recovery_tick` plus the three retention sweeps) and the
/// degree-maintenance worker need to run OFF the supervisor's select loop
/// (audit 2026-10-09 item 3: slow storage or a slow policy resolution must
/// never park control-plane reads and packet admission behind a tick).
/// Built once per incarnation by [`Supervisor::tick_state`] from the same
/// Arc-held collaborators the supervisor reads, so the workers observe the
/// one truth per field — no second controller, cache, or session table.
/// Mutation is confined to atomics and the briefly-held controller mutex,
/// so every method takes `&self` and both workers share one `Arc<TickState>`.
pub(super) struct TickState {
  pub(super) context: Arc<LocalIdentityContext>,
  pub(super) config: NodeConfig,
  pub(super) entropy: Arc<dyn crate::api::Entropy>,
  pub(super) extensions: Arc<ExtensionRegistry>,
  pub(super) sessions: crate::session::stream::SessionTable,
  pub(super) events: Arc<crate::node::EventHub>,
  /// The tracked connection tasks the recovery tick reaps (bounded task
  /// accounting shared with the shutdown path).
  pub(super) connection_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
  pub(super) driver: SessionDriver,
  pub(super) packet: Arc<SessionPacketContext>,
  /// The graceful-shutdown signal: each worker clones its receiver and
  /// exits cooperatively; the abort in `into_dependencies` is the
  /// backstop for a mid-tick stall.
  pub(super) shutdown: watch::Receiver<()>,
  /// The recovery controller (the same instance the supervisor's read
  /// view locks).
  pub(super) recovery: Arc<std::sync::Mutex<crate::membership::recovery::RecoveryController>>,
  /// In-flight recovery dials: bounds the isolated node's dial fan-out
  /// (the counter bounds in-flight dials, not lifetime volume).
  pub(super) recovery_pending: Arc<std::sync::atomic::AtomicUsize>,
  /// In-flight connection-degree maintenance dials: bounds one tick's
  /// batch so a slow mesh never doubles its own dial load every cadence
  /// (see `runtime/degree.rs`).
  pub(super) maintenance_pending: Arc<std::sync::atomic::AtomicUsize>,
  /// The degree plane's dial-batch serial: every maintenance tick that
  /// dials advances it once, and each selected member's published
  /// endpoints rotate by it (endpoint-level failover, aligned with the
  /// recovery plane's `recovery_endpoint` rotation — see
  /// `runtime/degree.rs`).
  pub(super) degree_attempt: Arc<std::sync::atomic::AtomicU64>,
  /// Recovery-tick cooldown before the next redundant-edge cut. Only
  /// the recovery worker mutates it; a racing read at worst shifts one
  /// cut by one tick.
  pub(super) prune_cooldown: Arc<std::sync::atomic::AtomicU32>,
  /// The departed-members exclusion cache (the same instance the
  /// supervisor's member pages memoize through).
  pub(super) exclusion_cache: super::recovery::ExclusionCache,
  /// The approximate live durable trace-record population the trace
  /// retention sweep decrements (the same counter the observability
  /// view reads).
  pub(super) trace_records: Arc<std::sync::atomic::AtomicUsize>,
}

/// Builds the node-shared packet context (single construction site):
/// every collaborator is cloned from one struct instead of a
/// ten-argument positional call where a transposed same-typed `Arc`
/// would compile and silently miswire.
fn session_packet_context(
  context: &Arc<LocalIdentityContext>, dependencies: &RuntimeDependencies,
  packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
  policy: crate::session::stream::SessionPolicy,
) -> Result<SessionPacketContext> {
  // The effective route policy: the caller selection, or the built-in
  // default policy tag (registered by the builder out of the box).
  let route_policy = dependencies.config.route_policy()?;
  // The durable trace sink is born with the packet context it serves (one
  // construction site): the origin pump's terminal facts and the read
  // loop's late-failure revisions share one bounded queue and one
  // live-record counter with the retention sweep and the observability
  // view (remaining items 2026-10-10, P2-7).
  let trace_records = Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let trace_sink = crate::routing::trace::TraceSink::new(
    Arc::clone(context),
    dependencies.entropy.clone(),
    Arc::new(crate::time::HostWallClock),
    Arc::clone(&trace_records),
  );
  Ok(SessionPacketContext::new(
    context.identity().node().clone(),
    dependencies.extensions.clone(),
    policy,
    crate::runtime::RuntimeClient::routing_only(packet_tx, dependencies.routes.clone()),
    std::sync::Arc::new(crate::time::HostWallClock),
    dependencies.entropy.clone(),
    dependencies.events.clone(),
    route_policy,
    dependencies.sessions.clone(),
    dependencies.routes.clone(),
    Some(trace_sink),
    crate::routing::forward::FORWARDING_ROUTE_CAPACITY_DEFAULT,
    dependencies.config.trace_metadata_limits().active(),
    Arc::clone(&dependencies.connection_tasks),
    crate::protocol::CONTROL_CBOR_LIMITS,
    dependencies.config.relay_hop_deadline(),
  ))
}

/// Builds the node-shared operation handles: the session driver (one
/// credential issuer and one leaf-SPKI anchor table for the whole
/// incarnation), the packet context, and the graceful-shutdown signal.
/// Called once by `spawn_runtime`, and by the supervisor unit tests that
/// build a standalone supervisor without the runtime's task manager.
pub(super) fn operation_deps(
  dependencies: &RuntimeDependencies, packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
  offer: crate::protocol::offer::FeatureOffer,
  features: std::sync::Arc<crate::protocol::feature::FeatureRegistry>,
) -> Result<Arc<super::task_effects::OperationDeps>> {
  let Some(context) = dependencies.context.clone() else {
    return Err(Error::internal("runtime context"));
  };
  let policy = crate::session::stream::SessionPolicy::from_config(&dependencies.config);
  let packet = Arc::new(session_packet_context(
    &context,
    dependencies,
    packet_tx,
    policy,
  )?);
  let (shutdown, _) = watch::channel(());
  let driver = SessionDriver::new(
    Arc::clone(&context),
    context.keys().clone(),
    dependencies.entropy.clone(),
    Arc::new(std::sync::Mutex::new(MergeCredentialIssuer::new())),
    offer,
    features,
    dependencies.config.authentication_deadline(),
    dependencies.config.merge_admission(),
  );
  Ok(Arc::new(super::task_effects::OperationDeps::new(
    dependencies,
    driver,
    packet,
    shutdown,
  )?))
}

impl Supervisor {
  /// Builds the supervisor; provisioning failures return the dependencies
  /// so the caller can still run a clean shutdown instead of panicking.
  pub(super) fn new(
    dependencies: RuntimeDependencies, packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
    sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  ) -> std::result::Result<Self, Box<(Error, RuntimeDependencies)>> {
    let Some(context) = dependencies.context.clone() else {
      return Err(Box::new((Error::internal("runtime context"), dependencies)));
    };
    // The operation handles were built by `spawn_runtime` (one construction
    // site for the driver, packet context, and shutdown signal this
    // supervisor shares with every migrated verb effect).
    let Some(operations) = dependencies.operations.clone() else {
      return Err(Box::new((
        Error::internal("runtime operations"),
        dependencies,
      )));
    };
    let (packet, shutdown_tx, exclusion_cache, published_endpoints) = match operations.planes() {
      Ok(planes) => (
        Arc::clone(&planes.packet),
        planes.shutdown.clone(),
        Arc::clone(&planes.exclusion_cache),
        Arc::clone(&planes.published_endpoints),
      ),
      Err(error) => return Err(Box::new((error, dependencies))),
    };
    let route_capacity = dependencies.config.trace_metadata_limits().active();
    // The durable trace sink was constructed with the packet context (one
    // construction site) and is read back here: the origin pump's terminal
    // facts, the read loop's late-failure revisions, the retention sweep,
    // and the observability view all share the one bounded instance and
    // its live-record counter (remaining items 2026-10-10, P2-7).
    let Some(trace_sink) = packet.trace_sink().cloned() else {
      return Err(Box::new((Error::internal("trace sink"), dependencies)));
    };
    let trace_records = trace_sink.live_records().clone();
    let sync_context = Arc::clone(&context);
    // The membership sync protocol was registered by `spawn_runtime`
    // before the runtime was marked ready.
    let sync_driver = Some(spawn_sync_driver(
      &sync_context,
      dependencies.entropy.clone(),
      crate::runtime::RuntimeClient::routing_only(packet_tx.clone(), dependencies.routes.clone()),
      Arc::clone(&published_endpoints),
      dependencies.config.anti_entropy_interval(),
      shutdown_tx.subscribe(),
      sync_rounds,
      dependencies.events.clone(),
      dependencies.member_revision.clone(),
      dependencies.reconcile.clone(),
    ));
    let recovery = {
      let Ok(planes) = operations.planes() else {
        return Err(Box::new((
          Error::internal("runtime operations"),
          dependencies,
        )));
      };
      std::sync::Arc::clone(&planes.recovery)
    };
    Ok(Self {
      dependencies,
      shutdown_tx,
      packet,
      route_capacity,
      recovery,
      exclusion_cache,
      sync_driver,
      tick_workers: Vec::new(),
      trace_sink,
      trace_records,
    })
  }

  /// Builds the periodic planes' shared state (see [`TickState`]):
  /// clones of the Arc-held collaborators this supervisor already
  /// reads, plus a fresh shutdown subscription and the tick-local
  /// counters. Called exactly once by `supervise` when it spawns the two
  /// tick workers.
  pub(super) fn tick_state(&self) -> Result<TickState> {
    let planes = self
      .dependencies
      .operations
      .as_ref()
      .ok_or_else(|| Error::internal("runtime operations"))?
      .planes()?;
    Ok(TickState {
      context: Arc::clone(&planes.context),
      config: planes.config.clone(),
      entropy: Arc::clone(&planes.entropy),
      extensions: Arc::clone(&self.dependencies.extensions),
      sessions: planes.sessions.clone(),
      events: Arc::clone(&self.dependencies.events),
      connection_tasks: Arc::clone(&planes.connection_tasks),
      driver: planes.driver.clone(),
      packet: Arc::clone(&planes.packet),
      shutdown: self.shutdown_tx.subscribe(),
      recovery: Arc::clone(&self.recovery),
      recovery_pending: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
      maintenance_pending: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
      degree_attempt: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
      prune_cooldown: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
      exclusion_cache: Arc::clone(&self.exclusion_cache),
      trace_records: Arc::clone(&self.trace_records),
    })
  }

  fn into_dependencies(mut self) -> (RuntimeDependencies, Vec<tokio::task::JoinHandle<()>>) {
    // Every open session task observes the shutdown signal and closes its
    // connection instead of being orphaned when the supervisor exits; the
    // tracked tasks (accept side and the anti-entropy driver) are aborted
    // and their handles returned so the shutdown path can await them and
    // their storage captures are deterministically dropped before a
    // restarted node reopens the same factory.
    let _ = self.shutdown_tx.send(());
    let mut aborted = Vec::new();
    if let Some(driver) = self.sync_driver.take() {
      driver.abort();
      aborted.push(driver);
    }
    // The tick workers observe the shutdown signal above and exit
    // cooperatively; the abort is the backstop for a worker stalled
    // mid-tick (its storage handles drop with the task), and the
    // returned handles keep the shutdown reply behind their teardown.
    for worker in self.tick_workers.drain(..) {
      worker.abort();
      aborted.push(worker);
    }
    if let Ok(mut handles) = self.dependencies.connection_tasks.lock() {
      for handle in handles.drain(..) {
        handle.abort();
        aborted.push(handle);
      }
    }
    // Definitive session teardown: the graceful shutdown signal lets live
    // session tasks run their exit cleanup, but an abort landing first
    // skips it — draining the table here drops each entry's frame sender
    // so the detached writer task still exits and the connection closes.
    if let Err(error) = crate::session::stream::retire_all_sessions(&self.dependencies.sessions) {
      tracing::warn!(kind = ?error.kind(), "session table teardown failed");
    }
    (self.dependencies, aborted)
  }

  /// Lazily publishes this node's own signed descriptor (revision 1) so
  /// the public views always expose the local identity, with the
  /// published listener endpoints. Delegates to the one shared
  /// implementation the resource-write effects also use
  /// ([`super::task_effects::ensure_self_descriptor`]).
  pub(super) async fn ensure_self_descriptor(&mut self) -> Result<()> {
    let operations = self
      .dependencies
      .operations
      .as_ref()
      .ok_or_else(|| Error::internal("runtime operations"))?;
    super::task_effects::ensure_self_descriptor(operations).await
  }

  pub(super) fn context(&self) -> Result<Arc<LocalIdentityContext>> {
    self
      .dependencies
      .context
      .clone()
      .ok_or_else(|| Error::internal("runtime context"))
  }
}

/// Dials one transport connection under the configured dial deadline: the
/// deadline bounds the whole connect (TCP dial, TLS handshake, and
/// WebSocket upgrade), so a peer that accepts and then goes silent
/// cannot stall the supervisor's control loop or hold a recovery slot
/// forever. An elapsed deadline maps onto the same coarse typed
/// transport-connect failure as any other dial error; the connect
/// future is cancelled, so the deadline and endpoint are the only real
/// cause a diagnostic can carry.
pub(super) async fn connect_with_deadline(
  transport: &Arc<dyn Transport>, receiver: Endpoint, trust: TransportTrust,
  deadline: std::time::Duration,
) -> Result<crate::transport::connection::Connection> {
  match tokio::time::timeout(deadline, transport.connect(receiver.clone(), trust)).await {
    Ok(result) => result,
    Err(_) => {
      tracing::debug!(
        endpoint = %receiver.as_str(),
        deadline = ?deadline,
        "transport dial deadline elapsed"
      );
      Err(Error::provider(
        crate::ProviderErrorKind::Io,
        crate::ProviderErrorContext::TransportConnect,
      ))
    }
  }
}

/// Runs one member-mode dial against an already-admitted peer: the
/// member-mode handshake proves both identities over a fresh transcript
/// and exporter binding, then the session is kept open for packet streams.
/// Called by `connect_member` and by the recovery controller's detached
/// dial tasks. The dial deadline travels with the call so a detached
/// recovery dial releases its in-flight slot within the bound.
#[allow(clippy::too_many_arguments)]
pub(super) async fn dial_member(
  transport: Arc<dyn Transport>, driver: SessionDriver,
  sessions: crate::session::stream::SessionTable, packet: Arc<SessionPacketContext>,
  shutdown: watch::Receiver<()>, receiver: Endpoint, peer: &NodeId, recovery_dialed: bool,
  dial_deadline: std::time::Duration,
) -> Result<NodeId> {
  crate::audit::dial_started(peer.as_str(), recovery_dialed);
  let result = async {
    // Member reconnects pin the peer's TLS leaf to the SPKI anchor learned
    // at join (same-listener reconnects); without an anchor this process
    // falls back to the join-mode relaxation and the application proof
    // layer remains the authenticator. The endpoint's transport class
    // decides whether either TLS mode applies at all.
    let pinned = driver.peer_spki(peer);
    let trust = TransportTrust::for_dial(
      &receiver.selector(),
      pinned
        .clone()
        .map(rustls::pki_types::SubjectPublicKeyInfoDer::from),
    );
    let mut connection =
      match connect_with_deadline(&transport, receiver.clone(), trust, dial_deadline).await {
        Ok(connection) => connection,
        // Certificate rollover fallback (audit 2026-10-09 item 8): a
        // pinned dial whose TLS establishment failed may be facing a peer
        // that legitimately re-issued its ephemeral leaf (same durable
        // identity, new certificate). Retry exactly once with the
        // merge-mode trust: the member-mode handshake still authenticates
        // the peer's durable identity key over the fresh channel binding —
        // identity authority lives in the proof layer, not in the pin —
        // and a success re-records the new leaf as the anchor below.
        // Network-level failures (unreachable peer, elapsed deadline) map
        // to other kinds and never take this path.
        Err(pin_error)
          if pinned.is_some() && pin_error.kind() == crate::ErrorKind::AuthenticationFailed =>
        {
          tracing::debug!(
            peer = %peer.as_str(),
            kind = ?pin_error.kind(),
            "pinned member dial failed; retrying once with merge trust for certificate rollover"
          );
          let fallback = TransportTrust::for_dial(&receiver.selector(), None);
          connect_with_deadline(&transport, receiver.clone(), fallback, dial_deadline).await?
        }
        Err(error) => return Err(error),
      };
    let session = driver.initiate_member(&mut connection, peer).await?;
    let authenticated = session.peer().clone();
    // Capture the peer's CURRENT leaf SPKI before the session pump takes
    // ownership of the connection: on a pinned dial whose application
    // proof just authenticated the identity, this leaf is the anchor of
    // record (identical on a normal pin, rotated after the fallback).
    let observed_spki = connection
      .merge_hint()
      .map(|hint| hint.leaf_spki().to_vec())
      .filter(|spki| !spki.is_empty());
    // The member-mode dial returns only after the session table settles, so
    // the caller's first packet cannot race registration (including the
    // crossed-dial loser outcome, which reports no usable session).
    keep_outbound_session(
      connection,
      session,
      packet,
      sessions,
      shutdown,
      receiver,
      recovery_dialed,
      |session_task| {
        tokio::spawn(session_task);
      },
    )
    .await?;
    if pinned.is_some()
      && let Some(spki) = observed_spki
    {
      // Process-local rollover: the re-issued leaf replaces the stale
      // anchor, so every later member dial to this peer pins again.
      driver.record_peer_spki(peer, spki);
    }
    Ok(authenticated)
  }
  .await;
  crate::audit::dial_settled(peer.as_str(), recovery_dialed, result.is_ok());
  result
}

/// The keep-open tail shared by join and member dials: spawns the
/// outbound session pump through the caller's spawner and returns only
/// after the session table registers the entry, so the caller's first
/// packet cannot race registration.
#[allow(clippy::too_many_arguments)]
pub(super) async fn keep_outbound_session(
  connection: crate::transport::connection::Connection,
  session: crate::session::EstablishedSession, packet: Arc<SessionPacketContext>,
  sessions: SessionTable, shutdown: watch::Receiver<()>, attachment: Endpoint,
  recovery_dialed: bool,
  spawn: impl FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>),
) -> Result<()> {
  let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
  spawn(Box::pin(run_session(
    connection,
    session,
    packet,
    sessions,
    shutdown,
    crate::session::stream::DialDirection::Outgoing,
    attachment,
    Some(registered_tx),
    recovery_dialed,
  )));
  if registered_rx.await.is_err() {
    return Err(Error::internal("session registration"));
  }
  Ok(())
}

#[cfg(test)]
mod dial_deadline_tests {
  use std::{
    sync::Arc,
    time::{Duration, Instant},
  };

  use super::connect_with_deadline;
  use crate::{
    Endpoint, ErrorKind,
    transport::{registry::TransportTrust, wss::WssTransport},
  };

  /// A peer that accepts TCP and then goes silent must surface the typed
  /// dial failure within the configured deadline instead of hanging the
  /// dialer. This exercises the one helper every production dial path
  /// shares (`reconcile_join`, and `reconcile_connect` plus the detached
  /// recovery and connection-degree dials through `dial_member`); the
  /// regression it guards is a connect with no bound at all, which
  /// stalled the supervisor's control loop and pinned recovery slots
  /// forever.
  #[tokio::test]
  async fn a_silent_peer_fails_the_dial_within_the_deadline() {
    // The listener accepts and then holds the socket without ever
    // speaking TLS: the TCP connect succeeds, then the handshake stalls
    // on a socket that never answers. Holding it open matters — an
    // early drop would reset the connection, let the TLS handshake fail
    // fast, and bypass the timeout path under test.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let holder = tokio::spawn(async move {
      let (_held, _) = listener.accept().await.unwrap();
      tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let transport: Arc<dyn crate::transport::registry::Transport> = Arc::new(WssTransport::new());
    let endpoint = Endpoint::parse(&format!("wss://127.0.0.1:{}", address.port())).unwrap();
    let deadline = Duration::from_millis(100);
    let started = Instant::now();
    let error = connect_with_deadline(&transport, endpoint, TransportTrust::Merge, deadline)
      .await
      .unwrap_err();
    let elapsed = started.elapsed();

    // The same coarse typed classification as any other dial failure.
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(error.context(), "transport connect");
    // The failure lands on the deadline, not instantaneously (an early
    // socket error) and not at the unbounded OS connect timeout.
    assert!(elapsed >= deadline);
    assert!(
      elapsed < Duration::from_secs(5),
      "the dial took {elapsed:?}"
    );

    holder.abort();
  }
}

#[cfg(test)]
mod receipt_retention_sweep_tests {
  use std::{sync::Arc, time::Duration};

  use tokio::sync::{mpsc, watch};

  use super::{RuntimeDependencies, Supervisor, node_offer};
  use crate::{
    NodeConfig, Result, StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreValue,
    TransactionId,
    extension_registry::ExtensionRegistry,
    identity::{
      lifecycle::open_local_identity,
      testing::{ScriptedKeys, SequenceEntropy},
    },
    protocol::feature,
    provider::{KeyProvider, StorageFactory},
    storage::receipt::retention_testing::anchor_receipt,
  };

  /// Builds a running supervisor over a fresh in-memory identity with the
  /// caller's receipt-retention window. No sessions, no listeners: the
  /// supervisor's tick-path sweeps run against a real metadata store.
  async fn sweep_supervisor(
    retention: Duration,
  ) -> (
    Supervisor,
    Arc<dyn crate::provider::StorageFactory>,
    Arc<dyn crate::api::Entropy>,
  ) {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let keys: Arc<dyn KeyProvider> = ScriptedKeys::full().as_provider();
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      open_local_identity(&factory, Some(&keys), entropy.as_ref(), retention)
        .await
        .unwrap(),
    );
    let config = NodeConfig::new().with_receipt_retention(retention).unwrap();
    let mut definitions = feature::builtin_definitions().unwrap();
    definitions.extend(ExtensionRegistry::new().feature_definitions());
    let registry = Arc::new(feature::FeatureRegistry::build(definitions).unwrap());
    let offer = node_offer(&registry, config.required_features()).unwrap();
    let (round_tx, round_rx) = mpsc::channel(super::SYNC_ROUND_CHANNEL_CAPACITY);
    let (revision_tx, _) = watch::channel(0_u64);
    let (packet_tx, _packet_rx) = mpsc::channel(super::PACKET_CHANNEL_CAPACITY);
    let mut dependencies = RuntimeDependencies {
      storage_factory: factory.clone(),
      context: Some(context.clone()),
      keys: Some(keys),
      config,
      entropy: entropy.clone(),
      extensions: Arc::new(ExtensionRegistry::new()),
      sessions: Default::default(),
      routes: Default::default(),
      events: Arc::new(crate::node::EventHub::new()),
      member_revision: crate::node::MemberRevisionSignal::new(revision_tx),
      leave_applied: crate::membership::sync::LeaveAppliedSignal::new(),
      reconcile: None,
      sync_round_requests: round_tx,
      connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
      listeners: Default::default(),
      task_manager: None,
      operations: None,
      runtime_seed: None,
    };
    // The operation handles are built the way `spawn_runtime` builds them,
    // so the test drives the exact production construction path for the
    // packet context and the session driver too.
    let operations = super::operation_deps(&dependencies, packet_tx.clone(), offer, registry)
      .expect("operation handles");
    dependencies.operations = Some(operations);
    let supervisor = match Supervisor::new(dependencies, packet_tx, round_rx) {
      Ok(supervisor) => supervisor,
      Err(boxed) => panic!("supervisor construction failed: {}", boxed.0),
    };
    (supervisor, factory, entropy)
  }

  fn test_namespace() -> Result<StoreNamespace> {
    Ok(StoreNamespace::new(crate::QualifiedTag::parse(
      "radiata.woooo.tech/metadata/retention-tick-test",
    )?))
  }

  /// Commits one ordinary caller transaction and returns its receipt: the
  /// anchoring seam needs a real committed transaction identity.
  async fn commit_one(
    supervisor: &Supervisor, entropy: &dyn crate::api::Entropy, marker: &[u8],
  ) -> crate::CommitReceipt {
    let context = supervisor.context().unwrap();
    let store = context.store();
    let snapshot = store.snapshot().await.unwrap();
    let prepared = store
      .prepare_transaction(
        TransactionId::generate(entropy).unwrap(),
        snapshot.revision().clone(),
        vec![StoreOperation::Put {
          namespace: test_namespace().unwrap(),
          key: StoreKey::new(Arc::from(marker.to_vec())),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(marker.to_vec())),
        }],
      )
      .unwrap();
    crate::provider::commit_verdict(store.commit(prepared).await.unwrap(), "retention test")
      .unwrap()
  }

  /// The recovery tick's receipt-retention sweep is the automatic driver
  /// for the `receipt_retention` knob: once a receipt's deadline elapses,
  /// the sweep alone forgets it, and the explicit command keeps working
  /// as the idempotent on-demand pass.
  #[tokio::test]
  async fn tick_sweep_forgets_elapsed_anchored_receipts() {
    let retention = Duration::from_millis(100);
    let (supervisor, _factory, entropy) = sweep_supervisor(retention).await;
    let ticks = supervisor.tick_state().unwrap();

    // The explicit command keeps working: over an empty anchor set it is
    // an idempotent no-op.
    let report = supervisor
      .context()
      .unwrap()
      .store()
      .apply_receipt_retention()
      .await
      .unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);

    // Anchor one committed receipt and let its deadline elapse.
    let receipt = commit_one(&supervisor, entropy.as_ref(), b"first").await;
    assert!(
      anchor_receipt(
        supervisor.context().unwrap().store(),
        entropy.as_ref(),
        &receipt
      )
      .await
      .unwrap()
    );
    tokio::time::sleep(retention + Duration::from_millis(250)).await;

    // The manual command forgets the elapsed receipt exactly once.
    let report = supervisor
      .context()
      .unwrap()
      .store()
      .apply_receipt_retention()
      .await
      .unwrap();
    assert_eq!(report.forgotten, 1);
    assert!(!report.remaining);
    // A forgotten receipt never grows a second anchor.
    assert!(
      !anchor_receipt(
        supervisor.context().unwrap().store(),
        entropy.as_ref(),
        &receipt
      )
      .await
      .unwrap()
    );

    // The automated path: a second elapsed anchor is forgotten by the
    // tick sweep alone, with no command issued.
    let receipt = commit_one(&supervisor, entropy.as_ref(), b"second").await;
    assert!(
      anchor_receipt(
        supervisor.context().unwrap().store(),
        entropy.as_ref(),
        &receipt
      )
      .await
      .unwrap()
    );
    tokio::time::sleep(retention + Duration::from_millis(250)).await;
    ticks.receipt_retention_sweep().await;
    assert!(
      !anchor_receipt(
        supervisor.context().unwrap().store(),
        entropy.as_ref(),
        &receipt
      )
      .await
      .unwrap(),
      "the tick sweep must forget the elapsed anchor"
    );

    // The explicit command stays available and idempotent afterwards.
    let report = supervisor
      .context()
      .unwrap()
      .store()
      .apply_receipt_retention()
      .await
      .unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);
  }
}

/// The runtime's shared supervisor-unit-test fixture: builds a
/// supervisor over a caller-supplied storage factory and config the way
/// `spawn_runtime` builds the real one (identity provisioning, builtin
/// transports, operation handles), so tick-plane tests drive the exact
/// production construction path. Shared by the degree-maintenance and
/// recovery-worker test modules.
#[cfg(test)]
pub(crate) mod test_support {
  use std::sync::Arc;

  use tokio::sync::{mpsc, watch};

  use super::{RuntimeDependencies, Supervisor, node_offer};
  use crate::{
    NodeConfig,
    extension_registry::ExtensionRegistry,
    identity::{
      lifecycle::open_local_identity,
      testing::{ScriptedKeys, SequenceEntropy},
    },
    protocol::feature,
    provider::StorageFactory,
    session::stream::SessionTable,
    storage::contract::{ReferenceFactory, required_capabilities},
  };

  /// Builds a supervisor over a fresh in-memory identity opened through
  /// the caller's factory: no sessions, no listeners — the tick planes
  /// run against a real store.
  pub(crate) async fn supervisor_over(
    factory: Arc<dyn StorageFactory>, config: NodeConfig,
  ) -> (Supervisor, Arc<dyn crate::api::Entropy>, SessionTable) {
    let keys = ScriptedKeys::full();
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      open_local_identity(
        &factory,
        Some(&keys.as_provider()),
        entropy.as_ref(),
        std::time::Duration::from_secs(3_600),
      )
      .await
      .unwrap(),
    );
    let mut extensions = ExtensionRegistry::new();
    // The built-in transports the node builder installs: the ticks
    // resolve the members' wss endpoints through this registry.
    for (tag, transport) in [
      (
        crate::transport::tls_transport::TlsTransport::tag().unwrap(),
        Arc::new(crate::transport::tls_transport::TlsTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        crate::transport::wss::WssTransport::tag().unwrap(),
        Arc::new(crate::transport::wss::WssTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        crate::transport::plain::PlainTransport::tag().unwrap(),
        Arc::new(crate::transport::plain::PlainTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
    ] {
      extensions
        .register_builtin_transport(tag, transport)
        .unwrap();
    }
    let mut definitions = feature::builtin_definitions().unwrap();
    definitions.extend(extensions.feature_definitions());
    let registry = Arc::new(feature::FeatureRegistry::build(definitions).unwrap());
    let offer = node_offer(&registry, config.required_features()).unwrap();
    let (round_tx, round_rx) = mpsc::channel(super::SYNC_ROUND_CHANNEL_CAPACITY);
    let (revision_tx, _revision_rx) = watch::channel(0_u64);
    let (packet_tx, _packet_rx) = mpsc::channel(super::PACKET_CHANNEL_CAPACITY);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let mut dependencies = RuntimeDependencies {
      storage_factory: factory,
      context: Some(context),
      keys: Some(keys),
      config,
      entropy: entropy.clone(),
      extensions: Arc::new(extensions),
      sessions: sessions.clone(),
      routes: Default::default(),
      events: Arc::new(crate::node::EventHub::new()),
      member_revision: crate::node::MemberRevisionSignal::new(revision_tx),
      leave_applied: crate::membership::sync::LeaveAppliedSignal::new(),
      reconcile: None,
      sync_round_requests: round_tx,
      connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
      listeners: Default::default(),
      task_manager: None,
      operations: None,
      runtime_seed: None,
    };
    // The operation handles are built the way `spawn_runtime` builds them,
    // so the tick drives the exact production packet context and session
    // driver instead of a stand-in.
    let operations = super::operation_deps(&dependencies, packet_tx.clone(), offer, registry)
      .expect("operation handles");
    dependencies.operations = Some(operations);
    let supervisor = match Supervisor::new(dependencies, packet_tx, round_rx) {
      Ok(supervisor) => supervisor,
      Err(boxed) => panic!("supervisor construction failed: {}", boxed.0),
    };
    (supervisor, entropy, sessions)
  }

  /// The reference factory plus the dialing config the maintenance
  /// fixture uses: a dial deadline long enough that the tick's detached
  /// dials stay in flight (stalled in the TLS handshake against a held
  /// silent listener) while the test observes them.
  pub(crate) fn reference_and_config() -> (Arc<ReferenceFactory>, NodeConfig) {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let config = NodeConfig::new()
      .with_dial_deadline(std::time::Duration::from_secs(2))
      .unwrap();
    (reference, config)
  }

  pub(crate) fn member_id(seed: u64) -> crate::NodeId {
    crate::NodeId::parse(&format!("node-{seed:021}")).unwrap()
  }

  pub(crate) fn member_key(seed: u64) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(seed);
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  /// Installs one active member: trusted binding (injected) plus
  /// descriptor (committed through the store path) with every listed
  /// endpoint (multi-homed members allowed), so the member universe
  /// counts it and any dial to a silent endpoint stalls in flight
  /// instead of failing before the test can observe it.
  pub(crate) async fn install_member(
    supervisor: &Supervisor, reference: &Arc<ReferenceFactory>, seed: u64, ports: &[u16],
  ) {
    let node = member_id(seed);
    let endpoints: Vec<crate::Endpoint> = ports
      .iter()
      .map(|port| crate::Endpoint::parse(&format!("wss://127.0.0.1:{port}")).unwrap())
      .collect();
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node.clone(),
      member_key(seed),
      endpoints,
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(
      supervisor.context().unwrap().store(),
      supervisor.dependencies.entropy.as_ref(),
      &descriptor,
    )
    .await
    .unwrap();
    let (namespace, key) = crate::identity::records::identity_binding_key(&node).unwrap();
    let binding = crate::identity::records::IdentityBindingV1::new(node, member_key(seed));
    crate::identity::testing::inject_entry(reference, (namespace, key), binding.encode().unwrap());
  }

  /// Inserts one live session entry for `peer` into the table: a
  /// synthetic entry is enough — the tick only reads liveness.
  pub(crate) fn insert_live_session(
    sessions: &SessionTable, peer: crate::NodeId, entropy: &dyn crate::api::Entropy,
  ) {
    let entry = crate::session::stream::SessionEntry::synthetic_entry(
      entropy,
      crate::Endpoint::parse("wss://127.0.0.1:1").unwrap(),
    )
    .unwrap();
    sessions.lock().unwrap().insert(peer, entry);
  }

  /// A silent TCP peer: accepts every connection, counts it, and holds
  /// it open, so a wss dial stalls in the TLS handshake until its
  /// deadline — and the connection counter tells the test WHICH of a
  /// member's endpoints was dialed. Holding the socket matters: dropping
  /// it would reset the connection and fail the dial early.
  pub(crate) async fn silent_peer() -> (
    u16,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
  ) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    let held: Arc<std::sync::Mutex<Vec<tokio::net::TcpStream>>> =
      Arc::new(std::sync::Mutex::new(Vec::new()));
    let handle = tokio::spawn(async move {
      while let Ok((stream, _)) = listener.accept().await {
        counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Holding the socket is the point: dropping it would reset the
        // connection and fail the dial early.
        held.lock().unwrap().push(stream);
      }
    });
    (port, connections, handle)
  }
}
