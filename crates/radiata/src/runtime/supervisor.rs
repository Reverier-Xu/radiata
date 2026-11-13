use std::{collections::BTreeMap, sync::Arc};

use tokio::{
  runtime::Handle,
  sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};

use super::{
  anti_entropy::spawn_sync_driver,
  packets::{PacketAdmission, PumpHandoff},
  shutdown::finish_shutdown,
  task_manager::{TaskClient, TaskManagerHandle, spawn_task_manager},
};
use crate::{
  Endpoint, Error, NodeConfig, Result, ShutdownOutcome, ShutdownReason,
  api::Entropy,
  extension_registry::ExtensionRegistry,
  identity::{
    credential::MergeCredentialIssuer,
    lifecycle::{LocalIdentityContext, ensure_self_binding, open_local_identity},
  },
  protocol::offer::node_offer,
  provider::{KeyProvider, StorageFactory},
  routing::{RouteTable, outbound::run_outbound},
  runtime::{Control, LeaveSignal, LifecycleSnapshot, RuntimeClient},
  session::{
    SessionDriver,
    stream::{SessionPacketContext, SessionTable},
  },
  transport::registry::TransportListener,
};

/// Depth of the node's control channel, the API verbs' command queue:
/// every writer is a request/reply call on a node handle
/// (`RuntimeClient::send_command`, including `shutdown`), each awaiting
/// its oneshot before returning, and the supervisor's select loop
/// answers one command inline per iteration. The depth is
/// therefore the accepted number of concurrently unanswered control
/// reads before a calling handle's `send_command` parks — no
/// packet-admission path ever writes a control message and no control
/// arm admits a packet, so it is independent of
/// `ADMISSION_CONCURRENCY`. The shutdown path reuses it to pre-size the
/// queued-reply drain, where it is a true bound: a closed bounded
/// channel can hold no more queued messages than its capacity.
pub(super) const CONTROL_CAPACITY: usize = 32;

/// The leave plane's signal depth: one leave per incarnation, and the
/// first signal is the one that decides the shutdown reason, so a
/// capacity of one parks nothing and refuses only a signal the loop is
/// already tearing down on.
const LEAVE_SIGNAL_CAPACITY: usize = 1;

/// Depth of the bounded channel for immediate sync-round requests
/// forwarded to the sync driver (the cursor owner): the only writer is
/// the `SyncRound` task effect, which sends one oneshot and awaits its
/// round's completion, so the queue depth is the accepted number of
/// concurrent on-demand rounds before the submitting effect parks —
/// rounds are self-limiting (one page per session per round), so a
/// small queue with typed backpressure matches the work. A round's
/// page dispatches ride the packet command channel, never this queue,
/// so this depth is independent of `ADMISSION_CONCURRENCY`.
pub(crate) const SYNC_ROUND_CHANNEL_CAPACITY: usize = 8;

/// Depth of the node's outbound packet command channel, deliberately
/// equal to the control channel's: both are caller-submitted command
/// queues into the same single-consumer select loop, so one depth
/// policy governs how far either plane may queue ahead of the loop
/// before its sender observes backpressure (`send` parking, or the
/// fire-and-forget `try_send` typed overload). This is a shared policy,
/// not a structural necessity: the packet plane's producers are the
/// public send verbs plus the internal-plane sync dispatches (the
/// membership pages and the reconcile lanes' rows and replies), and
/// the dispatch retry budget in `sync_common` rides out bursts that
/// outrun this depth.
pub(crate) const PACKET_CHANNEL_CAPACITY: usize = CONTROL_CAPACITY;

/// The bound on simultaneously running packet admission tasks: each
/// admission may await a caller-supplied routing
/// policy, so this bounds how many such waits are in flight. A
/// saturated pool disables the control loop's packet arm instead of
/// blocking the loop, and the bounded packet command channel carries the
/// backpressure. That backpressure hand-off is the only interaction
/// with `PACKET_CHANNEL_CAPACITY`: the queue absorbs the burst a
/// disabled arm cannot drain while the sync dispatch's bounded retry
/// rides out the window — no fixed ratio ties the two depths.
pub(crate) const ADMISSION_CONCURRENCY: usize = 4;

/// Depth of the bounded admission-to-loop pump handoff, structurally
/// tied to the admission pool: every writer is an admission task
/// holding exactly one permit and writing at most one handoff, and only
/// the control loop spawns admission tasks, so no more than
/// `ADMISSION_CONCURRENCY` handoffs can be produced between two loop
/// iterations. Equal depth means one fully parallel admission window's
/// handoffs always fit without parking. The loop is the sole consumer
/// and reaps the channel whenever it runs, so a finished admission
/// parks on a full channel for at most one scheduling window — never
/// behind its own pool — and defensively, a loop that has exited drops
/// the receiving end, so a late handoff send would observe `SendError`
/// and reject its request with the typed shutdown kind.
const PUMP_HANDOFF_CAPACITY: usize = ADMISSION_CONCURRENCY;

// The capacity constants' joint relations, pinned
// at compile time so a violation fails any build: the pump handoff
// queue must fit every handoff one fully parallel admission window can
// produce (each permit holder writes at most one handoff, and only the
// loop spawns admissions), and the packet command channel stays on the
// one depth policy shared with the control channel. A future edit that
// re-inlines either side as an independent literal and silently breaks
// the relation cannot compile.
const _: () = assert!(
  PUMP_HANDOFF_CAPACITY >= ADMISSION_CONCURRENCY,
  "the pump handoff queue must hold at least one handoff per admission slot"
);
const _: () = assert!(
  PACKET_CHANNEL_CAPACITY == CONTROL_CAPACITY,
  "both command planes into the control loop share one depth policy"
);

/// One bound listener's supervisor-side entry: the published endpoint,
/// the listener handle, and the abort handle of its accept loop.
pub(crate) type ListenerEntry = (Endpoint, std::sync::Arc<dyn TransportListener>, AbortHandle);

/// The node's bound listeners, shared by the supervisor's pages, the
/// leave teardown, and the task manager's listen/stop effects: one
/// registry, mutated under one lock.
pub(crate) type ListenerRegistry =
  Arc<std::sync::Mutex<BTreeMap<crate::identity::ListenerId, ListenerEntry>>>;

pub(super) struct LifecyclePublisher {
  state: watch::Sender<LifecycleSnapshot>,
  terminal: bool,
}

impl LifecyclePublisher {
  pub(super) fn new(state: watch::Sender<LifecycleSnapshot>) -> Self {
    Self {
      state,
      terminal: false,
    }
  }

  pub(super) fn publish(&self, snapshot: LifecycleSnapshot) {
    self.state.send_replace(snapshot);
  }

  pub(super) fn stop(&mut self, reason: ShutdownReason) {
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
  /// The node's effective next-hop route policy tag: the caller's
  /// selection, or the built-in default policy's tag — resolved once in
  /// the registration channel (the node builder, after the default
  /// registry pass) and read everywhere the runtime plans a node-level
  /// route. The runtime never defaults the policy itself.
  pub(crate) route_policy: crate::QualifiedTag,
  /// The node's effective endpoint-selection policy: the caller's
  /// selection, or the built-in preference-order policy over a declared
  /// scheme preference list, or the built-in published-order rotation —
  /// resolved once in the registration channel (the node builder, after
  /// the default registry pass) and wrapped with the per-member rotation
  /// serials every dial plane shares. The runtime never defaults the
  /// policy itself.
  pub(crate) endpoint_policy: Arc<dyn crate::EndpointSelectionPolicy>,
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
  /// The task manager's client half, installed by `spawn_runtime` right
  /// after the manager spawns: the tick workers' controller submissions
  /// (the retention sweeps, the checkpoint-gated tombstone collection,
  /// the trigger evaluation pass) read it. A fixture-built supervisor
  /// without a manager carries `None` and its sweeps run inline.
  pub(crate) tasks: Option<TaskClient>,
  /// The trigger engine's shared state, installed by `spawn_runtime`:
  /// the event-trigger cache the evaluation pass refreshes and the
  /// bounded fire queue the dispatch engine drains. Fixture-built
  /// dependencies carry `None` (the default state, closed queue).
  pub(crate) triggers: Option<crate::trigger::TriggerState>,
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
  // plane once the supervisor spawns it). The plane and the packet
  // context the operation handles build share one authorization
  // boundary, so a sync-delivered revocation
  // tombstone and a finishing handshake's publication serialize
  // exactly like the local revoke effect does.
  let authorization = crate::session::stream::AuthorizationBoundary::default();
  let reconcile_plane = crate::reconcile::plane::ReconcilePlane::new(
    Arc::clone(&runtime_context),
    dependencies.entropy.clone(),
    dependencies.events.clone(),
    dependencies.member_revision.clone(),
    dependencies.sessions.clone(),
    authorization.clone(),
    // The plane's reclaimed-knowledge predicate reads the same removal
    // window the periodic sweep deletes on.
    dependencies.config.resource_removal_retention(),
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
  // silently stopped. The registry holds exactly the definitions installed
  // by `ExtensionRegistry::register_default` plus every caller
  // registration; there is no hidden official fallback.
  let definitions = dependencies.extensions.feature_definitions();
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
  // The leave plane's signal to the control loop: the task manager sends
  // the success, and the leave effect itself sends the fatal failure of a
  // teardown that already began (see `LeaveSignal`). The effect's half
  // rides the operation planes, so it is created before them.
  let (leave_signal, leave_signals) = mpsc::channel(LEAVE_SIGNAL_CAPACITY);
  // The trigger engine's shared state is installed before the operation
  // planes are built: the evaluation pass reaches the fire queue through
  // them, and the dispatch engine owns the receiving end.
  let (trigger_fires, trigger_fires_rx) =
    tokio::sync::mpsc::channel(crate::trigger::TRIGGER_FIRE_QUEUE);
  dependencies.triggers = Some(crate::trigger::TriggerState::new(trigger_fires));
  // The node-shared operation handles are built here rather than inside
  // the supervisor: the supervisor's own fields, the verb effects, and
  // every node handle must read the same session driver (one credential
  // issuer), the same packet context, and the same shutdown signal.
  let operations = operation_deps(
    &dependencies,
    packet_tx.clone(),
    offer,
    registry,
    authorization,
    leave_signal.clone(),
  )?;
  dependencies.operations = Some(Arc::clone(&operations));
  // The task manager is spawned here, beside the supervisor and before the
  // node is marked running: the client side rides the node handle (so an
  // admitted task always has a live manager) and the teardown handle rides
  // the runtime dependencies (so the shutdown path drains it in order).
  let (task_client, task_manager) = spawn_task_manager(super::task_manager::TaskManagerDeps {
    entropy: dependencies.entropy.clone(),
    clock: Arc::new(crate::time::HostWallClock),
    operations: Arc::clone(&operations),
    leave_signal,
  })?;
  dependencies.task_manager = Some(task_manager);
  dependencies.tasks = Some(task_client.clone());
  let task_client_for_engine = task_client.clone();
  let client = RuntimeClient::new(
    control_tx,
    state_rx.clone(),
    routes.clone(),
    packet_tx.clone(),
    Some(task_client.clone()),
  );
  // The trigger dispatch engine: one long-lived task over the fire queue
  // and the live change stream, exiting on the incarnation's shutdown
  // signal. Its reconciler contexts ride an ordinary public node handle
  // over the internal engine client — no node-command sender, so holding
  // it never delays the last-handle-drop shutdown detection. The handle
  // joins the tracked task set the shutdown path drains and awaits, so
  // the engine's captures (the operation planes, the store) release
  // before the shutdown reply resolves and never race a restart's
  // storage reopen. The shutdown receiver is created here, before the
  // task is spawned: a receiver created after the send starts with the
  // new value already seen, so a shutdown signaled while the engine is
  // still waiting for its first poll must not be missed.
  let trigger_shutdown = operations.planes().shutdown.subscribe();
  let trigger_engine = runtime.spawn(super::trigger_engine::run_trigger_engine(
    operations,
    task_client,
    crate::NodeHandle::new(
      RuntimeClient::internal_engine_client(
        state_rx,
        routes,
        packet_tx.clone(),
        task_client_for_engine,
      ),
      dependencies.entropy.clone(),
      dependencies.extensions.clone(),
      dependencies.events.clone(),
      dependencies.member_revision.subscribe(),
    ),
    trigger_fires_rx,
    trigger_shutdown,
  ));
  if let Ok(mut handles) = dependencies.connection_tasks.lock() {
    handles.push(trigger_engine);
  }

  runtime.spawn(supervise(
    dependencies,
    (packet_tx, packet_rx),
    sync_rounds,
    RuntimeSignals {
      control: control_rx,
      leave_signal: leave_signals,
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
  /// The leave plane's signal (see [`LeaveSignal`] and `finish_shutdown`).
  leave_signal: mpsc::Receiver<LeaveSignal>,
  state: watch::Sender<LifecycleSnapshot>,
  ready: oneshot::Sender<()>,
}

/// The terminal phase one select arm decides: the reason the one shared
/// shutdown sequence answers with, and the shutdown reply that triggered
/// it. Only the explicit `Shutdown` command carries a reply — the
/// active-leave and control-channel-closed exits have no caller waiting on
/// a `ShutdownOutcome`, so the reply stays `None` and no handle is left
/// hanging on one.
struct TerminalPhase {
  reason: ShutdownReason,
  first_reply: Option<oneshot::Sender<ShutdownOutcome>>,
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
    mut leave_signal,
    state,
    ready,
  } = signals;
  let (packet_tx, mut packet_rx) = packets;
  let mut tasks = JoinSet::<()>::new();
  let mut lifecycle = LifecyclePublisher::new(state);
  if !announce_running(&mut lifecycle, ready) {
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
  terminate_stale_traces(&supervisor).await;
  match spawn_tick_workers(&supervisor) {
    Ok(workers) => supervisor.tick_workers = workers,
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
  }
  let terminal = run_control_loop(
    &mut supervisor,
    &mut control,
    &mut leave_signal,
    &mut packet_rx,
    &mut tasks,
  )
  .await;
  // The one shutdown sequence runs here, once the loop has stopped serving
  // arms: the supervisor releases its planes first so the teardown below
  // awaits them, and the reason the loop returned with is the reason every
  // queued reply answers.
  let (dependencies, drained) = supervisor.into_dependencies();
  finish_shutdown(
    control,
    tasks,
    dependencies,
    drained,
    &mut lifecycle,
    terminal.first_reply,
    terminal.reason,
  )
  .await;
}

/// Publishes the running snapshot and hands the caller its ready signal: the
/// node is observable as running before `start` returns, and a caller that
/// already dropped the signal (a cancelled start) is reported so `supervise`
/// runs the one shutdown sequence instead of serving arms no caller can
/// reach.
fn announce_running(lifecycle: &mut LifecyclePublisher, ready: oneshot::Sender<()>) -> bool {
  lifecycle.publish(LifecycleSnapshot::running());
  ready.send(()).is_ok()
}

/// Terminates any trace record still non-terminal from a previous
/// incarnation: a restart never continues a body, so a record the previous
/// process left open terminates explicitly here. A failure is diagnosed and
/// startup continues — a stale record must never keep a node from running.
async fn terminate_stale_traces(supervisor: &Supervisor) {
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
}

/// Spawns the periodic planes OFF the select loop:
/// one long-lived recovery-observation worker (recovery tick plus the
/// four retention sweeps), one degree-maintenance worker, and one
/// trigger-evaluation worker, each owning its own `sched` cadence, so
/// slow storage or a slow policy never parks control-plane reads and
/// packet admission behind a tick. Bounded accounting: exactly three
/// tasks for the node's lifetime, aborted and awaited by the shutdown
/// path — never one spawned task per tick.
fn spawn_tick_workers(supervisor: &Supervisor) -> Result<Vec<tokio::task::JoinHandle<()>>> {
  let ticks = std::sync::Arc::new(supervisor.tick_state()?);
  let recovery_schedule = supervisor
    .dependencies
    .config
    .recovery_schedule()
    .to_owned();
  let degree_schedule = supervisor.dependencies.config.degree_schedule().to_owned();
  let recovery_ticks = std::sync::Arc::clone(&ticks);
  let degree_ticks = std::sync::Arc::clone(&ticks);
  Ok(vec![
    tokio::spawn(async move {
      super::recovery::run_recovery_worker_with_schedule(recovery_ticks, &recovery_schedule).await;
    }),
    tokio::spawn(async move {
      super::degree::run_maintenance_worker_with_schedule(degree_ticks, &degree_schedule).await;
    }),
    tokio::spawn(super::retention::run_trigger_evaluation_worker(ticks)),
  ])
}

/// The control loop: one select iteration serves exactly one ready arm, and
/// the loop returns only when an arm reaches a terminal phase — a served
/// command never leaves it. The packet plane's admission slot, handoff
/// channel, and closed-channel flags are loop-local because they are this
/// loop's own state machine, not the supervisor's.
async fn run_control_loop(
  supervisor: &mut Supervisor, control: &mut mpsc::Receiver<Control>,
  leave_signal: &mut mpsc::Receiver<LeaveSignal>,
  packet_rx: &mut mpsc::Receiver<crate::packet::OutboundRequest>, tasks: &mut JoinSet<()>,
) -> TerminalPhase {
  // The packet admission plane: target
  // resolution, descriptor validation, first-hop selection, and the route
  // record run in spawned admission tasks, never inline here — a
  // caller-supplied policy that never resolves parks one bounded
  // admission slot instead of the control loop's control reads, other
  // packet admissions, and shutdown. Record-before-pump ordering
  // survives the move: the admission task records the route before it
  // hands the ready request back through the bounded channel below, and
  // only the loop (the pump `JoinSet`'s owner) spawns `run_outbound`.
  let admission = PacketAdmission::new(supervisor);
  let admission_permits = Arc::new(Semaphore::new(ADMISSION_CONCURRENCY));
  // The admission permit the packet arm holds while admitting: `None`
  // disables the arm (a saturated pool) until a running admission
  // releases one. The loop's own `pump_tx` keeps the handoff channel
  // open for the node's lifetime, and `packets_open` keeps a closed
  // command channel from being polled forever.
  let mut packet_permit: Option<OwnedSemaphorePermit> = None;
  let (pump_tx, mut pump_rx) = mpsc::channel::<PumpHandoff>(PUMP_HANDOFF_CAPACITY);
  let mut pump_open = true;
  let mut packets_open = true;
  // The leave plane's signal: the success tears down with the
  // active-leave reason, and a failure after the leave's teardown began
  // tears down with the failure's kind — the node cannot keep running
  // once its listeners and sessions are down. A closed channel means
  // every sender (the manager and the operation planes) is gone, so the
  // arm is disabled rather than polled again.
  let mut leave_signals_open = true;
  loop {
    // Fill the packet arm's admission slot without awaiting: a saturated
    // pool leaves the arm disabled, and the bounded packet command
    // channel carries the backpressure instead of the loop.
    if packets_open && packet_permit.is_none() {
      packet_permit = admission_permits.clone().try_acquire_owned().ok();
    }
    tokio::select! {
      message = control.recv() => {
        let Some(message) = message else {
          // The control channel closed: every handle is gone, so the node
          // tears down with the explicit reason and no reply to answer.
          return TerminalPhase {
            reason: ShutdownReason::Explicit,
            first_reply: None,
          };
        };
        if let Some(terminal) = serve_control_command(supervisor, tasks, message).await {
          return terminal;
        }
      }
      request = packet_rx.recv(), if packets_open && packet_permit.is_some() => {
        let Some(request) = request else {
          // The command channel closed: stop polling the arm (a closed
          // channel would otherwise be ready every iteration).
          packets_open = false;
          packet_permit = None;
          continue;
        };
        let Some(permit) = packet_permit.take() else {
          continue;
        };
        admit_packet(supervisor, &admission, &pump_tx, tasks, permit, request);
      }
      // A finishing admission releases its permit: this arm re-enables
      // the packet arm without parking any other arm, so control reads
      // stay served while every admission slot is busy.
      permit = admission_permits.clone().acquire_owned(), if packets_open && packet_permit.is_none() => {
        // The semaphore is never closed for the node's lifetime; a closed
        // one (shutdown) leaves the packet arm disabled, which is the
        // exit path.
        if let Ok(permit) = permit {
          packet_permit = Some(permit);
        }
      }
      handoff = pump_rx.recv(), if pump_open => {
        let Some(handoff) = handoff else {
          pump_open = false;
          continue;
        };
        pump_outbound(supervisor, tasks, handoff);
      }
      finished = tasks.join_next(), if !tasks.is_empty() => reap_packet_task(finished),
      signal = leave_signal.recv(), if leave_signals_open => {
        match signal {
          Some(LeaveSignal::Complete) => {
            return TerminalPhase {
              reason: ShutdownReason::ActiveLeave,
              first_reply: None,
            };
          }
          Some(LeaveSignal::Fatal(kind)) => {
            return TerminalPhase {
              reason: ShutdownReason::Fatal(kind),
              first_reply: None,
            };
          }
          None => leave_signals_open = false,
        }
      }
    }
  }
}

/// Serves one control command inline, as the loop's contract requires: the
/// calling handle awaits its oneshot before returning, so every command is
/// answered before the loop takes its next arm. Returns the terminal phase
/// only for `Shutdown`; every read verb answers its reply and returns
/// `None`, leaving the loop serving.
async fn serve_control_command(
  supervisor: &mut Supervisor, tasks: &JoinSet<()>, message: Control,
) -> Option<TerminalPhase> {
  match message {
    Control::Shutdown { reply } => {
      return Some(TerminalPhase {
        reason: ShutdownReason::Explicit,
        first_reply: Some(reply),
      });
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
    Control::PageMembers {
      cursor,
      limit,
      reply,
    } => {
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
    Control::PageResources {
      cursor,
      limit,
      reply,
    } => {
      let result = supervisor.page_resources(cursor, limit).await;
      let _ = reply.send(result);
    }
    Control::WatchResources { options, reply } => {
      let result = supervisor.watch_resources(options).await;
      let _ = reply.send(result);
    }
    Control::PageListeners {
      cursor,
      limit,
      reply,
    } => {
      let result = supervisor.page_listeners(cursor, limit).await;
      let _ = reply.send(result);
    }
    Control::PageSessions {
      cursor,
      limit,
      reply,
    } => {
      let result = supervisor.page_sessions(cursor, limit).await;
      let _ = reply.send(result);
    }
    Control::PageTopology {
      cursor,
      limit,
      reply,
    } => {
      let result = supervisor.page_topology(cursor, limit).await;
      let _ = reply.send(result);
    }
    Control::PageTrust {
      cursor,
      limit,
      reply,
    } => {
      let result = supervisor.page_trust(cursor, limit).await;
      let _ = reply.send(result);
    }
    Control::Observability { reply } => {
      let result = supervisor.observability_snapshot(tasks).await;
      let _ = reply.send(result);
    }
  }
  None
}

/// Hands one queued packet command to a spawned admission task: the permit
/// is the admission slot and lives as long as the resolution work, so
/// `ADMISSION_CONCURRENCY` bounds the in-flight admissions regardless of
/// what a caller-supplied policy awaits, and the recorded route returns to
/// the loop through the pump channel because only the loop (the pump set's
/// owner) spawns `run_outbound`. A request whose identity context is gone is
/// rejected in place with the internal kind, so no caller is left without a
/// terminal decision.
fn admit_packet(
  supervisor: &Supervisor, admission: &PacketAdmission, pump_tx: &mpsc::Sender<PumpHandoff>,
  tasks: &mut JoinSet<()>, permit: OwnedSemaphorePermit, request: crate::packet::OutboundRequest,
) {
  // The identity context (and the store handle it carries) is cloned per
  // admission and lives only inside the admission task: a long-lived clone
  // here would survive the shutdown path's storage drain.
  let Some(context) = supervisor.dependencies.context.clone() else {
    request.reject(crate::ErrorKind::Internal);
    return;
  };
  let admission = admission.clone();
  let pump = pump_tx.clone();
  // The packet context is cloned per admission for the local delivery leg;
  // the trace sink it carries holds the identity context only weakly, so
  // the clone never outlives the shutdown path's storage drain.
  let packet = Arc::clone(&supervisor.packet);
  tasks.spawn(async move {
    // The permit is the admission slot and lives as long as the resolution
    // work, so `ADMISSION_CONCURRENCY` bounds the in-flight admissions
    // regardless of what a policy awaits.
    let _permit = permit;
    match admission.admit(&context, &packet, request).await {
      // The recorded route returns to the loop, which owns the pump
      // `JoinSet` and spawns `run_outbound`.
      Ok(Some(handoff)) => {
        if let Err(mpsc::error::SendError(handoff)) = pump.send(handoff).await {
          // The loop is gone: the request must observe a typed shutdown
          // terminal, never a dangling admission decision.
          admission.reject_shutdown(handoff);
        }
      }
      Ok(None) => {}
      Err(error) => {
        tracing::warn!(kind = ?error.kind(), "packet admission failed");
      }
    }
  });
}

/// Spawns the pump for one admitted packet: the route record already landed
/// in the admission task (record-before-pump), so the pump only runs the
/// request under the loop's task set. The handoff's delivery leg decides
/// where the frames go: a session leg rides the outbound session pump; the
/// local leg admits and consumes the stream in-process.
fn pump_outbound(supervisor: &Supervisor, tasks: &mut JoinSet<()>, handoff: PumpHandoff) {
  let local = supervisor.packet.local().clone();
  let routes = supervisor.dependencies.routes.clone();
  let events = Arc::clone(&supervisor.dependencies.events);
  let PumpHandoff {
    leg,
    request,
    route,
  } = handoff;
  // Core-internal control traffic stays out of the durable trace store —
  // its volume is a runtime implementation detail, not caller evidence —
  // so the pump holds no sink for it, and the record flag carries the same
  // exclusion to the read loop's late-failure revision path.
  let trace = if request.internal {
    None
  } else {
    Some(supervisor.trace_sink.clone())
  };
  tasks.spawn(async move {
    run_outbound(leg, local, request, routes, route, trace, events).await;
  });
}

/// Reaps one finished packet task (an admission or its pump) as it completes
/// instead of letting its handle accumulate in the task set until shutdown:
/// the set stays bounded by the live
/// admission-plus-pump count, and a join error (a panicked or aborted task)
/// stays visible as a diagnostic.
fn reap_packet_task(finished: Option<std::result::Result<(), tokio::task::JoinError>>) {
  if let Some(Err(error)) = finished {
    tracing::warn!(%error, "packet task exited abnormally");
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
  // population, never one task per tick.
  pub(super) tick_workers: Vec<tokio::task::JoinHandle<()>>,
  pub(super) trace_sink: crate::routing::trace::TraceSink,
  // Approximate live durable trace-record population, shared with the
  // sink (incremented per successful persistence) and decremented by the
  // retention sweep's removals; zero means sweeps can stay skipped.
  pub(super) trace_records: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// The periodic planes' shared state: everything the recovery-observation
/// worker (`recovery_tick` plus the three retention sweeps) and the
/// degree-maintenance worker need to run OFF the supervisor's select loop,
/// because slow storage or a slow policy resolution must
/// never park control-plane reads and packet admission behind a tick.
/// Built once per incarnation by [`Supervisor::tick_state`] from the one
/// Arc-held operation-deps handle plus the tick-local counters, so the
/// workers observe the one truth per collaborator — no second
/// controller, cache, or session table.
/// Mutation is confined to atomics and the briefly-held controller mutex,
/// so every method takes `&self` and both workers share one `Arc<TickState>`.
pub(super) struct TickState {
  /// The node-shared operation planes behind one Arc handle: the
  /// identity context, the calibrated config, the entropy source, the
  /// session table, the driver, the packet context, the connection-task
  /// registry, the recovery controller, and the exclusion cache are read
  /// through it (see the accessors below) — the same instances the
  /// supervisor and the verb effects share, so the workers observe the
  /// one truth per collaborator.
  pub(super) operations: Arc<super::task_effects::OperationDeps>,
  pub(super) extensions: Arc<ExtensionRegistry>,
  pub(super) events: Arc<crate::node::EventHub>,
  /// The graceful-shutdown signal: each worker clones its receiver and
  /// exits cooperatively; the abort in `into_dependencies` is the
  /// backstop for a mid-tick stall.
  pub(super) shutdown: watch::Receiver<()>,
  /// The approximate live durable trace-record population the trace
  /// retention sweep decrements (the same counter the observability
  /// view reads).
  pub(super) trace_records: Arc<std::sync::atomic::AtomicUsize>,
  /// In-flight recovery dials: bounds the isolated node's dial fan-out
  /// (the counter bounds in-flight dials, not lifetime volume).
  pub(super) recovery_pending: Arc<std::sync::atomic::AtomicUsize>,
  /// In-flight connection-degree maintenance dials: bounds one tick's
  /// batch so a slow mesh never doubles its own dial load every cadence
  /// (see `runtime/degree.rs`).
  pub(super) maintenance_pending: Arc<std::sync::atomic::AtomicUsize>,
  /// The bridge-probe cadence bracket: maintenance ticks an otherwise
  /// quiescent healthy node waits before its next cross-partition probe
  /// dial (the plane's residual boundary — see `runtime/degree.rs`).
  /// Only the maintenance worker mutates it, so a racing read at worst
  /// shifts one probe by one tick.
  pub(super) bridge_probe_ticks: Arc<std::sync::atomic::AtomicU32>,
  /// The bridge-probe plane's own ledger: the probe edge it holds (with
  /// its age in probe intervals) and the peer it just released, so the
  /// one-edge cap is bounded in time instead of forever (see
  /// `runtime/degree.rs`).
  pub(super) probe_ledger: std::sync::Mutex<super::degree::ProbeLedger>,
  /// Recovery-tick cooldown before the next redundant-edge cut. Only
  /// the recovery worker mutates it; a racing read at worst shifts one
  /// cut by one tick.
  pub(super) prune_cooldown: Arc<std::sync::atomic::AtomicU32>,
  /// The task manager's client half, when the incarnation carries a
  /// manager (production always does): the controller submissions run
  /// the sweeps on the task machinery. `None` — the fixture-built
  /// supervisor without a manager — runs the same engine bodies inline.
  pub(super) tasks: Option<TaskClient>,
}

impl TickState {
  /// The opened identity context (through the operation planes).
  pub(super) fn context(&self) -> &Arc<LocalIdentityContext> {
    &self.operations.planes().context
  }

  /// The calibrated node configuration (through the operation planes).
  pub(super) fn config(&self) -> &NodeConfig {
    &self.operations.planes().config
  }

  /// The node's entropy source (through the operation planes).
  pub(super) fn entropy(&self) -> &Arc<dyn crate::api::Entropy> {
    &self.operations.planes().entropy
  }

  /// The live authenticated sessions (through the operation planes).
  pub(super) fn sessions(&self) -> &SessionTable {
    &self.operations.planes().sessions
  }

  /// The session driver (through the operation planes).
  pub(super) fn driver(&self) -> &SessionDriver {
    &self.operations.planes().driver
  }

  /// The node-shared packet context (through the operation planes).
  pub(super) fn packet(&self) -> &Arc<SessionPacketContext> {
    &self.operations.planes().packet
  }

  /// The tracked connection tasks the recovery tick reaps (through the
  /// operation planes).
  pub(super) fn connection_tasks(
    &self,
  ) -> &Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> {
    &self.operations.planes().connection_tasks
  }

  /// The recovery controller (the same instance the supervisor's read
  /// view locks; through the operation planes).
  pub(super) fn recovery(
    &self,
  ) -> &Arc<std::sync::Mutex<crate::membership::recovery::RecoveryController>> {
    &self.operations.planes().recovery
  }

  /// The departed-members exclusion cache (the same instance the
  /// supervisor's member pages memoize through; through the operation
  /// planes).
  pub(super) fn exclusion_cache(&self) -> &super::recovery::ExclusionCache {
    &self.operations.planes().exclusion_cache
  }

  /// The node's endpoint selector: the registration-channel-resolved
  /// policy wrapped with the per-member rotation serials every dial
  /// plane shares (through the operation planes).
  pub(super) fn endpoint_selector(&self) -> &Arc<crate::EndpointSelector> {
    &self.operations.planes().endpoint_selector
  }

  /// The task manager's client half, when the incarnation carries a
  /// manager (see [`TickState::tasks`]).
  pub(super) fn tasks(&self) -> Option<&TaskClient> {
    self.tasks.as_ref()
  }
}

/// Builds the node-shared packet context (single construction site):
/// every collaborator is cloned from one struct instead of a
/// ten-argument positional call where a transposed same-typed `Arc`
/// would compile and silently miswire.
fn session_packet_context(
  context: &Arc<LocalIdentityContext>, dependencies: &RuntimeDependencies,
  packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
  policy: crate::session::stream::SessionPolicy,
  authorization: crate::session::stream::AuthorizationBoundary,
) -> Result<SessionPacketContext> {
  // The effective route policy tag was resolved in the registration
  // channel (the node builder) and ships with the dependencies.
  let route_policy = dependencies.route_policy.clone();
  let trace_metadata_active = dependencies.config.trace_metadata_limits().active();
  // The durable trace sink is born with the packet context it serves (one
  // construction site): the origin pump's terminal facts and the read
  // loop's late-failure revisions share one bounded queue and one
  // live-record counter with the retention sweep and the observability
  // view.
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
    dependencies.sessions.clone(),
    crate::session::stream::RoutingPlaneContext::new(
      route_policy,
      dependencies.routes.clone(),
      Some(trace_sink),
      // One configured bound for both in-memory route populations: the
      // forwarding table and the terminal route records share the trace
      // metadata budget the route table derives its capacity from.
      trace_metadata_active,
      trace_metadata_active,
      dependencies.config.relay_hop_deadline(),
    ),
    Arc::clone(&dependencies.connection_tasks),
    crate::protocol::CONTROL_CBOR_LIMITS,
    authorization,
  ))
}

/// Builds the node-shared operation handles: the session driver (one
/// credential issuer for the whole incarnation), the packet context, and
/// the graceful-shutdown signal.
/// Called once by `spawn_runtime`, and by the supervisor unit tests that
/// build a standalone supervisor without the runtime's task manager.
pub(super) fn operation_deps(
  dependencies: &RuntimeDependencies, packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
  offer: crate::protocol::offer::FeatureOffer,
  features: std::sync::Arc<crate::protocol::feature::FeatureRegistry>,
  authorization: crate::session::stream::AuthorizationBoundary,
  leave_signal: mpsc::Sender<LeaveSignal>,
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
    authorization,
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
    leave_signal,
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
    let planes = operations.planes();
    let packet = Arc::clone(&planes.packet);
    let shutdown_tx = planes.shutdown.clone();
    let exclusion_cache = Arc::clone(&planes.exclusion_cache);
    let published_endpoints = Arc::clone(&planes.published_endpoints);
    let route_capacity = dependencies.config.trace_metadata_limits().active();
    // The durable trace sink was constructed with the packet context (one
    // construction site) and is read back here: the origin pump's terminal
    // facts, the read loop's late-failure revisions, the retention sweep,
    // and the observability view all share the one bounded instance and
    // its live-record counter.
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
      dependencies.config.anti_entropy_schedule(),
      shutdown_tx.subscribe(),
      sync_rounds,
      dependencies.events.clone(),
      dependencies.member_revision.clone(),
      dependencies.reconcile.clone(),
    ));
    let recovery = std::sync::Arc::clone(&operations.planes().recovery);
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

  /// Builds the periodic planes' shared state (see [`TickState`]): the
  /// one Arc handle to the node-shared operation planes, a fresh
  /// shutdown subscription, and the tick-local counters. Called exactly
  /// once by `supervise` when it spawns the two tick workers.
  pub(super) fn tick_state(&self) -> Result<TickState> {
    let operations = self
      .dependencies
      .operations
      .as_ref()
      .ok_or_else(|| Error::internal("runtime operations"))?
      .clone();
    Ok(TickState {
      operations,
      extensions: Arc::clone(&self.dependencies.extensions),
      events: Arc::clone(&self.dependencies.events),
      shutdown: self.shutdown_tx.subscribe(),
      trace_records: Arc::clone(&self.trace_records),
      tasks: self.dependencies.tasks.clone(),
      recovery_pending: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
      maintenance_pending: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
      bridge_probe_ticks: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(
        super::degree::BRIDGE_PROBE_INTERVAL_TICKS,
      )),
      probe_ledger: std::sync::Mutex::new(super::degree::ProbeLedger::default()),
      prune_cooldown: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
    })
  }

  fn into_dependencies(mut self) -> (RuntimeDependencies, Vec<tokio::task::JoinHandle<()>>) {
    // Every open session task observes the shutdown signal and closes its
    // connection instead of being orphaned when the supervisor exits; the
    // abortable node planes (the anti-entropy driver and the two tick
    // workers) are aborted now and their handles returned so the shutdown
    // path can await them and their storage captures are deterministically
    // dropped before a restarted node reopens the same factory.
    let _ = self.shutdown_tx.send(());
    let mut drained = Vec::new();
    if let Some(driver) = self.sync_driver.take() {
      driver.abort();
      drained.push(driver);
    }
    // The tick workers observe the shutdown signal above and exit
    // cooperatively; the abort is the backstop for a worker stalled
    // mid-tick (its storage handles drop with the task), and the
    // returned handles keep the shutdown reply behind their teardown.
    for worker in self.tick_workers.drain(..) {
      worker.abort();
      drained.push(worker);
    }
    // The accept loops park on `accept()` and cannot observe the graceful
    // signal, so they are aborted here through the same registry abort
    // handles the explicit stop and the leave teardown use (a second abort
    // of an already-stopped loop is a no-op): a loop left for the
    // cooperative window below could never finish it, and every listening
    // node would sit out the whole grace at shutdown.
    if let Ok(listeners) = self.dependencies.listeners.lock() {
      for (_, _, abort) in listeners.values() {
        abort.abort();
      }
    }
    // The tracked connection tasks (kept session pumps, in-flight dials,
    // and the graceful consumer drains) are returned LIVE, not aborted:
    // the signal above is their cooperative exit cue, and the shutdown
    // path gives them one bounded grace window before aborting only the
    // stragglers — an in-flight consumer apply must complete, and the
    // reply still waits behind every handle's teardown.
    if let Ok(mut handles) = self.dependencies.connection_tasks.lock() {
      drained.extend(handles.drain(..));
    }
    // Definitive session teardown: the graceful shutdown signal lets live
    // session tasks run their exit cleanup, but an abort landing first
    // skips it — draining the table here drops each entry's frame sender
    // so the detached writer task still exits and the connection closes.
    if let Err(error) = crate::session::stream::retire_all_sessions(&self.dependencies.sessions) {
      tracing::warn!(kind = ?error.kind(), "session table teardown failed");
    }
    (self.dependencies, drained)
  }

  pub(super) fn context(&self) -> Result<Arc<LocalIdentityContext>> {
    self
      .dependencies
      .context
      .clone()
      .ok_or_else(|| Error::internal("runtime context"))
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
    Arc<crate::storage::contract::ReferenceFactory>,
    Arc<dyn crate::api::Entropy>,
  ) {
    let reference = Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ));
    let factory: Arc<dyn StorageFactory> = reference.clone();
    let keys: Arc<dyn KeyProvider> = ScriptedKeys::full().as_provider();
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      open_local_identity(&factory, Some(&keys), entropy.as_ref(), retention)
        .await
        .unwrap(),
    );
    let config = NodeConfig::new().with_receipt_retention(retention).unwrap();
    let mut extensions = ExtensionRegistry::new();
    extensions.register_default().unwrap();
    let extensions = Arc::new(extensions);
    // The same registration-channel resolution the node builder applies.
    let route_policy = extensions
      .effective_route_policy(config.route_policy())
      .unwrap();
    let endpoint_policy = extensions
      .effective_endpoint_policy(config.endpoint_policy(), config.endpoint_preference())
      .unwrap();
    let definitions = extensions.feature_definitions();
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
      route_policy,
      endpoint_policy,
      entropy: entropy.clone(),
      extensions,
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
      tasks: None,
      triggers: None,
      operations: None,
      runtime_seed: None,
    };
    // The operation handles are built the way `spawn_runtime` builds them,
    // so the test drives the exact production construction path for the
    // packet context and the session driver too.
    let (leave_signal, _leave_signals) = mpsc::channel(super::LEAVE_SIGNAL_CAPACITY);
    let operations = super::operation_deps(
      &dependencies,
      packet_tx.clone(),
      offer,
      registry,
      crate::session::stream::AuthorizationBoundary::default(),
      leave_signal,
    )
    .expect("operation handles");
    dependencies.operations = Some(operations);
    let supervisor = match Supervisor::new(dependencies, packet_tx, round_rx) {
      Ok(supervisor) => supervisor,
      Err(boxed) => panic!("supervisor construction failed: {}", boxed.0),
    };
    (supervisor, reference, entropy)
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
      .prepare_core_verb_transaction(
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
    assert_eq!(report.forgotten(), 0);
    assert!(!report.remaining());

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

    // The manual command forgets the elapsed receipt. The ceremony
    // behind the fixture forgets its own receipts inline, so no
    // candidate population hides behind this pass: the forgotten count
    // is exactly the receipt anchored above.
    let report = supervisor
      .context()
      .unwrap()
      .store()
      .apply_receipt_retention()
      .await
      .unwrap();
    assert_eq!(report.forgotten(), 1);
    assert!(!report.remaining());
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
    assert_eq!(report.forgotten(), 0);
    assert!(!report.remaining());
  }

  /// The retention tick holds the same quietness contract as the
  /// reconcile tick's quiescence probe: a fresh single node that just
  /// completed its identity ceremony leaves no retention candidate and
  /// no anchor behind, so repeated retention sweeps find nothing and the
  /// store's commit count does not grow (a leftover ceremony retention
  /// candidate would make the first tick commit the anchor
  /// and the candidate consumption as two background writes, drifting
  /// commit-count pins and racing conditional commits on CI).
  #[tokio::test]
  async fn fresh_node_retention_sweeps_stay_storage_quiet() {
    let (supervisor, reference, _entropy) = sweep_supervisor(Duration::from_secs(10)).await;
    let ticks = supervisor.tick_state().unwrap();
    let commits_before = reference
      .commit_calls
      .load(std::sync::atomic::Ordering::SeqCst);
    for _ in 0..3 {
      ticks.receipt_retention_sweep().await;
    }
    assert_eq!(
      reference
        .commit_calls
        .load(std::sync::atomic::Ordering::SeqCst),
      commits_before,
      "a fresh node's retention sweeps must not commit anything"
    );
  }
}

/// The shutdown drain contract for the tracked connection tasks: the
/// graceful consumer drains (and every kept session pump) must survive
/// node shutdown long enough to finish an in-flight apply, while a task
/// that never settles can only delay the shutdown reply to the
/// cooperative window's edge. Both drive the real teardown sequence —
/// `into_dependencies` then `finish_shutdown` — over the shared
/// supervisor fixture, with tokio's paused clock making the window
/// deterministic.
#[cfg(test)]
mod shutdown_drain_tests {
  use std::{
    sync::{
      Arc,
      atomic::{AtomicBool, Ordering},
    },
    time::Duration,
  };

  use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
  };

  use super::{CONTROL_CAPACITY, LifecyclePublisher, test_support};
  use crate::{
    BoxFuture, CommitOutcome, Digest, ReconcileOutcome, ShutdownReason, StoreCapabilities,
    StoreRequirements, StoreTransaction, TransactionId,
    extension::StoreSnapshot,
    provider::{Storage, StorageFactory},
    runtime::{
      LifecycleSnapshot,
      shutdown::{CONNECTION_TASK_SHUTDOWN_GRACE, finish_shutdown},
    },
    storage::contract::ReferenceFactory,
  };

  /// A storage whose `flush` (the execution completion barrier) parks on
  /// a gate until the test releases it, so the shutdown path's wait
  /// behind the barrier is directly observable. Everything else is the
  /// reference store unchanged.
  #[derive(Debug)]
  struct FlushHoldingStorage {
    reference: Box<dyn Storage>,
    gate: watch::Receiver<bool>,
    reached: std::sync::Arc<AtomicBool>,
  }

  #[derive(Debug)]
  struct FlushHoldingFactory {
    reference: Arc<ReferenceFactory>,
    gate: watch::Sender<bool>,
    reached: std::sync::Arc<AtomicBool>,
  }

  impl StorageFactory for FlushHoldingFactory {
    fn open<'a>(
      &'a self, requirements: StoreRequirements,
    ) -> BoxFuture<'a, crate::Result<Box<dyn Storage>>> {
      let reference = Arc::clone(&self.reference);
      let gate = self.gate.subscribe();
      let reached = std::sync::Arc::clone(&self.reached);
      Box::pin(async move {
        let reference = reference.open(requirements).await?;
        Ok(Box::new(FlushHoldingStorage {
          reference,
          gate,
          reached,
        }) as Box<dyn Storage>)
      })
    }
  }

  impl Storage for FlushHoldingStorage {
    fn capabilities(&self) -> StoreCapabilities {
      self.reference.capabilities()
    }

    fn snapshot<'a>(&'a self) -> BoxFuture<'a, crate::Result<Box<dyn StoreSnapshot>>> {
      self.reference.snapshot()
    }

    fn commit<'a>(
      &'a self, transaction: StoreTransaction,
    ) -> BoxFuture<'a, crate::Result<CommitOutcome>> {
      self.reference.commit(transaction)
    }

    fn reconcile<'a>(
      &'a self, transaction: &'a TransactionId, digest: &'a Digest,
    ) -> BoxFuture<'a, crate::Result<ReconcileOutcome>> {
      self.reference.reconcile(transaction, digest)
    }

    fn flush<'a>(&'a self) -> BoxFuture<'a, crate::Result<()>> {
      let mut gate = self.gate.clone();
      Box::pin(async move {
        self.reached.store(true, Ordering::Relaxed);
        while !*gate.borrow_and_update() {
          if gate.changed().await.is_err() {
            break;
          }
        }
        self.reference.flush().await
      })
    }
  }

  /// An in-flight consumer drain's apply completes at shutdown instead
  /// of being aborted mid-apply: the tracked drain task is handed out
  /// live by `into_dependencies`, and `finish_shutdown`'s cooperative
  /// window outlasts the apply's settle (the `ConsumerDrainGuard`
  /// contract in `session::inbound`). An abort-everything
  /// teardown would kill the parked apply with the node and leave the flag
  /// false.
  #[tokio::test(start_paused = true)]
  async fn shutdown_completes_an_in_flight_consumer_drain_apply() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, _sessions) = test_support::supervisor_over(
      reference as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;

    // One tracked connection task shaped like the read loop's teardown
    // drain: it owns a `JoinSet` whose single consumer is an apply parked
    // mid-persist, and it exits only when that apply settles.
    let applied = Arc::new(AtomicBool::new(false));
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let settle = Arc::clone(&applied);
    let drain = tokio::spawn(async move {
      let mut consumers = tokio::task::JoinSet::new();
      consumers.spawn(async move {
        let _ = release_rx.await;
        settle.store(true, Ordering::Relaxed);
      });
      while consumers.join_next().await.is_some() {}
    });
    supervisor
      .dependencies
      .connection_tasks
      .lock()
      .unwrap()
      .push(drain);
    // The apply settles 100ms into the cooperative window, well inside
    // the bound.
    tokio::spawn(async move {
      tokio::time::sleep(Duration::from_millis(100)).await;
      let _ = release_tx.send(());
    });

    let (_control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
    let (state_tx, _state_rx) = watch::channel(LifecycleSnapshot::starting());
    let mut lifecycle = LifecyclePublisher::new(state_tx);
    let started = tokio::time::Instant::now();
    let (dependencies, drained) = supervisor.into_dependencies();
    finish_shutdown(
      control_rx,
      JoinSet::new(),
      dependencies,
      drained,
      &mut lifecycle,
      None,
      ShutdownReason::Explicit,
    )
    .await;

    assert!(
      applied.load(Ordering::Relaxed),
      "the in-flight consumer apply must complete at shutdown, not be aborted mid-apply"
    );
    assert!(
      started.elapsed() < CONNECTION_TASK_SHUTDOWN_GRACE,
      "a settling apply must not sit out the whole window ({} elapsed)",
      started.elapsed().as_millis()
    );
  }

  /// The negative space: a deliberately wedged connection task cannot
  /// delay the shutdown reply past the cooperative window — the
  /// straggler is aborted at the window's edge, reaped, and the reply
  /// resolves, so total shutdown stays bounded no matter what a task
  /// holds.
  #[tokio::test(start_paused = true)]
  async fn shutdown_bounds_a_wedged_connection_task_at_the_grace() {
    let (reference, config) = test_support::reference_and_config();
    let (supervisor, _entropy, _sessions) = test_support::supervisor_over(
      reference as Arc<dyn crate::provider::StorageFactory>,
      config,
    )
    .await;

    // A task that never settles: no signal it observes, no completion.
    supervisor
      .dependencies
      .connection_tasks
      .lock()
      .unwrap()
      .push(tokio::spawn(std::future::pending::<()>()));

    let (_control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
    let (state_tx, _state_rx) = watch::channel(LifecycleSnapshot::starting());
    let mut lifecycle = LifecyclePublisher::new(state_tx);
    let tracked = Arc::clone(&supervisor.dependencies.connection_tasks);
    let (dependencies, drained) = supervisor.into_dependencies();
    assert!(
      tracked.lock().unwrap().is_empty(),
      "the tracked set must be drained into the shutdown path, not aborted in place"
    );
    let started = tokio::time::Instant::now();
    finish_shutdown(
      control_rx,
      JoinSet::new(),
      dependencies,
      drained,
      &mut lifecycle,
      None,
      ShutdownReason::Explicit,
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
      elapsed >= CONNECTION_TASK_SHUTDOWN_GRACE,
      "the wedged task must actually get the cooperative window ({elapsed:?})"
    );
    assert!(
      elapsed < CONNECTION_TASK_SHUTDOWN_GRACE + Duration::from_millis(500),
      "the wedged task must not hold the reply past the window ({elapsed:?})"
    );
  }

  /// `finish_shutdown` provides the storage execution completion barrier:
  /// the shutdown reply must not return while
  /// the node's storage still has an in-flight execution — represented
  /// here by a flush that parks on a gate — and must return promptly
  /// once the barrier resolves. An immediate-return flush would land the
  /// reply while the "execution" still holds the database.
  #[tokio::test]
  async fn shutdown_awaits_the_storage_execution_completion_barrier() {
    let (reference, config) = test_support::reference_and_config();
    let (gate_tx, _gate_rx) = watch::channel(false);
    let reached = Arc::new(AtomicBool::new(false));
    let factory = FlushHoldingFactory {
      reference,
      gate: gate_tx.clone(),
      reached: Arc::clone(&reached),
    };
    let (supervisor, _entropy, _sessions) =
      test_support::supervisor_over(Arc::new(factory) as Arc<dyn StorageFactory>, config).await;

    let (_control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
    let (state_tx, _state_rx) = watch::channel(LifecycleSnapshot::starting());
    let mut lifecycle = LifecyclePublisher::new(state_tx);
    let (dependencies, drained) = supervisor.into_dependencies();
    let mut finish = std::pin::pin!(finish_shutdown(
      control_rx,
      JoinSet::new(),
      dependencies,
      drained,
      &mut lifecycle,
      None,
      ShutdownReason::Explicit,
    ));

    // The barrier is reached and the reply stays behind it.
    let observed = Arc::clone(&reached);
    tokio::select! {
      _ = &mut finish => panic!("the shutdown reply must not return before the barrier is even reached"),
      _ = async {
        while !observed.load(Ordering::Relaxed) {
          tokio::task::yield_now().await;
        }
      } => {},
      _ = tokio::time::sleep(Duration::from_secs(5)) => {
        panic!("the shutdown path must await the storage barrier");
      }
    }
    tokio::select! {
      _ = &mut finish => panic!("the shutdown reply must not return while the barrier holds"),
      _ = tokio::time::sleep(Duration::from_millis(200)) => {}
    }

    // Releasing the barrier releases the reply.
    gate_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), &mut finish)
      .await
      .expect("the shutdown reply must return once the barrier resolves");
  }
}

/// The control-loop admission contract: a
/// caller-supplied next-hop policy that never resolves may park only one
/// bounded admission slot. Control reads, another packet's admission,
/// and shutdown all complete inside their bounds while that admission
/// waits, and the admission decision still records the route before the
/// pump starts. The real `supervise` loop drives the shared fixture with
/// the pending policy registered through the same public registry path
/// the node builder uses.
#[cfg(test)]
mod admission_loop_tests {
  use std::{
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
  };

  use tokio::sync::{mpsc, oneshot, watch};

  use super::{
    ADMISSION_CONCURRENCY, CONTROL_CAPACITY, Control, LeaveSignal, LifecycleSnapshot,
    RuntimeSignals, ShutdownReason, supervise,
    test_support::{self, RuntimeFixture},
  };
  use crate::{
    BoxFuture, NextHopView, NodeId, QualifiedTag, Result, RouteNextHop, StreamTarget, TraceId,
    packet::{OutboundRequest, RoutedAckOutcome, StaticBody},
  };

  /// The box a control read or a packet admission must fit in while the
  /// pending policy's admission slot holds: the pre-fix inline await
  /// parked both for as long as the policy never resolves.
  const PROBE_BOX: Duration = Duration::from_secs(2);
  /// The box the shutdown drive and the control loop's exit must fit in.
  const SHUTDOWN_BOX: Duration = Duration::from_secs(10);
  /// The tag the fixture config selects and the pending policy owns.
  const PENDING_POLICY: &str = "example.com/policies/pending-admission";

  /// A next-hop policy that never resolves: exactly the caller-supplied
  /// policy an admission must be able to await off the control loop.
  #[derive(Debug, Default)]
  struct PendingNextHop {
    calls: Arc<AtomicUsize>,
  }

  impl RouteNextHop for PendingNextHop {
    fn plan<'a>(&'a self, _view: NextHopView<'a>) -> BoxFuture<'a, Result<Option<Vec<NodeId>>>> {
      self.calls.fetch_add(1, Ordering::Relaxed);
      Box::pin(std::future::pending())
    }
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace-{seed:021}")).unwrap()
  }

  /// One probe request plus its admission-ack receiver, shaped like a
  /// caller's exact-node send.
  fn probe_request(
    trace_id: TraceId, target: StreamTarget,
  ) -> (OutboundRequest, oneshot::Receiver<RoutedAckOutcome>) {
    probe_request_with_policy(trace_id, target, crate::RoutingPolicy::DIRECT)
  }

  /// The same probe under an explicit stream routing policy.
  fn probe_request_with_policy(
    trace_id: TraceId, target: StreamTarget, routing_policy: crate::RoutingPolicy,
  ) -> (OutboundRequest, oneshot::Receiver<RoutedAckOutcome>) {
    let (ack_notify, ack) = oneshot::channel();
    let request = OutboundRequest {
      trace_id,
      target,
      routing_policy,
      load_balancer: None,
      max_hops: 1,
      protocol: crate::ProtocolTag::parse("radiata.woooo.tech/protocols/admission-probe").unwrap(),
      metadata: crate::StreamMetadata::new(),
      body: Box::pin(StaticBody::new(Arc::from(&b"probe"[..]))),
      internal: false,
      ack_notify,
    };
    (request, ack)
  }

  /// The running control loop over the pending-policy fixture: the probe
  /// surface both admission tests drive.
  struct PendingLoop {
    control: mpsc::Sender<Control>,
    packet: mpsc::Sender<OutboundRequest>,
    routes: crate::routing::RouteTable,
    sessions: crate::session::stream::SessionTable,
    entropy: Arc<dyn crate::api::Entropy>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
    // A live node keeps both signal ends alive; the loop's leave and
    // lifecycle arms then stay armed exactly as in production.
    leave: mpsc::Sender<LeaveSignal>,
    state: watch::Receiver<LifecycleSnapshot>,
  }

  /// Starts the real control loop over the fixture with the pending policy
  /// registered through the public registry path the node builder uses.
  async fn start_pending_policy_loop() -> PendingLoop {
    let (reference, config) = test_support::reference_and_config();
    let policy = QualifiedTag::parse(PENDING_POLICY).unwrap();
    let config = config.with_route_policy(policy.clone());
    let pending = Arc::new(PendingNextHop::default());
    let calls = Arc::clone(&pending.calls);
    let RuntimeFixture {
      dependencies,
      packet_tx,
      packet_rx,
      sync_rounds,
      entropy,
      sessions,
      leave_signals,
    } = test_support::runtime_fixture_over(
      reference as Arc<dyn crate::provider::StorageFactory>,
      config,
      move |extensions| {
        extensions
          .register_next_hop(policy, pending)
          .expect("pending next-hop registration");
      },
    )
    .await;
    let routes = dependencies.routes.clone();
    // The signal's sender is the one the leave effect itself holds, so the
    // test drives the loop's arm through the production channel.
    let leave = dependencies
      .operations
      .as_ref()
      .expect("operation handles")
      .planes()
      .leave_signal
      .clone();
    let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
    let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(supervise(
      dependencies,
      (packet_tx.clone(), packet_rx),
      sync_rounds,
      RuntimeSignals {
        control: control_rx,
        leave_signal: leave_signals,
        state: state_tx,
        ready: ready_tx,
      },
    ));
    ready_rx.await.expect("the control loop starts");
    PendingLoop {
      control: control_tx,
      packet: packet_tx,
      routes,
      sessions,
      entropy,
      calls,
      task,
      leave,
      state: state_rx,
    }
  }

  impl PendingLoop {
    /// Waits until the pending policy has been reached `target` times.
    async fn wait_for_policy_calls(&self, target: usize) {
      tokio::time::timeout(PROBE_BOX, async {
        while self.calls.load(Ordering::Relaxed) < target {
          tokio::task::yield_now().await;
        }
      })
      .await
      .expect("the admission task must reach the pending policy");
    }

    /// Sends one probe request.
    async fn send(
      &self, seed: u32, destination: crate::NodeId,
    ) -> oneshot::Receiver<RoutedAckOutcome> {
      let (request, ack) = probe_request(trace(seed), StreamTarget::Exact(destination));
      self.packet.send(request).await.expect("packet channel");
      ack
    }

    /// A control read must answer inside the probe bound.
    async fn read(&self) {
      let (reply, reply_rx) = oneshot::channel();
      self
        .control
        .send(Control::GetRecovery { reply })
        .await
        .expect("control channel");
      tokio::time::timeout(PROBE_BOX, reply_rx)
        .await
        .expect("a control read must not queue behind a pending routing policy")
        .expect("control reply")
        .expect("recovery view");
    }

    /// The leave plane's fatal signal must stop the node with the
    /// failure's kind — never leave it `Running` after its teardown began.
    async fn fatal_leave(self, kind: crate::ErrorKind) {
      self
        .leave
        .send(LeaveSignal::Fatal(kind))
        .await
        .expect("leave channel");
      let mut state = self.state.clone();
      let reason = tokio::time::timeout(SHUTDOWN_BOX, async {
        loop {
          if let Some(reason) = state.borrow().reason() {
            return reason;
          }
          state.changed().await.expect("lifecycle state");
        }
      })
      .await
      .expect("the fatal leave stops the node");
      assert_eq!(reason, ShutdownReason::Fatal(kind));
      tokio::time::timeout(SHUTDOWN_BOX, self.task)
        .await
        .expect("the control loop must exit")
        .expect("the control loop must not panic");
    }

    /// Shutdown must answer inside the shutdown bound and the loop must
    /// exit without panicking.
    async fn shutdown(self) {
      let (reply, reply_rx) = oneshot::channel();
      self
        .control
        .send(Control::Shutdown { reply })
        .await
        .expect("control channel");
      let outcome = tokio::time::timeout(SHUTDOWN_BOX, reply_rx)
        .await
        .expect("shutdown must not queue behind a pending routing policy")
        .expect("shutdown reply");
      assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
      tokio::time::timeout(SHUTDOWN_BOX, self.task)
        .await
        .expect("the control loop must exit")
        .expect("the control loop must not panic");
    }
  }

  /// A leave that failed after its network teardown began cannot leave the
  /// node running: the leave plane's fatal signal drives the one shutdown
  /// sequence with the failure's kind.
  #[tokio::test]
  async fn a_fatal_leave_signal_stops_the_node_with_the_failure_kind() {
    let pending = start_pending_policy_loop().await;
    pending.fatal_leave(crate::ErrorKind::Internal).await;
  }

  #[tokio::test]
  async fn a_pending_policy_parks_only_its_admission_slot() {
    let pending = start_pending_policy_loop().await;

    // The wedge: one packet toward an unconnected destination, so its
    // admission consults the next-hop policy that never resolves.
    let _wedged_ack = pending.send(1, test_support::member_id(9)).await;
    pending.wait_for_policy_calls(1).await;

    // (a) The control loop still answers a read while that admission
    // awaits the policy forever.
    pending.read().await;

    // (b) A second packet toward a directly connected destination is
    // admitted inside the same bound: the wedged admission occupies one
    // slot, never the admission plane.
    let direct = test_support::member_id(11);
    let (direct_entry, _direct_frames) =
      crate::session::stream::test_entry(pending.entropy.as_ref());
    pending
      .sessions
      .lock()
      .expect("session table")
      .insert(direct.clone(), direct_entry);
    let direct_trace = trace(2);
    let _direct_ack = pending.send(2, direct).await;
    tokio::time::timeout(PROBE_BOX, async {
      while !pending
        .routes
        .lock()
        .expect("route table")
        .contains_key(&direct_trace)
      {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("a direct-destination packet must be admitted while the pending policy holds its slot");

    // (c) Shutdown still completes: the wedged admission task is part of
    // the control loop's task set and is torn down with it.
    pending.shutdown().await;
  }

  /// The permit bound is real, not cosmetic: once `ADMISSION_CONCURRENCY`
  /// admissions are parked on the policy, the packet arm disables itself
  /// and a further request waits in the bounded command channel. The loop
  /// itself keeps serving control reads and shutdown — saturation never
  /// blocks it.
  #[tokio::test]
  async fn a_saturated_admission_pool_disables_the_packet_arm() {
    let pending = start_pending_policy_loop().await;

    for seed in 0..u32::try_from(ADMISSION_CONCURRENCY).unwrap() {
      let _ack = pending
        .send(seed + 1, test_support::member_id(u64::from(seed) + 20))
        .await;
    }
    pending.wait_for_policy_calls(ADMISSION_CONCURRENCY).await;

    // No permit is free and the wedged admissions never release one, so
    // the overflow request stays queued (the packet arm is disabled)
    // instead of oversubscribing the policy.
    let _overflow_ack = pending.send(99, test_support::member_id(90)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
      pending.calls.load(Ordering::Relaxed),
      ADMISSION_CONCURRENCY,
      "a saturated admission pool must backpressure the packet arm, not oversubscribe it"
    );

    pending.read().await;
    pending.shutdown().await;
  }

  /// A stream whose routing-policy tag names no registered policy fails
  /// typed at admission: the sender observes the invalid-input kind and
  /// the bounded route record ends failed with it, instead of the stream
  /// silently routing direct.
  #[tokio::test]
  async fn an_unregistered_stream_routing_policy_fails_typed_at_admission() {
    let pending = start_pending_policy_loop().await;
    let unregistered = crate::RoutingPolicy::parse("example.com/route-policies/unregistered")
      .expect("a canonical caller tag");
    let trace_id = trace(7);
    let (request, ack) = probe_request_with_policy(
      trace_id.clone(),
      StreamTarget::Exact(test_support::member_id(9)),
      unregistered,
    );
    pending.packet.send(request).await.expect("packet channel");
    let outcome = tokio::time::timeout(PROBE_BOX, ack)
      .await
      .expect("the admission must answer")
      .expect("the admission ack channel");
    assert_eq!(outcome.err(), Some(crate::ErrorKind::InvalidInput));
    // The typed failure is also the route record's terminal state.
    let state = pending
      .routes
      .lock()
      .expect("route table")
      .get(&trace_id)
      .map(|record| record.state.clone());
    assert_eq!(
      state,
      Some(crate::packet::RouteState::Failed(
        crate::ErrorKind::InvalidInput
      ))
    );
    // The pending next-hop policy the fixture registers is never reached:
    // the stream policy resolves (and fails) first.
    assert_eq!(pending.calls.load(Ordering::Relaxed), 0);

    pending.shutdown().await;
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

  use super::{LeaveSignal, RuntimeDependencies, Supervisor, node_offer};
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

  /// The fixture's runtime inputs: everything `spawn_runtime` hands the
  /// control loop, so a test can drive the real `supervise` loop (control
  /// reads, packet admission, shutdown) instead of a pre-built supervisor.
  pub(crate) struct RuntimeFixture {
    pub(crate) dependencies: RuntimeDependencies,
    pub(crate) packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
    pub(crate) packet_rx: mpsc::Receiver<crate::packet::OutboundRequest>,
    pub(crate) sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
    pub(crate) entropy: Arc<dyn crate::api::Entropy>,
    pub(crate) sessions: SessionTable,
    /// The leave plane's signal receiver: the production `supervise` loop
    /// owns it, so a fixture that drives a real leave effect reads the
    /// signal here.
    pub(crate) leave_signals: mpsc::Receiver<LeaveSignal>,
  }

  /// Builds the runtime dependencies over a fresh in-memory identity
  /// opened through the caller's factory: no sessions, no listeners — the
  /// control and tick planes run against a real store. `prepare` registers
  /// caller extensions (the same public registry path the node builder
  /// uses) before the operation handles are built.
  pub(crate) async fn runtime_fixture_over(
    factory: Arc<dyn StorageFactory>, config: NodeConfig,
    prepare: impl FnOnce(&mut ExtensionRegistry),
  ) -> RuntimeFixture {
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
    // Caller extensions first, then the explicit default path: the same
    // order the node builder applies, so a caller override or a
    // caller-claimed next-hop tag wins over the official entry.
    prepare(&mut extensions);
    extensions.register_default().unwrap();
    let extensions = Arc::new(extensions);
    // The same registration-channel resolution the node builder applies.
    let route_policy = extensions
      .effective_route_policy(config.route_policy())
      .unwrap();
    let endpoint_policy = extensions
      .effective_endpoint_policy(config.endpoint_policy(), config.endpoint_preference())
      .unwrap();
    let definitions = extensions.feature_definitions();
    let registry = Arc::new(feature::FeatureRegistry::build(definitions).unwrap());
    let offer = node_offer(&registry, config.required_features()).unwrap();
    let (round_tx, round_rx) = mpsc::channel(super::SYNC_ROUND_CHANNEL_CAPACITY);
    let (revision_tx, _revision_rx) = watch::channel(0_u64);
    let (packet_tx, packet_rx) = mpsc::channel(super::PACKET_CHANNEL_CAPACITY);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let mut dependencies = RuntimeDependencies {
      storage_factory: factory,
      context: Some(context),
      keys: Some(keys),
      config,
      route_policy,
      endpoint_policy,
      entropy: entropy.clone(),
      extensions,
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
      tasks: None,
      triggers: None,
      operations: None,
      runtime_seed: None,
    };
    // The operation handles are built the way `spawn_runtime` builds them,
    // so the tick drives the exact production packet context and session
    // driver instead of a stand-in.
    let (leave_signal, leave_signals) = mpsc::channel(super::LEAVE_SIGNAL_CAPACITY);
    let operations = super::operation_deps(
      &dependencies,
      packet_tx.clone(),
      offer,
      registry,
      crate::session::stream::AuthorizationBoundary::default(),
      leave_signal,
    )
    .expect("operation handles");
    dependencies.operations = Some(operations);
    RuntimeFixture {
      dependencies,
      packet_tx,
      packet_rx,
      sync_rounds: round_rx,
      entropy,
      sessions,
      leave_signals,
    }
  }

  /// Builds a supervisor over the fixture's runtime dependencies: the
  /// tick-plane tests drive the exact production construction path without
  /// running the control loop.
  pub(crate) async fn supervisor_over(
    factory: Arc<dyn StorageFactory>, config: NodeConfig,
  ) -> (Supervisor, Arc<dyn crate::api::Entropy>, SessionTable) {
    let RuntimeFixture {
      dependencies,
      packet_tx,
      sync_rounds,
      entropy,
      sessions,
      ..
    } = runtime_fixture_over(factory, config, |_| {}).await;
    let supervisor = match Supervisor::new(dependencies, packet_tx, sync_rounds) {
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
    let descriptor =
      crate::membership::NodeDescriptorV1::new(node.clone(), member_key(seed), endpoints, 1, 1);
    crate::membership::store::store_descriptor_ctx(
      supervisor.context().unwrap().store(),
      supervisor.dependencies.entropy.as_ref(),
      &descriptor,
    )
    .await
    .unwrap();
    let (namespace, key) = crate::identity::records::identity_binding_key(&node).unwrap();
    let binding = crate::identity::records::IdentityBindingV1::new(node, member_key(seed));
    crate::identity::testing::inject_enveloped_entry(
      reference,
      &namespace,
      &key,
      binding.encode().unwrap(),
    );
  }

  /// Inserts one live session entry for `peer` into the table: a
  /// synthetic entry is enough — the tick only reads liveness and the
  /// edge class.
  pub(crate) fn insert_live_session(
    sessions: &SessionTable, peer: crate::NodeId, entropy: &dyn crate::api::Entropy,
    class: crate::session::stream::DialClass,
  ) {
    let entry = crate::session::stream::SessionEntry::synthetic_entry(
      entropy,
      crate::Endpoint::parse("wss://127.0.0.1:1").unwrap(),
      class,
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

  /// A refusing TCP peer: accepts every connection and immediately drops
  /// it, so a wss dial fails fast and deterministically at the handshake
  /// on every platform — unlike a connect to an unbound port, whose
  /// refusal timing is OS-dependent (on Windows the connect can hold the
  /// full dial deadline, collapsing the window an in-flight test needs).
  pub(crate) async fn refusing_peer() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
      while let Ok((stream, _)) = listener.accept().await {
        drop(stream);
      }
    });
    (port, handle)
  }
}
