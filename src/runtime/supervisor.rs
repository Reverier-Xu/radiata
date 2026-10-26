use std::{collections::BTreeMap, sync::Arc};

use tokio::{
  runtime::Handle,
  sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};

use super::{
  anti_entropy::spawn_sync_driver,
  packets::{PacketAdmission, PumpHandoff},
  task_effects::{ConnectionTasks, track_connection_task},
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
  routing::{RouteTable, outbound::run_outbound},
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
  session::{
    SessionDriver,
    stream::{SessionPacketContext, SessionTable, run_session},
  },
  transport::registry::{Transport, TransportListener, TransportTrust},
};

const CONTROL_CAPACITY: usize = 32;

/// The bounded cooperative window the drained connection tasks get at
/// shutdown before only the stragglers are aborted: the graceful
/// signal was already broadcast, so an in-flight consumer drain (a
/// fully received control payload mid persist-and-emit) completes
/// instead of being aborted mid-apply, while a task that never settles
/// can hold the shutdown reply no longer than this bound. Handles
/// already aborted upstream (the anti-entropy driver, the tick
/// workers, the accept loops) resolve immediately, so a quiet node's
/// shutdown stays as prompt as before.
const CONNECTION_TASK_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

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

/// The bound on simultaneously running packet admission tasks (audit
/// 2026-10-23 P1-5): each admission may await a caller-supplied routing
/// policy, so this bounds how many such waits are in flight. A
/// saturated pool disables the control loop's packet arm instead of
/// blocking the loop, and the bounded packet command channel carries the
/// backpressure.
pub(crate) const ADMISSION_CONCURRENCY: usize = 4;

/// Capacity of the bounded admission-to-loop pump handoff: the loop is
/// the only consumer and reaps it every iteration, so a full channel
/// only parks one admission task (holding its admission slot) for one
/// scheduling window.
const PUMP_HANDOFF_CAPACITY: usize = ADMISSION_CONCURRENCY;

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
  // plane once the supervisor spawns it). The plane and the packet
  // context the operation handles build share one authorization
  // boundary (audit 2026-10-23, P1-11), so a sync-delivered revocation
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
  let operations = operation_deps(
    &dependencies,
    packet_tx.clone(),
    offer,
    registry,
    authorization,
  )?;
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
  // The packet admission plane (audit 2026-10-23 P1-5): target
  // resolution, descriptor validation, first-hop selection, and the route
  // record run in spawned admission tasks, never inline here — a
  // caller-supplied policy that never resolves parks one bounded
  // admission slot instead of the control loop's control reads, other
  // packet admissions, and shutdown. Record-before-pump ordering
  // survives the move: the admission task records the route before it
  // hands the ready request back through the bounded channel below, and
  // only the loop (the pump `JoinSet`'s owner) spawns `run_outbound`.
  let admission = PacketAdmission::new(&supervisor);
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
  // The leave effect's completion signal: once it lands, the caller has
  // already observed the task's terminal outcome (the publication precedes
  // the signal) and the node tears down with the active-leave reason. A
  // closed channel means the manager (the sender's only owner) is gone, so
  // the arm is disabled rather than polled again.
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
        // The identity context (and the store handle it carries) is
        // cloned per admission and lives only inside the admission task:
        // a long-lived clone here would survive the shutdown path's
        // storage drain (audit 2026-10-23 P1-10).
        let Some(context) = supervisor.dependencies.context.clone() else {
          request.reject(crate::ErrorKind::Internal);
          continue;
        };
        let admission = admission.clone();
        let pump = pump_tx.clone();
        tasks.spawn(async move {
          // The permit is the admission slot and lives as long as the
          // resolution work, so `ADMISSION_CONCURRENCY` bounds the
          // in-flight admissions regardless of what a policy awaits.
          let _permit = permit;
          match admission.admit(&context, request).await {
            // The recorded route returns to the loop, which owns the
            // pump `JoinSet` and spawns `run_outbound`.
            Ok(Some(handoff)) => {
              if let Err(mpsc::error::SendError(handoff)) = pump.send(handoff).await {
                // The loop is gone: the request must observe a typed
                // shutdown terminal, never a dangling admission decision.
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
        let local = supervisor.packet.local().clone();
        let routes = supervisor.dependencies.routes.clone();
        let events = Arc::clone(&supervisor.dependencies.events);
        // Core-internal control traffic stays out of the durable trace
        // store: its volume is a runtime implementation detail, not
        // caller evidence. The pump simply holds no sink for it, and the
        // record flag carries the same exclusion to the read loop's
        // late-failure revision path.
        let trace = if handoff.request.internal {
          None
        } else {
          Some(supervisor.trace_sink.clone())
        };
        tasks.spawn(async move {
          run_outbound(
            handoff.entry,
            local,
            handoff.request,
            routes,
            handoff.force_routed,
            trace,
            events,
          )
          .await;
        });
      }
      finished = tasks.join_next(), if !tasks.is_empty() => {
        // Reap finished packet tasks (an admission or its pump) as they
        // complete instead of letting their handles accumulate in the
        // JoinSet until shutdown (audit 2026-10-09, item 4): the set
        // stays bounded by the live admission-plus-pump count. A join
        // error (a panicked or aborted task) stays visible as a
        // diagnostic.
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
  // Drain the returned task teardown so every storage capture is dropped
  // before the shutdown reply returns (a restarted node on the same
  // factory must not race the release). The handles aborted upstream (the
  // anti-entropy driver, the tick workers, the accept loops) resolve
  // immediately; the live connection tasks get one shared, bounded
  // cooperative window — the graceful signal was already broadcast — so
  // an in-flight consumer drain finishes its apply, and only a task still
  // unfinished at the window's edge is aborted and reaped: a wedged task
  // can never hang the reply past the bound.
  let deadline = tokio::time::Instant::now() + CONNECTION_TASK_SHUTDOWN_GRACE;
  for mut handle in drained {
    if tokio::time::timeout_at(deadline, &mut handle)
      .await
      .is_err()
    {
      // Straggler: abort it, then reap the aborted join so its captures
      // still drop before the reply. (A handle that settled inside the
      // window was already joined by the timed poll — re-polling a
      // completed `JoinHandle` panics, so only this arm awaits again.)
      handle.abort();
      let _ = handle.await;
    }
  }
  // The storage execution completion barrier (audit 2026-10-23 P1-10):
  // every runtime plane is torn down above, so no new execution can
  // start; the storage flush now resolves only when every detached
  // execution the node spawned has ended (committed, failed, or rolled
  // back), so the shutdown reply returns only once no in-flight commit
  // still holds the database — a restarted node on the same factory
  // cannot race a landing execution. Like the task manager's journaled
  // drain, the wait is deliberately unbounded: it awaits durability
  // obligations, not cancellable effects. A flush failure is diagnosed
  // and teardown continues, because the reply itself must still answer.
  if let Some(context) = dependencies.context.as_ref()
    && let Err(error) = context.store().provider().flush().await
  {
    tracing::warn!(
      kind = ?error.kind(),
      "storage execution completion barrier failed at shutdown"
    );
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
  /// Per-member endpoint dial serials shared by both dial planes
  /// (recovery and degree maintenance): each dial of a member advances
  /// that member's own serial, so `recovery_endpoint` rotates the
  /// member through ALL its published endpoints — endpoint-level
  /// failover independent of which members any one step happens to
  /// select (see `runtime/recovery.rs`).
  pub(super) endpoint_attempts: std::sync::Mutex<std::collections::BTreeMap<NodeId, u64>>,
  /// The bridge-probe cadence bracket: maintenance ticks an otherwise
  /// quiescent healthy node waits before its next cross-partition probe
  /// dial (audit finding #1's residual boundary — see `runtime/degree.rs`).
  /// Only the maintenance worker mutates it, so a racing read at worst
  /// shifts one probe by one tick.
  pub(super) bridge_probe_ticks: Arc<std::sync::atomic::AtomicU32>,
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
  authorization: crate::session::stream::AuthorizationBoundary,
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
    authorization,
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
  authorization: crate::session::stream::AuthorizationBoundary,
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
      endpoint_attempts: std::sync::Mutex::new(std::collections::BTreeMap::new()),
      bridge_probe_ticks: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(
        super::degree::BRIDGE_PROBE_INTERVAL_TICKS,
      )),
      prune_cooldown: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
      exclusion_cache: Arc::clone(&self.exclusion_cache),
      trace_records: Arc::clone(&self.trace_records),
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
/// recovery dial releases its in-flight slot within the bound. The kept
/// session pump joins the node's tracked connection tasks through the
/// same registration the join effect uses, so the recovery tick reaps
/// it and the shutdown path owns it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn dial_member(
  transport: Arc<dyn Transport>, driver: SessionDriver,
  sessions: crate::session::stream::SessionTable, packet: Arc<SessionPacketContext>,
  shutdown: watch::Receiver<()>, connection_tasks: ConnectionTasks, receiver: Endpoint,
  peer: &NodeId, recovery_dialed: bool, dial_deadline: std::time::Duration,
) -> Result<NodeId> {
  crate::audit::dial_started(peer.as_str(), recovery_dialed);
  let result = async {
    // Member reconnects pin the peer's TLS leaf to the SPKI anchor
    // learned for this exact concrete target (scheme and address: a
    // repeated dial to the same endpoint); any other listener of the
    // same peer — another scheme, a second listener, a rebound address
    // — has no anchor here and dials under the join-mode relaxation,
    // where the application proof layer remains the authenticator. The
    // endpoint's transport class decides whether either TLS mode applies
    // at all.
    let pinned = driver.peer_spki(peer, &receiver);
    let trust = TransportTrust::for_dial(
      &receiver.selector(),
      pinned
        .clone()
        .map(rustls::pki_types::SubjectPublicKeyInfoDer::from),
    );
    // The whole member dial — pinned attempt plus any rollover fallback —
    // must fit inside ONE dial deadline: the fallback funds itself from
    // the remainder of the first attempt, so a peer that wastes the
    // budget on a failed pin cannot double the dial's bound. The clock is
    // tokio's monotonic instant — the same clock `connect_with_deadline`'s
    // timeout runs on — so the remainder and the timeout cannot drift.
    let pinned_started = tokio::time::Instant::now();
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
          // Only the unspent remainder of the dial budget funds the
          // fallback; a saturated remainder (the first attempt consumed
          // the whole deadline) fails the dial outright instead of
          // granting the retry a second full budget.
          let remaining = dial_deadline.saturating_sub(pinned_started.elapsed());
          if remaining.is_zero() {
            return Err(pin_error);
          }
          let fallback = TransportTrust::for_dial(&receiver.selector(), None);
          connect_with_deadline(&transport, receiver.clone(), fallback, remaining).await?
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
    let tracked_tasks = Arc::clone(&connection_tasks);
    keep_outbound_session(
      connection,
      session,
      packet,
      sessions,
      shutdown,
      receiver.clone(),
      recovery_dialed,
      |session_task| track_connection_task(&tracked_tasks, session_task),
    )
    .await?;
    if pinned.is_some()
      && let Some(spki) = observed_spki
    {
      // Process-local rollover on this target: the re-issued leaf
      // replaces the stale anchor, so every later member dial to the
      // same endpoint pins again.
      driver.record_peer_spki(peer, &receiver, spki);
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

  /// A scripted transport for the rollover-budget regression: the first
  /// (pinned) dial fails its TLS establishment with the typed
  /// authentication failure a stale SPKI pin produces, and the
  /// merge-trust fallback peer accepts and then goes silent, so only the
  /// dial budget can end the attempt.
  #[derive(Debug)]
  struct RolloverFaultTransport {
    attempts: Arc<std::sync::atomic::AtomicUsize>,
  }

  impl crate::transport::registry::Transport for RolloverFaultTransport {
    fn bind(
      &self, _endpoint: crate::Endpoint,
    ) -> crate::BoxFuture<
      'static,
      crate::Result<Box<dyn crate::transport::registry::TransportListener>>,
    > {
      Box::pin(async { Err(crate::Error::internal("test transport bind")) })
    }

    fn connect(
      &self, _endpoint: crate::Endpoint, _trust: TransportTrust,
    ) -> crate::BoxFuture<'static, crate::Result<crate::transport::connection::Connection>> {
      let attempts = Arc::clone(&self.attempts);
      Box::pin(async move {
        match attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed) {
          // The pinned attempt: the handshake runs, then the stale pin
          // fails it with the typed authentication error.
          0 => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Err(crate::Error::authentication_failed("tls transport"))
          }
          // The rollover fallback: the peer accepts and goes silent, so
          // the connect never settles inside any sane test budget.
          _ => {
            tokio::time::sleep(Duration::from_secs(3_600)).await;
            Err(crate::Error::internal("test transport"))
          }
        }
      })
    }
  }

  /// The certificate-rollover fallback shares ONE dial deadline with the
  /// pinned attempt that preceded it: the retry dials on the unspent
  /// remainder only, so a pinned failure that cost part of the budget
  /// cannot stretch the whole member dial past the configured bound (the
  /// double-budget fallback used to reach deadline + first-attempt cost).
  #[tokio::test(start_paused = true)]
  async fn the_rollover_fallback_dials_within_one_dial_deadline() {
    let (reference, config) = super::test_support::reference_and_config();
    let (supervisor, _entropy, _sessions) =
      super::test_support::supervisor_over(reference, config).await;
    let operations = supervisor
      .dependencies
      .operations
      .clone()
      .expect("supervisor fixture builds operation handles");
    let planes = operations.planes().expect("effect planes");
    let driver = planes.driver.clone();
    let peer = super::test_support::member_id(7);
    let endpoint = crate::Endpoint::parse("wss://127.0.0.1:9").unwrap();
    // Pin a leaf anchor for this exact target so the first dial carries
    // the member-mode SPKI pin and its failure takes the rollover arm.
    driver.record_peer_spki(&peer, &endpoint, vec![7; 32]);

    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport: Arc<dyn crate::transport::registry::Transport> =
      Arc::new(RolloverFaultTransport {
        attempts: Arc::clone(&attempts),
      });
    let dial_deadline = Duration::from_secs(1);
    let started = tokio::time::Instant::now();
    let error = super::dial_member(
      transport,
      driver,
      planes.sessions.clone(),
      Arc::clone(&planes.packet),
      planes.shutdown.subscribe(),
      Arc::clone(&planes.connection_tasks),
      endpoint,
      &peer,
      false,
      dial_deadline,
    )
    .await
    .unwrap_err();
    let elapsed = started.elapsed();

    // Both attempts ran (pinned dial, then the merge-trust fallback).
    assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 2);
    // The elapsed fallback budget surfaced as the same coarse typed
    // transport-connect failure as any other dial timeout.
    assert_eq!(error.kind(), crate::ErrorKind::Io);
    assert_eq!(error.context(), "transport connect");
    // The whole dial landed ON the deadline: the fallback spent only the
    // 900ms remainder, not a second full budget (which would have ended
    // at 1.1s).
    assert!(
      elapsed >= dial_deadline,
      "the dial must use its budget ({elapsed:?})"
    );
    assert!(
      elapsed < dial_deadline + Duration::from_millis(50),
      "the fallback must not exceed one dial deadline ({elapsed:?})"
    );
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
    let operations = super::operation_deps(
      &dependencies,
      packet_tx.clone(),
      offer,
      registry,
      crate::session::stream::AuthorizationBoundary::default(),
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

  /// The retention tick holds the same quietness contract as the
  /// reconcile tick's quiescence probe: a fresh single node that just
  /// completed its identity ceremony leaves no retention candidate and
  /// no anchor behind, so repeated retention sweeps find nothing and the
  /// store's commit count does not grow (regression: the ceremony's
  /// leftover retention candidate made the first tick commit the anchor
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

  use super::{
    CONNECTION_TASK_SHUTDOWN_GRACE, CONTROL_CAPACITY, LifecyclePublisher, finish_shutdown,
    test_support,
  };
  use crate::{
    BoxFuture, CommitOutcome, Digest, ReconcileOutcome, ShutdownReason, StoreCapabilities,
    StoreRequirements, StoreTransaction, TransactionId,
    extension::StoreSnapshot,
    provider::{Storage, StorageFactory},
    runtime::LifecycleSnapshot,
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
  /// contract in `session::inbound`). Under the old abort-everything
  /// teardown the parked apply dies with the node and the flag stays
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

  /// `finish_shutdown` provides the storage execution completion barrier
  /// (audit 2026-10-23 P1-10): the shutdown reply must not return while
  /// the node's storage still has an in-flight execution — represented
  /// here by a flush that parks on a gate — and must return promptly
  /// once the barrier resolves. Under the old immediate-return flush the
  /// reply would land while the "execution" still holds the database.
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

/// The control-loop admission contract (audit 2026-10-23 P1-5): a
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
    ADMISSION_CONCURRENCY, CONTROL_CAPACITY, Control, LifecycleSnapshot, RuntimeSignals,
    ShutdownReason, supervise,
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
    fn next_hop<'a>(&'a self, _view: NextHopView<'a>) -> BoxFuture<'a, Result<NodeId>> {
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
    let (ack_notify, ack) = oneshot::channel();
    let request = OutboundRequest {
      trace_id,
      target,
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
    _leave: mpsc::Sender<()>,
    _state: watch::Receiver<LifecycleSnapshot>,
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
    let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
    let (leave_tx, leave_rx) = mpsc::channel(1);
    let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(supervise(
      dependencies,
      (packet_tx.clone(), packet_rx),
      sync_rounds,
      RuntimeSignals {
        control: control_rx,
        leave_complete: leave_rx,
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
      _leave: leave_tx,
      _state: state_rx,
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
    NodeConfig, TransportScheme,
    extension_registry::ExtensionRegistry,
    identity::{
      lifecycle::open_local_identity,
      testing::{ScriptedKeys, SequenceEntropy},
    },
    protocol::feature,
    provider::StorageFactory,
    session::stream::SessionTable,
    storage::contract::{ReferenceFactory, required_capabilities},
    transport::registry::builtin_transport_tag,
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
    // The built-in transports the node builder installs: the ticks
    // resolve the members' wss endpoints through this registry.
    for (tag, transport) in [
      (
        builtin_transport_tag(TransportScheme::Tls).unwrap(),
        Arc::new(crate::transport::tls_transport::TlsTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        builtin_transport_tag(TransportScheme::Wss).unwrap(),
        Arc::new(crate::transport::wss::WssTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
      (
        builtin_transport_tag(TransportScheme::Tcp).unwrap(),
        Arc::new(crate::transport::plain::PlainTransport::new())
          as Arc<dyn crate::transport::registry::Transport>,
      ),
    ] {
      extensions
        .register_builtin_transport(tag, transport)
        .unwrap();
    }
    prepare(&mut extensions);
    let mut definitions = feature::builtin_definitions().unwrap();
    definitions.extend(extensions.feature_definitions());
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
    let operations = super::operation_deps(
      &dependencies,
      packet_tx.clone(),
      offer,
      registry,
      crate::session::stream::AuthorizationBoundary::default(),
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
