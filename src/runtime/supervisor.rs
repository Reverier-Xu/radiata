use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};
use tracing::debug;

use crate::{
  Endpoint, Error, ErrorKind, IssuedMergeCredential, ListenerView, MergeView, NodeConfig, NodeId,
  Result, ShutdownOutcome, ShutdownReason, StreamTarget, TraceId,
  api::Entropy,
  extension_registry::ExtensionRegistry,
  identity::{
    credential::MergeCredentialIssuer,
    lifecycle::{LocalIdentityContext, ensure_self_binding, open_local_identity},
  },
  packet::{OutboundRequest, RouteRecord},
  protocol::offer::node_offer,
  provider::{KeyProvider, StorageFactory},
  routing::{RouteTable, insert_route, record_terminal_failure},
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
  session::{
    SessionDriver,
    stream::{SessionPacketContext, SessionTable, run_outbound, run_session},
  },
  transport::{
    registry::{Transport, TransportListener},
    tls,
  },
};

const CONTROL_CAPACITY: usize = 32;

/// The recovery controller's observation period (unnamed literal kept
/// every other period out of `NodeConfig`).
const RECOVERY_TICK_PERIOD: std::time::Duration = std::time::Duration::from_secs(2);

/// The accept-loop backoff: every consecutive failed upgrade delays the
/// next accept by one step, capped at `ACCEPT_BACKOFF_MAX_STEPS` steps,
/// so a persistently broken accept cannot spin hot; one success clears
/// the backoff. A single failed upgrade still costs nothing (the delay
/// applies only from the second consecutive failure on).
const ACCEPT_BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(100);
const ACCEPT_BACKOFF_MAX_STEPS: u32 = 5;

/// Capacity of the node's outbound packet command channel, shared with
/// the builder so both channel ends are created at one construction site.
/// The bounded request channel for RunSyncRound commands: rounds are
/// self-limiting (one page per session per round), so a small queue with
/// typed backpressure matches the work.
pub(crate) const SYNC_ROUND_CHANNEL_CAPACITY: usize = 8;

pub(crate) const PACKET_CHANNEL_CAPACITY: usize = CONTROL_CAPACITY;

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
  pub(crate) keys: Arc<dyn KeyProvider>,
  pub(crate) config: NodeConfig,
  pub(crate) entropy: Arc<dyn Entropy>,
  pub(crate) extensions: Arc<ExtensionRegistry>,
  /// The registered transport every dial and listen flows through, so
  /// configured attempts are observable at one boundary.
  pub(crate) transport: Arc<dyn Transport>,
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
  /// Requests for one immediate anti-entropy round, forwarded to the
  /// sync driver (the cursor owner) by the RunSyncRound command.
  pub(crate) sync_round_requests: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<()>>,
  /// Node-scoped task handles: connection tasks plus the graceful
  /// consumer-drain tasks. Shutdown awaits them and the recovery tick
  /// reaps finished ones (bounded task accounting).
  pub(crate) connection_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
  /// The 32-byte runtime seed drawn once at startup, before identity
  /// provisioning. Deliberately reserved and pinned by the lifecycle
  /// entropy-sequence test.
  pub(crate) runtime_seed: Option<[u8; 32]>,
}

/// Spawns the anti-entropy membership-sync driver: it pages descriptors
/// and the issuer trust snapshot over every authenticated session on the
/// configured interval and stops on the shutdown signal (streams metadata
/// pages; bounded work per tick).
#[allow(clippy::too_many_arguments)]
fn spawn_sync_driver(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  sessions: crate::session::stream::SessionTable, runtime: crate::runtime::RuntimeClient,
  published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>, interval: std::time::Duration,
  shutdown: tokio::sync::watch::Receiver<()>,
  mut round_requests: tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  events: Arc<crate::node::EventHub>, revision: crate::node::MemberRevisionSignal,
) -> tokio::task::JoinHandle<()> {
  let driver_context = Arc::clone(context);
  let driver_entropy = entropy;
  let driver_sessions = sessions;
  let driver_runtime = runtime;
  let driver_endpoints = published_endpoints;
  let mut driver_shutdown = shutdown;
  let driver_events = events;
  let driver_revision = revision;
  tokio::spawn(async move {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sync_cursor = crate::membership::sync::MembershipSyncCursors::default();
    let mut resource_cursor = crate::resource::sync::ResourceSyncCursors::default();
    async fn run_round(
      context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn crate::api::Entropy>,
      sessions: &crate::session::stream::SessionTable, runtime: &crate::runtime::RuntimeClient,
      endpoints: &[Endpoint], sync_cursor: &mut crate::membership::sync::MembershipSyncCursors,
      resource_cursor: &mut crate::resource::sync::ResourceSyncCursors,
      events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
    ) {
      if let Err(error) = crate::membership::sync::sync_tick(
        context,
        entropy,
        sessions,
        runtime,
        endpoints,
        sync_cursor,
        events,
        revision,
      )
      .await
      {
        // Persistent anti-entropy failure must stay visible in
        // diagnostics; the next tick retries regardless.
        tracing::warn!(kind = ?error.kind(), "membership sync tick failed");
      }
      if let Err(error) = crate::resource::sync::resource_sync_tick(
        context,
        entropy,
        sessions,
        runtime,
        resource_cursor,
      )
      .await
      {
        tracing::warn!(kind = ?error.kind(), "resource sync tick failed");
      }
    }
    loop {
      tokio::select! {
        changed = driver_shutdown.changed() => {
          let _ = changed;
          break;
        }
        _ = timer.tick() => {
          let endpoints: Vec<Endpoint> = driver_endpoints
            .lock()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default();
          run_round(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &endpoints,
            &mut sync_cursor,
            &mut resource_cursor,
            &driver_events,
            &driver_revision,
          )
          .await;
        }
        // The RunSyncRound command's deterministic round: identical work
        // to a wall-clock tick, but the caller awaits its completion, so
        // convergence checks need no interval-cadence sleeps.
        round = round_requests.recv() => {
          let reply = round;
          let endpoints: Vec<Endpoint> = driver_endpoints
            .lock()
            .map(|endpoints| endpoints.clone())
            .unwrap_or_default();
          run_round(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &endpoints,
            &mut sync_cursor,
            &mut resource_cursor,
            &driver_events,
            &driver_revision,
          )
          .await;
          if let Some(reply) = reply {
            let _ = reply.send(());
          }
        }
      }
    }
  })
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
  // `dependencies.transport` is resolved once in the builder from the
  // extension registry, so every dial and listen flows through the
  // registered transport (a counting wrapper registered under the WSS tag
  // observes configured attempts). It is not re-resolved or
  // overridden here.
  let receipt_retention = dependencies.config.receipt_retention();
  let context = open_local_identity(
    &dependencies.storage_factory,
    &dependencies.keys,
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
  // The core resource sync protocol rides the same authenticated sessions
  // and anti-entropy driver as membership sync.
  let resource_definition = crate::resource::sync::resource_sync_protocol_definition()?;
  let resource_consumer = Arc::new(crate::resource::sync::ResourceSyncConsumer::new(
    runtime_context,
    dependencies.entropy.clone(),
  ));
  dependencies
    .extensions
    .register_core_protocol(resource_definition, resource_consumer)?;
  let routes = dependencies.routes.clone();
  let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();
  let (packet_tx, packet_rx) = packets;
  let client = RuntimeClient::new(control_tx, state_rx, routes, packet_tx.clone());

  runtime.spawn(supervise(
    dependencies,
    control_rx,
    packet_tx,
    packet_rx,
    sync_rounds,
    state_tx,
    ready_tx,
  ));

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(client)
}

async fn supervise(
  dependencies: RuntimeDependencies, mut control: mpsc::Receiver<Control>,
  packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
  mut packets: mpsc::Receiver<crate::packet::OutboundRequest>,
  sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  state: watch::Sender<LifecycleSnapshot>, ready: oneshot::Sender<()>,
) {
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
      let (error, dependencies) = *failure;
      tracing::error!(kind = ?error.kind(), "supervisor provisioning failed");
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
  };
  // Any trace records still non-terminal from a previous incarnation
  // terminate explicitly at startup: a restart never continues a body.
  if let Some(context) = supervisor.dependencies.context.as_ref()
    && let Err(error) = crate::routing::trace::terminate_stale(
      context.store(),
      supervisor.dependencies.entropy.as_ref(),
      &crate::storage::receipt::HostWallClock,
    )
    .await
  {
    tracing::warn!(kind = ?error.kind(), "stale trace termination failed");
  }
  let mut recovery_timer = tokio::time::interval(RECOVERY_TICK_PERIOD);
  recovery_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
      Control::RotateMergeCredential { reply } => {
        let result = supervisor.rotate_merge_credential();
        let _ = reply.send(result);
      }
      Control::Listen { endpoint, reply } => {
        let result = supervisor.listen(endpoint, &mut tasks).await;
        let _ = reply.send(result);
      }
      Control::StopListener { listener, reply } => {
        let result = supervisor.stop_listener(&listener).await;
        let _ = reply.send(result);
      }
      Control::MergeCluster {
        receiver,
        credential,
        reply,
      } => {
        let result = supervisor
          .merge_cluster(receiver, credential, &mut tasks)
          .await;
        let _ = reply.send(result);
      }
      Control::ConnectMember {
        receiver,
        peer,
        reply,
      } => {
        let result = supervisor.connect_member(receiver, peer).await;
        let _ = reply.send(result);
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
      Control::StartRecovery { reply } => {
        let result = supervisor.start_recovery();
        let _ = reply.send(result);
      }
      Control::DisconnectPeer { peer, reply } => {
        let result = supervisor.disconnect_peer(&peer);
        let _ = reply.send(result);
      }
      Control::UpdateNodeMetadata {
        expected_revision,
        patch,
        reply,
      } => {
        let result = supervisor.update_node_metadata(expected_revision, patch).await;
        let _ = reply.send(result);
      }
      Control::PutResource { write, reply } => {
        let result = supervisor.put_resource(write).await;
        let _ = reply.send(result);
      }
      Control::RevokeNode {
        subject,
        expected_key,
        reply,
      } => {
        let result = supervisor.revoke_node(subject, expected_key).await;
        let _ = reply.send(result);
      }
      Control::CleanupNode { subject, reply } => {
        let result = supervisor.cleanup_node(subject).await;
        let _ = reply.send(result);
      }
      Control::PurgeRevocation { subject, reply } => {
        let result = supervisor.purge_revocation(subject).await;
        let _ = reply.send(result);
      }
      Control::IssueCleanupCheckpoint { reply } => {
        let result = supervisor.issue_cleanup_checkpoint().await;
        let _ = reply.send(result);
      }
      Control::ApplyReceiptRetention { reply } => {
        let result = supervisor.apply_receipt_retention().await;
        let _ = reply.send(result);
      }
      Control::RunSyncRound { reply } => {
        let result = supervisor.run_sync_round().await;
        let _ = reply.send(result);
      }      Control::RemoveResource {
        name,
        expected,
        reply,
      } => {
        let result = supervisor.remove_resource(name, expected).await;
        let _ = reply.send(result);
      }
      Control::LeaveCluster {
        acknowledgement,
        reply,
      } => {
        match supervisor.leave_cluster(acknowledgement).await {
          Ok(outcome) => {
            handle_leave(
              outcome,
              reply,
              supervisor.into_dependencies(),
              control,
              tasks,
              &mut lifecycle,
            )
            .await;
            return;
          }
          Err(error) => {
            let _ = reply.send(Err(error));
          }
        }
      }
      Control::Observability { reply } => {
        let result = supervisor.observability_snapshot(&tasks).await;
        let _ = reply.send(result);
      }
        }
      }
      request = packets.recv() => {
        let Some(request) = request else {
          continue;
        };
        let _ = supervisor.send_packet(request, &mut tasks).await;
      }
      _ = recovery_timer.tick() => {
        let _ = supervisor.recovery_tick().await;
        supervisor.trace_retention_sweep().await;
        supervisor.resource_removal_sweep().await;
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

/// The `LeaveCluster` shutdown sequence, hoisted out of the select arm so
/// the arm stays symmetric with the observation arms: the leave outcome
/// reaches the caller before teardown begins, then the runtime drains and
/// shuts down with the active-leave reason. Consumes the control loop and
/// task set, so `supervise` returns right after.
async fn handle_leave(
  outcome: crate::LeaveOutcome, reply: oneshot::Sender<Result<crate::LeaveOutcome>>,
  (dependencies, drained): (RuntimeDependencies, Vec<tokio::task::JoinHandle<()>>),
  control: mpsc::Receiver<Control>, tasks: JoinSet<()>, lifecycle: &mut LifecyclePublisher,
) {
  // The outcome reaches the caller before teardown begins; the node then
  // shuts down with the active-leave reason.
  let _ = reply.send(Ok(outcome));
  finish_shutdown(
    control,
    tasks,
    dependencies,
    drained,
    lifecycle,
    None,
    ShutdownReason::ActiveLeave,
  )
  .await;
}

async fn finish_shutdown(
  mut control: mpsc::Receiver<Control>, mut tasks: JoinSet<()>, dependencies: RuntimeDependencies,
  drained: Vec<tokio::task::JoinHandle<()>>, lifecycle: &mut LifecyclePublisher,
  first_reply: Option<oneshot::Sender<ShutdownOutcome>>, reason: ShutdownReason,
) {
  lifecycle.publish(LifecycleSnapshot::shutting_down());
  control.close();

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
  pub(super) driver: SessionDriver,
  pub(super) packet: Arc<SessionPacketContext>,
  pub(super) route_capacity: usize,
  pub(super) listeners: BTreeMap<
    crate::identity::ListenerId,
    (Endpoint, std::sync::Arc<dyn TransportListener>, AbortHandle),
  >,
  pub(super) recovery: crate::membership::recovery::RecoveryController,
  pub(super) recovery_pending: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  pub(super) published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>,
  // Members this node has ever authenticated a session with: the recovery
  // "known online" set. Recovery restores authenticated paths to exactly
  // these members (edge-loss healing) and never dials strangers, so it
  // cannot add edges beyond the caller-configured topology.
  pub(super) recovery_history: std::collections::BTreeSet<NodeId>,
  /// Set once the known-online set has been seeded from the durable
  /// member evidence (a restarted process's past-life sessions); later
  /// ticks never re-seed, so pruned departed members stay forgotten.
  pub(super) recovery_seeded: bool,
  /// Memoized departed-members exclusion set, keyed by the store
  /// revision it was computed at: the set only changes when a leave or
  /// cleanup tombstone lands or gets GC'd, and every such change commits
  /// (advancing the revision). A tick or member view over an unchanged
  /// revision reuses the cached set instead of rescanning and decoding
  /// every accumulated tombstone; any other commit also invalidates,
  /// which merely recomputes once (commit-writes are rare metadata
  /// events).
  pub(super) exclusion_cache:
    std::sync::Mutex<Option<(crate::StoreRevision, super::recovery::Departed)>>,
  /// The highest resource-write stamp this writer has issued: a
  /// writer's own successive writes must strictly outrank their
  /// predecessor, so the issue clock advances at least one millisecond
  /// per write and rides through wall-clock regressions (a
  /// same-millisecond stamp would fall to the digest tie-break, and the
  /// writer's own second write could lose to its first). Both the put
  /// and the remove paths issue through [`Self::issue_resource_stamp`].
  pub(super) resource_write_clock: std::sync::atomic::AtomicU64,
  // Intentionally disconnected peers: recovery never heals them until an
  // explicit reconnect (a new session to the peer) restores the
  // relationship (no-extra-edge).
  pub(super) recovery_excluded: std::collections::BTreeSet<NodeId>,
  // The anti-entropy driver task: aborted on shutdown so the node's
  // storage handle is released promptly (a restarted node reopening the
  // same factory must not race a lingering driver).
  pub(super) sync_driver: Option<tokio::task::JoinHandle<()>>,
  pub(super) trace_sink: crate::routing::trace::TraceSink,
  // Approximate live durable trace-record population, shared with the
  // sink (incremented per successful persistence) and decremented by the
  // retention sweep's removals; zero means sweeps can stay skipped.
  pub(super) trace_records: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// Builds the node-shared packet context (single construction site):
/// every collaborator is cloned from one struct instead of a
/// ten-argument positional call where a transposed same-typed `Arc`
/// would compile and silently miswire.
fn session_packet_context(
  context: &LocalIdentityContext, dependencies: &RuntimeDependencies,
  packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
  policy: crate::session::stream::SessionPolicy,
) -> SessionPacketContext {
  SessionPacketContext::new(
    context.identity().node().clone(),
    dependencies.extensions.clone(),
    policy,
    crate::runtime::RuntimeClient::routing_only(packet_tx, dependencies.routes.clone()),
    std::sync::Arc::new(crate::storage::receipt::HostWallClock),
    dependencies.entropy.clone(),
    dependencies.events.clone(),
    dependencies.config.route_policy().cloned(),
    dependencies.sessions.clone(),
    dependencies.routes.clone(),
    crate::routing::forward::FORWARDING_ROUTE_CAPACITY_DEFAULT,
    dependencies.config.trace_metadata_limits().active(),
    Arc::clone(&dependencies.connection_tasks),
    dependencies.config.parser_cbor_limits(),
  )
}

impl Supervisor {
  /// Builds the supervisor; provisioning failures return the dependencies
  /// so the caller can still run a clean shutdown instead of panicking.
  fn new(
    dependencies: RuntimeDependencies, packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
    sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  ) -> std::result::Result<Self, Box<(Error, RuntimeDependencies)>> {
    let Some(context) = dependencies.context.clone() else {
      return Err(Box::new((Error::internal("runtime context"), dependencies)));
    };
    // The negotiation registry is the frozen built-in set plus every
    // caller-registered feature definition.
    let mut definitions = match crate::protocol::feature::builtin_definitions() {
      Ok(definitions) => definitions,
      Err(error) => return Err(Box::new((error, dependencies))),
    };
    definitions.extend(dependencies.extensions.feature_definitions());
    let registry = match crate::protocol::feature::FeatureRegistry::build(definitions) {
      Ok(registry) => registry,
      Err(error) => return Err(Box::new((error, dependencies))),
    };
    let offer = match node_offer(&registry, dependencies.config.required_features()) {
      Ok(offer) => offer,
      Err(error) => return Err(Box::new((error, dependencies))),
    };
    let policy = crate::session::stream::SessionPolicy::from_config(&dependencies.config);
    let packet = Arc::new(session_packet_context(
      &context,
      &dependencies,
      packet_tx.clone(),
      policy,
    ));
    let route_capacity = dependencies.config.trace_metadata_limits().active();
    let sync_context = Arc::clone(&context);
    let driver_context = Arc::clone(&context);
    let driver = SessionDriver::new(
      driver_context,
      dependencies.keys.clone(),
      dependencies.entropy.clone(),
      Arc::new(std::sync::Mutex::new(MergeCredentialIssuer::new())),
      offer,
    );
    // The membership sync protocol was registered by `spawn_runtime`
    // before the runtime was marked ready.
    let (shutdown_tx, _) = watch::channel(());
    let published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>> = Arc::default();
    let sync_driver = Some(spawn_sync_driver(
      &sync_context,
      dependencies.entropy.clone(),
      dependencies.sessions.clone(),
      crate::runtime::RuntimeClient::routing_only(packet_tx.clone(), dependencies.routes.clone()),
      Arc::clone(&published_endpoints),
      dependencies.config.anti_entropy_interval(),
      shutdown_tx.subscribe(),
      sync_rounds,
      dependencies.events.clone(),
      dependencies.member_revision.clone(),
    ));
    // The durable trace-metadata sink shares the runtime identity context
    // and injected entropy; persistence failures never touch the data plane.
    let trace_records = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let trace_sink = crate::routing::trace::TraceSink::new(
      Arc::clone(&context),
      dependencies.entropy.clone(),
      std::sync::Arc::new(crate::storage::receipt::HostWallClock),
      std::sync::Arc::clone(&trace_records),
    );
    let recovery = crate::membership::recovery::RecoveryController::new(
      crate::membership::recovery::RecoveryPolicy::new(
        dependencies.config.recovery().neighbors(),
        dependencies.config.recovery().fan_out(),
        dependencies.config.recovery().initial_backoff_seconds(),
        dependencies.config.recovery().maximum_backoff_seconds(),
      ),
    );
    Ok(Self {
      dependencies,
      shutdown_tx,
      driver,
      packet,
      route_capacity,
      listeners: BTreeMap::new(),
      recovery,
      recovery_pending: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
      published_endpoints,
      recovery_history: std::collections::BTreeSet::new(),
      recovery_seeded: false,
      exclusion_cache: std::sync::Mutex::new(None),
      resource_write_clock: std::sync::atomic::AtomicU64::new(0),
      recovery_excluded: std::collections::BTreeSet::new(),
      sync_driver,
      trace_sink,
      trace_records,
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
    if let Ok(mut handles) = self.dependencies.connection_tasks.lock() {
      for handle in handles.drain(..) {
        handle.abort();
        aborted.push(handle);
      }
    }
    (self.dependencies, aborted)
  }

  fn rotate_merge_credential(&mut self) -> Result<IssuedMergeCredential> {
    self.require_unblocked()?;
    self
      .driver
      .issuer()
      .lock()
      .map_err(|_| Error::internal("join credential issuer"))?
      .rotate(self.dependencies.entropy.as_ref(), SystemTime::now())
  }

  async fn listen(&mut self, endpoint: Endpoint, tasks: &mut JoinSet<()>) -> Result<ListenerView> {
    self.require_unblocked()?;
    let listener: std::sync::Arc<dyn TransportListener> =
      std::sync::Arc::from(self.dependencies.transport.bind(endpoint.clone()).await?);
    let bound = listener.local_endpoint();
    let driver = self.driver.clone();
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    let connection_tasks = self.dependencies.connection_tasks.clone();
    let accept_listener = std::sync::Arc::clone(&listener);
    let insert_listener = std::sync::Arc::clone(&listener);
    let attachment = bound.clone();
    let abort = tasks.spawn(async move {
      tracing::debug!("accept loop started");
      // The hint provider is evaluated per accepted connection (after the
      // kernel accept, before the upgrade response): a credential rotation
      // during the blocking wait is reflected in the very next join.
      let hint_provider_driver = driver.clone();
      let hint_provider = move || hint_provider_driver.merge_hint().ok().flatten();
      // Consecutive failed upgrades: drives the bounded accept backoff,
      // so a persistently failing accept sleeps longer instead of
      // spinning; a success clears it.
      let mut accept_failures: u32 = 0;
      loop {
        let accepted = accept_listener.accept(&hint_provider).await;
        let mut connection = match accepted {
          Ok(connection) => {
            accept_failures = 0;
            connection
          }
          Err(error) => {
            // A failed TLS/prelude upgrade must not kill the listener;
            // consecutive failures back off on a bounded growing delay.
            accept_failures = accept_failures.saturating_add(1);
            let delay = ACCEPT_BACKOFF_STEP
              .saturating_mul(accept_failures.min(ACCEPT_BACKOFF_MAX_STEPS));
            tracing::debug!(
              kind = ?error.kind(),
              consecutive = accept_failures,
              delay_ms = delay.as_millis(),
              "accept failed; backing off"
            );
            tokio::time::sleep(delay).await;
            continue;
          }
        };
        let driver = driver.clone();
        let packet = packet.clone();
        let sessions = sessions.clone();
        let shutdown = shutdown.clone();
        let attachment = attachment.clone();
        let task = tokio::spawn(async move {
          match driver.respond(&mut connection).await {
            Ok(session) => {
              // Keep the authenticated session open: it serves packet
              // streams until the connection closes.
              run_session(
                connection,
                session,
                packet,
                sessions,
                shutdown,
                crate::session::stream::DialDirection::Incoming,
                attachment.clone(),
                None,
              )
              .await;
            }
            Err(error) => {
              // A typed rejection must reach the dialer before the socket
              // disappears: close gracefully so the failure frame drains
              // instead of being lost to a reset (hardening).
              let _ = connection.close().await;
              tracing::warn!(kind = ?error.kind(), context = %error, "session establishment failed");
            }
          }
        });
        if let Ok(mut tasks) = connection_tasks.lock() {
          tasks.push(task);
        }
      }
    });
    let id = crate::identity::ListenerId::generate(self.dependencies.entropy.as_ref())?;
    // Publish the caller's advertised endpoint, not the bound socket
    // address: peers dial the advertised name, which re-resolves across
    // network moves. A named endpoint binds the wildcard socket (see
    // WssTransport::bind), whose local address (0.0.0.0) is local
    // plumbing and undialable from other nodes. Literal-IP endpoints
    // publish the bound form directly: the requested host is the bound
    // host, and a wildcard port resolves to the real one.
    let published = if endpoint.host() == bound.host() {
      bound
    } else {
      endpoint.with_port(bound.port())
    };
    self.listeners.insert(
      id.clone(),
      (
        published.clone(),
        std::sync::Arc::clone(&insert_listener),
        abort,
      ),
    );
    // Publish the advertised endpoint so the next anti-entropy tick pages
    // it in the local descriptor (recovery dials peers through published
    // endpoints).
    if let Ok(mut endpoints) = self.published_endpoints.lock()
      && !endpoints.contains(&published)
    {
      endpoints.push(published.clone());
    }
    Ok(ListenerView::new(id, published))
  }

  async fn stop_listener(&mut self, listener: &crate::identity::ListenerId) -> Result<()> {
    let Some((endpoint, listener_handle, abort)) = self.listeners.remove(listener) else {
      return Err(Error::not_found("listener"));
    };
    // Close only wakes the pending accept so it observes the shutdown;
    // the address is released by dropping the listener — the removal
    // above and the aborted accept task drop the last owners, so a
    // later rebind on the same port works.
    let _ = listener_handle.close().await;
    abort.abort();
    if let Ok(mut endpoints) = self.published_endpoints.lock() {
      endpoints.retain(|candidate| candidate != &endpoint);
    }
    Ok(())
  }

  async fn merge_cluster(
    &mut self, receiver: Endpoint, credential: crate::identity::credential::MergeCredential,
    tasks: &mut JoinSet<()>,
  ) -> Result<MergeView> {
    self.require_unblocked()?;
    let mut connection = self
      .dependencies
      .transport
      .connect(receiver.clone(), tls::merge_client_config()?)
      .await?;
    let hint = connection
      .merge_hint()
      .cloned()
      .ok_or_else(|| Error::authentication_failed("join hint"))?;
    let secret = crate::protocol::credential::CredentialSecret::from_credential(&credential);
    let (session, view) = self.driver.merge(&mut connection, &hint, secret).await?;
    // Remember the peer's leaf SPKI from the merge as the member-mode
    // reconnect pinning anchor (hardening).
    let peer = session.peer().clone();
    if !hint.leaf_spki().is_empty() {
      self
        .driver
        .record_peer_spki(&peer, hint.leaf_spki().to_vec());
    }
    // Keep the merge session open so both sides can stream packets over
    // it. The merge view returns only after the session table registers
    // the entry, so the caller's first packet cannot race registration.
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    keep_outbound_session(
      connection,
      session,
      packet,
      sessions,
      shutdown,
      receiver,
      |session_task| {
        tasks.spawn(session_task);
      },
    )
    .await?;
    Ok(view)
  }

  /// Reconnects to an already-admitted peer with key trust only: the
  /// member-mode handshake proves both identities over a fresh transcript
  /// and exporter binding without consulting any join credential, then
  /// keeps the session open for packet streams.
  async fn connect_member(&mut self, receiver: Endpoint, peer: NodeId) -> Result<NodeId> {
    self.require_unblocked()?;
    // A deliberate caller connect restores an intentionally disconnected
    // relationship: recovery may heal it again.
    self.recovery_excluded.remove(&peer);
    let driver = self.driver.clone();
    let sessions = self.dependencies.sessions.clone();
    let packet = self.packet.clone();
    let shutdown = self.shutdown_tx.subscribe();
    dial_member(
      self.dependencies.transport.clone(),
      driver,
      sessions,
      packet,
      shutdown,
      receiver,
      &peer,
    )
    .await
  }

  /// Records one bounded terminal route failure for an outbound trace so
  /// asynchronous senders can observe it through `GetRoute`: identity and
  /// typed failure only, never a body or a fabricated selected node. An
  /// already-tracked route keeps its real selected node — only the state
  /// moves to the typed failure.
  fn record_route_failure(&self, trace_id: &TraceId, kind: ErrorKind) {
    record_terminal_failure(
      &self.dependencies.routes,
      self.route_capacity,
      trace_id,
      kind,
    );
    self
      .dependencies
      .events
      .emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
  }

  /// Routes one outbound packet. Matching-node targets resolve through the
  /// registered load-balancing policy over the descriptor store before the
  /// pump starts; the selected node is validated against the authoritative
  /// descriptors. Failure paths still record the terminal
  /// route state so asynchronous senders can observe them through
  /// `GetRoute`.
  async fn send_packet(
    &mut self, mut request: OutboundRequest, tasks: &mut JoinSet<()>,
  ) -> Result<()> {
    let trace_id = request.trace_id.clone();
    // Resolve matching-node targets to exactly one eligible destination
    // before any frame moves: candidates stream from the descriptor store,
    // the caller's policy picks one, and core re-validates the pick.
    let resolved = match &request.target {
      StreamTarget::Exact(destination) => Ok(destination.clone()),
      StreamTarget::MatchingNodes(selector) => {
        self
          .select_matching_destination(selector, request.load_balancer.as_ref())
          .await
      }
    };
    let destination = match resolved {
      Ok(destination) => {
        // The resolved target drives the rest of the pump.
        request.target = StreamTarget::Exact(destination.clone());
        destination
      }
      Err(error) => {
        // A failed selection records bounded terminal trace metadata
        // only: identity and typed failure, never a body or a fabricated
        // selected node.
        self.record_route_failure(&trace_id, error.kind());
        request.reject(error.kind());
        return Ok(());
      }
    };
    if let Err(error) = insert_route(
      &self.dependencies.routes,
      self.route_capacity,
      RouteRecord::new(trace_id.clone(), destination.clone()),
    ) {
      request.reject(error.kind());
      return Err(error);
    }
    self
      .dependencies
      .events
      .emit(crate::RouteChanged::new(crate::RouteHandle::from_trace_id(
        trace_id.clone(),
      )));
    let fail = |request: OutboundRequest, kind: ErrorKind| {
      self.record_route_failure(&trace_id, kind);
      request.reject(kind);
    };
    let entry = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .get(&destination)
      .cloned();
    // A direct path is preferred; without one, the node's registered
    // next-hop policy may route through a connected peer. The
    // pump then emits the route envelope so every intermediate hop
    // re-validates the chain.
    let direct = entry.filter(|entry| entry.alive());
    debug!(
      destination = %destination,
      direct = direct.is_some(),
      "routing packet toward destination"
    );
    let (entry, force_routed) = match direct {
      Some(entry) => (entry, false),
      None => match self.select_forward_entry(&destination).await? {
        Some(entry) => (entry, true),
        None => {
          fail(request, ErrorKind::RouteUnavailable);
          return Err(Error::route_unavailable("packet session"));
        }
      },
    };
    let local = self.packet.local().clone();
    let routes = self.dependencies.routes.clone();
    // Core-internal control traffic stays out of the durable trace store:
    // its volume is a runtime implementation detail, not caller evidence.
    let trace = if request.internal {
      None
    } else {
      Some(self.trace_sink.clone())
    };
    let events = self.dependencies.events.clone();
    tasks.spawn(async move {
      run_outbound(entry, local, request, routes, force_routed, trace, events).await;
    });
    Ok(())
  }

  /// One host-wall-clock retention pass over the durable route-trace
  /// records: terminal records expire at their configured deadline and the
  /// terminal population stays within the caller-selected cap; active
  /// records are never removed. Skipped while no durable record exists.
  async fn trace_retention_sweep(&mut self) {
    if self
      .trace_records
      .load(std::sync::atomic::Ordering::Relaxed)
      == 0
    {
      return;
    }
    let limits = self.dependencies.config.trace_metadata_limits();
    let Ok(context) = self.context() else {
      return;
    };
    match crate::routing::trace::sweep(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &crate::storage::receipt::HostWallClock,
      limits.terminal(),
      limits.retention(),
    )
    .await
    {
      Ok(removed) => {
        self
          .trace_records
          .try_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |live| Some(live.saturating_sub(removed)),
          )
          .ok();
      }
      Err(error) => {
        tracing::warn!(kind = ?error.kind(), "trace retention sweep failed");
      }
    }
  }

  /// One host-wall-clock retention pass over the resource removal
  /// evidence: expired and excess signed removal records leave
  /// by exact conditional deletes that never dereference a resource URI
  /// or touch caller data; live resource metadata is never evicted.
  async fn resource_removal_sweep(&mut self) {
    let Ok(context) = self.context() else {
      return;
    };
    if let Err(error) = crate::resource::retention::sweep_removed_ctx(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &crate::storage::receipt::HostWallClock,
      crate::resource::retention::RESOURCE_REMOVAL_RETENTION,
      crate::resource::retention::RESOURCE_REGISTER_CAP,
    )
    .await
    {
      tracing::warn!(kind = ?error.kind(), "resource removal sweep failed");
    }
  }

  /// Lazily publishes this node's own signed descriptor (revision 1) so
  /// the public views always expose the local identity, with the
  /// published listener endpoints.
  pub(super) async fn ensure_self_descriptor(&mut self) -> Result<()> {
    let context = self.context()?;
    let endpoints = self
      .published_endpoints
      .lock()
      .map(|endpoints| endpoints.clone())
      .unwrap_or_default();
    crate::membership::sync::ensure_local_descriptor(
      &context,
      &self.dependencies.entropy,
      endpoints,
      &self.dependencies.events,
      &self.dependencies.member_revision,
    )
    .await
  }

  /// Forces one bounded immediate recovery cycle and
  /// returns the public recovery view.
  fn start_recovery(&mut self) -> Result<crate::RecoveryView> {
    let before = self.recovery_view();
    self.recovery.immediate(crate::time::now_seconds());
    let after = self.recovery_view();
    if after != before {
      self
        .dependencies
        .events
        .emit(crate::RecoveryChanged::new(after.clone()));
    }
    Ok(after)
  }

  /// Closes the authenticated session to one peer (partition simulation)
  /// and removes it from the recovery known-online set: an
  /// intentional disconnect is respected by recovery (a real edge loss, by
  /// contrast, leaves the member online and gets healed on the next cycle).
  fn disconnect_peer(&mut self, peer: &NodeId) -> Result<()> {
    crate::session::stream::retire_session(&self.dependencies.sessions, peer)?;
    self
      .dependencies
      .events
      .emit(crate::SessionChanged::new(peer.clone()));
    self.recovery_history.remove(peer);
    // An intentional disconnect is never re-healed until the relationship
    // is deliberately re-established (a new session to the peer).
    self.recovery_excluded.insert(peer.clone());
    Ok(())
  }

  /// Applies one owner-only metadata patch to this node's own descriptor
  /// (`UpdateNodeMetadata`): endpoint candidates and capability labels are
  /// replaced at a strictly higher revision than `expected_revision`, and
  /// the updated member view is returned (owner records).
  async fn update_node_metadata(
    &mut self, expected_revision: u64, patch: crate::NodeMetadataPatch,
  ) -> Result<crate::MemberView> {
    self.require_unblocked()?;
    let context = self.context()?;
    let local = context.identity().node().clone();
    let store = context.store();
    let current = crate::membership::store::read_descriptor_ctx(store, &local)
      .await?
      .ok_or_else(|| Error::not_ready("local descriptor"))?;
    if current.revision() != expected_revision {
      return Err(Error::conflict("node metadata revision"));
    }
    let updated = crate::membership::apply_metadata_patch(&current, patch)?;
    crate::membership::store::store_descriptor_ctx(
      store,
      self.dependencies.entropy.as_ref(),
      &updated,
    )
    .await?;
    self
      .dependencies
      .events
      .emit(crate::MemberChanged::new(local.clone()));
    self.dependencies.member_revision.bump();
    crate::membership::member_view(&updated, crate::ConnectivityStatus::Connected)
  }

  /// Issues the next resource-write stamp for this node: strictly
  /// greater than every stamp this writer has issued before, riding
  /// through host wall-clock regressions. The issued stamp is folded
  /// back into the issue clock so a third write inside the millisecond
  /// that produced the second cannot reuse the same candidate stamp.
  fn issue_resource_stamp(&self) -> u64 {
    issue_write_stamp(&self.resource_write_clock)
  }

  /// Commits one resource write intent as a signed candidate record
  /// (`PutResource`): the supervisor stamps the host wall-clock
  /// tuple, signs through the node's key provider, and commits the whole
  /// record in one conditional transaction. A committed winner emits
  /// exactly one [`crate::ResourceChanged`] after durability; an accepted
  /// but superseded candidate emits nothing, and an indeterminate commit
  /// reports `CommitUnknown` without an event.
  async fn put_resource(
    &mut self, write: crate::ResourceWrite,
  ) -> Result<crate::ResourceMutationView> {
    self.require_unblocked()?;
    let context = self.context()?;
    // The writer's descriptor anchors the record's signature: publish it
    // before the commit so peers can verify this candidate as soon as it
    // arrives (a writing member that never listens must still propagate).
    self.ensure_self_descriptor().await?;
    let writer = context.identity().node().clone();
    let labels = write.labels().clone();
    // A snapshot-exact CAS can lose a race against a concurrent internal
    // committer (anti-entropy convergence or the descriptor ensure) that
    // moved the base revision between the snapshot and the commit. That
    // refusal says nothing about the candidate itself, so the write
    // re-snapshots and re-signs with a fresh tuple timestamp; a bounded
    // retry keeps the semantic that Conflict means the register rejected
    // the candidate, not a lost bookkeeping race.
    let mut attempts = 0_u32;
    loop {
      attempts += 1;
      let timestamp_millis = self.issue_resource_stamp();
      let record = crate::resource::ResourceRecordV1::sign_with_provider(
        write.name().clone(),
        labels.resource_type().clone(),
        labels.uri().clone(),
        labels.custom_labels().clone(),
        timestamp_millis,
        writer.clone(),
        0,
        false,
        &self.dependencies.keys,
        context.identity().handle(),
      )
      .await?;
      let accepted = crate::resource::select::resource_view(&record);
      let outcome = match crate::resource::store::commit_record_ctx(
        context.store(),
        self.dependencies.entropy.as_ref(),
        &record,
      )
      .await
      {
        Err(error) if error.kind() == crate::ErrorKind::Conflict && attempts < 3 => {
          tracing::debug!(attempts, "resource put lost the commit race; retrying");
          tokio::time::sleep(std::time::Duration::from_millis(10 * u64::from(attempts))).await;
          continue;
        }
        result => result?,
      };
      return Ok(match outcome {
        crate::resource::store::ResourceCommitOutcome::Installed(_) => {
          self
            .dependencies
            .events
            .emit(crate::ResourceChanged::new(record.name().clone()));
          crate::ResourceMutationView::new(accepted, true)
        }
        crate::resource::store::ResourceCommitOutcome::Superseded(_) => {
          crate::ResourceMutationView::new(accepted, false)
        }
        crate::resource::store::ResourceCommitOutcome::Indeterminate { .. } => {
          return Err(Error::provider(
            crate::ProviderErrorKind::CommitUnknown,
            crate::ProviderErrorContext::StorageCommit,
          ));
        }
      });
    }
  }

  /// Creates signed removal evidence for one resource (`RemoveResource`):
  /// only when the stored winner still equals the caller's
  /// observed version exactly and the removal strictly wins the tuple.
  /// The removal record carries the winner's labels (removal evidence
  /// stays comparable), and the operation touches core metadata only —
  /// the resource URI is never followed and no caller object is deleted.
  async fn remove_resource(
    &mut self, name: crate::ResourceName, expected: crate::ResourceVersion,
  ) -> Result<crate::ResourceMutationView> {
    self.require_unblocked()?;
    let context = self.context()?;
    // The writer's descriptor anchors the removal's signature for the
    // same propagation reason as a put.
    self.ensure_self_descriptor().await?;
    let writer = context.identity().node().clone();
    // The snapshot-exact CAS can lose a race against a concurrent internal
    // committer, so the observation, signature, and commit re-run within
    // a bounded retry; the caller's `expected` stays the only authority
    // on which register state the removal may replace.
    let mut attempts = 0_u32;
    loop {
      attempts += 1;
      let store = context.store();
      let stored = crate::resource::store::read_record_ctx(store, &name)
        .await?
        .ok_or_else(|| Error::not_found("resource"))?;
      if !expected.matches_record(&stored) {
        // A stale observation never becomes a newer wall-clock winner.
        return Err(Error::conflict("resource version"));
      }
      if stored.removed() {
        // The exact removal already won: idempotent, no new transition.
        return Ok(crate::ResourceMutationView::new(
          crate::resource::select::resource_view(&stored),
          true,
        ));
      }
      // The removal rides the same monotonic issue clock as a put, so a
      // writer removing its own fresh record always outranks it, and a
      // rolled-back host clock cannot issue a stale-looking stamp.
      let timestamp_millis = self.issue_resource_stamp();
      // A synced record may legally carry the maximum rank; a saturated
      // register cannot host a further removal and fails closed instead of
      // wrapping the rank order.
      let removal_rank = stored
        .removal_rank()
        .checked_add(1)
        .ok_or_else(|| Error::conflict("resource removal rank"))?;
      // The removal signs through the same single sign-and-seal path as a
      // put (`removed = true`): one canonical encode, one digest, and no
      // second body construction inside `seal`.
      let removal = crate::resource::ResourceRecordV1::sign_with_provider(
        name.clone(),
        stored.resource_type().clone(),
        stored.resource_uri().clone(),
        stored.labels().clone(),
        timestamp_millis,
        writer.clone(),
        removal_rank,
        true,
        &self.dependencies.keys,
        context.identity().handle(),
      )
      .await?;
      if !removal.wins_over(&stored) {
        // A rolled-back host clock cannot pose as a newer winner: the
        // removal is refused and the live record stays.
        return Err(Error::conflict("resource removal clock"));
      }
      let outcome = match crate::resource::store::commit_removal_ctx(
        store,
        self.dependencies.entropy.as_ref(),
        &removal,
        &stored,
      )
      .await
      {
        Err(error) if error.kind() == crate::ErrorKind::Conflict && attempts < 3 => {
          tracing::debug!(attempts, "resource removal lost the commit race; retrying");
          tokio::time::sleep(std::time::Duration::from_millis(10 * u64::from(attempts))).await;
          continue;
        }
        result => result?,
      };
      return Ok(match outcome {
        crate::resource::store::ResourceCommitOutcome::Installed(_) => {
          self
            .dependencies
            .events
            .emit(crate::ResourceChanged::new(name));
          crate::ResourceMutationView::new(crate::resource::select::resource_view(&removal), true)
        }
        // The register moved between the observation and the commit.
        crate::resource::store::ResourceCommitOutcome::Superseded(_) => {
          return Err(Error::conflict("resource version"));
        }
        crate::resource::store::ResourceCommitOutcome::Indeterminate { .. } => {
          return Err(Error::provider(
            crate::ProviderErrorKind::CommitUnknown,
            crate::ProviderErrorContext::StorageCommit,
          ));
        }
      });
    }
  }

  /// Revokes one exact subject binding's connection and admission
  /// authority (`RevokeNode`): the revocation commits
  /// conditionally first, then the revoked identity's sessions close and
  /// its new sessions, admissions, and operations are rejected. Stored
  /// metadata is never erased or reinterpreted.
  /// Issues one convergent issuer-signed cleanup tombstone:
  /// the record persists locally and converges through the sync plane.
  async fn cleanup_node(&mut self, subject: NodeId) -> Result<()> {
    self.require_unblocked()?;
    let context = self.context()?;
    if &subject == context.identity().node() {
      // Self-removal is the explicit leave path, never a self-cleanup.
      return Err(Error::invalid_input("cleanup subject"));
    }
    let record =
      crate::identity::cleanup::sign_cleanup_record(&context, &self.dependencies.keys, &subject)
        .await?;
    crate::identity::cleanup::persist_cleanup_record_ctx(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &record,
    )
    .await?;
    self
      .dependencies
      .events
      .emit(crate::MemberChanged::new(subject));
    self.dependencies.member_revision.bump();
    Ok(())
  }

  /// Clears the local revocation record for one subject:
  /// local-only, idempotent, deliberate.
  async fn purge_revocation(&mut self, subject: NodeId) -> Result<()> {
    self.require_unblocked()?;
    let context = self.context()?;
    crate::identity::revocation::purge_revocation_ctx(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &subject,
    )
    .await
  }

  /// Starts a new checkpoint GC epoch at the current wall clock. The
  /// watermark converges through the sync plane; collected tombstones are
  /// swept after sync rounds.
  async fn issue_cleanup_checkpoint(&mut self) -> Result<u64> {
    self.require_unblocked()?;
    let context = self.context()?;
    crate::identity::cleanup::issue_checkpoint_ctx(&context, self.dependencies.entropy.as_ref())
      .await
  }

  /// Forgets every anchored receipt past its retention deadline. The
  /// unknown-outcome freeze blocks the pass: a pending unknown may still
  /// reference its receipt, and cleanup conflicts rather than guesses.
  async fn apply_receipt_retention(&mut self) -> Result<crate::view::ReceiptRetentionReport> {
    self.require_unblocked()?;
    let context = self.context()?;
    context.store().apply_receipt_retention().await
  }

  /// Forwards the RunSyncRound request to the sync driver (the cursor
  /// owner) and awaits the round's completion. A dropped reply means the
  /// node is shutting down.
  async fn run_sync_round(&self) -> Result<()> {
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    self
      .dependencies
      .sync_round_requests
      .clone()
      .send(reply)
      .await
      .map_err(|_| Error::shutting_down("sync round"))?;
    reply_rx
      .await
      .map_err(|_| Error::shutting_down("sync round"))?;
    Ok(())
  }

  async fn revoke_node(
    &mut self, subject: NodeId, expected_key: crate::PublicKey,
  ) -> Result<crate::RevokeOutcome> {
    self.require_unblocked()?;
    let context = self.context()?;
    let local = context.identity().node();
    if &subject == local {
      // Self-removal is the explicit leave path, never a self-revoke.
      return Err(Error::invalid_input("revoke subject"));
    }
    // The tombstone is issuer-signed and converges through the sync plane:
    // any member may expel a compromised binding
    // cluster-wide, and the record is permanent until an explicit local
    // purge.
    let record = crate::identity::revocation::sign_revocation_record(
      &context,
      &self.dependencies.keys,
      &subject,
      &expected_key,
    )
    .await?;
    let outcome = crate::identity::revocation::revoke_binding_ctx(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &record,
    )
    .await?;
    let was_already_revoked = matches!(
      outcome,
      crate::identity::revocation::RevokeStoreOutcome::AlreadyRevoked
    );
    if !was_already_revoked {
      // After the known-committed transition: close the exact identity's
      // active sessions and exclude it from recovery redial.
      crate::session::stream::retire_session(&self.dependencies.sessions, &subject)?;
      self
        .dependencies
        .events
        .emit(crate::SessionChanged::new(subject.clone()));
      self.recovery_history.remove(&subject);
      self.recovery_excluded.insert(subject.clone());
      self
        .dependencies
        .events
        .emit(crate::NodeRevoked::new(subject.clone()));
    }
    Ok(crate::RevokeOutcome::new(subject, was_already_revoked))
  }

  /// Executes one acknowledged active leave (`LeaveCluster`):
  /// tears down listeners and sessions, replaces the identity, wipes the
  /// old identity's local core metadata, and deletes the old key — all
  /// through the journaled, crash-recoverable leave phases. The caller's
  /// outcome is reported, then the control loop shuts the runtime down
  /// with `ShutdownReason::ActiveLeave`.
  async fn leave_cluster(
    &mut self, acknowledgement: crate::ReplaceIdentityAndDeleteOldCoreMetadata,
  ) -> Result<crate::LeaveOutcome> {
    self.require_unblocked()?;
    // The acknowledgement is a proof-of-construction marker: only the
    // deliberate constructor produces it.
    if !acknowledgement.is_acknowledged() {
      return Err(Error::invalid_input("leave acknowledgement"));
    }
    let context = self.context()?;

    // Crash-retryable ordering: journal the intent
    // and the signed record before any network effect, announce with the
    // journaled record, then rotate. A crash anywhere before rotation
    // resumes at startup with the same journaled record, so the leave is
    // never forgotten and never diverges from what peers may already
    // hold. A receipt-less budget expires into the documented silent
    // leave, which the cleanup path covers.
    let journaled = crate::identity::leave::journal_leave(
      &context,
      &self.dependencies.keys,
      self.dependencies.entropy.as_ref(),
    )
    .await?;
    crate::membership::sync::announce_leave(
      &context,
      &self.dependencies.entropy,
      &journaled.record,
      &self.dependencies.sessions,
      &self.dependencies.routes,
      &self.dependencies.events,
      &self.dependencies.leave_applied,
    )
    .await?;

    // Network teardown first: no new sessions or inbound metadata while
    // the identity is replaced and the old metadata is wiped.
    let listener_ids: Vec<crate::identity::ListenerId> = self.listeners.keys().cloned().collect();
    for listener in listener_ids {
      self.stop_listener(&listener).await?;
    }
    let peers: Vec<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .keys()
      .cloned()
      .collect();
    for peer in peers {
      crate::session::stream::retire_session(&self.dependencies.sessions, &peer)?;
      self.recovery_history.remove(&peer);
    }

    crate::identity::leave::run_leave(
      context.store(),
      &self.dependencies.keys,
      self.dependencies.entropy.as_ref(),
      &journaled.stored,
      &journaled.intent,
    )
    .await?;
    let (former, replacement) = (
      journaled.intent.former_node().clone(),
      journaled.intent.replacement_node().clone(),
    );
    self.dependencies.events.emit(crate::IdentityReplaced::new(
      former.clone(),
      replacement.clone(),
    ));
    Ok(crate::LeaveOutcome::new(former, replacement))
  }

  pub(super) fn context(&self) -> Result<Arc<LocalIdentityContext>> {
    self
      .dependencies
      .context
      .clone()
      .ok_or_else(|| Error::internal("runtime context"))
  }

  /// Blocks admission-sensitive operations while the metadata store is
  /// frozen on an indeterminate outcome: credential
  /// reuse, rotation, signing, and new networking stay unavailable until
  /// an authoritative reopen reconciles the exact transaction or proves
  /// absence. Established authenticated sessions are unaffected.
  pub(super) fn require_unblocked(&self) -> Result<()> {
    let context = self.context()?;
    if context.store().is_blocked()? {
      return Err(Error::not_ready("metadata storage reconciliation"));
    }
    Ok(())
  }
}

/// Runs one member-mode dial against an already-admitted peer: the
/// member-mode handshake proves both identities over a fresh transcript
/// and exporter binding, then the session is kept open for packet streams.
/// Called by `connect_member` and by the recovery controller's detached
/// dial tasks.
pub(super) async fn dial_member(
  transport: Arc<dyn Transport>, driver: SessionDriver,
  sessions: crate::session::stream::SessionTable, packet: Arc<SessionPacketContext>,
  shutdown: watch::Receiver<()>, receiver: Endpoint, peer: &NodeId,
) -> Result<NodeId> {
  // Member reconnects pin the peer's TLS leaf to the SPKI anchor learned
  // at join (same-listener reconnects); without an anchor this process
  // falls back to the join-mode relaxation and the application proof
  // layer remains the authenticator.
  let config = match driver.peer_spki(peer) {
    Some(spki) => {
      tls::member_client_config(rustls::pki_types::SubjectPublicKeyInfoDer::from(spki))?
    }
    None => tls::merge_client_config()?,
  };
  let mut connection = transport.connect(receiver.clone(), config).await?;
  let session = driver.initiate_member(&mut connection, peer).await?;
  let authenticated = session.peer().clone();
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
    |session_task| {
      tokio::spawn(session_task);
    },
  )
  .await?;
  Ok(authenticated)
}

/// The keep-open tail shared by join and member dials: spawns the
/// outbound session pump through the caller's spawner and returns only
/// after the session table registers the entry, so the caller's first
/// packet cannot race registration.
async fn keep_outbound_session(
  connection: crate::transport::connection::Connection,
  session: crate::session::EstablishedSession, packet: Arc<SessionPacketContext>,
  sessions: SessionTable, shutdown: watch::Receiver<()>, attachment: Endpoint,
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
  )));
  if registered_rx.await.is_err() {
    return Err(Error::internal("session registration"));
  }
  Ok(())
}

/// Issues the next resource-write stamp from the writer's issue clock:
/// strictly greater than every stamp previously issued through this
/// clock, and never below the observed wall clock. The issued stamp is
/// folded back into the clock, so successive issues inside one
/// millisecond keep advancing by one instead of colliding on
/// `previous + 1` and falling to the register's digest tie-break.
fn issue_write_stamp(clock: &std::sync::atomic::AtomicU64) -> u64 {
  issue_write_stamp_since(clock, crate::time::now_millis())
}

/// [`issue_write_stamp`] against an injected observation, so the
/// same-millisecond collision the fold prevents stays deterministic to
/// test.
fn issue_write_stamp_since(clock: &std::sync::atomic::AtomicU64, observed: u64) -> u64 {
  let previous = clock.fetch_max(observed, std::sync::atomic::Ordering::Relaxed);
  let stamp = previous.saturating_add(1).max(observed);
  clock.fetch_max(stamp, std::sync::atomic::Ordering::Relaxed);
  stamp
}

#[cfg(test)]
mod resource_stamp_tests {
  use super::issue_write_stamp_since;

  #[test]
  fn stamps_advance_inside_one_millisecond() {
    let clock = std::sync::atomic::AtomicU64::new(0);
    // Three issues inside the same observed millisecond: the second
    // issue advances past the first without moving the clock, so the
    // fold-back is what keeps the third from reusing the second's stamp.
    let first = issue_write_stamp_since(&clock, 1_000);
    let second = issue_write_stamp_since(&clock, 1_000);
    let third = issue_write_stamp_since(&clock, 1_000);
    assert_eq!(first, 1_000);
    assert_eq!(second, 1_001);
    assert_eq!(third, 1_002);
  }

  #[test]
  fn stamps_ride_through_wall_clock_regressions() {
    let clock = std::sync::atomic::AtomicU64::new(0);
    let _ = issue_write_stamp_since(&clock, 5_000);
    // A rolled-back observation issues above the last stamp, never below.
    let next = issue_write_stamp_since(&clock, 4_000);
    assert_eq!(next, 5_001);
    assert!(clock.load(std::sync::atomic::Ordering::Relaxed) >= next);
  }
}
