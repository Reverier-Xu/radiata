use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};

use super::anti_entropy::spawn_sync_driver;
use crate::{
  Endpoint, Error, IssuedMergeCredential, MergeView, NodeConfig, NodeId, Result, ShutdownOutcome,
  ShutdownReason,
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
  transport::{
    registry::{Transport, TransportListener},
    tls,
  },
};

const CONTROL_CAPACITY: usize = 32;

/// The recovery controller's observation period (unnamed literal kept
/// every other period out of `NodeConfig`).
const RECOVERY_TICK_PERIOD: std::time::Duration = std::time::Duration::from_secs(2);

/// Capacity of the node's outbound packet command channel:
/// `PACKET_CHANNEL_CAPACITY` derives from it so one bound governs both
/// control ends.
///
/// The bounded request channel for `RunSyncRound` commands: rounds are
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
  /// The caller's custody injection, if any. `open_local_identity`
  /// resolves `None` to the default store-backed provider, and the
  /// resolved provider lives on the identity context; this field is only
  /// the pre-open injection.
  pub(crate) keys: Option<Arc<dyn KeyProvider>>,
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
    dependencies.sessions.clone(),
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
  // The negotiation registry and the node offer are built before the
  // runtime is marked ready (the core protocols above joined the feature
  // set): a provisioning failure (a caller-required feature outside the
  // registry) is a typed start() error, never a running node that
  // silently stopped.
  let mut definitions = crate::protocol::feature::builtin_definitions()?;
  definitions.extend(dependencies.extensions.feature_definitions());
  let registry = crate::protocol::feature::FeatureRegistry::build(definitions)?;
  let offer = node_offer(&registry, dependencies.config.required_features())?;
  let routes = dependencies.routes.clone();
  let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
  let (state_tx, state_rx) = watch::channel(LifecycleSnapshot::starting());
  let (ready_tx, ready_rx) = oneshot::channel();
  let (packet_tx, packet_rx) = packets;
  let client = RuntimeClient::new(control_tx, state_rx, routes, packet_tx.clone());

  runtime.spawn(supervise(
    dependencies,
    control_rx,
    (packet_tx, packet_rx),
    sync_rounds,
    state_tx,
    ready_tx,
    offer,
  ));

  ready_rx
    .await
    .map_err(|_| Error::internal("node runtime startup"))?;
  Ok(client)
}

async fn supervise(
  dependencies: RuntimeDependencies, mut control: mpsc::Receiver<Control>,
  packets: (
    mpsc::Sender<crate::packet::OutboundRequest>,
    mpsc::Receiver<crate::packet::OutboundRequest>,
  ),
  sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
  state: watch::Sender<LifecycleSnapshot>, ready: oneshot::Sender<()>,
  offer: crate::protocol::offer::FeatureOffer,
) {
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

  let mut supervisor = match Supervisor::new(dependencies, packet_tx, sync_rounds, offer) {
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
      Control::IssueMergeCredential { reply } => {
        let result = supervisor.issue_merge_credential();
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
      Control::PutResource {
        write,
        expected,
        reply,
      } => {
        let result = supervisor.put_resource(write, expected).await;
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
        // The round runs in the sync driver; waiting it out here would
        // freeze this select loop for the round's whole duration, and the
        // loop is the only drainer of the outbound packet channel the
        // round dispatches through: a saturated round would then deadlock
        // against its own dispatch queue. The wait is owned by a tracked
        // task instead, so the loop keeps routing while the round runs and
        // the caller still observes its completion.
        let requests = supervisor.dependencies.sync_round_requests.clone();
        tasks.spawn(async move {
          let (round, round_rx) = tokio::sync::oneshot::channel();
          let shut_down = Error::shutting_down("sync round");
          let result = match requests.send(round).await {
            Ok(()) => round_rx.await.map_err(|_| shut_down),
            Err(_) => Err(shut_down),
          };
          let _ = reply.send(result);
        });
      }
      Control::RemoveResource {
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
      Control::ResolveFrozenJournal {
        acknowledgement,
        reply,
      } => {
        let result = supervisor.resolve_frozen_journal(acknowledgement).await;
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
        let _ = supervisor.send_packet(request, &mut tasks).await;
      }
      _ = recovery_timer.tick() => {
        // A failed tick (store outage, tombstone scan failure) must stay
        // visible: silent drops would starve recovery diagnostics.
        if let Err(error) = supervisor.recovery_tick().await {
          tracing::warn!(kind = ?error.kind(), "recovery tick failed");
        }
        supervisor.trace_retention_sweep().await;
        supervisor.resource_removal_sweep().await;
        supervisor.receipt_retention_sweep().await;
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
  /// Recovery-tick cooldown before the next redundant-edge cut.
  pub(super) prune_cooldown: u32,
  pub(super) published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>,
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
) -> Result<SessionPacketContext> {
  // The effective route policy: the caller selection, or the built-in
  // default policy tag (registered by the builder out of the box).
  let route_policy = dependencies.config.route_policy()?;
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
    crate::routing::forward::FORWARDING_ROUTE_CAPACITY_DEFAULT,
    dependencies.config.trace_metadata_limits().active(),
    Arc::clone(&dependencies.connection_tasks),
    dependencies.config.parser_cbor_limits(),
  ))
}

impl Supervisor {
  /// Builds the supervisor; provisioning failures return the dependencies
  /// so the caller can still run a clean shutdown instead of panicking.
  fn new(
    dependencies: RuntimeDependencies, packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
    sync_rounds: mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
    offer: crate::protocol::offer::FeatureOffer,
  ) -> std::result::Result<Self, Box<(Error, RuntimeDependencies)>> {
    let Some(context) = dependencies.context.clone() else {
      return Err(Box::new((Error::internal("runtime context"), dependencies)));
    };
    let policy = crate::session::stream::SessionPolicy::from_config(&dependencies.config);
    let packet = match session_packet_context(&context, &dependencies, packet_tx.clone(), policy) {
      Ok(packet) => packet,
      Err(error) => return Err(Box::new((error, dependencies))),
    };
    let packet = Arc::new(packet);
    let route_capacity = dependencies.config.trace_metadata_limits().active();
    let sync_context = Arc::clone(&context);
    let driver_context = Arc::clone(&context);
    let driver = SessionDriver::new(
      driver_context,
      context.keys().clone(),
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
      std::sync::Arc::new(crate::time::HostWallClock),
      std::sync::Arc::clone(&trace_records),
    );
    let recovery = crate::membership::recovery::RecoveryController::new(
      crate::membership::recovery::RecoveryPolicy::new(
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
      prune_cooldown: 0,
      published_endpoints,
      exclusion_cache: std::sync::Mutex::new(None),
      resource_write_clock: std::sync::atomic::AtomicU64::new(0),
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
    // Definitive session teardown: the graceful shutdown signal lets live
    // session tasks run their exit cleanup, but an abort landing first
    // skips it — draining the table here drops each entry's frame sender
    // so the detached writer task still exits and the connection closes.
    if let Err(error) = crate::session::stream::retire_all_sessions(&self.dependencies.sessions) {
      tracing::warn!(kind = ?error.kind(), "session table teardown failed");
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

  fn issue_merge_credential(&mut self) -> Result<IssuedMergeCredential> {
    self.require_unblocked()?;
    self
      .driver
      .issuer()
      .lock()
      .map_err(|_| Error::internal("join credential issuer"))?
      .issue(self.dependencies.entropy.as_ref(), SystemTime::now())
  }

  async fn merge_cluster(
    &mut self, receiver: Endpoint, credential: crate::identity::credential::MergeCredential,
    tasks: &mut JoinSet<()>,
  ) -> Result<MergeView> {
    self.require_unblocked()?;
    crate::audit::dial_started(&receiver.to_string(), false);
    // The configured dial deadline bounds the connect so a peer that
    // accepts and then goes silent cannot stall the supervisor's control
    // loop (every command, tick, and keepalive shares that loop).
    let mut connection = connect_with_deadline(
      &self.dependencies.transport,
      receiver.clone(),
      tls::merge_client_config()?,
      self.dependencies.config.dial_deadline(),
    )
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
    crate::audit::dial_settled(peer.as_str(), false, true);
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
      false,
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
      false,
      self.dependencies.config.dial_deadline(),
    )
    .await
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

  /// Closes the authenticated session to one peer and forgets it in the
  /// recovery plane for now: the member keeps its binding and descriptor,
  /// so any later session (inbound, healed, or a deliberate connect)
  /// restores it to the recovery plane like any other member. Ending a
  /// membership is the leave flow, not disconnecting a session.
  fn disconnect_peer(&mut self, peer: &NodeId) -> Result<()> {
    crate::session::stream::retire_session(&self.dependencies.sessions, peer)?;
    self
      .dependencies
      .events
      .emit(crate::SessionChanged::new(peer.clone()));
    // A disconnect only tears the session down: the peer stays a known
    // member (its binding and descriptor are untouched), so a later
    // session — inbound or healed — restores it to the recovery plane
    // like any other member. Leaving the cluster is the way to end a
    // membership, not disconnecting a session.
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

  /// Forgets every anchored receipt past its retention deadline. The
  /// recovery tick runs the same pass on every sweep cadence; the explicit
  /// command remains the way to force an idempotent pass on demand. The
  /// unknown-outcome freeze blocks the pass: a pending unknown may still
  /// reference its receipt, and cleanup conflicts rather than guesses.
  async fn apply_receipt_retention(&mut self) -> Result<crate::view::ReceiptRetentionReport> {
    self.require_unblocked()?;
    let context = self.context()?;
    context.store().apply_receipt_retention().await
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
    self.context()?.require_unblocked()
  }
}

/// Dials one transport connection under the configured dial deadline:
/// the deadline bounds the whole connect (TCP dial, TLS handshake, and
/// WebSocket upgrade), so a peer that accepts and then goes silent
/// cannot stall the supervisor's control loop or hold a recovery slot
/// forever. An elapsed deadline maps onto the same coarse typed
/// transport-connect failure as any other dial error; the connect
/// future is cancelled, so the deadline and endpoint are the only real
/// cause a diagnostic can carry.
async fn connect_with_deadline(
  transport: &Arc<dyn Transport>, receiver: Endpoint, client: std::sync::Arc<rustls::ClientConfig>,
  deadline: std::time::Duration,
) -> Result<crate::transport::connection::Connection> {
  match tokio::time::timeout(deadline, transport.connect(receiver.clone(), client)).await {
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
    // layer remains the authenticator.
    let config = match driver.peer_spki(peer) {
      Some(spki) => {
        tls::member_client_config(rustls::pki_types::SubjectPublicKeyInfoDer::from(spki))?
      }
      None => tls::merge_client_config()?,
    };
    let mut connection =
      connect_with_deadline(&transport, receiver.clone(), config, dial_deadline).await?;
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
      recovery_dialed,
      |session_task| {
        tokio::spawn(session_task);
      },
    )
    .await?;
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
async fn keep_outbound_session(
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
    transport::{registry::WssTransport, tls},
  };

  /// A peer that accepts TCP and then goes silent must surface the typed
  /// dial failure within the configured deadline instead of hanging the
  /// dialer. This exercises the one helper every production dial path
  /// shares (`merge_cluster`, `connect_member`, and the detached
  /// recovery dials through `dial_member`); the regression it guards is
  /// a connect with no bound at all, which stalled the supervisor's
  /// control loop and pinned recovery slots forever.
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
    let error = connect_with_deadline(
      &transport,
      endpoint,
      tls::merge_client_config().unwrap(),
      deadline,
    )
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
    let registry = feature::FeatureRegistry::build(definitions).unwrap();
    let offer = node_offer(&registry, config.required_features()).unwrap();
    let (round_tx, round_rx) = mpsc::channel(super::SYNC_ROUND_CHANNEL_CAPACITY);
    let (revision_tx, _) = watch::channel(0_u64);
    let (packet_tx, _packet_rx) = mpsc::channel(super::PACKET_CHANNEL_CAPACITY);
    let dependencies = RuntimeDependencies {
      transport: Arc::new(crate::transport::registry::WssTransport::new()),
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
      sync_round_requests: round_tx,
      connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
      runtime_seed: None,
    };
    // Supervisor::new builds the shared packet context itself, so the
    // test drives the exact production construction path.
    let supervisor = match Supervisor::new(dependencies, packet_tx, round_rx, offer) {
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
    let (mut supervisor, _factory, entropy) = sweep_supervisor(retention).await;

    // The explicit command keeps working: over an empty anchor set it is
    // an idempotent no-op.
    let report = supervisor.apply_receipt_retention().await.unwrap();
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
    let report = supervisor.apply_receipt_retention().await.unwrap();
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
    supervisor.receipt_retention_sweep().await;
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
    let report = supervisor.apply_receipt_retention().await.unwrap();
    assert_eq!(report.forgotten, 0);
    assert!(!report.remaining);
  }
}
