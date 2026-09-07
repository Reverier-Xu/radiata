use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use tokio::{
  runtime::Handle,
  sync::{mpsc, oneshot, watch},
  task::{AbortHandle, JoinSet},
};
use tracing::debug;

use crate::{
  Endpoint, Error, ErrorKind, IssuedMergeCredential, ListenerView, LocalNodeView, MergeView,
  NodeConfig, NodeId, Result, ShutdownOutcome, ShutdownReason, StreamTarget, TraceId,
  api::Entropy,
  extension_registry::ExtensionRegistry,
  identity::{
    credential::MergeCredentialIssuer,
    lifecycle::{LocalIdentityContext, ensure_self_binding, open_local_identity},
  },
  packet::{OutboundRequest, RouteRecord, RouteState},
  protocol::offer::node_offer,
  provider::{KeyProvider, StorageFactory},
  runtime::{Control, LifecycleSnapshot, RuntimeClient},
  session::{
    SessionDriver,
    stream::{
      RouteTable, SessionEntry, SessionPacketContext, SessionTable, insert_route, run_outbound,
      run_session,
    },
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

/// Capacity of the node's outbound packet command channel, shared with
/// the builder so both channel ends are created at one construction site.
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
  /// configured attempts are observable at one boundary (SC-G05-P0-22).
  pub(crate) transport: Arc<dyn Transport>,
  pub(crate) sessions: SessionTable,
  pub(crate) routes: RouteTable,
  /// The typed event hub shared with every node handle (G9-03).
  pub(crate) events: Arc<crate::node::EventHub>,
  /// The 32-byte runtime seed drawn once at startup, before identity
  /// provisioning. Deliberately reserved and pinned by the G1 lifecycle
  /// entropy-sequence test; future runtime lanes consume it from here
  /// instead of re-drawing.
  pub(crate) runtime_seed: Option<[u8; 32]>,
}

/// Spawns the anti-entropy membership-sync driver: it pages descriptors
/// and the issuer trust snapshot over every authenticated session on the
/// configured interval and stops on the shutdown signal (SC-G05-P0-22:
/// streams metadata pages; bounded work per tick).
fn spawn_sync_driver(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn crate::api::Entropy>,
  sessions: crate::session::stream::SessionTable, runtime: crate::runtime::RuntimeClient,
  published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>, interval: std::time::Duration,
  shutdown: tokio::sync::watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
  let driver_context = Arc::clone(context);
  let driver_entropy = entropy;
  let driver_sessions = sessions;
  let driver_runtime = runtime;
  let driver_endpoints = published_endpoints;
  let mut driver_shutdown = shutdown;
  tokio::spawn(async move {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sync_cursor = crate::membership::sync::SyncCursor::default();
    let mut resource_cursor = crate::resource::sync::ResourceSyncCursor::default();
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
          if let Err(error) = crate::membership::sync::sync_tick(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &endpoints,
            &mut sync_cursor,
          )
          .await
          {
            // Persistent anti-entropy failure must stay visible in
            // diagnostics; the next tick retries regardless.
            tracing::warn!(kind = ?error.kind(), "membership sync tick failed");
          }
          if let Err(error) = crate::resource::sync::resource_sync_tick(
            &driver_context,
            &driver_entropy,
            &driver_sessions,
            &driver_runtime,
            &mut resource_cursor,
          )
          .await
          {
            tracing::warn!(kind = ?error.kind(), "resource sync tick failed");
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
  // observes configured attempts, SC-G05-P0-22). It is not re-resolved or
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
    // Born-with-cluster (ADR-0009 decision 1): every started node holds
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
  ));
  dependencies
    .extensions
    .register_core_protocol(sync_definition, sync_consumer)?;
  // The core resource sync protocol rides the same authenticated sessions
  // and anti-entropy driver as membership sync (T-G07-04).
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

  let mut supervisor = match Supervisor::new(dependencies, packet_tx) {
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
            // The outcome reaches the caller before teardown begins; the
            // node then shuts down with the active-leave reason.
            let _ = reply.send(Ok(outcome));
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

struct Supervisor {
  dependencies: RuntimeDependencies,
  shutdown_tx: watch::Sender<()>,
  connection_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
  driver: SessionDriver,
  packet: Arc<SessionPacketContext>,
  route_capacity: usize,
  listeners: BTreeMap<
    crate::identity::ListenerId,
    (Endpoint, std::sync::Arc<dyn TransportListener>, AbortHandle),
  >,
  recovery: crate::membership::recovery::RecoveryController,
  recovery_pending: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  published_endpoints: Arc<std::sync::Mutex<Vec<Endpoint>>>,
  // Members this node has ever authenticated a session with: the recovery
  // "known online" set. Recovery restores authenticated paths to exactly
  // these members (edge-loss healing) and never dials strangers, so it
  // cannot add edges beyond the caller-configured topology (SC-G05-P0-26).
  recovery_history: std::collections::BTreeSet<NodeId>,
  // Intentionally disconnected peers: recovery never heals them until an
  // explicit reconnect (a new session to the peer) restores the
  // relationship (SC-G05-P0-26 no-extra-edge).
  recovery_excluded: std::collections::BTreeSet<NodeId>,
  // The anti-entropy driver task: aborted on shutdown so the node's
  // storage handle is released promptly (a restarted node reopening the
  // same factory must not race a lingering driver).
  sync_driver: Option<tokio::task::JoinHandle<()>>,
  trace_sink: crate::routing::trace::TraceSink,
  // Approximate live durable trace-record population, shared with the
  // sink (incremented per successful persistence) and decremented by the
  // retention sweep's removals; zero means sweeps can stay skipped.
  trace_records: std::sync::Arc<std::sync::atomic::AtomicUsize>,
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
    crate::session::forward::FORWARDING_ROUTE_CAPACITY_DEFAULT,
    dependencies.config.trace_metadata_limits().active(),
    dependencies.config.parser_cbor_limits(),
  )
}

impl Supervisor {
  /// Builds the supervisor; provisioning failures return the dependencies
  /// so the caller can still run a clean shutdown instead of panicking.
  fn new(
    dependencies: RuntimeDependencies, packet_tx: mpsc::Sender<crate::packet::OutboundRequest>,
  ) -> std::result::Result<Self, Box<(Error, RuntimeDependencies)>> {
    let Some(context) = dependencies.context.clone() else {
      return Err(Box::new((Error::internal("runtime context"), dependencies)));
    };
    // The negotiation registry is the frozen built-in set plus every
    // caller-registered feature definition (T-G09-07).
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
      connection_tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
      driver,
      packet,
      route_capacity,
      listeners: BTreeMap::new(),
      recovery,
      recovery_pending: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
      published_endpoints,
      recovery_history: std::collections::BTreeSet::new(),
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
    if let Ok(mut handles) = self.connection_tasks.lock() {
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
    let connection_tasks = self.connection_tasks.clone();
    let accept_listener = std::sync::Arc::clone(&listener);
    let insert_listener = std::sync::Arc::clone(&listener);
    let attachment = bound.clone();
    let abort = tasks.spawn(async move {
      tracing::debug!("accept loop started");
      loop {
        // The join hint is computed per accepted connection so the accept
        // path stays fast and never stalls on the credential issuer lock;
        // a hint failure skips this connection only.
        let mut hint = match driver.merge_hint().await {
          Ok(Some(hint)) => Some(hint),
          _ => None,
        };
        if let Some(hint) = hint.as_mut()
          && let Some(spki) = listener.leaf_spki()
        {
          *hint = hint.clone().with_leaf_spki(spki);
        }
        let accepted = accept_listener.accept(hint.as_ref()).await;
        let mut connection = match accepted {
          Ok(connection) => connection,
          // A failed TLS/prelude upgrade must not kill the listener.
          Err(_) => continue,
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
              // streams until the connection closes (ADR-0007).
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
              // instead of being lost to a reset (THR-002 hardening).
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
    self.listeners.insert(
      id.clone(),
      (
        bound.clone(),
        std::sync::Arc::clone(&insert_listener),
        abort,
      ),
    );
    // Publish the bound endpoint so the next anti-entropy tick pages it in
    // the local descriptor (recovery dials peers through published
    // endpoints).
    if let Ok(mut endpoints) = self.published_endpoints.lock()
      && !endpoints.contains(&bound)
    {
      endpoints.push(bound.clone());
    }
    Ok(ListenerView::new(id, bound))
  }

  async fn stop_listener(&mut self, listener: &crate::identity::ListenerId) -> Result<()> {
    let Some((endpoint, listener_handle, abort)) = self.listeners.remove(listener) else {
      return Err(Error::not_found("listener"));
    };
    // Close releases the bound address immediately (a later rebind on the
    // same port works); aborting the accept task alone would not.
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
    // reconnect pinning anchor (THR-002 hardening).
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

  /// The bounded wait for the first leave-record admission
  /// acknowledgement (ADR-0009 decision 3): five seconds, well inside the
  /// fixed authentication deadline's order of magnitude.
  const LEAVE_ACK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

  /// Signs the owner leave record and injects it into every connected
  /// session, waiting at most [`Self::LEAVE_ACK_WAIT`] for the first
  /// current-process admission acknowledgement plus the local flush of the
  /// record bodies (the acknowledgement proves admission; the awaited pump
  /// proves the record left this process before teardown retires the
  /// session).
  async fn announce_leave(&mut self) -> Result<()> {
    let context = self.context()?;
    let record =
      crate::identity::leave::sign_leave_record(&context, &self.dependencies.keys).await?;
    let peers = crate::sync_common::alive_peers(&self.dependencies.sessions)?;
    if peers.is_empty() {
      return Ok(());
    }
    tracing::debug!(peers = peers.len(), "leave announcement starting");
    let protocol = crate::ProtocolTag::parse(crate::membership::sync::MEMBERSHIP_SYNC_PROTOCOL)?;
    let encoded =
      crate::membership::sync::SyncPayload::Leave(minicbor::bytes::ByteVec::from(record.encode()?))
        .encode()?;
    let acked = std::sync::Arc::new(tokio::sync::Notify::new());
    let local = context.identity().node().clone();
    let mut pumps = Vec::new();
    for peer in peers {
      let entry = self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?
        .get(&peer)
        .cloned()
        .filter(|entry| entry.alive());
      // A peer without a live session is skipped: the bounded wait covers
      // the rest, and a lost announcement degrades to a silent leave.
      let Some(entry) = entry else {
        continue;
      };
      let (ack_notify, ack) = tokio::sync::oneshot::channel();
      let trace_id = TraceId::generate(self.dependencies.entropy.as_ref())?;
      let request = crate::packet::OutboundRequest {
        trace_id,
        target: crate::StreamTarget::Exact(peer.clone()),
        load_balancer: None,
        max_hops: 1,
        protocol: protocol.clone(),
        metadata: crate::packet::StreamMetadata::new(),
        body: Box::pin(crate::packet::StaticBody::new(Arc::from(encoded.clone()))),
        internal: true,
        ack_notify,
      };
      // The pump runs as its own task: the acknowledgement channel
      // resolves at admission and the task itself completes after the
      // record body flushed to the session.
      let pump = tokio::spawn(crate::session::stream::run_outbound(
        entry,
        local.clone(),
        request,
        self.dependencies.routes.clone(),
        false,
        None,
        self.dependencies.events.clone(),
      ));
      let acked = std::sync::Arc::clone(&acked);
      tokio::spawn(async move {
        if matches!(ack.await, Ok(Ok(_))) {
          acked.notify_one();
        }
      });
      pumps.push(pump);
    }
    if pumps.is_empty() {
      return Ok(());
    }
    let deadline = tokio::time::Instant::now() + Self::LEAVE_ACK_WAIT;
    let waited = tokio::time::timeout_at(deadline, acked.notified()).await;
    tracing::debug!(
      acknowledged = waited.is_ok(),
      "leave announcement wait completed"
    );
    // Drain the pumps with the remaining budget so the record bodies are
    // flushed before the leave's network teardown retires the sessions.
    for pump in pumps {
      let _ = tokio::time::timeout_at(deadline, pump).await;
    }
    Ok(())
  }

  /// Reconnects to an already-admitted peer with key trust only (G3-04,
  /// THR-002): the member-mode handshake proves both identities over a
  /// fresh transcript and exporter binding without consulting any join
  /// credential, then keeps the session open for packet streams.
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
  /// typed failure only, never a body or a fabricated selected node.
  fn record_route_failure(&self, trace_id: &TraceId, kind: ErrorKind) {
    let _ = insert_route(
      &self.dependencies.routes,
      self.route_capacity,
      RouteRecord::failing(trace_id.clone()),
    );
    if let Ok(mut routes) = self.dependencies.routes.lock()
      && let Some(record) = routes.get_mut(trace_id)
    {
      record.update(RouteState::Failed(kind));
    }
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
  /// descriptors (SC-G06-P0-02). Failure paths still record the terminal
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
    // next-hop policy may route through a connected peer (T-G06-03). The
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
  /// evidence (T-G07-05): expired and excess signed removal records leave
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

  /// Resolves one live downstream session for a routed first hop through
  /// the node's configured next-hop policy. `Ok(None)` means no policy or
  /// no eligible hop exists and the caller fails the route explicitly.
  async fn select_forward_entry(&self, destination: &NodeId) -> Result<Option<SessionEntry>> {
    let Some(tag) = self.dependencies.config.route_policy() else {
      debug!(destination = %destination, "no route policy configured; forward unavailable");
      return Ok(None);
    };
    let Some(policy) = self.dependencies.extensions.next_hop_policy(tag) else {
      tracing::warn!(tag = %tag, "configured route policy is not registered");
      return Ok(None);
    };
    let local = self.packet.local().clone();
    let peers = crate::sync_common::alive_peers(&self.dependencies.sessions)?;
    let view = crate::routing::NextHopView {
      destination,
      local: &local,
      peers: &peers,
    };
    let hop = policy.next_hop(view).await?;
    let entry = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .get(&hop)
      .filter(|entry| entry.alive())
      .cloned();
    debug!(hop = %hop, selected = entry.is_some(), "forward candidate resolved");
    Ok(entry)
  }

  /// Resolves one matching-node target to exactly one eligible destination
  /// (SC-G06-P0-02): the registered load-balancing policy selects among the
  /// incrementally streamed candidates, and core independently validates
  /// the pick against the authoritative descriptors — an unknown, removed,
  /// or nonmatching node fails closed before any frame moves.
  async fn select_matching_destination(
    &self, selector: &crate::Selector, load_balancer: Option<&crate::QualifiedTag>,
  ) -> Result<NodeId> {
    let Some(load_balancer) = load_balancer else {
      return Err(Error::invalid_input("packet load balancer"));
    };
    let policy = self
      .dependencies
      .extensions
      .load_balancer(load_balancer)
      .ok_or_else(|| Error::invalid_input("packet load balancer"))?;
    let snapshot = self.context()?.store().snapshot().await?;
    let reader = crate::routing::StoreCandidateReader::new(snapshot);
    let selected = policy.select(selector, &reader).await?;
    // Authoritative re-validation of the selected destination.
    let descriptor =
      crate::membership::store::read_descriptor_ctx(self.context()?.store(), &selected).await?;
    let Some(descriptor) = descriptor else {
      return Err(Error::not_found("packet destination"));
    };
    if descriptor.removed() || !selector.matches(descriptor.labels()) {
      return Err(Error::not_trusted("packet destination"));
    }
    Ok(selected)
  }

  /// Lazily publishes this node's own signed descriptor (revision 1) so
  /// the public views always expose the local identity, with the
  /// published listener endpoints.
  async fn ensure_self_descriptor(&mut self) -> Result<()> {
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
    )
    .await
  }

  /// One member's public observation from the signed descriptor store and
  /// the session table (SC-G05-P0-23..26).
  async fn member(&mut self, node: NodeId) -> Result<Option<crate::MemberView>> {
    self.ensure_self_descriptor().await?;
    let connected = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .contains_key(&node);
    let Some(descriptor) =
      crate::membership::store::read_descriptor_ctx(self.context()?.store(), &node).await?
    else {
      return Ok(None);
    };
    Ok(Some(crate::membership::member_view(
      &descriptor,
      if connected {
        crate::ConnectivityStatus::Connected
      } else {
        crate::ConnectivityStatus::Reachable
      },
    )?))
  }

  /// Pages the signed descriptors, annotating connectivity from the
  /// session table (SC-G05-P0-23..25).
  async fn page_members(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::MemberPage> {
    self.ensure_self_descriptor().await?;
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Snapshot the connected set under the lock, then release it before
    // any await so the supervisor future stays `Send`.
    let connected: std::collections::BTreeSet<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .keys()
      .cloned()
      .collect();
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      crate::membership::NODE_DESCRIPTOR_NAMESPACE,
    )?);
    let snapshot = self.context()?.store().snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let paged = crate::paging::scan_paged(
      scan.as_mut(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
      |_key, bytes| {
        let descriptor = crate::membership::page::decode_descriptor(bytes)?;
        crate::membership::member_view(
          &descriptor,
          if connected.contains(descriptor.node()) {
            crate::ConnectivityStatus::Connected
          } else {
            crate::ConnectivityStatus::Reachable
          },
        )
        .map(Some)
      },
    )
    .await?;
    let next = paged
      .next
      .map(|key| crate::PageCursor::new(std::sync::Arc::from(key)));
    Ok(crate::MemberPage::new(paged.items, next))
  }

  /// Pages the live resource winners matching one selector (SC-G09-P1-08).
  async fn select_resources(
    &mut self, selector: &crate::Selector, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::ResourcePage> {
    crate::resource::select::select_page_ctx(
      self.context()?.store(),
      selector,
      cursor.as_ref(),
      limit,
    )
    .await
  }

  /// Pages every live resource winner in canonical name order (G9-07):
  /// the reserved type label is always present, so its existence selector
  /// is exactly the unfiltered catalog.
  async fn page_resources(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::ResourcePage> {
    let all = crate::Selector::parse(crate::resource::RESERVED_TYPE_LABEL_KEY)?;
    self.select_resources(&all, cursor, limit).await
  }

  /// Reads the live winner of one named resource (G9-07); a removed or
  /// unknown name reads as absent.
  async fn get_resource(
    &mut self, name: &crate::ResourceName,
  ) -> Result<Option<crate::ResourceView>> {
    let record = crate::resource::store::read_record_ctx(self.context()?.store(), name).await?;
    Ok(match record {
      Some(record) if !record.removed() => Some(crate::resource::select::resource_view(&record)),
      _ => None,
    })
  }

  /// Pages the node's bound listeners in canonical id order (G9-07).
  async fn page_listeners(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::ListenerPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    let entries = self
      .listeners
      .iter()
      .map(|(id, (endpoint, ..))| {
        (
          id.as_str().as_bytes().to_vec(),
          crate::ListenerView::new(id.clone(), endpoint.clone()),
        )
      })
      .collect::<Vec<_>>();
    let paged = crate::paging::page_keys(
      entries.into_iter(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    let next = paged
      .next
      .map(|key| crate::PageCursor::new(std::sync::Arc::from(key)));
    Ok(crate::ListenerPage::new(paged.items, next))
  }

  /// Pages the live authenticated sessions in canonical peer order
  /// (G9-07); selected features resolve their exact definition digests at
  /// query time (SC-G09-P0-23).
  async fn page_sessions(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::SessionPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    let entries: Vec<(Vec<u8>, crate::SessionView)> = {
      let sessions = self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?;
      sessions
        .iter()
        .filter(|(_, entry)| entry.alive())
        .map(|(peer, entry)| {
          let features = entry
            .meta
            .features
            .iter()
            .filter_map(|tag| {
              self
                .dependencies
                .extensions
                .feature_digest(tag)
                .map(|digest| crate::SessionFeatureView::new(tag.clone(), digest))
            })
            .collect();
          (
            peer.as_str().as_bytes().to_vec(),
            crate::SessionView::new(
              entry.meta.id.clone(),
              entry.meta.generation,
              peer.clone(),
              entry.meta.endpoint.clone(),
              features,
            ),
          )
        })
        .collect()
    };
    let paged = crate::paging::page_keys(
      entries.into_iter(),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    let next = paged
      .next
      .map(|key| crate::PageCursor::new(std::sync::Arc::from(key)));
    Ok(crate::SessionPage::new(paged.items, next))
  }

  /// The bounded observability snapshot (T-G10-05, SC-G10-P0-15):
  /// session/listener/task counters, queue totals, route and trace
  /// counters, the pending-transaction count, and metadata-store
  /// availability, captured at the local host wall clock. Counters and
  /// flags only; the snapshot never enumerates a whole population and
  /// carries no identity, address, path, selector, body, or credential
  /// material.
  async fn observability_snapshot(
    &mut self, tasks: &JoinSet<()>,
  ) -> Result<crate::ObservabilitySnapshot> {
    let Some(context) = self.dependencies.context.clone() else {
      return Err(Error::not_ready("observability snapshot"));
    };
    let (sessions, queued_messages, queued_bytes, audit_delta) = {
      let table = self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?;
      let messages = table.values().map(|entry| entry.queued_messages()).sum();
      let bytes = table.values().map(|entry| entry.queued_bytes()).sum();
      let audit: usize = table.values().map(|entry| entry.queue_audit_delta()).sum();
      (table.len(), messages, bytes, audit)
    };
    let open_routes = {
      let routes = self
        .dependencies
        .routes
        .lock()
        .map_err(Error::session_table)?;
      routes.len()
    };
    let connection_tasks = self
      .connection_tasks
      .lock()
      .map_err(Error::session_table)?
      .len();
    let background_tasks = tasks.len() + connection_tasks + usize::from(self.sync_driver.is_some());
    let trace_records = self
      .trace_records
      .load(std::sync::atomic::Ordering::Relaxed);
    let pending_transactions =
      crate::storage::pending::pending_transaction_count(context.store()).await?;
    let storage_available = !context.store().is_blocked()?;
    if queued_messages > 0 || audit_delta != queued_messages {
      tracing::warn!(
        queued_messages,
        queued_bytes,
        audit_reserved_minus_removed = audit_delta,
        "runtime status: queued session frames"
      );
    }
    crate::ObservabilitySnapshot::new(
      std::time::SystemTime::now(),
      sessions,
      self.listeners.len(),
      background_tasks,
      queued_messages,
      queued_bytes,
      open_routes,
      trace_records,
      pending_transactions,
      storage_available,
    )
  }

  /// Pages the authenticated sessions as directed topology edges
  /// (SC-G05-P0-26).
  async fn page_topology(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::TopologyPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Build the edge list entirely under the lock (no await inside), so the
    // guard drops before the future completes.
    let context_node = self.context()?.identity().node().clone();
    let paged = crate::paging::page_keys(
      self
        .dependencies
        .sessions
        .lock()
        .map_err(Error::session_table)?
        .iter()
        .map(|(peer, entry)| {
          (
            peer.as_str().as_bytes().to_vec(),
            crate::TopologyEdgeView::new(
              context_node.clone(),
              peer.clone(),
              entry.alive(),
              std::time::SystemTime::now(),
            ),
          )
        }),
      cursor.as_ref().map(|cursor| cursor.as_bytes()),
      limit,
    );
    let next = paged
      .next
      .map(|key| crate::PageCursor::new(std::sync::Arc::from(key)));
    Ok(crate::TopologyPage::new(paged.items, next))
  }

  /// Pages the public trust observations (SC-G05-P0-25): the exact
  /// NodeId-to-key bindings verified locally, deterministically ordered
  /// and bounded.
  async fn page_trust(
    &mut self, cursor: Option<crate::PageCursor>, limit: usize,
  ) -> Result<crate::TrustPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Trust paging is offset-based (the trust store scans an ordered
    // namespace in slices) while the other views keyset-paginate. The
    // encoding still lives behind the opaque `PageCursor`, and a cursor
    // that does not decode exactly fails closed instead of restarting
    // the page at offset zero.
    let offset = match cursor.as_ref() {
      None => 0,
      Some(cursor) => std::str::from_utf8(cursor.as_bytes())
        .map_err(|_| Error::invalid_input("trust page cursor"))?
        .parse::<usize>()
        .map_err(|_| Error::invalid_input("trust page cursor"))?,
    };
    let context = self.context()?;
    let observations =
      crate::identity::trust::store::paged_trust_ctx(context.store(), offset, limit).await?;
    let mut items = Vec::with_capacity(observations.bindings().len());
    for binding in observations.bindings() {
      // A locally revoked binding reports its exact status; the binding
      // itself is never erased (ADR-0006: revoke is an authorization
      // boundary, not content erasure).
      let status = match crate::identity::revocation::revoked_key_ctx(
        context.store(),
        binding.node(),
      )
      .await?
      {
        Some(revoked) if &revoked == binding.key() => crate::TrustStatus::Revoked,
        _ => crate::TrustStatus::Trusted,
      };
      items.push(crate::TrustedIdentityView::new(
        binding.node().clone(),
        binding.key().clone(),
        status,
      ));
    }
    let next = observations
      .next()
      .map(|next| crate::PageCursor::new(std::sync::Arc::from(next.to_string().into_bytes())));
    Ok(crate::TrustPage::new(items, next))
  }

  /// Forces one bounded immediate recovery cycle (SC-G05-P0-19) and
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

  /// Closes the authenticated session to one peer (SC-G05-P0-22 partition
  /// simulation) and removes it from the recovery known-online set: an
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
  /// the updated member view is returned (ADR-0007 owner records).
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
    crate::membership::member_view(&updated, crate::ConnectivityStatus::Connected)
  }

  /// Commits one resource write intent as a signed candidate record
  /// (`PutResource`, T-G09-03): the supervisor stamps the host wall-clock
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
      let timestamp_millis = crate::time::now_millis();
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

  /// Creates signed removal evidence for one resource (`RemoveResource`,
  /// T-G09-05): only when the stored winner still equals the caller's
  /// observed version exactly and the removal strictly wins the tuple.
  /// The removal record carries the winner's labels (removal evidence
  /// stays comparable), and the operation touches core metadata only —
  /// the resource URI is never followed and no caller object is deleted
  /// (SC-G09-P0-15..17).
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
      let timestamp_millis = crate::time::now_millis();
      // A synced record may legally carry the maximum rank; a saturated
      // register cannot host a further removal and fails closed instead of
      // wrapping the rank order.
      let removal_rank = stored
        .removal_rank()
        .checked_add(1)
        .ok_or_else(|| Error::conflict("resource removal rank"))?;
      let body = crate::resource::ResourceRecordV1::encode_signed_body(
        &name,
        stored.resource_type(),
        stored.resource_uri(),
        stored.labels(),
        timestamp_millis,
        &writer,
        removal_rank,
        true,
      )?;
      let signature = self
        .dependencies
        .keys
        .sign(
          context.identity().handle(),
          &crate::identity::signature::signature_message(
            crate::resource::RESOURCE_RECORD_V1_DOMAIN,
            &body,
          ),
        )
        .await?;
      let removal = crate::resource::ResourceRecordV1::seal(
        name.clone(),
        stored.resource_type().clone(),
        stored.resource_uri().clone(),
        stored.labels().clone(),
        timestamp_millis,
        writer.clone(),
        removal_rank,
        true,
        signature,
      )?;
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
  /// authority (`RevokeNode`, T-G09-04): the revocation commits
  /// conditionally first, then the revoked identity's sessions close and
  /// its new sessions, admissions, and operations are rejected. Stored
  /// metadata is never erased or reinterpreted.
  /// Issues one convergent issuer-signed cleanup tombstone (T-G11-08):
  /// the record persists locally and converges through the sync plane.
  async fn cleanup_node(&mut self, subject: NodeId) -> Result<()> {
    self.require_unblocked()?;
    let context = self.context()?;
    if &subject == context.identity().node() {
      // Self-removal is the explicit leave path (ADR-0009 decision 3),
      // never a self-cleanup.
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
    Ok(())
  }

  /// Clears the local revocation record for one subject (T-G11-08):
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

  /// Starts a new checkpoint GC epoch at the current wall clock
  /// (T-G11-09, ADR-0009 decision 5). The watermark converges through the
  /// sync plane; collected tombstones are swept after sync rounds.
  async fn issue_cleanup_checkpoint(&mut self) -> Result<u64> {
    self.require_unblocked()?;
    let context = self.context()?;
    crate::identity::cleanup::issue_checkpoint_ctx(&context, self.dependencies.entropy.as_ref())
      .await
  }

  async fn revoke_node(
    &mut self, subject: NodeId, expected_key: crate::PublicKey,
  ) -> Result<crate::RevokeOutcome> {
    self.require_unblocked()?;
    let context = self.context()?;
    let local = context.identity().node();
    if &subject == local {
      // Self-removal is the explicit leave path (ADR-0009 decision 3),
      // never a self-revoke.
      return Err(Error::invalid_input("revoke subject"));
    }
    // The tombstone is issuer-signed and converges through the sync plane
    // (ADR-0009 decision 6): any member may expel a compromised binding
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

  /// Executes one acknowledged active leave (`LeaveCluster`, T-G09-06):
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

    // ADR-0009 decision 3: announce the owner-signed leave record to the
    // connected sessions and wait a bounded time for the first
    // current-process admission acknowledgement; a timeout degrades to a
    // silent leave, which the cleanup path covers. The announcement drives
    // the packet pump directly (spawned stream tasks carry it), so the
    // bounded wait never stalls the control loop.
    self.announce_leave().await?;

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

    let (former, replacement) = crate::identity::leave::execute(
      &context,
      &self.dependencies.keys,
      self.dependencies.entropy.as_ref(),
    )
    .await?;
    self.dependencies.events.emit(crate::IdentityReplaced::new(
      former.clone(),
      replacement.clone(),
    ));
    Ok(crate::LeaveOutcome::new(former, replacement))
  }

  /// The public recovery observation: whether every known online member
  /// has an authenticated path, how many members remain unreachable, and
  /// the next scheduled attempt.
  fn recovery_view(&self) -> crate::RecoveryView {
    let now = crate::time::now_seconds();
    crate::RecoveryView::new(
      self.recovery.state() == crate::membership::recovery::RecoveryState::Connected,
      self.recovery.pending_count(),
      self
        .recovery
        .next_attempt_seconds(now)
        .map(crate::time::from_seconds),
    )
  }

  /// One recovery observation tick: feed the controller the known-online
  /// set (members this node ever authenticated a session with) and the
  /// current direct sessions, then dial unreachable members whose
  /// endpoints are published, through the configured bounded fan-out
  /// (SC-G05-P0-14/17/22: recovery restores authenticated path
  /// connectivity to known members and quiesces; it never dials strangers
  /// or the local node, so it cannot add edges beyond the configured
  /// topology).
  async fn recovery_tick(&mut self) -> Result<()> {
    let before = self.recovery_view();
    let result = self.recovery_tick_inner().await;
    let after = self.recovery_view();
    if after != before {
      self
        .dependencies
        .events
        .emit(crate::RecoveryChanged::new(after));
    }
    result
  }

  async fn recovery_tick_inner(&mut self) -> Result<()> {
    // Finished connection tasks keep their JoinHandles until reaped, so a
    // long-lived listener would otherwise grow one dead handle per ever
    // accepted connection and inflate the observability counts. Reaping
    // each tick keeps the vec and the counts live-work only; abort() on a
    // finished handle is a no-op, so shutdown semantics are unchanged.
    if let Ok(mut handles) = self.connection_tasks.lock() {
      handles.retain(|handle| !handle.is_finished());
    }
    let direct: std::collections::BTreeSet<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    for peer in &direct {
      self.recovery_history.insert(peer.clone());
    }
    let online = self.recovery_history.clone();
    let now = crate::time::now_seconds();
    self.recovery.observe(&online, &direct);
    if self.recovery.state() != crate::membership::recovery::RecoveryState::Recovering
      || !self.recovery.due(now)
      || {
        self
          .recovery_pending
          .load(std::sync::atomic::Ordering::Relaxed)
          >= self.dependencies.config.recovery().fan_out().max(1)
      }
    {
      return Ok(());
    }
    // Candidates are unreachable known members with a published endpoint
    // from their signed descriptor; reachability stays distinct from the
    // active topology and recovery never dials strangers (SC-G05-P0-11/18).
    let bindings = crate::identity::trust::store::trusted_bindings(self.context()?.store()).await?;
    // Left and cleaned nodes are excluded from recovery dialing
    // (ADR-0009 decisions 3-4).
    let mut excluded = crate::identity::cleanup::cleaned_nodes_ctx(self.context()?.store()).await?;
    excluded.append(&mut crate::identity::leave::left_nodes_ctx(self.context()?.store()).await?);
    // One snapshot for the whole cycle: per-member descriptor reads must
    // not pay one snapshot acquisition each (a 1,024-member recovery tick
    // would otherwise acquire 1,024 snapshots).
    let snapshot = self.context()?.store().snapshot().await?;
    let mut candidates = std::collections::BTreeSet::new();
    for member in online.difference(&direct) {
      if self.recovery_excluded.contains(member) || excluded.contains(member) {
        continue;
      }
      // Only known members (a durable binding exists) are dialled.
      if !bindings.contains_key(member) {
        continue;
      }
      let descriptor =
        crate::membership::store::read_descriptor_snapshot(snapshot.as_ref(), member).await;
      if let Ok(Some(descriptor)) = descriptor
        && let Some(endpoint) = descriptor.endpoints().first()
      {
        candidates.insert((member.clone(), endpoint.clone()));
      }
    }
    let step = self.recovery.next_step(
      now,
      &candidates
        .iter()
        .map(|(member, _)| member.clone())
        .collect(),
    );
    for (member, endpoint) in candidates {
      if step.targets.contains(&member) {
        // Recovery dials run in a detached task so the supervisor select
        // loop never blocks on a handshake (each can take the full
        // authentication deadline); the result is reconciled by the next
        // observation tick.
        self
          .recovery_pending
          .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let receiver = endpoint.clone();
        let peer = member.clone();
        let driver = self.driver.clone();
        let sessions = self.dependencies.sessions.clone();
        let packet = self.packet.clone();
        let shutdown = self.shutdown_tx.subscribe();
        let pending = std::sync::Arc::clone(&self.recovery_pending);
        let transport = Arc::clone(&self.dependencies.transport);
        tokio::spawn(async move {
          let _ = dial_member(
            transport, driver, sessions, packet, shutdown, receiver, &peer,
          )
          .await;
          // Release the in-flight slot when the dial resolves, so recovery
          // stays alive across repeated partition waves (the counter bounds
          // in-flight dials, not lifetime volume).
          pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
      }
    }
    Ok(())
  }

  async fn local_node(&mut self) -> Result<LocalNodeView> {
    let context = self.context()?;
    Ok(LocalNodeView::new(
      context.identity().node().clone(),
      context.identity().public_key().clone(),
    ))
  }

  fn context(&self) -> Result<Arc<LocalIdentityContext>> {
    self
      .dependencies
      .context
      .clone()
      .ok_or_else(|| Error::internal("runtime context"))
  }

  /// Blocks admission-sensitive operations while the metadata store is
  /// frozen on an indeterminate outcome (ADR-0007, THR-015): credential
  /// reuse, rotation, signing, and new networking stay unavailable until
  /// an authoritative reopen reconciles the exact transaction or proves
  /// absence. Established authenticated sessions are unaffected.
  fn require_unblocked(&self) -> Result<()> {
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
async fn dial_member(
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
