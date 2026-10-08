//! The migrated mutating verbs: caller-side admission plus the effect
//! the task manager reconciles.
//!
//! Admission is the synchronous half — pure validation, then the task
//! submission — and never performs IO. The effect is the verb body that
//! used to run inline on the supervisor's select loop, moved here
//! unchanged: same durable writes, same events, same audit lines, same
//! typed errors. Migrating a verb therefore moves code and changes only
//! *where* its failures surface (the task's `wait` instead of the verb
//! call).
//!
//! [`OperationDeps`] is the node-shared handle bundle every effect reads.
//! It is built once per incarnation in `spawn_runtime` and owned by the
//! task manager, never by a caller: a node handle keeps only the *submit*
//! half, so a caller holding a handle never keeps the metadata store's
//! exclusive lock alive past node shutdown.

use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use super::{
  recovery::Departed,
  supervisor::{
    ListenerRegistry, RuntimeDependencies, connect_with_deadline, dial_member,
    keep_outbound_session,
  },
  task_manager::{EffectOutcome, TaskClient, TaskEffect, TaskPayload, TaskSpec},
};
use crate::{
  Endpoint, Error, MergeView, NodeConfig, NodeId, Result, StoreRevision, Task, TaskKind,
  TaskOutput,
  api::Entropy,
  extension_registry::ExtensionRegistry,
  identity::{credential::MergeCredential, lifecycle::LocalIdentityContext},
  node::{EventHub, MemberRevisionSignal},
  session::{
    SessionDriver,
    stream::{SessionPacketContext, SessionTable, retire_session},
  },
  transport::registry::TransportTrust,
};

/// The node's tracked connection tasks: the kept session tasks of the
/// completed joins and member dials plus the accept-side drain tasks. The
/// shutdown path aborts them and the recovery tick reaps finished ones.
pub(crate) type ConnectionTasks = Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>;

/// The per-incarnation effect planes: every collaborator the migrated
/// verb effects read. Built once by [`OperationDeps::new`]; every field is
/// a cheap clone of state the node already owns, so the bundle adds owners
/// but never a second truth.
pub(crate) struct EffectPlanes {
  /// The opened identity context: the metadata store and the local
  /// identity of every effect.
  pub(crate) context: Arc<LocalIdentityContext>,
  /// The calibrated node configuration (dial deadline, admission limits).
  pub(crate) config: NodeConfig,
  /// The node's entropy source (the effects' draws).
  #[allow(dead_code)] // read by the identity-effect stage; that migration lands next
  pub(crate) entropy: Arc<dyn Entropy>,
  /// The session driver shared with the supervisor and the recovery
  /// plane: its credential issuer and leaf-SPKI anchors are process-wide.
  pub(crate) driver: SessionDriver,
  /// The node-shared packet context every kept session routes through.
  pub(crate) packet: Arc<SessionPacketContext>,
  /// The live authenticated sessions.
  pub(crate) sessions: SessionTable,
  /// The in-memory route records the leave announcement dispatches over.
  #[allow(dead_code)] // read by the leave-effect stage; that migration lands next
  pub(crate) routes: crate::routing::RouteTable,
  /// The graceful-shutdown signal every kept session observes.
  pub(crate) shutdown: watch::Sender<()>,
  /// The tracked connection tasks, aborted at node shutdown.
  pub(crate) connection_tasks: ConnectionTasks,
  /// The member-set revision signal, bumped one-to-one with the member
  /// events the identity effects emit.
  #[allow(dead_code)] // bumped by the identity-effect stage; that migration lands next
  pub(crate) member_revision: MemberRevisionSignal,
  /// The leave-plane applied-receipt signal the announcement parks on.
  #[allow(dead_code)] // read by the leave-effect stage; that migration lands next
  pub(crate) leave_applied: crate::membership::sync::LeaveAppliedSignal,
  /// The node's bound listeners: the listen/stop effects mutate the same
  /// registry the supervisor's pages read.
  #[allow(dead_code)] // torn down by the leave-effect stage; that migration lands next
  pub(crate) listeners: ListenerRegistry,
  /// The advertised endpoints the listeners publish (never the bound
  /// wildcard sockets).
  #[allow(dead_code)] // unpublished by the leave-effect stage; that migration lands next
  pub(crate) published_endpoints: Arc<Mutex<Vec<Endpoint>>>,
  /// The memoized departed-members exclusion set, shared with the
  /// supervisor's own pages: the checkpoint guard reads the same cache.
  #[allow(dead_code)] // read by the identity-effect stage; that migration lands next
  pub(crate) exclusion_cache: Arc<Mutex<Option<(StoreRevision, Departed)>>>,
}

/// The node-shared operation handles behind every migrated mutating verb,
/// read by the manager (bookkeeping) and the verb effects (the planes).
pub(crate) struct OperationDeps {
  /// The typed event hub: the manager's phase transitions and every
  /// effect's events ride the one hub the handles subscribe to.
  events: Arc<EventHub>,
  /// The node-local extension registry: the manager's hook source and
  /// the registered transports the admissions resolve against.
  extensions: Arc<ExtensionRegistry>,
  /// The effect planes. `None` only on the task manager's unit-test
  /// double ([`OperationDeps::test_double`]), whose scripted effects read
  /// nothing; every production incarnation carries them.
  planes: Option<EffectPlanes>,
}

impl OperationDeps {
  /// Builds the shared operation handles from the runtime dependencies
  /// plus the handles the supervisor shares with its own state (the
  /// session driver, the packet context, and the shutdown signal).
  pub(super) fn new(
    dependencies: &RuntimeDependencies, driver: SessionDriver, packet: Arc<SessionPacketContext>,
    shutdown: watch::Sender<()>,
  ) -> Result<Self> {
    Ok(Self {
      events: Arc::clone(&dependencies.events),
      extensions: Arc::clone(&dependencies.extensions),
      planes: Some(EffectPlanes {
        context: dependencies
          .context
          .clone()
          .ok_or_else(|| Error::internal("runtime context"))?,
        config: dependencies.config.clone(),
        entropy: Arc::clone(&dependencies.entropy),
        driver,
        packet,
        sessions: dependencies.sessions.clone(),
        routes: dependencies.routes.clone(),
        shutdown,
        connection_tasks: Arc::clone(&dependencies.connection_tasks),
        member_revision: dependencies.member_revision.clone(),
        leave_applied: dependencies.leave_applied.clone(),
        listeners: dependencies.listeners.clone(),
        published_endpoints: Arc::default(),
        exclusion_cache: Arc::new(Mutex::new(None)),
      }),
    })
  }

  /// A manager-test double: the manager's own bookkeeping collaborators
  /// are real (the event hub and the extension registry), the effect
  /// planes are absent because a scripted test effect reads nothing.
  #[cfg(test)]
  pub(crate) fn test_double(events: Arc<EventHub>, extensions: Arc<ExtensionRegistry>) -> Self {
    Self {
      events,
      extensions,
      planes: None,
    }
  }

  /// The typed event hub.
  pub(super) fn events(&self) -> &Arc<EventHub> {
    &self.events
  }

  /// The node-local extension registry.
  pub(super) fn extensions(&self) -> &Arc<ExtensionRegistry> {
    &self.extensions
  }

  /// The process-wide session driver (one credential issuer, one
  /// leaf-SPKI anchor table). Production incarnations always carry it.
  pub(super) fn driver(&self) -> Result<&SessionDriver> {
    Ok(&self.planes()?.driver)
  }

  /// The node-shared packet context every kept session routes through.
  /// Production incarnations always carry it.
  pub(super) fn packet(&self) -> Result<&Arc<SessionPacketContext>> {
    Ok(&self.planes()?.packet)
  }

  /// The graceful-shutdown signal every kept session observes.
  /// Production incarnations always carry it.
  pub(super) fn shutdown(&self) -> Result<&watch::Sender<()>> {
    Ok(&self.planes()?.shutdown)
  }

  /// The effect planes: every production incarnation carries them; the
  /// typed internal error is unreachable there.
  pub(super) fn planes(&self) -> Result<&EffectPlanes> {
    self
      .planes
      .as_ref()
      .ok_or_else(|| Error::internal("runtime operations"))
  }
}

/// Admits one join: the receiver's listen endpoint plus the live join
/// credential it issued. The effect dials, merges, and keeps the session
/// open.
///
/// Admission-time failures are the pure shape checks — the transport
/// selector must resolve in the registry. The dial, the merge handshake,
/// and the frozen-store refusal are effect-time and surface on the task's
/// [`Task::wait`].
pub(crate) async fn join(
  extensions: &ExtensionRegistry, tasks: &TaskClient, receiver: Endpoint,
  credential: MergeCredential,
) -> Result<Task<MergeView>> {
  let transport = extensions.resolve_transport(&receiver.selector())?;
  // The credential is deliberately not `Clone`; the effect needs it on
  // every retry attempt, so it is shared rather than copied.
  let credential = Arc::new(credential);
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let transport = Arc::clone(&transport);
    let receiver = receiver.clone();
    let credential = Arc::clone(&credential);
    Box::pin(async move { reconcile_join(deps, transport, receiver, credential).await })
  });
  let id = tasks
    .submit(TaskSpec::new(TaskKind::Join, TaskPayload::None), effect)
    .await?;
  Ok(Task::from_parts(id, TaskKind::Join, tasks.observer.clone()))
}

/// Admits one member re-connect: key trust only, no join credential. The
/// effect dials and keeps the session open.
///
/// Admission-time failures are the pure shape checks — the transport
/// selector must resolve in the registry. The dial and member-mode
/// handshake failures are effect-time and surface on the task's
/// [`Task::wait`], with the documented dial contract's retry
/// classification.
pub(crate) async fn connect(
  extensions: &ExtensionRegistry, tasks: &TaskClient, receiver: Endpoint, peer: NodeId,
) -> Result<Task<NodeId>> {
  let transport = extensions.resolve_transport(&receiver.selector())?;
  let payload = TaskPayload::Peer(peer.clone());
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let transport = Arc::clone(&transport);
    let receiver = receiver.clone();
    let peer = peer.clone();
    Box::pin(async move { reconcile_connect(deps, transport, receiver, peer).await })
  });
  let id = tasks
    .submit(TaskSpec::new(TaskKind::Connect, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::Connect,
    tasks.observer.clone(),
  ))
}

/// Admits one session teardown for one peer. The effect closes the
/// session now; the peer's membership is untouched.
///
/// Admission keeps only the shutdown gate; the teardown itself is
/// idempotent (a peer with no session is not an error), so the task's
/// [`Task::wait`] fails only with a session-table failure.
pub(crate) async fn disconnect(tasks: &TaskClient, peer: NodeId) -> Result<Task<()>> {
  let payload = TaskPayload::Peer(peer.clone());
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let peer = peer.clone();
    Box::pin(async move { reconcile_disconnect(deps, peer).await })
  });
  let id = tasks
    .submit(TaskSpec::new(TaskKind::Disconnect, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::Disconnect,
    tasks.observer.clone(),
  ))
}

/// The join effect: dial under the configured deadline, merge with the
/// presented credential, anchor the peer's leaf SPKI, and keep the
/// session open.
async fn reconcile_join(
  deps: Arc<OperationDeps>, transport: Arc<dyn crate::transport::registry::Transport>,
  receiver: Endpoint, credential: Arc<MergeCredential>,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  crate::audit::dial_started(&receiver.to_string(), false);
  let mut connection = connect_with_deadline(
    &transport,
    receiver.clone(),
    TransportTrust::for_dial(&receiver.selector(), None),
    planes.config.dial_deadline(),
  )
  .await?;
  let hint = connection
    .merge_hint()
    .cloned()
    .ok_or_else(|| Error::authentication_failed("join hint"))?;
  let secret = crate::protocol::credential::CredentialSecret::from_credential(&credential);
  let (session, view) = planes.driver.merge(&mut connection, &hint, secret).await?;
  // Remember the peer's leaf SPKI from the merge as the member-mode
  // reconnect pinning anchor (hardening).
  let peer = session.peer().clone();
  crate::audit::dial_settled(peer.as_str(), false, true);
  if !hint.leaf_spki().is_empty() {
    planes
      .driver
      .record_peer_spki(&peer, hint.leaf_spki().to_vec());
  }
  // Keep the merge session open so both sides can stream packets over it.
  // The view returns only after the session table registers the entry, so
  // the caller's first packet cannot race registration.
  let connection_tasks = Arc::clone(&planes.connection_tasks);
  keep_outbound_session(
    connection,
    session,
    Arc::clone(&planes.packet),
    planes.sessions.clone(),
    planes.shutdown.subscribe(),
    receiver,
    false,
    |session_task| track_connection_task(&connection_tasks, session_task),
  )
  .await?;
  Ok(EffectOutcome::new(TaskOutput::Join(view)))
}

/// The member reconnect effect: one key-trust dial that keeps the session
/// open.
async fn reconcile_connect(
  deps: Arc<OperationDeps>, transport: Arc<dyn crate::transport::registry::Transport>,
  receiver: Endpoint, peer: NodeId,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let authenticated = dial_member(
    transport,
    planes.driver.clone(),
    planes.sessions.clone(),
    Arc::clone(&planes.packet),
    planes.shutdown.subscribe(),
    receiver,
    &peer,
    false,
    planes.config.dial_deadline(),
  )
  .await?;
  Ok(EffectOutcome::new(TaskOutput::Connect(authenticated)))
}

/// The disconnect effect: tear the peer's session down and emit the
/// session change.
async fn reconcile_disconnect(deps: Arc<OperationDeps>, peer: NodeId) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  retire_session(&planes.sessions, &peer)?;
  deps.events().emit(crate::SessionChanged::new(peer));
  Ok(EffectOutcome::new(TaskOutput::Disconnect(())))
}

/// Spawns one kept session task into the node's tracked connection tasks:
/// the recovery tick reaps finished handles and the shutdown path aborts
/// the live ones.
fn track_connection_task(
  tasks: &ConnectionTasks, task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) {
  let handle = tokio::spawn(task);
  if let Ok(mut tasks) = tasks.lock() {
    tasks.push(handle);
  }
}
