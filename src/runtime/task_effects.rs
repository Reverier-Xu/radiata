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
  recovery::departed_exclusions,
  supervisor::{
    ListenerRegistry, RuntimeDependencies, connect_with_deadline, dial_member,
    keep_outbound_session,
  },
  task_manager::{EffectOutcome, TaskClient, TaskEffect, TaskPayload, TaskSpec},
};
use crate::{
  Endpoint, Error, MergeView, NodeConfig, NodeId, PublicKey, Result, RevokeOutcome, Task, TaskKind,
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
  pub(crate) entropy: Arc<dyn Entropy>,
  /// The session driver shared with the supervisor and the recovery
  /// plane: its credential issuer and leaf-SPKI anchors are process-wide.
  pub(crate) driver: SessionDriver,
  /// The node-shared packet context every kept session routes through.
  pub(crate) packet: Arc<SessionPacketContext>,
  /// The live authenticated sessions.
  pub(crate) sessions: SessionTable,
  /// The in-memory route records the leave announcement dispatches over.
  pub(crate) routes: crate::routing::RouteTable,
  /// The graceful-shutdown signal every kept session observes.
  pub(crate) shutdown: watch::Sender<()>,
  /// The tracked connection tasks: kept session pumps, in-flight dials,
  /// the graceful consumer drains, and the lazy local-descriptor
  /// publication task. The recovery tick reaps finished handles;
  /// shutdown drains them inside its bounded cooperative window and
  /// aborts only the stragglers.
  pub(crate) connection_tasks: ConnectionTasks,
  /// The member-set revision signal, bumped one-to-one with the member
  /// events the identity effects emit.
  pub(crate) member_revision: MemberRevisionSignal,
  /// The leave-plane applied-receipt signal the announcement parks on.
  pub(crate) leave_applied: crate::membership::sync::LeaveAppliedSignal,
  /// The node's bound listeners: the listen/stop effects mutate the same
  /// registry the supervisor's pages read.
  pub(crate) listeners: ListenerRegistry,
  /// The advertised endpoints the listeners publish (never the bound
  /// wildcard sockets).
  pub(crate) published_endpoints: Arc<Mutex<Vec<Endpoint>>>,
  /// The local descriptor's lazy-publication gate: the endpoint set the
  /// descriptor was last successfully ensured against plus the
  /// single-flight flag bounding the read views' kicked publications at
  /// one task (see [`kick_self_descriptor_publication`]; remaining
  /// items 2026-10-10, P2-9). Module-private: only this module's ensure
  /// and kick touch it.
  descriptor_publication: DescriptorPublication,
  /// The memoized departed-members exclusion set, shared with the
  /// supervisor's own pages: the checkpoint guard reads the same cache.
  pub(crate) exclusion_cache: super::recovery::ExclusionCache,
  /// The writer's monotonic resource-write stamp clock, shared by the
  /// put and removal effects (see
  /// [`super::resources::issue_write_stamp`]).
  pub(crate) resource_write_clock: super::resources::ResourceWriteClock,
  /// The recovery controller, shared with the supervisor's recovery
  /// tick: the start-recovery effect forces the immediate cycle on the
  /// one controller instance the tick observes (one truth per
  /// incarnation).
  pub(crate) recovery: Arc<Mutex<crate::membership::recovery::RecoveryController>>,
  /// Requests for one immediate anti-entropy round, forwarded to the
  /// sync driver (the cursor owner) by the sync-round effect.
  pub(crate) sync_round_requests: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<()>>,
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
        descriptor_publication: DescriptorPublication::default(),
        exclusion_cache: Arc::new(Mutex::new(None)),
        resource_write_clock: Arc::default(),
        recovery: Arc::new(Mutex::new(
          crate::membership::recovery::RecoveryController::new(
            crate::membership::recovery::RecoveryPolicy::new(
              dependencies.config.recovery().fan_out(),
              dependencies.config.recovery().initial_backoff_seconds(),
              dependencies.config.recovery().maximum_backoff_seconds(),
            ),
          ),
        )),
        sync_round_requests: dependencies.sync_round_requests.clone(),
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
  // The endpoint rides the payload, not just the effect closure: a
  // coalesced submission joins the in-flight dial only when the whole
  // intent (endpoint and peer) equals the in-flight one — a different
  // endpoint for the same peer conflicts instead of silently riding a
  // dial to the old endpoint.
  let payload = TaskPayload::PeerDial {
    endpoint: receiver.clone(),
    peer: peer.clone(),
  };
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
  // reconnect pinning anchor for THIS endpoint (each listener of the
  // peer binds its own ephemeral leaf; other targets stay unpinned and
  // dial under merge trust — hardening, the identity proof is the
  // authority).
  let peer = session.peer().clone();
  crate::audit::dial_settled(peer.as_str(), false, true);
  if !hint.leaf_spki().is_empty() {
    planes
      .driver
      .record_peer_spki(&peer, &receiver, hint.leaf_spki().to_vec());
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
    Arc::clone(&planes.connection_tasks),
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

/// Spawns one kept session task into the node's tracked connection
/// tasks: the recovery tick reaps finished handles and the shutdown path
/// awaits the live ones inside its bounded cooperative window, aborting
/// only the stragglers. Shared by the join effect and `dial_member`, so
/// every kept outbound session pump — join, member connect, recovery,
/// and maintenance dial alike — has the one ownership path.
pub(super) fn track_connection_task(
  tasks: &ConnectionTasks, task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) {
  let handle = tokio::spawn(task);
  if let Ok(mut tasks) = tasks.lock() {
    tasks.push(handle);
  }
}

// -- identity, trust, and cleanup verbs ---------------------------------

/// Admits one revocation of an exact subject binding. The effect signs and
/// commits the tombstone, closes the subject's sessions, and announces the
/// revocation.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal, the self-subject refusal, and the
/// expected-key pin are effect-time and surface on the task's
/// [`Task::wait`].
pub(crate) async fn revoke(
  tasks: &TaskClient, subject: NodeId, expected_key: PublicKey,
) -> Result<Task<RevokeOutcome>> {
  // The pinned key rides the payload, not just the effect closure: a
  // coalesced submission joins the in-flight revoke only when it pins
  // the same key — a different key for the same subject conflicts
  // instead of silently riding a revoke whose effect checks only the
  // first caller's comparand.
  let payload = TaskPayload::Revoke {
    subject: subject.clone(),
    expected_key: expected_key.clone(),
  };
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let subject = subject.clone();
    let expected_key = expected_key.clone();
    Box::pin(async move { reconcile_revoke(deps, subject, expected_key).await })
  });
  let id = tasks
    .submit(TaskSpec::new(TaskKind::Revoke, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::Revoke,
    tasks.observer.clone(),
  ))
}

/// Admits one local revocation-record purge. The effect deletes the
/// record; the purge is local-only and idempotent.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal is effect-time and surfaces on the
/// task's [`Task::wait`].
pub(crate) async fn purge_revocation(tasks: &TaskClient, subject: NodeId) -> Result<Task<()>> {
  let payload = TaskPayload::Peer(subject.clone());
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let subject = subject.clone();
    Box::pin(async move { reconcile_purge_revocation(deps, subject).await })
  });
  let id = tasks
    .submit(TaskSpec::new(TaskKind::PurgeRevocation, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::PurgeRevocation,
    tasks.observer.clone(),
  ))
}

/// Admits one convergent issuer-signed cleanup tombstone for a
/// decommissioned node. The effect signs and persists the record.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal and the self-subject refusal are
/// effect-time and surface on the task's [`Task::wait`].
pub(crate) async fn cleanup(tasks: &TaskClient, subject: NodeId) -> Result<Task<()>> {
  let payload = TaskPayload::Peer(subject.clone());
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let subject = subject.clone();
    Box::pin(async move { reconcile_cleanup(deps, subject).await })
  });
  let id = tasks
    .submit(TaskSpec::new(TaskKind::Cleanup, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::Cleanup,
    tasks.observer.clone(),
  ))
}

/// Admits one cleanup checkpoint GC epoch. The effect enforces the
/// convergence precondition (every non-terminal member connected) and
/// persists the watermark.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal and the member-connectivity
/// precondition are effect-time and surface on the task's [`Task::wait`]
/// (the precondition as [`crate::ErrorKind::NotReady`]).
pub(crate) async fn issue_cleanup_checkpoint(tasks: &TaskClient) -> Result<Task<u64>> {
  let effect: TaskEffect = Arc::new(|deps, _attempt| {
    Box::pin(async move { reconcile_issue_cleanup_checkpoint(deps).await })
  });
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::IssueCleanupCheckpoint, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::IssueCleanupCheckpoint,
    tasks.observer.clone(),
  ))
}

/// Admits one operator-acknowledged frozen-journal resolution. The effect
/// re-checks the durable evidence and resolves the frozen pending journal
/// in one atomic transaction.
///
/// Admission-time failures are the pure shape checks (a stopped node, a
/// missing acknowledgement marker); the store's evidence verdict on the
/// declaration is effect-time and surfaces on the task's [`Task::wait`].
pub(crate) async fn resolve_frozen_journal(
  tasks: &TaskClient, acknowledgement: crate::DeclareInterruptedTransactionUncommitted,
) -> Result<Task<()>> {
  // The acknowledgement is a proof-of-construction marker: only the
  // deliberate constructor produces it.
  if !acknowledgement.is_acknowledged() {
    return Err(Error::invalid_input("frozen journal acknowledgement"));
  }
  let effect: TaskEffect = Arc::new(|deps, _attempt| {
    Box::pin(async move { reconcile_resolve_frozen_journal(deps).await })
  });
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::ResolveFrozenJournal, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::ResolveFrozenJournal,
    tasks.observer.clone(),
  ))
}

/// The revoke effect: sign the tombstone against the pinned expected key,
/// commit it, then close the exact identity's sessions and announce the
/// revocation (skipped when the binding was already revoked — the record
/// is permanent until an explicit local purge).
async fn reconcile_revoke(
  deps: Arc<OperationDeps>, subject: NodeId, expected_key: PublicKey,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let context = &planes.context;
  if &subject == context.identity().node() {
    // Self-removal is the explicit leave path, never a self-revoke.
    return Err(Error::invalid_input("revoke subject"));
  }
  // The tombstone is issuer-signed and converges through the sync plane:
  // any member may expel a compromised binding cluster-wide, and the
  // record is permanent until an explicit local purge.
  let record = crate::identity::revocation::sign_revocation_record(
    context,
    context.keys(),
    &subject,
    &expected_key,
  )
  .await?;
  let outcome = crate::identity::revocation::revoke_binding_ctx(
    context.store(),
    planes.entropy.as_ref(),
    &record,
  )
  .await?;
  let transition = outcome.transition();
  // The execution plane is independent of the evidence verdict: a revoked
  // identity must never keep a live session, so the exact identity's
  // sessions retire on every outcome (retiring an already-retired peer is
  // a no-op). Redial is impossible by construction — the revoked binding
  // is gone, so neither recovery candidates nor an inbound handshake can
  // admit this identity again.
  retire_session(&planes.sessions, &subject)?;
  if transition.changed_authorization() {
    deps
      .events()
      .emit(crate::SessionChanged::new(subject.clone()));
    deps.events().emit(crate::NodeRevoked::new(subject.clone()));
  }
  Ok(EffectOutcome::new(TaskOutput::Revoke(RevokeOutcome::new(
    subject,
    !transition.changed_authorization(),
  ))))
}

/// The cleanup effect: sign and persist one convergent cleanup tombstone,
/// then announce the member change.
async fn reconcile_cleanup(deps: Arc<OperationDeps>, subject: NodeId) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let context = &planes.context;
  if &subject == context.identity().node() {
    // Self-removal is the explicit leave path, never a self-cleanup.
    return Err(Error::invalid_input("cleanup subject"));
  }
  let record =
    crate::identity::cleanup::sign_cleanup_record(context, context.keys(), &subject).await?;
  let install = crate::identity::cleanup::persist_cleanup_record_ctx(
    context.store(),
    planes.entropy.as_ref(),
    &record,
  )
  .await?;
  // An exact replay or a legitimate losing record changed nothing: the
  // member set may be notified only for a real install.
  if install == crate::identity::records::TerminalInstall::Installed {
    deps.events().emit(crate::MemberChanged::new(subject));
    planes.member_revision.bump();
  }
  Ok(EffectOutcome::new(TaskOutput::Cleanup(())))
}

/// The purge effect: clear the local revocation record (local-only,
/// idempotent, deliberate).
async fn reconcile_purge_revocation(
  deps: Arc<OperationDeps>, subject: NodeId,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  crate::identity::revocation::purge_revocation_ctx(
    planes.context.store(),
    planes.entropy.as_ref(),
    &subject,
  )
  .await?;
  Ok(EffectOutcome::new(TaskOutput::PurgeRevocation(())))
}

/// The checkpoint effect: enforce the convergence precondition, then
/// start the new GC epoch at the current wall clock.
async fn reconcile_issue_cleanup_checkpoint(deps: Arc<OperationDeps>) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  require_members_connected(planes).await?;
  let watermark =
    crate::identity::cleanup::issue_checkpoint_ctx(&planes.context, planes.entropy.as_ref())
      .await?;
  Ok(EffectOutcome::new(TaskOutput::IssueCleanupCheckpoint(
    watermark,
  )))
}

/// The frozen-journal resolution effect: resolve the store's frozen
/// pending journal as uncommitted and unfreeze the store. The store's
/// blocked state is this operation's precondition, so the
/// `require_unblocked` gate that refuses admission-sensitive effects
/// while frozen deliberately does not apply here. The effect deliberately
/// does not queue on the store's writer exclusion: on a frozen store the
/// background anti-entropy writers park inside that exclusion on the
/// commit-slot refusal and would starve the operator resolution forever.
async fn reconcile_resolve_frozen_journal(deps: Arc<OperationDeps>) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  let operation = crate::TransactionId::generate(planes.entropy.as_ref())?;
  planes
    .context
    .store()
    .resolve_frozen_journal_uncommitted(operation)
    .await?;
  Ok(EffectOutcome::new(TaskOutput::ResolveFrozenJournal(())))
}

/// The checkpoint issue precondition: every known member other than self
/// whose removal record is not terminal (left or cleaned) must hold at
/// least one live authenticated session — the crate's own any-one-route
/// connectivity contract. A non-terminal member is still owed tombstone
/// deliveries, so an epoch issued while it is unreachable could collect
/// records it has not received yet; a member with a terminal removal
/// record is exactly what the epoch may collect and never blocks. A
/// singleton cluster passes trivially (no other member).
async fn require_members_connected(planes: &EffectPlanes) -> Result<()> {
  // Snapshot the live-session peers under the lock, then release it
  // before any await so the effect future stays `Send`.
  let live: std::collections::BTreeSet<NodeId> = planes
    .sessions
    .lock()
    .map_err(Error::session_table)?
    .iter()
    .filter(|(_, entry)| entry.alive())
    .map(|(peer, _)| peer.clone())
    .collect();
  let store = planes.context.store();
  let departed = departed_exclusions(&planes.exclusion_cache, store).await?;
  let snapshot = store.snapshot().await?;
  let namespace = crate::membership::descriptor_namespace()?;
  let mut scan = snapshot.scan_from(&namespace, &[], None).await?;
  let mut unreachable = 0_usize;
  while let Some(entry) = scan.next().await? {
    let descriptor = match crate::membership::page::decode_descriptor(entry.value().as_bytes()) {
      Ok(descriptor) => descriptor,
      // The scan is best-effort over durable evidence, matching the
      // recovery tick's enumeration; an undecodable entry stays visible
      // in diagnostics.
      Err(error) => {
        tracing::debug!(kind = ?error.kind(), "checkpoint guard skipped an undecodable descriptor");
        continue;
      }
    };
    let node = descriptor.node();
    if descriptor.removed()
      || node == planes.context.identity().node()
      || departed.status(node) != crate::MemberStatus::Active
    {
      continue;
    }
    if !live.contains(node) {
      unreachable += 1;
    }
  }
  if unreachable > 0 {
    tracing::debug!(
      unreachable,
      "cleanup checkpoint refused: non-terminal members without a live session"
    );
    return Err(Error::not_ready("cleanup checkpoint"));
  }
  Ok(())
}

// -- resource and node-metadata verbs ----------------------------------

/// Admits one resource write intent as a signed candidate record
/// (`PutResource`): `put` passes `None` (last-writer-wins) and
/// `put_expected` passes the compare-and-swap precondition. The effect
/// stamps, signs, and commits the record in one conditional transaction.
///
/// Admission-time failures are the pure shape checks (a stopped node, a
/// malformed write, a resource hook's rejection) plus the hook-composed
/// write; the frozen-store refusal, the CAS loss, and every commit
/// failure are effect-time and surface on the task's [`Task::wait`] (a
/// lost CAS as [`crate::ErrorKind::Conflict`]).
pub(crate) async fn put_resource(
  extensions: &ExtensionRegistry, tasks: &TaskClient, write: crate::ResourceWrite,
  expected: Option<crate::ResourceVersion>,
) -> Result<Task<crate::ResourceMutationView>> {
  crate::resource::check_write_shape(write.name(), write.labels())?;
  let write = crate::task::apply_resource_hooks(&extensions.resource_hooks(), write)?;
  // The write intent is a single-use value (no `Clone`), so the effect
  // owns it through an `Arc` every retry attempt reborrows.
  let write = Arc::new(write);
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let write = Arc::clone(&write);
    let expected = expected.clone();
    Box::pin(async move { reconcile_put_resource(deps, write, expected).await })
  });
  let payload = TaskPayload::None;
  let id = tasks
    .submit(TaskSpec::new(TaskKind::PutResource, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::PutResource,
    tasks.observer.clone(),
  ))
}

/// Admits one resource removal (`RemoveResource`): the removal commits
/// only when the locally stored winner still equals `expected` exactly
/// and the removal strictly wins the tuple.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal, the stale-observation conflict, and
/// every commit failure are effect-time and surface on the task's
/// [`Task::wait`].
pub(crate) async fn delete_resource(
  tasks: &TaskClient, name: crate::ResourceName, expected: crate::ResourceVersion,
) -> Result<Task<crate::ResourceMutationView>> {
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let name = name.clone();
    let expected = expected.clone();
    Box::pin(async move { reconcile_delete_resource(deps, name, expected).await })
  });
  let payload = TaskPayload::None;
  let id = tasks
    .submit(TaskSpec::new(TaskKind::DeleteResource, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::DeleteResource,
    tasks.observer.clone(),
  ))
}

/// Admits one owner-only metadata patch for this node's own descriptor.
/// The effect applies the patch at a strictly higher revision than
/// `expected_revision` and returns the updated member view.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the revision compare-and-swap and the frozen-store refusal are
/// effect-time and surface on the task's [`Task::wait`] (a stale or
/// same-revision expectation as [`crate::ErrorKind::Conflict`]).
pub(crate) async fn patch_metadata(
  tasks: &TaskClient, expected_revision: u64, patch: crate::NodeMetadataPatch,
) -> Result<Task<crate::MemberView>> {
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let patch = patch.clone();
    Box::pin(async move { reconcile_patch_metadata(deps, expected_revision, patch).await })
  });
  let payload = TaskPayload::None;
  let id = tasks
    .submit(TaskSpec::new(TaskKind::PatchNodeMetadata, payload), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::PatchNodeMetadata,
    tasks.observer.clone(),
  ))
}

/// The local descriptor's lazy-publication coordination (remaining
/// items 2026-10-10, P2-9): the endpoint set the descriptor was last
/// successfully ensured against, plus the single-flight flag for the
/// publication task the read views schedule. Together they keep the
/// lazy path's task population bounded — a steady-state member read
/// spawns nothing (the stamp matches), and at most ONE publication task
/// is ever alive (the audit item 4 lesson applied to the lazy path).
#[derive(Default)]
struct DescriptorPublication {
  /// Whether a scheduled publication task is currently in flight.
  in_flight: std::sync::atomic::AtomicBool,
  /// The published endpoints the descriptor was last ensured against;
  /// `None` until the first successful ensure. Invalidated only by a
  /// listener transition (the sole writers of `published_endpoints`).
  ensured: Mutex<Option<Vec<Endpoint>>>,
}

impl DescriptorPublication {
  /// Whether the descriptor was already ensured against exactly this
  /// published endpoint set — a member read then needs no ensure work.
  fn ensured_against(&self, endpoints: &[Endpoint]) -> bool {
    self
      .ensured
      .lock()
      .is_ok_and(|ensured| ensured.as_deref() == Some(endpoints))
  }

  /// Claims the single publication slot; `false` means a publication
  /// is already in flight (it re-reads the fresher published set, so
  /// the losing read needs no second task).
  fn begin(&self) -> bool {
    !self
      .in_flight
      .swap(true, std::sync::atomic::Ordering::AcqRel)
  }

  /// Releases the publication slot.
  fn end(&self) {
    self
      .in_flight
      .store(false, std::sync::atomic::Ordering::Release);
  }

  /// Records a successful ensure against this published endpoint set.
  fn record(&self, endpoints: &[Endpoint]) {
    if let Ok(mut ensured) = self.ensured.lock() {
      *ensured = Some(endpoints.to_vec());
    }
  }
}

/// Lazily publishes this node's own signed descriptor (revision 1) so
/// the public views always expose the local identity, with the published
/// listener endpoints. Shared by the resource-write effects (a writer's
/// descriptor anchors every record it signs), the listen effect's eager
/// publication at the listener transition, and the read views' lazy
/// kick ([`kick_self_descriptor_publication`]) — every caller but the
/// kick awaits it on its own lane, never the supervisor's select loop.
/// A successful ensure memoizes the endpoint set it settled against, so
/// steady-state member reads stop scheduling ensure work entirely.
pub(super) async fn ensure_self_descriptor(deps: &OperationDeps) -> Result<()> {
  let planes = deps.planes()?;
  let endpoints = planes
    .published_endpoints
    .lock()
    .map(|endpoints| endpoints.clone())
    .unwrap_or_default();
  crate::membership::sync::ensure_local_descriptor(
    &planes.context,
    &planes.entropy,
    endpoints.clone(),
    deps.events(),
    &planes.member_revision,
  )
  .await?;
  planes.descriptor_publication.record(&endpoints);
  Ok(())
}

/// Schedules the local descriptor's lazy publication OFF the
/// supervisor's select loop (remaining items 2026-10-10, P2-9): the
/// member read views call this instead of awaiting the ensure, so a
/// first member read on a node that never bound a listener can no
/// longer park every control-plane operation behind the descriptor
/// commit on slow storage. Bounded accounting: the endpoint-set stamp
/// suppresses the kick in steady state, and the single-flight gate
/// bounds the population at exactly one task; a failed publication
/// only clears the slot (never the stamp), so the next member read
/// retries while the maintenance tick remains the drift backstop.
/// The task is enrolled in the tracked connection-task registry (the
/// same ownership path as the maintenance plane's in-flight dials): it
/// holds the metadata store's exclusive handle through the shared deps
/// Arcs, so the shutdown path must await it inside the bounded
/// cooperative window and abort the straggler before the reply returns
/// — a detached spawn would keep the store locked past shutdown.
///
/// The kicking read answers from committed state only: on a node whose
/// descriptor is not yet published, that single read may not include
/// the local node — the scheduled publication lands asynchronously with
/// its paired [`crate::MemberChanged`] event and revision bump (the
/// one-to-one promise lives inside the ensure itself), and every later
/// read observes it. Listener transitions publish synchronously in the
/// listen effect, so a read after a bound listener stays deterministic.
pub(super) fn kick_self_descriptor_publication(deps: &Arc<OperationDeps>) {
  let Ok(planes) = deps.planes() else {
    return;
  };
  let endpoints = planes
    .published_endpoints
    .lock()
    .map(|endpoints| endpoints.clone())
    .unwrap_or_default();
  if planes.descriptor_publication.ensured_against(&endpoints) {
    return;
  }
  if !planes.descriptor_publication.begin() {
    return;
  }
  let deps = Arc::clone(deps);
  track_connection_task(
    &planes.connection_tasks,
    Box::pin(async move {
      // The slot must release even if the provider-backed ensure panics:
      // a stuck flag would suppress every later kick for the node's
      // lifetime, so the guard clears it on any exit path.
      let slot = PublicationSlot {
        deps: Arc::clone(&deps),
      };
      if let Err(error) = ensure_self_descriptor(&deps).await {
        tracing::warn!(
          kind = ?error.kind(),
          "lazy local-descriptor publication failed; the next member read retries"
        );
      }
      drop(slot);
    }),
  );
}

/// Releases the single-flight publication slot on every exit path of
/// the kicked task, including a panic unwind.
struct PublicationSlot {
  deps: Arc<OperationDeps>,
}

impl Drop for PublicationSlot {
  fn drop(&mut self) {
    if let Ok(planes) = self.deps.planes() {
      planes.descriptor_publication.end();
    }
  }
}

/// The put effect: the moved supervisor body — stamp the host wall-clock
/// tuple, sign through the node's key provider, and commit the whole
/// record in one conditional transaction under the shared bounded
/// commit-race retry. A committed winner emits exactly one
/// [`crate::ResourceChanged`] after durability; an accepted but
/// superseded candidate emits nothing, and an indeterminate commit
/// reports `CommitUnknown` without an event. The resource hooks'
/// `observed` fires on the accepted record after this node's own commit
/// lands, before the task terminalizes.
async fn reconcile_put_resource(
  deps: Arc<OperationDeps>, write: Arc<crate::ResourceWrite>,
  expected: Option<crate::ResourceVersion>,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  ensure_self_descriptor(&deps).await?;
  let context = Arc::clone(&planes.context);
  let writer = context.identity().node().clone();
  let labels = write.labels().clone();
  // Shared reborrows so the retry closure can capture by reference and
  // stay callable (FnMut) across attempts.
  let write = &write;
  let labels = &labels;
  let writer = &writer;
  let expected = &expected;
  let events = deps.events();
  let context = &context;
  let (accepted, name, outcome) = super::resources::with_commit_race_retry("resource put", || {
    Box::pin(async move {
      // The caller's expected version is the only authority on which
      // register state the write may replace. This pre-check is the
      // early bail (a stale observation never pays the signature); the
      // authoritative re-verification runs inside the commit's own
      // snapshot (`commit_expected_record_ctx`), so the asynchronous
      // signature step between the two cannot race the precondition
      // away — a register that moved past the expected version refuses
      // the write instead of being silently overwritten by a tuple
      // winner. A mismatch is final and never retried; the CAS race
      // guard below covers only the snapshot-commit window and re-runs
      // this check per attempt.
      if let Some(expected) = expected {
        let stored = crate::resource::store::read_record_ctx(context.store(), write.name())
          .await?
          .ok_or_else(|| Error::not_found("resource"))?;
        if !expected.matches_record(&stored) {
          return Ok(super::resources::CommitRace::Final(Err(Error::conflict(
            "resource version",
          ))));
        }
      }
      let timestamp_millis = super::resources::issue_write_stamp(&planes.resource_write_clock);
      let record = crate::resource::ResourceRecordV1::sign_with_provider(
        write.name().clone(),
        labels.resource_type().clone(),
        labels.uri().clone(),
        labels.custom_labels().clone(),
        timestamp_millis,
        writer.clone(),
        0,
        false,
        context.keys(),
        context.identity().handle(),
      )
      .await?;
      let accepted = crate::resource::select::resource_view(&record);
      match crate::resource::store::commit_expected_record_ctx(
        context.store(),
        planes.entropy.as_ref(),
        &record,
        expected.as_ref(),
      )
      .await
      {
        // A lost register race is the only retryable outcome; every
        // other error inside the attempt is final.
        Err(error) if error.kind() == crate::ErrorKind::Conflict => {
          Ok(super::resources::CommitRace::Raced(error))
        }
        Err(error) => Err(error),
        Ok(outcome) => Ok(super::resources::CommitRace::Final(Ok((
          accepted,
          record.name().clone(),
          outcome,
        )))),
      }
    })
  })
  .await?;
  // A preconditioned write that lost the tuple can no longer be
  // replacing the expected version: the register moved past it, so the
  // precondition surfaces as an explicit conflict instead of a
  // silently accepted loser.
  let superseded = if expected.is_some() {
    None
  } else {
    Some(crate::ResourceMutationView::new(accepted.clone(), false))
  };
  let view = super::resources::resource_mutation_outcome(
    events,
    &name,
    outcome,
    crate::ResourceMutationView::new(accepted.clone(), true),
    superseded,
  )?;
  crate::task::notify_resource_observers(&deps.extensions().resource_hooks(), view.accepted())
    .await;
  Ok(EffectOutcome::new(TaskOutput::PutResource(view)))
}

/// The removal effect: the moved supervisor body — only when the stored
/// winner still equals the caller's observed version exactly and the
/// removal strictly wins the tuple. The removal record carries the
/// winner's labels (removal evidence stays comparable), and the effect
/// touches core metadata only — the resource URI is never followed and
/// no caller object is deleted. The resource hooks' `observed` fires on
/// the removal record after this node's own commit lands.
async fn reconcile_delete_resource(
  deps: Arc<OperationDeps>, name: crate::ResourceName, expected: crate::ResourceVersion,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  ensure_self_descriptor(&deps).await?;
  let context = Arc::clone(&planes.context);
  let writer = context.identity().node().clone();
  // The snapshot-exact CAS can lose a race against a concurrent internal
  // committer, so the observation, signature, and commit re-run within
  // a bounded retry; the caller's `expected` stays the only authority
  // on which register state the removal may replace.
  // Shared reborrows so the retry closure can capture by reference and
  // stay callable (FnMut) across attempts; the outer `name` is cloned
  // per attempt and re-bound to the helper's result afterwards.
  let writer = &writer;
  let expected = &expected;
  let events = deps.events();
  let context = &context;
  let name = &name;
  let view = super::resources::with_commit_race_retry("resource removal", || {
    Box::pin(async move {
      let store = context.store();
      let stored = crate::resource::store::read_record_ctx(store, name)
        .await?
        .ok_or_else(|| Error::not_found("resource"))?;
      if !expected.matches_record(&stored) {
        // A stale observation never becomes a newer wall-clock winner:
        // the caller's expected version is final, never retried.
        return Ok(super::resources::CommitRace::Final(Err(Error::conflict(
          "resource version",
        ))));
      }
      if stored.removed() {
        // The exact removal already won: idempotent, no new transition
        // (and no event — only a fresh install emits).
        return Ok(super::resources::CommitRace::Final(Ok(
          crate::ResourceMutationView::new(crate::resource::select::resource_view(&stored), true),
        )));
      }
      // The removal rides the same monotonic issue clock as a put, so a
      // writer removing its own fresh record always outranks it, and a
      // rolled-back host clock cannot issue a stale-looking stamp.
      let timestamp_millis = super::resources::issue_write_stamp(&planes.resource_write_clock);
      // A synced record may legally carry the maximum rank; a saturated
      // register cannot host a further removal and fails closed instead
      // of wrapping the rank order.
      let removal_rank = stored
        .removal_rank()
        .checked_add(1)
        .ok_or_else(|| Error::conflict("resource removal rank"))?;
      // The removal signs through the same single sign-and-seal path as
      // a put (`removed = true`): one canonical encode, one digest, and
      // no second body construction inside `seal`.
      let removal = crate::resource::ResourceRecordV1::sign_with_provider(
        name.clone(),
        stored.resource_type().clone(),
        stored.resource_uri().clone(),
        stored.labels().clone(),
        timestamp_millis,
        writer.clone(),
        removal_rank,
        true,
        context.keys(),
        context.identity().handle(),
      )
      .await?;
      if !removal.wins_over(&stored) {
        // A rolled-back host clock cannot pose as a newer winner: the
        // removal is refused and the live record stays.
        return Ok(super::resources::CommitRace::Final(Err(Error::conflict(
          "resource removal clock",
        ))));
      }
      match crate::resource::store::commit_removal_ctx(
        store,
        planes.entropy.as_ref(),
        &removal,
        &stored,
      )
      .await
      {
        // A lost register race is the only retryable outcome.
        Err(error) if error.kind() == crate::ErrorKind::Conflict => {
          Ok(super::resources::CommitRace::Raced(error))
        }
        Err(error) => Err(error),
        Ok(outcome) => {
          // A committed removal emits exactly one event after
          // durability; the raced/moved/indeterminate arms below never
          // reach the emit as successes. A removal has no accepted-
          // loser report: a register move conflicts.
          Ok(super::resources::CommitRace::Final(
            super::resources::resource_mutation_outcome(
              events,
              name,
              outcome,
              crate::ResourceMutationView::new(
                crate::resource::select::resource_view(&removal),
                true,
              ),
              None,
            ),
          ))
        }
      }
    })
  })
  .await?;
  crate::task::notify_resource_observers(&deps.extensions().resource_hooks(), view.accepted())
    .await;
  Ok(EffectOutcome::new(TaskOutput::DeleteResource(view)))
}

/// The metadata-patch effect: the moved supervisor body — replace this
/// node's own descriptor's endpoint candidates and capability labels at
/// a strictly higher revision than `expected_revision`, commit it, and
/// emit the paired member change and revision bump.
async fn reconcile_patch_metadata(
  deps: Arc<OperationDeps>, expected_revision: u64, patch: crate::NodeMetadataPatch,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let context = Arc::clone(&planes.context);
  let local = context.identity().node().clone();
  let store = context.store();
  let current = crate::membership::store::read_descriptor_ctx(store, &local)
    .await?
    .ok_or_else(|| Error::not_ready("local descriptor"))?;
  if current.revision() != expected_revision {
    return Err(Error::conflict("node metadata revision"));
  }
  let updated = crate::membership::apply_metadata_patch(&current, patch)?;
  crate::membership::store::store_descriptor_ctx(store, planes.entropy.as_ref(), &updated).await?;
  deps.events().emit(crate::MemberChanged::new(local.clone()));
  planes.member_revision.bump();
  let view = crate::membership::member_view(&updated, crate::ConnectivityStatus::Connected)?;
  Ok(EffectOutcome::new(TaskOutput::PatchNodeMetadata(view)))
}

// -- listener, credential, recovery, retention, and sync verbs ------

/// Admits one new listener binding. The effect binds the advertised
/// endpoint and runs its bounded-backoff accept loop.
///
/// Admission-time failures are the pure shape checks (a stopped node,
/// an endpoint whose transport selector does not resolve in the
/// registry); the bind syscall and the frozen-store refusal are
/// effect-time and surface on the task's [`Task::wait`].
pub(crate) async fn listen(
  extensions: &ExtensionRegistry, tasks: &TaskClient, endpoint: Endpoint,
) -> Result<Task<crate::ListenerView>> {
  let transport = extensions.resolve_transport(&endpoint.selector())?;
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let transport = Arc::clone(&transport);
    let endpoint = endpoint.clone();
    Box::pin(async move { reconcile_listen(deps, transport, endpoint).await })
  });
  let id = tasks
    .submit(TaskSpec::new(TaskKind::Listen, TaskPayload::None), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::Listen,
    tasks.observer.clone(),
  ))
}

/// Admits one listener teardown by id. The effect unbinds the listener
/// and unpublishes its advertised endpoint.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); an unknown listener id is effect-time and surfaces on the
/// task's [`Task::wait`] as [`crate::ErrorKind::NotFound`].
pub(crate) async fn stop_listener(
  tasks: &TaskClient, listener: crate::identity::ListenerId,
) -> Result<Task<()>> {
  let effect: TaskEffect = Arc::new(move |deps, _attempt| {
    let listener = listener.clone();
    Box::pin(async move { reconcile_stop_listener(deps, listener).await })
  });
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::StopListener, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::StopListener,
    tasks.observer.clone(),
  ))
}

/// Admits one non-rotating issue of the live join credential
/// generation. The effect issues (or creates) the generation and hands
/// the secret to the first [`Task::wait`] caller only.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal is effect-time and surfaces on the
/// task's `wait`. The issued secret is deliberately once-only: a later
/// `wait` on the same task fails typed, and the status views carry the
/// generation's expiry alone.
pub(crate) async fn issue_merge_credential(
  tasks: &TaskClient,
) -> Result<Task<crate::IssuedMergeCredential>> {
  let effect: TaskEffect =
    Arc::new(|deps, _attempt| Box::pin(async move { reconcile_credential(deps, false).await }));
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::IssueCredential, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::IssueCredential,
    tasks.observer.clone(),
  ))
}

/// Admits one rotation of the live join credential generation. The
/// effect replaces the generation (the revocation/upgrade step) and
/// hands the replacement secret to the first [`Task::wait`] caller only.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal is effect-time and surfaces on the
/// task's `wait`. The replacement secret is deliberately once-only: a
/// later `wait` on the same task fails typed, and the status views carry
/// the generation's expiry alone.
pub(crate) async fn rotate_merge_credential(
  tasks: &TaskClient,
) -> Result<Task<crate::IssuedMergeCredential>> {
  let effect: TaskEffect =
    Arc::new(|deps, _attempt| Box::pin(async move { reconcile_credential(deps, true).await }));
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::RotateCredential, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::RotateCredential,
    tasks.observer.clone(),
  ))
}

/// Admits one bounded immediate recovery cycle. The effect forces the
/// controller's immediate cycle on the shared controller instance and
/// publishes the recovery view (with its [`crate::RecoveryChanged`]
/// event when the observation moved).
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the cycle itself never fails the task.
pub(crate) async fn start_recovery(tasks: &TaskClient) -> Result<Task<crate::RecoveryView>> {
  let effect: TaskEffect =
    Arc::new(|deps, _attempt| Box::pin(async move { reconcile_start_recovery(deps).await }));
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::StartRecovery, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::StartRecovery,
    tasks.observer.clone(),
  ))
}

/// Admits one on-demand receipt-retention pass. The effect runs the
/// same idempotent pass the recovery tick runs on its sweep cadence.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); the frozen-store refusal is effect-time and surfaces on the
/// task's `wait`.
pub(crate) async fn apply_receipt_retention(
  tasks: &TaskClient,
) -> Result<Task<crate::ReceiptRetentionReport>> {
  let effect: TaskEffect = Arc::new(|deps, _attempt| {
    Box::pin(async move { reconcile_apply_receipt_retention(deps).await })
  });
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::ApplyReceiptRetention, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::ApplyReceiptRetention,
    tasks.observer.clone(),
  ))
}

/// Admits one immediate anti-entropy round. The effect forwards the
/// round request to the sync driver (the cursor owner) and resolves
/// when the round finishes — the driver-side round the wall-clock tick
/// also schedules.
///
/// Admission-time failures are the pure shape checks only (a stopped
/// node); a driver that stopped first surfaces as the task's typed
/// [`crate::ErrorKind::ShuttingDown`].
pub(crate) async fn sync_round(tasks: &TaskClient) -> Result<Task<()>> {
  let effect: TaskEffect =
    Arc::new(|deps, _attempt| Box::pin(async move { reconcile_sync_round(deps).await }));
  let id = tasks
    .submit(
      TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
      effect,
    )
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::SyncRound,
    tasks.observer.clone(),
  ))
}

/// The listen effect: the moved supervisor body — bind the advertised
/// endpoint, spawn the bounded-backoff accept loop into the node's
/// tracked connection tasks, register the listener, and publish the
/// advertised endpoint. Peers dial the advertised name (never the bound
/// wildcard socket); custom transports publish the endpoint their
/// listener reports.
async fn reconcile_listen(
  deps: Arc<OperationDeps>, transport: Arc<dyn crate::transport::registry::Transport>,
  endpoint: Endpoint,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let listener: std::sync::Arc<dyn crate::transport::registry::TransportListener> =
    std::sync::Arc::from(transport.bind(endpoint.clone()).await?);
  let bound = listener.local_endpoint();
  let driver = planes.driver.clone();
  let sessions = planes.sessions.clone();
  let packet = Arc::clone(&planes.packet);
  let shutdown = planes.shutdown.subscribe();
  let connection_tasks = Arc::clone(&planes.connection_tasks);
  let accept_listener = std::sync::Arc::clone(&listener);
  let insert_listener = std::sync::Arc::clone(&listener);
  let attachment = bound.clone();
  // The accept loop is a tracked connection task: shutdown aborts it
  // through the registry's abort handle (it parks on `accept()` and
  // cannot exit cooperatively with the graceful signal), and the registry
  // keeps that handle for the explicit stop and the leave teardown too (a
  // second abort of an already-aborted task is a no-op).
  let accept = tokio::spawn(async move {
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
          let delay = super::listeners::ACCEPT_BACKOFF_STEP
            .saturating_mul(accept_failures.min(super::listeners::ACCEPT_BACKOFF_MAX_STEPS));
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
            crate::session::stream::run_session(
              connection,
              session,
              packet,
              sessions,
              shutdown,
              crate::session::stream::DialDirection::Incoming,
              attachment.clone(),
              None,
              false,
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
  let abort = accept.abort_handle();
  if let Ok(mut tasks) = planes.connection_tasks.lock() {
    tasks.push(accept);
  }
  let id = crate::identity::ListenerId::generate(planes.entropy.as_ref())?;
  // Publish the caller's advertised endpoint, not the bound socket
  // address: peers dial the advertised name, which re-resolves across
  // network moves. A named endpoint binds the wildcard socket (see
  // the TCP bind rule), whose local address (0.0.0.0) is local
  // plumbing and undialable from other nodes. Literal-IP endpoints
  // publish the bound form directly: the requested host is the bound
  // host, and a wildcard port resolves to the real one. Custom
  // transports publish the endpoint their listener reports: the
  // medium owns its own address resolution, and the reported form is
  // its dialable contract.
  let published = match endpoint.selector() {
    crate::transport::TransportSelector::Custom(_) => bound,
    crate::transport::TransportSelector::Builtin(_) => {
      if endpoint.host() == bound.host() {
        bound
      } else {
        endpoint.with_port(
          bound
            .port()
            .ok_or_else(|| Error::internal("listener port"))?,
        )?
      }
    }
  };
  planes
    .listeners
    .lock()
    .map_err(|_| Error::internal("listener registry"))?
    .insert(id.clone(), (published.clone(), insert_listener, abort));
  // Publish the advertised endpoint so the next anti-entropy tick pages
  // it in the local descriptor (recovery dials peers through published
  // endpoints).
  if let Ok(mut endpoints) = planes.published_endpoints.lock()
    && !endpoints.contains(&published)
  {
    endpoints.push(published.clone());
  }
  // Eager publication at the listener transition (remaining items
  // 2026-10-10, P2-9): the member read views no longer await the lazy
  // ensure inline, so the listener effect publishes the descriptor
  // here, on this effect's own lane — a read that follows the listen
  // task's completion deterministically observes the local node.
  // Best-effort by the maintenance tick's contract: a failed
  // publication defers to the read views' kick and the tick's own
  // rewrite without failing the already-bound listener.
  if let Err(error) = ensure_self_descriptor(&deps).await {
    tracing::warn!(
      kind = ?error.kind(),
      "eager descriptor publication at listen deferred to the lazy paths"
    );
  }
  Ok(EffectOutcome::new(TaskOutput::Listen(
    crate::ListenerView::new(id, published),
  )))
}

/// The stop-listener effect: the shared teardown — remove the registry
/// entry, wake and abort the accept loop, unpublish the advertised
/// endpoint.
async fn reconcile_stop_listener(
  deps: Arc<OperationDeps>, listener: crate::identity::ListenerId,
) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  super::listeners::stop_listener(&planes.listeners, &planes.published_endpoints, &listener)
    .await?;
  Ok(EffectOutcome::new(TaskOutput::StopListener(())))
}

/// The credential effect: issue (or rotate) the live join credential
/// generation through the session driver's one issuer. The secret rides
/// the consumed-once slot: the task's observation carries the expiry,
/// and exactly the first `wait` collects the credential.
async fn reconcile_credential(deps: Arc<OperationDeps>, rotate: bool) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let mut issuer = planes
    .driver
    .issuer()
    .lock()
    .map_err(|_| Error::internal("join credential issuer"))?;
  let issued = if rotate {
    issuer.rotate(planes.entropy.as_ref(), std::time::SystemTime::now())?
  } else {
    issuer.issue(planes.entropy.as_ref(), std::time::SystemTime::now())?
  };
  Ok(if rotate {
    EffectOutcome::credential_rotated(issued)
  } else {
    EffectOutcome::credential_issued(issued)
  })
}

/// The start-recovery effect: force the immediate cycle on the shared
/// controller, publish the view, and emit the change event when the
/// observation moved — the moved supervisor body.
async fn reconcile_start_recovery(deps: Arc<OperationDeps>) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  let mut controller = planes
    .recovery
    .lock()
    .map_err(|_| Error::internal("recovery controller"))?;
  let before = super::recovery::recovery_view(&controller);
  controller.immediate(crate::time::now_seconds());
  let after = super::recovery::recovery_view(&controller);
  drop(controller);
  if after != before {
    deps
      .events()
      .emit(crate::RecoveryChanged::new(after.clone()));
  }
  Ok(EffectOutcome::new(TaskOutput::StartRecovery(after)))
}

/// The receipt-retention effect: the idempotent on-demand pass — the
/// moved supervisor body. The unknown-outcome freeze blocks the pass:
/// a pending unknown may still reference its receipt, and cleanup
/// conflicts rather than guesses.
async fn reconcile_apply_receipt_retention(deps: Arc<OperationDeps>) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let report = planes.context.store().apply_receipt_retention().await?;
  Ok(EffectOutcome::new(TaskOutput::ApplyReceiptRetention(
    report,
  )))
}

/// The sync-round effect: forward one round request to the sync driver
/// and resolve when the round finishes. The round still executes in
/// the driver (the cursor owner), exactly like the wall-clock tick.
async fn reconcile_sync_round(deps: Arc<OperationDeps>) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  let (round, round_rx) = tokio::sync::oneshot::channel();
  if planes.sync_round_requests.send(round).await.is_err() {
    return Err(Error::shutting_down("sync round"));
  }
  round_rx
    .await
    .map_err(|_| Error::shutting_down("sync round"))?;
  Ok(EffectOutcome::new(TaskOutput::SyncRound(())))
}

// -- the leave verb ------------------------------------------------------

/// Admits one acknowledged active leave. The effect journals the intent,
/// announces the leave, tears the network down, replaces the identity,
/// wipes the old core metadata, and deletes the old key; the node then
/// shuts down with the active-leave reason.
///
/// Admission-time failures are the pure shape checks (a stopped node, a
/// missing acknowledgement marker, a second leave while one is in
/// flight — [`crate::ErrorKind::Conflict`]); the frozen-store refusal
/// and every journal/teardown failure are effect-time and surface on the
/// task's [`Task::wait`].
pub(crate) async fn leave(
  tasks: &TaskClient, acknowledgement: crate::ReplaceIdentityAndDeleteOldCoreMetadata,
) -> Result<Task<crate::LeaveOutcome>> {
  // The acknowledgement is a proof-of-construction marker: only the
  // deliberate constructor produces it.
  if !acknowledgement.is_acknowledged() {
    return Err(Error::invalid_input("leave acknowledgement"));
  }
  let effect: TaskEffect =
    Arc::new(|deps, _attempt| Box::pin(async move { reconcile_leave(deps).await }));
  let id = tasks
    .submit(TaskSpec::new(TaskKind::Leave, TaskPayload::None), effect)
    .await?;
  Ok(Task::from_parts(
    id,
    TaskKind::Leave,
    tasks.observer.clone(),
  ))
}

/// The leave effect: crash-retryable ordering — journal the intent and the
/// signed record before any network effect, announce with the journaled
/// record, tear the network down, then rotate. A crash anywhere before
/// rotation resumes at startup with the same journaled record, so the
/// leave is never forgotten and never diverges from what peers may
/// already hold. A receipt-less budget expires into the documented
/// silent leave, which the cleanup path covers. The task's terminal
/// publication lands before the manager signals the supervisor's
/// active-leave shutdown, so a `wait` caller always observes the outcome
/// before any teardown begins.
async fn reconcile_leave(deps: Arc<OperationDeps>) -> Result<EffectOutcome> {
  let planes = deps.planes()?;
  planes.context.require_unblocked()?;
  let context = &planes.context;
  let journaled =
    crate::identity::leave::journal_leave(context, context.keys(), planes.entropy.as_ref()).await?;
  crate::membership::sync::announce_leave(
    context,
    &planes.entropy,
    &journaled.record,
    &planes.sessions,
    &planes.routes,
    deps.events(),
    &planes.leave_applied,
  )
  .await?;

  // Network teardown first: no new sessions or inbound metadata while
  // the identity is replaced and the old metadata is wiped.
  let listener_ids: Vec<crate::identity::ListenerId> = planes
    .listeners
    .lock()
    .map_err(|_| Error::internal("listener registry"))?
    .keys()
    .cloned()
    .collect();
  for listener in listener_ids {
    super::listeners::stop_listener(&planes.listeners, &planes.published_endpoints, &listener)
      .await?;
  }
  let peers: Vec<NodeId> = planes
    .sessions
    .lock()
    .map_err(Error::session_table)?
    .keys()
    .cloned()
    .collect();
  for peer in peers {
    retire_session(&planes.sessions, &peer)?;
  }

  crate::identity::leave::run_leave(
    context.store(),
    context.keys(),
    planes.entropy.as_ref(),
    &journaled.stored,
    &journaled.intent,
  )
  .await?;
  let (former, replacement) = (
    journaled.intent.former_node().clone(),
    journaled.intent.replacement_node().clone(),
  );
  deps.events().emit(crate::IdentityReplaced::new(
    former.clone(),
    replacement.clone(),
  ));
  Ok(EffectOutcome::new(TaskOutput::Leave(
    crate::LeaveOutcome::new(former, replacement),
  )))
}

#[cfg(test)]
mod descriptor_publication_tests {
  use super::DescriptorPublication;
  use crate::Endpoint;

  fn endpoints(ports: &[u16]) -> Vec<Endpoint> {
    ports
      .iter()
      .map(|port| Endpoint::parse(&format!("wss://127.0.0.1:{port}")).unwrap())
      .collect()
  }

  /// The gate's two bounds (remaining items 2026-10-10, P2-9): the
  /// endpoint-set stamp suppresses ensure work while the published
  /// endpoints are unchanged (a listener transition is the only
  /// invalidation), and the single-flight flag admits exactly one
  /// publication task at a time.
  #[test]
  fn the_stamp_suppresses_unchanged_kicks_and_the_slot_serializes() {
    let gate = DescriptorPublication::default();
    assert!(
      !gate.ensured_against(&endpoints(&[1])),
      "nothing is ensured before the first record"
    );
    assert!(gate.begin(), "the first publication claims the slot");
    assert!(
      !gate.begin(),
      "a second publication waits for the in-flight one"
    );
    gate.end();
    gate.record(&endpoints(&[1]));
    assert!(
      gate.ensured_against(&endpoints(&[1])),
      "a recorded ensure suppresses the same published set"
    );
    assert!(
      !gate.ensured_against(&endpoints(&[1, 2])),
      "a listener transition invalidates the stamp"
    );
    assert!(gate.begin(), "the slot is free again once released");
  }
}

#[cfg(test)]
mod lazy_publication_shutdown_tests {
  use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  };

  use crate::{
    BoxFuture, NodeConfig, NodeId, TransportScheme,
    extension_registry::ExtensionRegistry,
    identity::testing::{ScriptedKeys, SequenceEntropy},
    provider::{
      CommitOutcome, ReconcileOutcome, Storage, StorageFactory, StoreCapabilities, StoreOperation,
      StoreRequirements, StoreSnapshot, StoreTransaction,
    },
    runtime::{
      Control, PACKET_CHANNEL_CAPACITY, RuntimeClient, RuntimeDependencies,
      SYNC_ROUND_CHANNEL_CAPACITY, spawn_runtime,
    },
    storage::contract::{ReferenceFactory, required_capabilities},
    transport::registry::{Transport, builtin_transport_tag},
  };

  /// The descriptor-commit park: a fault-injecting factory whose every
  /// descriptor-namespace commit never settles (the slow-storage commit
  /// the lazy path exists for, made permanent so the test can observe a
  /// publication wedged exactly mid-commit), while every other
  /// operation delegates to the reference store untouched.
  #[derive(Debug)]
  struct ParkedDescriptorFactory {
    reference: Arc<ReferenceFactory>,
    reached: Arc<AtomicUsize>,
  }

  impl StorageFactory for ParkedDescriptorFactory {
    fn open<'a>(
      &'a self, requirements: StoreRequirements,
    ) -> BoxFuture<'a, crate::Result<Box<dyn Storage>>> {
      let reference = &self.reference;
      let reached = Arc::clone(&self.reached);
      Box::pin(async move {
        let storage = reference.open(requirements).await?;
        Ok(Box::new(ParkedDescriptorStorage { storage, reached }) as Box<dyn Storage>)
      })
    }
  }

  #[derive(Debug)]
  struct ParkedDescriptorStorage {
    storage: Box<dyn Storage>,
    reached: Arc<AtomicUsize>,
  }

  impl ParkedDescriptorStorage {
    fn parks(transaction: &StoreTransaction) -> bool {
      let Ok(namespace) = crate::membership::descriptor_namespace() else {
        return false;
      };
      transaction
        .operations()
        .iter()
        .any(|operation| match operation {
          StoreOperation::Check {
            namespace: target, ..
          }
          | StoreOperation::Put {
            namespace: target, ..
          }
          | StoreOperation::Delete {
            namespace: target, ..
          } => *target == namespace,
          StoreOperation::ForgetReceipt { .. } => false,
        })
    }
  }

  impl Storage for ParkedDescriptorStorage {
    fn capabilities(&self) -> StoreCapabilities {
      self.storage.capabilities()
    }

    fn snapshot<'a>(&'a self) -> BoxFuture<'a, crate::Result<Box<dyn StoreSnapshot>>> {
      self.storage.snapshot()
    }

    fn commit<'a>(
      &'a self, transaction: StoreTransaction,
    ) -> BoxFuture<'a, crate::Result<CommitOutcome>> {
      if Self::parks(&transaction) {
        self.reached.fetch_add(1, Ordering::Relaxed);
        // The wedged commit: it never settles, so only a shutdown abort
        // can end it — exactly the straggler the grace window bounds.
        return Box::pin(std::future::pending());
      }
      self.storage.commit(transaction)
    }

    fn reconcile<'a>(
      &'a self, transaction: &'a crate::TransactionId, digest: &'a crate::Digest,
    ) -> BoxFuture<'a, crate::Result<ReconcileOutcome>> {
      self.storage.reconcile(transaction, digest)
    }

    fn flush<'a>(&'a self) -> BoxFuture<'a, crate::Result<()>> {
      self.storage.flush()
    }
  }

  /// Spawns a listenerless runtime over the caller's factory, the same
  /// shape `spawn_runtime` builds in production (the recovery-plane
  /// test's `supervised_runtime` precedent): the returned registry is
  /// the node's tracked connection-task set, so the test can observe
  /// what the lazy publication enrolls.
  async fn listenerless_runtime(
    factory: Arc<dyn StorageFactory>,
  ) -> (
    RuntimeClient,
    Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
  ) {
    let keys = ScriptedKeys::full();
    let entropy: Arc<dyn crate::api::Entropy> = Arc::new(SequenceEntropy::default());
    let mut extensions = ExtensionRegistry::new();
    for (tag, transport) in [
      (
        builtin_transport_tag(TransportScheme::Tls).unwrap(),
        Arc::new(crate::transport::tls_transport::TlsTransport::new()) as Arc<dyn Transport>,
      ),
      (
        builtin_transport_tag(TransportScheme::Wss).unwrap(),
        Arc::new(crate::transport::wss::WssTransport::new()) as Arc<dyn Transport>,
      ),
      (
        builtin_transport_tag(TransportScheme::Tcp).unwrap(),
        Arc::new(crate::transport::plain::PlainTransport::new()) as Arc<dyn Transport>,
      ),
    ] {
      extensions
        .register_builtin_transport(tag, transport)
        .unwrap();
    }
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let (round_tx, round_rx) = tokio::sync::mpsc::channel(SYNC_ROUND_CHANNEL_CAPACITY);
    let (packet_tx, packet_rx) = tokio::sync::mpsc::channel(PACKET_CHANNEL_CAPACITY);
    let connection_tasks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let client = spawn_runtime(
      RuntimeDependencies {
        storage_factory: factory,
        context: None,
        keys: Some(keys.as_provider()),
        config: NodeConfig::new(),
        entropy,
        extensions: Arc::new(extensions),
        sessions: Default::default(),
        routes: Default::default(),
        events: Arc::new(crate::node::EventHub::new()),
        member_revision: crate::node::MemberRevisionSignal::new(revision_tx),
        leave_applied: crate::membership::sync::LeaveAppliedSignal::new(),
        reconcile: None,
        sync_round_requests: round_tx,
        connection_tasks: Arc::clone(&connection_tasks),
        listeners: Default::default(),
        task_manager: None,
        operations: None,
        runtime_seed: None,
      },
      (packet_tx, packet_rx),
      round_rx,
    )
    .await
    .unwrap();
    (client, connection_tasks)
  }

  /// Audit A08: the lazy local-descriptor publication used to spawn
  /// detached, outside every shutdown registry, so a member read that
  /// kicked a publication could still be mid descriptor commit when
  /// `shutdown()` returned — the storage exclusive lifetime lock
  /// outlived the reply, and an immediate reopen of the same factory
  /// failed `StorageLocked` until the stray commit finished. This
  /// drives the real shutdown path end to end against a store whose
  /// descriptor commit parks forever (the slow-storage commit the lazy
  /// path exists for): the kicked task must sit in the tracked
  /// connection-task set, the shutdown reply must resolve inside the
  /// bounded cooperative window (the grace-edge abort — a wedged
  /// commit can never be waited out), and the same factory must reopen
  /// immediately after the reply, proving the storage capture dropped
  /// before it.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn shutdown_aborts_and_awaits_the_lazy_descriptor_publication() {
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let reached = Arc::new(AtomicUsize::new(0));
    let (client, connection_tasks) = listenerless_runtime(Arc::new(ParkedDescriptorFactory {
      reference: Arc::clone(&reference),
      reached: Arc::clone(&reached),
    }))
    .await;

    // The kick: one member read on the listenerless node. The view
    // answers from committed state while the publication runs behind
    // it — the read itself must never await the parked commit.
    let query = NodeId::parse("node-00000000000000000000p").unwrap();
    client
      .send_command(move |reply| Control::GetMember { node: query, reply })
      .await
      .expect("the member read resolves without awaiting the publication");

    // The kicked publication reached the store and parked inside its
    // descriptor commit (the fault): this is the window the finding
    // describes — a commit mid-flight with the storage handle held.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
        if reached.load(Ordering::Relaxed) >= 1 {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the kicked publication must reach its descriptor commit");

    // The parked publication's JoinHandle must sit in the tracked set
    // the shutdown path drains — an empty set is the finding's
    // detached shape.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      loop {
        if !connection_tasks.lock().unwrap().is_empty() {
          break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      }
    })
    .await
    .expect("the lazy publication must register its JoinHandle");

    // The reply resolves via the grace-edge abort — the cooperative
    // window is 3s and the commit never settles, so the reply may only
    // come from the bounded abort, never an unbounded await (and a
    // detached task, invisible to the drain, would strand the store
    // instead of freeing it below).
    tokio::time::timeout(std::time::Duration::from_secs(4), client.shutdown())
      .await
      .expect("shutdown must resolve inside the cooperative window")
      .expect("the shutdown reply must resolve");

    // The sharpest assertion: with the reply returned, every storage
    // capture is already dropped, so the same factory reopens
    // immediately — the parked task's store handle went with the
    // abort, never past the reply. A detached spawn answers
    // `StorageLocked` here until its commit finishes, and this fault
    // never finishes.
    let reopened = tokio::time::timeout(
      std::time::Duration::from_secs(2),
      reference.open(StoreRequirements::metadata()),
    )
    .await
    .expect("the factory must reopen immediately after the reply")
    .unwrap();
    drop(reopened);
    assert_eq!(reached.load(Ordering::Relaxed), 1);
  }
}
