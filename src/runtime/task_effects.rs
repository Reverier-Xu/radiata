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
  /// The tracked connection tasks, aborted at node shutdown.
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
  /// The memoized departed-members exclusion set, shared with the
  /// supervisor's own pages: the checkpoint guard reads the same cache.
  pub(crate) exclusion_cache: super::recovery::ExclusionCache,
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
  let payload = TaskPayload::Peer(subject.clone());
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
  let was_already_revoked = matches!(
    outcome,
    crate::identity::revocation::RevokeStoreOutcome::AlreadyRevoked
  );
  if !was_already_revoked {
    // After the known-committed transition: close the exact identity's
    // active sessions. Redial is impossible by construction — the revoked
    // binding is gone, so neither recovery candidates nor an inbound
    // handshake can admit this identity again.
    retire_session(&planes.sessions, &subject)?;
    deps
      .events()
      .emit(crate::SessionChanged::new(subject.clone()));
    deps.events().emit(crate::NodeRevoked::new(subject.clone()));
  }
  Ok(EffectOutcome::new(TaskOutput::Revoke(RevokeOutcome::new(
    subject,
    was_already_revoked,
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
  crate::identity::cleanup::persist_cleanup_record_ctx(
    context.store(),
    planes.entropy.as_ref(),
    &record,
  )
  .await?;
  deps.events().emit(crate::MemberChanged::new(subject));
  planes.member_revision.bump();
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
