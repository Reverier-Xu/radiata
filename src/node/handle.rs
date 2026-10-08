use std::sync::Arc;

use crate::{
  Endpoint, Error, Event, EventOptions, EventSubscription, MergeCredential, NodeId,
  NodeMetadataPatch, NodeStatus, OutboundStream, ProtocolTag, PublicKey, Result, ShutdownOutcome,
  ShutdownReason, StreamMetadata, StreamPolicy, StreamTarget, Task, TraceId,
  api::{BoxFuture, Entropy},
  extension_registry::ExtensionRegistry,
  node::{Credentials, Listeners, Members, Resources, Routes, Sessions, Topology, Trust},
  packet::DeliveryAck,
  runtime::{Control, RuntimeClient},
  view::{
    ConnectionDegreeView, DeclareInterruptedTransactionUncommitted, LeaveOutcome, LocalNodeView,
    MemberView, MergeView, ObservabilitySnapshot, ReceiptRetentionReport, RecoveryView,
    ReplaceIdentityAndDeleteOldCoreMetadata, RevokeOutcome,
  },
};

#[derive(Clone)]
pub struct NodeHandle {
  runtime: RuntimeClient,
  entropy: Arc<dyn Entropy>,
  extensions: Arc<ExtensionRegistry>,
  events: Arc<crate::node::EventHub>,
  member_revision: crate::node::MemberRevision,
}

impl NodeHandle {
  pub(crate) fn new(
    runtime: RuntimeClient, entropy: Arc<dyn Entropy>, extensions: Arc<ExtensionRegistry>,
    events: Arc<crate::node::EventHub>, member_revision: crate::node::MemberRevision,
  ) -> Self {
    Self {
      runtime,
      entropy,
      extensions,
      events,
      member_revision,
    }
  }

  /// Opens an outbound stream, allocating its core-generated [`TraceId`]
  /// synchronously from the injected entropy. No body delivery starts
  /// until [`OutboundStream::send_sync`] or [`OutboundStream::send_async`]
  /// consumes the body.
  ///
  /// An exact-node target rejects a load-balancer selection; a
  /// matching-node target requires one whose tag resolves in the node's
  /// [`ExtensionRegistry`]. The routing policy must be the built-in
  /// direct policy — enforced up front when the [`StreamPolicy`] is
  /// constructed — and the protocol tag must be registered.
  pub fn open_stream(
    &self, target: StreamTarget, protocol: ProtocolTag, policy: StreamPolicy,
    metadata: StreamMetadata,
  ) -> Result<OutboundStream> {
    let load_balancer = match (&target, policy.load_balancing_policy()) {
      (StreamTarget::Exact(_), Some(_)) => {
        return Err(Error::invalid_input("packet load balancer"));
      }
      (StreamTarget::Exact(_), None) => None,
      (StreamTarget::MatchingNodes(_), None) => {
        return Err(Error::invalid_input("packet load balancer"));
      }
      (StreamTarget::MatchingNodes(_), Some(tag)) => {
        // Every referenced policy tag must resolve in the registry.
        if !self.extensions.has_load_balancer(tag) {
          return Err(Error::invalid_input("packet load balancer"));
        }
        Some(tag.clone())
      }
    };
    if !self.extensions.has_protocol(&protocol) {
      return Err(Error::unsupported("packet protocol"));
    }
    let trace_id = TraceId::generate(self.entropy.as_ref())?;
    Ok(OutboundStream::new(
      trace_id,
      target,
      load_balancer,
      policy.max_hops(),
      protocol,
      metadata,
      self.runtime.clone(),
    ))
  }

  /// Subscribes to this node's member-set revision. Unlike the transient
  /// event stream, the revision is value-based state: a watcher created
  /// before an action observes every later change, and a watcher created
  /// after it reads the current revision immediately. Await
  /// `MemberRevision::changed` after driving an operation instead of
  /// polling the member pages with wall-clock sleeps.
  pub fn member_revision(&self) -> crate::node::MemberRevision {
    self.member_revision.clone()
  }
}

// ---------------------------------------------------------------------
// The client-go-shaped verb surface. Resource accessors hang the
// standard verbs (get/list/create/delete) off one resource; the
// node-level operation verbs below carry the cluster lifecycle and
// operator actions. Each method's contract is the migrated contract of
// the command or query type it replaces.
// ---------------------------------------------------------------------

impl NodeHandle {
  // -- resource accessors -------------------------------------------

  /// The public membership observations: point reads (`get`) and pages
  /// (`list`).
  pub fn members(&self) -> Members {
    Members::new(&self.runtime)
  }

  /// The node's resource register: `get`, `list`, `select`, `put`,
  /// `put_expected`, and `delete` over the live winners.
  pub fn resources(&self) -> Resources {
    Resources::new(&self.runtime)
  }

  /// The node's bound listeners: `create` binds a new listener,
  /// `delete` unbinds one, `list` pages the live set.
  pub fn listeners(&self) -> Listeners {
    Listeners::new(&self.runtime)
  }

  /// The live authenticated sessions: `list` pages the session set.
  pub fn sessions(&self) -> Sessions {
    Sessions::new(&self.runtime)
  }

  /// The public topology edges: `list` pages the edge set.
  pub fn topology(&self) -> Topology {
    Topology::new(&self.runtime)
  }

  /// The public trust observations: `list` pages the trust set.
  pub fn trust(&self) -> Trust {
    Trust::new(&self.runtime)
  }

  /// The cluster's live join credentials: `issue` hands out the live
  /// generation, `rotate` replaces it.
  pub fn credentials(&self) -> Credentials {
    Credentials::new(&self.runtime)
  }

  /// The in-memory packet route records: `get` reads one route's
  /// bounded status.
  pub fn routes(&self) -> Routes {
    Routes::new(&self.runtime)
  }

  // -- lifecycle ------------------------------------------------------

  /// Shuts the node down and returns the outcome. The stop is
  /// cooperative: every runtime plane observes the stop request and
  /// completes before the outcome resolves.
  pub async fn shutdown(&self) -> Result<ShutdownOutcome> {
    self.runtime.shutdown().await
  }

  /// Waits for the node to finish shutting down and returns the reason.
  pub async fn wait_for_shutdown(&self) -> Result<ShutdownReason> {
    self.runtime.wait_for_shutdown().await
  }

  /// The node's coarse lifecycle status, read locally without touching
  /// the runtime.
  pub fn status(&self) -> NodeStatus {
    self.runtime.status()
  }

  /// The local node's own public view (identity, endpoint candidates,
  /// capability labels).
  pub async fn local_node(&self) -> Result<LocalNodeView> {
    self
      .runtime
      .send_command(|reply| Control::GetLocalNode { reply })
      .await
  }

  // -- cluster lifecycle ----------------------------------------------

  /// Merges this node into the receiver's cluster by presenting the
  /// join credential: `receiver` is the receiver's listen endpoint and
  /// `credential` is the live credential the receiver issued
  /// ([`NodeHandle::credentials`]). Returns the admitted [`Task`], whose
  /// `wait` resolves with the merged membership view.
  ///
  /// Admission-time failures are the pure shape checks (a stopped node,
  /// an endpoint whose transport selector does not resolve); the dial,
  /// the merge handshake, and the frozen-store refusal are effect-time
  /// and surface on the task's `wait`.
  pub async fn join(
    &self, receiver: Endpoint, credential: MergeCredential,
  ) -> Result<Task<MergeView>> {
    crate::runtime::join(
      &self.extensions,
      self.runtime.admit()?,
      receiver,
      credential,
    )
    .await
  }

  /// Actively leaves the cluster: replaces the node's identity
  /// with a fresh node id and key, deletes the old identity's local core
  /// metadata and key through the journaled custody protocols, and shuts
  /// the node down with [`ShutdownReason::ActiveLeave`]. The explicit
  /// acknowledgement makes the identity replacement and metadata deletion
  /// a deliberate caller decision. Returns the admitted [`Task`], whose
  /// `wait` resolves with the outcome; the active-leave shutdown starts
  /// only after the task terminalizes, and the terminal publication
  /// precedes the shutdown signal, so `wait` always observes the outcome
  /// before any teardown begins.
  ///
  /// Admission-time failures are the pure shape checks (a stopped node, a
  /// missing acknowledgement marker, a second leave while one is in
  /// flight); the frozen-store refusal and every journal/teardown failure
  /// are effect-time and surface on the task's `wait`.
  ///
  /// The leave is journaled before any network effect, and once the
  /// journal commits there is no abort: a crash or a restart mid-leave
  /// resumes from the durable record and completes the replacement, so
  /// the node never boots as the former identity again. Treat this as
  /// the point of no return for that node slot: the outcome names the
  /// exact former and replacement identities, and the same storage
  /// restarted afterwards boots the replacement.
  pub async fn leave(
    &self, acknowledgement: ReplaceIdentityAndDeleteOldCoreMetadata,
  ) -> Result<Task<LeaveOutcome>> {
    crate::runtime::leave(self.runtime.admit()?, acknowledgement).await
  }

  /// Connects to an already-admitted peer using key trust only: no
  /// join credential is consulted or required, the expected peer's
  /// trusted identity binding gates the handshake, and the negotiated
  /// feature policy is the same exact offer/selection machinery as a
  /// join.
  ///
  /// Typed dial contract: a peer whose trusted binding has not spread
  /// to this node yet fails with [`crate::ErrorKind::NotFound`] — a
  /// retryable convergence state that the runtime's healing planes
  /// (recovery, connection-degree maintenance) also absorb on their own
  /// cadence. A contradicted or revoked binding, or any handshake
  /// failure, is [`crate::ErrorKind::AuthenticationFailed`] or
  /// [`crate::ErrorKind::Revoked`] and is never retryable.
  ///
  /// Returns the admitted [`Task`], whose `wait` resolves with the
  /// authenticated peer. Admission-time failures are the pure shape
  /// checks (a stopped node, an endpoint whose transport selector does
  /// not resolve); the dial and handshake failures are effect-time and
  /// surface on the task's `wait`.
  pub async fn connect(&self, receiver: Endpoint, peer: NodeId) -> Result<Task<NodeId>> {
    crate::runtime::connect(&self.extensions, self.runtime.admit()?, receiver, peer).await
  }

  /// Closes the authenticated session to one peer: the session is torn
  /// down by the admitted task and the peer leaves the recovery plane
  /// until a later session restores it. The peer's membership (binding
  /// and descriptor) is untouched — to end a membership, use the leave
  /// flow instead.
  ///
  /// The verb's only failure is the admission-time shutdown gate; the
  /// teardown itself is idempotent (a peer with no session is not an
  /// error), so a `wait` on the task fails only with a store or session
  /// table failure.
  pub async fn disconnect(&self, peer: NodeId) -> Result<Task<()>> {
    crate::runtime::disconnect(self.runtime.admit()?, peer).await
  }

  /// Updates the local node's own descriptor (owner-only node
  /// metadata): endpoint candidates and capability labels are applied at
  /// a strictly higher revision than `expected_revision`, and the updated
  /// member view is returned. Same-revision or stale expectations
  /// conflict.
  pub async fn patch_metadata(
    &self, expected_revision: u64, patch: NodeMetadataPatch,
  ) -> Result<MemberView> {
    self
      .runtime
      .send_command(move |reply| Control::UpdateNodeMetadata {
        expected_revision,
        patch,
        reply,
      })
      .await
  }

  // -- identity, trust, and cleanup ------------------------------------

  /// Revokes one exact subject binding's connection and admission
  /// authority: a durable local authorization boundary that
  /// closes the identity's sessions and rejects its new sessions, raw
  /// grants, and admissions — without deleting or reinterpreting any
  /// stored metadata. `expected_key` pins the exact trusted binding so a
  /// stale or substituted revocation fails closed. Returns the admitted
  /// [`Task`], whose `wait` resolves with the outcome (already-revoked is
  /// a success, not an error).
  ///
  /// Admission-time failures are the pure shape checks only (a stopped
  /// node); the frozen-store refusal, the self-subject refusal, and the
  /// expected-key pin are effect-time and surface on the task's `wait`.
  pub async fn revoke(
    &self, subject: NodeId, expected_key: PublicKey,
  ) -> Result<Task<RevokeOutcome>> {
    crate::runtime::revoke(self.runtime.admit()?, subject, expected_key).await
  }

  /// Explicitly clears the local revocation record for one subject.
  /// Local-only and idempotent. Returns the admitted [`Task`], whose
  /// `wait` resolves once the record is gone.
  ///
  /// Admission-time failures are the pure shape checks only (a stopped
  /// node); the frozen-store refusal is effect-time and surfaces on the
  /// task's `wait`.
  pub async fn purge_revocation(&self, subject: NodeId) -> Result<Task<()>> {
    crate::runtime::purge_revocation(self.runtime.admit()?, subject).await
  }

  /// Issues a convergent issuer-signed cleanup tombstone for one
  /// decommissioned node. Terminal: there is no
  /// resurrection path. The caller is responsible for never cleaning a
  /// node that is merely offline. Returns the admitted [`Task`], whose
  /// `wait` resolves once the tombstone is persisted.
  ///
  /// Admission-time failures are the pure shape checks only (a stopped
  /// node); the frozen-store refusal and the self-subject refusal are
  /// effect-time and surface on the task's `wait`.
  pub async fn cleanup(&self, subject: NodeId) -> Result<Task<()>> {
    crate::runtime::cleanup(self.runtime.admit()?, subject).await
  }

  /// Starts a new cleanup checkpoint GC epoch at the current wall
  /// clock. Max-wins: a stored checkpoint with a higher
  /// watermark survives. The library enforces the convergence
  /// precondition itself: the issue is refused with
  /// [`crate::ErrorKind::NotReady`] while any known member other than
  /// self whose removal record is not terminal (left or cleaned) lacks a
  /// live authenticated session, because tombstones that member has not
  /// received yet could be collected by the new epoch. Re-issue once the
  /// member is connected. Returns the admitted [`Task`], whose `wait`
  /// resolves with the persisted watermark.
  ///
  /// Admission-time failures are the pure shape checks only (a stopped
  /// node); the frozen-store refusal and the member-connectivity
  /// precondition are effect-time and surface on the task's `wait`.
  pub async fn issue_cleanup_checkpoint(&self) -> Result<Task<u64>> {
    crate::runtime::issue_cleanup_checkpoint(self.runtime.admit()?).await
  }

  /// Resolves a metadata store frozen on a pending journal whose
  /// durable provider evidence permanently contradicts the journal: the
  /// journaled record is present, but the provider proves no committed
  /// receipt for the journaled transaction, so every restart-based
  /// reconciliation re-derives the same contradiction and the store
  /// refuses all admission-sensitive operations.
  ///
  /// Restart-based reconciliation is the first remedy and stays
  /// authoritative whenever the evidence resolves; this command is the
  /// operator-confirmed last resort for the permanent-contradiction
  /// case. The acknowledgement asserts the interrupted journaled
  /// transaction did not durably commit; the node re-checks the durable
  /// evidence (a provider verdict that the transaction committed or
  /// digest-conflicted refuses the declaration and keeps the store
  /// frozen), then deletes the pending journal record for the frozen
  /// purpose in one atomic transaction and unfreezes the store. The
  /// resolution is durable: a restart after it reopens ready with no
  /// pending journal. There is deliberately no opposite declaration —
  /// without provider evidence there is nothing to anchor a
  /// "committed" override on.
  ///
  /// On a store that is not frozen on a resolvable pending journal — a
  /// ready store, an in-flight commit, or a freeze matching no durable
  /// journal record — the command fails typed without changing anything.
  /// Returns the admitted [`Task`], whose `wait` resolves once the store
  /// is unfrozen. The task is deliberately non-cancellable on shutdown:
  /// the resolution is one atomic store transaction.
  ///
  /// Admission-time failures are the pure shape checks (a stopped node,
  /// a missing acknowledgement marker); the store's evidence verdict on
  /// the declaration is effect-time and surfaces on the task's `wait`.
  pub async fn resolve_frozen_journal(
    &self, acknowledgement: DeclareInterruptedTransactionUncommitted,
  ) -> Result<Task<()>> {
    crate::runtime::resolve_frozen_journal(self.runtime.admit()?, acknowledgement).await
  }

  // -- maintenance and diagnostics -------------------------------------

  /// Forces one bounded immediate recovery cycle and returns its view.
  pub async fn start_recovery(&self) -> Result<RecoveryView> {
    self
      .runtime
      .send_command(|reply| Control::StartRecovery { reply })
      .await
  }

  /// The recovery plane's current observation: whether every known
  /// online member has an authenticated path, how many members remain
  /// unreachable, and when the next dial round is scheduled. The pull
  /// complement of the transient [`crate::RecoveryChanged`] event.
  pub async fn recovery(&self) -> Result<RecoveryView> {
    self
      .runtime
      .send_command(|reply| Control::GetRecovery { reply })
      .await
  }

  /// The connection-degree maintenance observation: the effective
  /// target degree, the live authenticated session count, and whether
  /// the target is met. The pull complement of the maintenance plane's
  /// work — the operator's signal for reading (and fixing) mesh health.
  pub async fn connection_degree(&self) -> Result<ConnectionDegreeView> {
    self
      .runtime
      .send_command(|reply| Control::GetConnectionDegree { reply })
      .await
  }

  /// The bounded observability snapshot: one snapshot of counters and
  /// flags, never an enumeration.
  pub async fn metrics(&self) -> Result<ObservabilitySnapshot> {
    self
      .runtime
      .send_command(|reply| Control::Observability { reply })
      .await
  }

  /// Applies receipt retention across the node's metadata store: every
  /// anchored receipt whose retention deadline has elapsed is forgotten
  /// through the cleanup state machine, and every other receipt is left
  /// exactly as it is. The pass is idempotent and latency bounded; issue
  /// it again while [`crate::ReceiptRetentionReport::remaining`] reports
  /// true. The recovery tick runs the same pass automatically on its
  /// sweep cadence; this forces one idempotent pass on demand (tests,
  /// operations, a bounded drain of a large backlog). Anchoring itself
  /// is the owning state machine's decision and is not performed here.
  pub async fn apply_receipt_retention(&self) -> Result<ReceiptRetentionReport> {
    self
      .runtime
      .send_command(|reply| Control::ApplyReceiptRetention { reply })
      .await
  }

  /// Runs one full sync round now — the membership maintenance tick
  /// plus the reconciliation plane's tick — exactly like a wall-clock
  /// tick, and completes when the round finishes. Convergence checks
  /// become deterministic: drive rounds, await each, then read the
  /// registers — no tick-cadence sleeps; the quiet ROOT rotation covers
  /// the alive set across consecutive rounds.
  pub fn sync(&self) -> impl Future<Output = Result<()>> + Send {
    let runtime = self.runtime.clone();
    async move {
      runtime
        .send_command(|reply| Control::RunSyncRound { reply })
        .await
    }
  }

  // -- observation and data plane --------------------------------------

  /// Subscribes to node events. Subscriptions are bounded and
  /// transient: a lagging subscriber observes `EventReceive::Lagged`
  /// and must re-read through the paged accessors.
  pub fn watch<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>> {
    if self.runtime.status() != NodeStatus::Running {
      return Err(Error::shutting_down("node events"));
    }
    Ok(self.events.subscribe::<E>(options))
  }

  /// Sends one whole body as a single stream and waits for the
  /// destination's admission acknowledgement — the one-shot form of
  /// [`NodeHandle::open_stream`] plus `send_sync`, with empty metadata.
  /// The returned [`DeliveryAck`] proves authenticated admission to the
  /// destination's bounded incoming stream, never durable retention,
  /// processing, or success.
  ///
  /// Callers needing stream metadata or the async (route-handle) form
  /// use [`NodeHandle::open_stream`] directly.
  pub fn send<S>(
    &self, target: StreamTarget, protocol: ProtocolTag, policy: StreamPolicy, body: S,
  ) -> BoxFuture<'static, Result<DeliveryAck>>
  where
    S: futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static, {
    match self.open_stream(target, protocol, policy, StreamMetadata::new()) {
      Ok(stream) => stream.send_sync(body),
      Err(error) => Box::pin(async move { Err(error) }),
    }
  }
}
