use std::sync::Arc;

use crate::{
  Endpoint, Error, Event, EventOptions, EventSubscription, MergeCredential, NodeId,
  NodeMetadataPatch, NodeStatus, OutboundStream, ProtocolTag, PublicKey, Result, ShutdownOutcome,
  ShutdownReason, StreamMetadata, StreamPolicy, StreamTarget, TraceId,
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
  /// ([`NodeHandle::credentials`]). Returns the merged membership view.
  pub async fn join(&self, receiver: Endpoint, credential: MergeCredential) -> Result<MergeView> {
    self
      .runtime
      .send_command(move |reply| Control::MergeCluster {
        receiver,
        credential,
        reply,
      })
      .await
  }

  /// Actively leaves the cluster: replaces the node's identity
  /// with a fresh node id and key, deletes the old identity's local core
  /// metadata and key through the journaled custody protocols, and shuts
  /// the node down with [`ShutdownReason::ActiveLeave`]. The explicit
  /// acknowledgement makes the identity replacement and metadata deletion
  /// a deliberate caller decision.
  ///
  /// The leave is journaled before any network effect, and once the
  /// journal commits there is no abort: a crash or a restart mid-leave
  /// resumes from the durable record and completes the replacement, so
  /// the node never boots as the former identity again. Treat this as
  /// the point of no return for that node slot: the returned
  /// [`LeaveOutcome`](crate::LeaveOutcome) names the exact former and
  /// replacement identities, and the same storage restarted afterwards
  /// boots the replacement.
  pub async fn leave(
    &self, acknowledgement: ReplaceIdentityAndDeleteOldCoreMetadata,
  ) -> Result<LeaveOutcome> {
    self
      .runtime
      .send_command(move |reply| Control::LeaveCluster {
        acknowledgement,
        reply,
      })
      .await
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
  pub async fn connect(&self, receiver: Endpoint, peer: NodeId) -> Result<NodeId> {
    self
      .runtime
      .send_command(move |reply| Control::ConnectMember {
        receiver,
        peer,
        reply,
      })
      .await
  }

  /// Closes the authenticated session to one peer: the session is torn
  /// down now and the peer leaves the recovery plane until a later
  /// session restores it. The peer's membership (binding and descriptor)
  /// is untouched — to end a membership, use the leave flow instead.
  pub async fn disconnect(&self, peer: NodeId) -> Result<()> {
    self
      .runtime
      .send_command(move |reply| Control::DisconnectPeer { peer, reply })
      .await
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
  /// stale or substituted revocation fails closed.
  pub async fn revoke(&self, subject: NodeId, expected_key: PublicKey) -> Result<RevokeOutcome> {
    self
      .runtime
      .send_command(move |reply| Control::RevokeNode {
        subject,
        expected_key,
        reply,
      })
      .await
  }

  /// Explicitly clears the local revocation record for one subject.
  /// Local-only and idempotent.
  pub async fn purge_revocation(&self, subject: NodeId) -> Result<()> {
    self
      .runtime
      .send_command(move |reply| Control::PurgeRevocation { subject, reply })
      .await
  }

  /// Issues a convergent issuer-signed cleanup tombstone for one
  /// decommissioned node. Terminal: there is no
  /// resurrection path. The caller is responsible for never cleaning a
  /// node that is merely offline.
  pub async fn cleanup(&self, subject: NodeId) -> Result<()> {
    self
      .runtime
      .send_command(move |reply| Control::CleanupNode { subject, reply })
      .await
  }

  /// Starts a new cleanup checkpoint GC epoch at the current wall
  /// clock. Max-wins: a stored checkpoint with a higher
  /// watermark survives. The library enforces the convergence
  /// precondition itself: the issue is refused with
  /// [`crate::ErrorKind::NotReady`] while any known member other than
  /// self whose removal record is not terminal (left or cleaned) lacks a
  /// live authenticated session, because tombstones that member has not
  /// received yet could be collected by the new epoch. Re-issue once the
  /// member is connected. Returns the persisted watermark.
  pub async fn issue_cleanup_checkpoint(&self) -> Result<u64> {
    self
      .runtime
      .send_command(|reply| Control::IssueCleanupCheckpoint { reply })
      .await
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
  pub async fn resolve_frozen_journal(
    &self, acknowledgement: DeclareInterruptedTransactionUncommitted,
  ) -> Result<()> {
    self
      .runtime
      .send_command(move |reply| Control::ResolveFrozenJournal {
        acknowledgement,
        reply,
      })
      .await
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

  /// Runs one full anti-entropy round now: pages the local membership
  /// and resource registers and pushes them over a fair window of the
  /// authenticated sessions (a small bounded fan-out per round, in
  /// rotation), exactly like a wall-clock tick, and completes when the
  /// round finishes. Convergence checks become deterministic: drive
  /// rounds, await each, then read the pages — no tick-cadence sleeps; a
  /// cluster denser than the window converges across consecutive rounds.
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
