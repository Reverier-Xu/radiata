//! Session-carried membership sync.
//!
//! An authenticated session carries bounded sync payloads in one
//! direction: a [`MembershipPage`] of node descriptors and the issuer's
//! trust bindings as keyset pages of the snapshot record. Entries are
//! trusted through the
//! authenticated session that delivered them; decoding checks
//! only canonical wire rules and bounded capacities. Every node refreshes
//! its own snapshot when its binding set changes, and every member pages
//! its local descriptors, so reciprocal trust, exact descriptors, and
//! topology converge over the same authenticated sessions the facade
//! observes.

use std::sync::Arc;

use minicbor::bytes::ByteVec;

use crate::{
  Error, IncomingStream, NodeId, ProtocolTag, Result,
  api::{BoxFuture, Entropy},
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::{
    lifecycle::LocalIdentityContext,
    trust::{
      TRUST_BINDINGS_PAGE_LIMIT, accept_snapshot, refresh_issuer_snapshot, store as trust_store,
    },
  },
  membership::page::{DEFAULT_PAGE_LIMIT, MembershipPage, sync as page_sync},
  runtime::RuntimeClient,
  session::stream::SessionTable,
};

/// The canonical protocol tag of the membership sync stream.
pub(crate) const MEMBERSHIP_SYNC_PROTOCOL: &str = "radiata.woooo.tech/protocols/membership-sync";

/// The wire schema of one sync payload.
const SYNC_PAYLOAD_SCHEMA: &str = "radiata.woooo.tech/schemas/membership-sync-payload-v1";

/// Payload kinds: a membership page of descriptors, or an issuer trust
/// snapshot (grant set).
pub(crate) const SYNC_KIND_PAGE: u8 = 1;
pub(crate) const SYNC_KIND_SNAPSHOT: u8 = 2;
pub(crate) const SYNC_KIND_LEAVE: u8 = 3;
pub(crate) const SYNC_KIND_CLEANUP: u8 = 4;
pub(crate) const SYNC_KIND_REVOCATION: u8 = 5;
pub(crate) const SYNC_KIND_CHECKPOINT: u8 = 6;
/// A leave-applied receipt: the applying peer confirms one leave record
/// persisted. Additive (post-0.1 peers only): peers that never send it
/// leave the announcement on its documented bounded-degradation path.
pub(crate) const SYNC_KIND_LEAVE_APPLIED: u8 = 7;

/// One sync payload: an encoded membership page, an encoded issuer trust
/// snapshot, or an encoded signed removal tombstone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SyncPayload {
  /// An encoded [`MembershipPage`].
  Page(ByteVec),
  /// One encoded issuer snapshot page.
  Snapshot(ByteVec),
  /// An encoded [`crate::identity::leave::LeaveRecordV1`].
  Leave(ByteVec),
  /// An encoded [`crate::identity::cleanup::CleanupRecordV1`].
  Cleanup(ByteVec),
  /// An encoded [`crate::identity::revocation::RevocationRecordV1`].
  Revocation(ByteVec),
  /// An encoded [`crate::identity::cleanup::CleanupCheckpointV1`].
  Checkpoint(ByteVec),
  /// The applying peer's receipt for one leave record, addressed to the
  /// leaver. A hint only: never re-forwarded, never stored, and absent
  /// from pre-receipt peers by design.
  LeaveApplied { node: NodeId },
}

impl SyncPayload {
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    let (kind, payload) = match self {
      Self::Page(encoded) => (SYNC_KIND_PAGE, encoded.clone()),
      Self::Snapshot(encoded) => (SYNC_KIND_SNAPSHOT, encoded.clone()),
      Self::Leave(encoded) => (SYNC_KIND_LEAVE, encoded.clone()),
      Self::Cleanup(encoded) => (SYNC_KIND_CLEANUP, encoded.clone()),
      Self::Revocation(encoded) => (SYNC_KIND_REVOCATION, encoded.clone()),
      Self::Checkpoint(encoded) => (SYNC_KIND_CHECKPOINT, encoded.clone()),
      Self::LeaveApplied { node } => (
        SYNC_KIND_LEAVE_APPLIED,
        ByteVec::from(node.as_str().as_bytes().to_vec()),
      ),
    };
    crate::sync_common::encode_sync_envelope(SYNC_PAYLOAD_SCHEMA, Some(kind), payload)
  }

  /// Decodes one payload, rejecting unknown schemas and kinds and any
  /// non-canonical encoding (fail closed).
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let (kind, payload) = crate::sync_common::decode_kinded_sync_envelope(
      bytes,
      SYNC_PAYLOAD_SCHEMA,
      "membership sync payload canonical form",
      "membership sync payload schema",
    )?;
    match kind {
      SYNC_KIND_PAGE => Ok(Self::Page(payload)),
      SYNC_KIND_SNAPSHOT => Ok(Self::Snapshot(payload)),
      SYNC_KIND_LEAVE => Ok(Self::Leave(payload)),
      SYNC_KIND_CLEANUP => Ok(Self::Cleanup(payload)),
      SYNC_KIND_REVOCATION => Ok(Self::Revocation(payload)),
      SYNC_KIND_CHECKPOINT => Ok(Self::Checkpoint(payload)),
      SYNC_KIND_LEAVE_APPLIED => Ok(Self::LeaveApplied {
        node: NodeId::parse(
          std::str::from_utf8(payload.as_ref())
            .map_err(|_| Error::invalid_input("membership sync payload kind"))?,
        )?,
      }),
      _ => Err(Error::invalid_input("membership sync payload kind")),
    }
  }
}

/// The core receiver of membership sync streams over authenticated
/// sessions. Entries are trusted through the session that delivered them;
/// decoding enforces canonical wire rules and bounded capacities before
/// install.
pub(crate) struct MembershipSyncConsumer {
  // Held weakly so the registry shared with a live node handle never pins
  // the node's metadata store after shutdown; a packet arriving after the
  // runtime dropped is rejected as shutting down.
  context: std::sync::Weak<LocalIdentityContext>,
  entropy: Arc<dyn Entropy>,
  events: Arc<crate::node::EventHub>,
  revision: crate::node::MemberRevisionSignal,
  leave_applied: LeaveAppliedSignal,
  // The live session table: persisting a revocation tombstone retires the
  // revoked identity's session on this node immediately.
  sessions: crate::session::stream::SessionTable,
}

impl std::fmt::Debug for MembershipSyncConsumer {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("MembershipSyncConsumer(..)")
  }
}

impl MembershipSyncConsumer {
  pub(crate) fn new(
    context: Arc<LocalIdentityContext>, entropy: Arc<dyn Entropy>,
    events: Arc<crate::node::EventHub>, revision: crate::node::MemberRevisionSignal,
    leave_applied: LeaveAppliedSignal, sessions: crate::session::stream::SessionTable,
  ) -> Self {
    Self {
      context: Arc::downgrade(&context),
      entropy,
      events,
      revision,
      leave_applied,
      sessions,
    }
  }
}

impl PacketConsumer for MembershipSyncConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      let source = packet.source().clone();
      let runtime = packet.reply_runtime();
      let bytes = crate::sync_common::drain_body(packet.body(), "membership sync body").await?;
      let payload = SyncPayload::decode(&bytes)?;
      let context = self
        .context
        .upgrade()
        .ok_or_else(|| Error::shutting_down("membership sync"))?;
      accept_payload(
        &context,
        self.entropy.clone(),
        &self.events,
        &self.revision,
        &self.leave_applied,
        &self.sessions,
        &runtime,
        &source,
        &payload,
      )
      .await
    })
  }
}

/// Emits the paired member-set change notification: the transient event
/// for live subscribers plus the persistent revision bump for watch-based
/// observers. The bump trails the persist, so a released watcher is
/// guaranteed the change is durable and query-visible.
fn member_changed(
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal, node: NodeId,
) {
  events.emit(crate::MemberChanged::new(node));
  revision.bump();
}

/// The leave-plane's applied-receipt signal: bumped once per durable
/// leave-record install on this node (the node itself being the record's
/// subject). [`announce_leave`] parks on it so the announcement resolves
/// on durable application instead of mere admission.
#[derive(Clone, Debug, Default)]
pub(crate) struct LeaveAppliedSignal {
  notify: Arc<tokio::sync::Notify>,
}

impl LeaveAppliedSignal {
  pub(crate) fn new() -> Self {
    Self {
      notify: Arc::new(tokio::sync::Notify::new()),
    }
  }

  pub(crate) fn bump(&self) {
    self.notify.notify_one();
  }

  /// Arms and awaits one notification. The enable-before-await ordering
  /// inside keeps a bump that races the arming captured (Notify permits).
  pub(crate) async fn wait(&self) {
    let notified = self.notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    notified.await;
  }
}

/// The bounded wait for the first leave-record admission acknowledgement:
/// five seconds, well inside the configured authentication deadline's
/// order of magnitude.
const LEAVE_ACK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The bounded wait for flushing the record bodies after the first
/// acknowledgement. Deliberately a fresh budget, not the ack wait's
/// remainder: a slow acknowledgement must not shrink the flush window
/// toward zero, or the record body dies in the outbound queue when the
/// teardown retires the sessions (at-most-once loss of terminal
/// evidence).
const LEAVE_FLUSH_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The leave-plane announcement: injects the
/// owner-signed leave record into every connected session and waits at
/// most [`LEAVE_ACK_WAIT`] for the first durable-install receipt
/// (post-receipt peers) or the first admission acknowledgement
/// (pre-receipt peers), then [`LEAVE_FLUSH_WAIT`] for the local flush of
/// the record bodies. The caller owns the record — signed exactly once
/// and journaled before this call, so re-drives cannot diverge from what
/// peers already hold. A timeout degrades to the documented silent
/// leave, which the cleanup path covers.
pub(crate) async fn announce_leave(
  context: &LocalIdentityContext, entropy: &Arc<dyn Entropy>,
  record: &crate::identity::leave::LeaveRecordV1, sessions: &crate::session::stream::SessionTable,
  routes: &crate::routing::RouteTable, events: &Arc<crate::node::EventHub>,
  leave_applied: &LeaveAppliedSignal,
) -> Result<()> {
  let peers = crate::sync_common::alive_peers(sessions)?;
  if peers.is_empty() {
    // The documented silent-leave degradation, made audible: without
    // this line a silent leave is indistinguishable from a lost log
    // line.
    crate::audit::leave_announcement_skipped();
    return Ok(());
  }
  crate::audit::leave_announcement_started(peers.len());
  let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
  let encoded = SyncPayload::Leave(minicbor::bytes::ByteVec::from(record.encode()?)).encode()?;
  let acked = std::sync::Arc::new(tokio::sync::Notify::new());
  // Register the applied-receipt interest before any pump runs: the
  // enable-before-check ordering closes the lost-wakeup window against
  // an apply that completes while the wait is being armed.
  let (resolved_tx, resolved_rx) = tokio::sync::oneshot::channel();
  let applied_signal = leave_applied.clone();
  let acked_waiter = acked.clone();
  tokio::spawn(async move {
    // The receipt is the durable outcome; an admission acknowledgement is
    // the pre-receipt-peer outcome. Notify permits make the arming race
    // against a fast receipt harmless.
    let applied = tokio::select! {
      _ = applied_signal.wait() => true,
      _ = acked_waiter.notified() => false,
    };
    let _ = resolved_tx.send(applied);
  });
  let local = context.identity().node().clone();
  let mut pumps = Vec::new();
  for peer in peers {
    let entry = sessions
      .lock()
      .map_err(crate::Error::session_table)?
      .get(&peer)
      .cloned()
      .filter(|entry| entry.alive());
    // A peer without a live session is skipped: the bounded wait covers
    // the rest, and a lost announcement degrades to a silent leave.
    let Some(entry) = entry else {
      continue;
    };
    let (ack, pump) = crate::sync_common::send_pumped_payload(
      crate::sync_common::PumpContext {
        entry,
        local: &local,
        routes,
        events,
      },
      entropy,
      &peer,
      &protocol,
      &encoded,
    )?;
    let acked = std::sync::Arc::clone(&acked);
    tokio::spawn(async move {
      if matches!(ack.await, Ok(Ok(_))) {
        acked.notify_one();
      }
    });
    pumps.push(pump);
  }
  if pumps.is_empty() {
    // Every alive-peer entry died between the table read and the pump
    // setup: the same silent-leave degradation as above.
    crate::audit::leave_announcement_skipped();
    return Ok(());
  }
  let deadline = tokio::time::Instant::now() + LEAVE_ACK_WAIT;
  // The wait resolves on whichever lands first: the applied receipt (the
  // durable outcome) or an admission acknowledgement (pre-receipt peers).
  // Neither lands inside the budget: the documented silent-leave
  // degradation. The journaled record keeps the leave retryable.
  let applied_in_time = tokio::time::timeout_at(deadline, resolved_rx)
    .await
    .ok()
    .and_then(|resolved| resolved.ok())
    .unwrap_or(false);
  tracing::debug!(
    applied = applied_in_time,
    "leave announcement wait completed"
  );
  // Drain the pumps with their own fresh budget so the record bodies
  // are flushed before the leave's network teardown retires the
  // sessions, regardless of how long the acknowledgement took.
  let flush_deadline = tokio::time::Instant::now() + LEAVE_FLUSH_WAIT;
  for pump in pumps {
    let _ = tokio::time::timeout_at(flush_deadline, pump).await;
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn accept_payload(
  context: &Arc<LocalIdentityContext>, entropy: Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
  leave_applied: &LeaveAppliedSignal, sessions: &crate::session::stream::SessionTable,
  runtime: &RuntimeClient, source: &NodeId, payload: &SyncPayload,
) -> Result<()> {
  let store = context.store();
  // The three tombstone lanes verify against the same trusted-binding
  // set: one load per payload covers every tombstone arm (the snapshot
  // lane keeps its own accept policy inside the trust module).
  let tombstone_bindings = if matches!(
    payload,
    SyncPayload::Leave(_) | SyncPayload::Cleanup(_) | SyncPayload::Revocation(_)
  ) {
    Some(trust_store::trusted_bindings(store).await?)
  } else {
    None
  };
  match payload {
    SyncPayload::Page(encoded) => {
      let page = MembershipPage::decode(encoded.as_ref())?;
      // Every newly installed descriptor is one member change.
      let installed = page_sync::apply_page_ctx(store, entropy.as_ref(), &page).await?;
      for descriptor in page.descriptors() {
        if installed.contains(descriptor.node()) {
          // The audit event is the propagation path proof: a
          // descriptor exists on this peer only because this page
          // carried it.
          crate::audit::descriptor_installed(descriptor.node().as_str(), descriptor.revision());
          member_changed(events, revision, descriptor.node().clone());
        }
      }
    }
    SyncPayload::Snapshot(encoded) => {
      let page = crate::identity::trust::TrustSnapshotPage::decode(encoded.as_ref())?;
      // The trust adoption policy lives in the trust module: issuer key
      // verification and per-binding adoption (a delivered snapshot page
      // is never persisted; only the issuer's own refresh persists one).
      accept_snapshot(store, entropy.as_ref(), &page).await?;
    }
    SyncPayload::Leave(encoded) => {
      // An owner-signed leave record is terminal evidence: verified
      // against the permanently retained binding
      // before any persistence. A record whose binding has not converged
      // yet is skipped; the resend cadence heals the ordering.
      let record = crate::identity::leave::LeaveRecordV1::decode(encoded.as_ref())?;
      let Some(bindings) = tombstone_bindings.as_ref() else {
        // Unreachable: the Leave arm pre-loads the tombstone binding set.
        return Err(Error::internal("tombstone bindings"));
      };
      let Some(bound_key) = bindings.get(record.node()) else {
        tracing::debug!(node = %record.node(), "leave record skipped: binding unknown");
        return Ok(());
      };
      if bound_key != record.public_key() {
        return Err(Error::not_trusted("leave record binding"));
      }
      // The writer exclusion serializes the persist against every other
      // store writer, so terminal evidence cannot be dropped on contention.
      // A persist failure must be attributable at the apply site: the
      // sender keeps forwarding the record (the resend cadence heals), so
      // an unlogged failure here looks like a receiver-side roster stall.
      if let Err(error) =
        crate::identity::leave::persist_leave_record_ctx(store, entropy.as_ref(), &record).await
      {
        tracing::debug!(
          node = %record.node(),
          kind = ?error.kind(),
          "leave record persist failed"
        );
        return Err(error);
      }
      crate::audit::leave_record_persisted(record.node().as_str());
      member_changed(events, revision, record.node().clone());
      let receipt = SyncPayload::LeaveApplied {
        node: record.node().clone(),
      }
      .encode()?;
      let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
      // The applied receipt: one durable-install confirmation back to
      // the leaver, best-effort and retried by the announcement budget.
      // Pre-receipt peers simply never send it. The admission ack is
      // still observed (delivery truth): the wait runs detached so
      // the pump never serializes behind it, and a failed admission is
      // diagnostics only — the receipt is a hint, never a trust
      // decision, and is never retried here.
      match crate::sync_common::send_payload(runtime, &entropy, source, &protocol, &receipt).await {
        Ok(ack) => {
          let peer = source.clone();
          tokio::spawn(async move {
            if !crate::sync_common::delivered_within_bound(ack).await {
              tracing::debug!(peer = %peer.as_str(), "leave applied receipt not admitted");
            }
          });
        }
        Err(error) => {
          tracing::debug!(kind = ?error.kind(), "leave applied receipt skipped");
        }
      }
    }
    SyncPayload::LeaveApplied { node } => {
      // A receipt is a hint addressed to the record's subject only:
      // fail-open for every other receiver, and never a trust decision.
      if *node != *context.identity().node() {
        return Ok(());
      }
      leave_applied.bump();
    }
    SyncPayload::Cleanup(encoded) => {
      // An issuer-signed cleanup tombstone is terminal evidence: verified
      // against the retained issuer and subject
      // bindings before any persistence. A tombstone whose bindings have
      // not converged yet is skipped; the resend cadence heals ordering.
      let record = crate::identity::cleanup::CleanupRecordV1::decode(encoded.as_ref())?;
      let Some(bindings) = tombstone_bindings.as_ref() else {
        // Unreachable: the Cleanup arm pre-loads the tombstone binding set.
        return Err(Error::internal("tombstone bindings"));
      };
      if !bindings.contains_key(record.issuer()) || !bindings.contains_key(record.subject()) {
        tracing::debug!(subject = %record.subject(), "cleanup record skipped: bindings unknown");
        return Ok(());
      }
      crate::identity::cleanup::persist_cleanup_record_ctx(store, entropy.as_ref(), &record)
        .await?;
      member_changed(events, revision, record.subject().clone());
    }
    SyncPayload::Revocation(encoded) => {
      // A revocation tombstone is convergent permanent evidence: verified
      // against the retained issuer and subject
      // bindings before any persistence, never covered by checkpoints, and
      // never re-adoptable away. A tombstone whose bindings have not
      // converged yet is skipped; the resend cadence heals ordering.
      let record = crate::identity::revocation::RevocationRecordV1::decode(encoded.as_ref())?;
      let Some(bindings) = tombstone_bindings.as_ref() else {
        // Unreachable: the Revocation arm pre-loads the tombstone binding set.
        return Err(Error::internal("tombstone bindings"));
      };
      if !bindings.contains_key(record.issuer()) || !bindings.contains_key(record.subject()) {
        tracing::debug!(subject = %record.subject(), "revocation record skipped: bindings unknown");
        return Ok(());
      }
      crate::identity::revocation::persist_revocation_ctx(store, entropy.as_ref(), &record).await?;
      events.emit(crate::NodeRevoked::new(record.subject().clone()));
      // A persisted revocation closes the authorization boundary
      // immediately on this node too: retire any live session with the
      // revoked identity (its recovery dials race the propagation, so a
      // session admitted before this tombstone landed must not linger).
      crate::session::stream::retire_session(sessions, record.subject())?;
    }
    SyncPayload::Checkpoint(encoded) => {
      // A cleanup checkpoint is unsigned hygiene knowledge: max-wins by
      // watermark, never gating live entries or
      // revocations.
      let checkpoint = crate::identity::cleanup::CleanupCheckpointV1::decode(encoded.as_ref())?;
      crate::identity::cleanup::persist_checkpoint_ctx(store, entropy.as_ref(), &checkpoint)
        .await?;
    }
  }
  Ok(())
}

/// The protocol definition that gates the sync stream on authenticated
/// sessions: owned by the data-messages feature both sides select.
pub(crate) fn sync_protocol_definition() -> Result<ProtocolDefinition> {
  Ok(ProtocolDefinition::new(
    ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?,
    crate::FeatureTag::parse(crate::protocol::feature::DATA_MESSAGES)?,
  ))
}

/// Ensures the local descriptor exists (revision 1) with the given
/// endpoint candidates, so the anti-entropy tick can page it. An install
/// or an endpoint change advances the store's descriptor revision — a
/// member-set change — so the paired member-set notification fires here:
/// the transient [`crate::MemberChanged`] event plus the persistent
/// revision bump, keeping the revision counter's one-to-one promise.
pub(crate) async fn ensure_local_descriptor(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>, endpoints: Vec<crate::Endpoint>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
) -> Result<()> {
  let store = context.store();
  let node = context.identity().node().clone();
  let public_key = context.identity().public_key().clone();
  let existing = crate::membership::store::read_descriptor_ctx(store, &node).await?;
  let changed = match &existing {
    Some(current) => {
      let same_endpoints = current.endpoints().len() == endpoints.len()
        && current
          .endpoints()
          .iter()
          .zip(&endpoints)
          .all(|(left, right)| left == right);
      if same_endpoints {
        false
      } else if endpoints.is_empty() {
        // An empty candidate set never downgrades published endpoints:
        // the startup tick fires before any listener exists and must not
        // bump the revision (descriptor endpoint stability).
        return Ok(());
      } else {
        true
      }
    }
    None => true,
  };
  if !changed {
    return Ok(());
  }
  let descriptor_revision = existing
    .as_ref()
    .map_or(1, |current| current.revision().saturating_add(1));
  let descriptor = crate::membership::NodeDescriptorV1::new(
    node.clone(),
    public_key,
    endpoints,
    descriptor_revision,
    false,
    1,
  );
  if let Err(error) =
    crate::membership::store::store_descriptor_ctx(store, entropy.as_ref(), &descriptor).await
  {
    // A concurrent caller may have installed the same descriptor between
    // the read and the commit (every public operation ensures the local
    // descriptor first). The ensure is idempotent: the conflict is
    // acceptable only when the descriptor now exists at revision >= ours
    // for this exact node and key.
    let installed = crate::membership::store::read_descriptor_ctx(store, &node)
      .await?
      .map(|current| current.revision() >= descriptor_revision)
      .unwrap_or(false);
    if !installed {
      return Err(error);
    }
  }
  // The member set genuinely changed (the local descriptor was installed
  // or its endpoint set moved): fire the paired notification so a watcher
  // that subscribes before acting never misses the bump.
  member_changed(events, revision, node);
  Ok(())
}

/// The driver's per-peer anti-entropy continuation state, tracked
/// separately for every alive peer: the state is dropped when a peer's
/// session is gone, so the returning peer's first round re-delivers
/// everything it missed — including writes made while it was
/// partitioned away.
#[derive(Debug, Default)]
pub(crate) struct MembershipSyncCursors {
  peers: std::collections::BTreeMap<NodeId, PeerSyncState>,
  /// The rotation continuation point: the last peer the previous round
  /// served, so consecutive rounds cover the alive set fairly while each
  /// round's dispatch stays bounded (see
  /// [`crate::sync_common::SYNC_PEERS_PER_ROUND`]).
  rotation: Option<NodeId>,
  /// The register-install epoch at this driver's last tick: any advance
  /// since then means a local store write (a caller write, an applied
  /// page, a persisted tombstone, a snapshot refresh) may belong in some
  /// peer's diff, so every walk arms and pushes the diff within one tick
  /// per hop instead of one detection cadence per hop.
  install_epoch: u64,
}

/// One peer's membership anti-entropy state: the descriptor and trust
/// planes' shared watermark walks (see
/// [`crate::sync_common::WatermarkWalk`]) plus the tombstone plane's
/// confirmed set. Every plane sends only what the peer is missing —
/// the git remote-tracking model — so a changed row costs one diff row
/// per peer per hop, never a whole-catalog pass (the 2026-10 audit's
/// 98% redundancy finding against the whole-catalog fingerprint
/// rounds this replaced).
#[derive(Debug, Clone)]
pub(crate) struct PeerSyncState {
  /// The descriptor plane's watermark walk over the node's descriptor
  /// catalog: diff pages only, detection cadence shared with the
  /// resource lane.
  descriptors: crate::sync_common::WatermarkWalk<Vec<u8>>,
  /// The trust plane's watermark walk over the local issuer snapshot's
  /// binding set. Bindings are append-only and adopted per record, so a
  /// missing binding in a diff page is never a removal (removals retire
  /// through the tombstone planes), and the digest filter is exact.
  trust: crate::sync_common::WatermarkWalk<NodeId>,
  /// The digests of tombstone payloads this peer has admitted, paired
  /// with the dispatched-round counter since the last confirmation
  /// refresh: a confirmed tombstone is not re-forwarded until
  /// [`TOMBSTONE_CONFIRM_REFRESH_TICKS`] ticks have passed (bounded by
  /// [`TOMBSTONE_CONFIRMED_CAP`]; overflow clears the set for a full
  /// re-forward — bounded memory over bounded re-delivery). Admission
  /// is not application: a receiver skips a tombstone whose bindings
  /// have not converged yet (the leave/revocation evidence out-runs its
  /// subject's binding on a fresh peer), so the confirmations expire on
  /// a slow roll and the set re-forwards — the old design's every-
  /// cadence resend, at an eighth of its cadence and zero traffic in
  /// between.
  confirmed_tombstones: std::collections::BTreeSet<u64>,
  /// Ticks since the last confirmation refresh: the confirmed set
  /// expires when it reaches
  /// [`TOMBSTONE_CONFIRM_REFRESH_TICKS`].
  tombstone_ticks: u32,
  /// Ticks since this peer's last fully delivered tombstone round: a
  /// lost payload retries on this cadence with only the unconfirmed
  /// remainder. Advances every tick, independent of the page planes.
  ticks_since_tombstone_send: u32,
}

impl Default for PeerSyncState {
  fn default() -> Self {
    Self {
      descriptors: crate::sync_common::WatermarkWalk::new(
        crate::sync_common::DETECTION_CADENCE_TICKS,
      ),
      trust: crate::sync_common::WatermarkWalk::new(SNAPSHOT_RESEND_TICKS),
      confirmed_tombstones: std::collections::BTreeSet::new(),
      tombstone_ticks: 0,
      // A fresh peer is immediately due its first tombstone round: the
      // confirmed set is empty, so the full bounded set forwards at
      // once.
      ticks_since_tombstone_send: SNAPSHOT_RESEND_TICKS,
    }
  }
}

/// The bounded number of known leave records forwarded per snapshot
/// round (anti-entropy healing without unbounded per-tick work).
const LEAVE_RESEND_CAP: usize = 64;

/// Confirmed tombstone digests held per peer before the set resets to a
/// full re-forward: the loaded tombstone set is bounded by
/// [`LEAVE_RESEND_CAP`] plus one checkpoint, so this cap never binds in
/// practice — it only guards a slow leak if the loading policy ever
/// changes.
const TOMBSTONE_CONFIRMED_CAP: usize = LEAVE_RESEND_CAP + 16;

/// Ticks between tombstone-confirmation refreshes: after this many
/// ticks the peer's confirmed set expires and the next cadence round
/// re-forwards the whole bounded set, healing the admitted-but-not-
/// applied divergence (a tombstone skipped because its bindings had
/// not converged yet). Binding deliveries to the peer also expire the
/// set (see `apply_round_effects`), which makes the common case heal
/// within a round; this tick roll is the backstop for a binding the
/// peer learned from a third party.
const TOMBSTONE_CONFIRM_REFRESH_TICKS: u32 = SNAPSHOT_RESEND_TICKS * 2;

/// The trust and tombstone planes' shared detection cadence (ticks): a
/// quiet peer's binding walk re-runs on it — an in-memory digest walk
/// that emits nothing when every binding matches — and unconfirmed
/// tombstones retry on it. The descriptor plane runs on the page
/// lanes' shared cadence (single-sourced in [`crate::sync_common`]).
const SNAPSHOT_RESEND_TICKS: u32 = 8;

/// The tombstone forwarding decision for one peer round: unconfirmed
/// tombstones exist and the slow cadence elapsed (a fresh peer, or the
/// epoch arm after a local persist, starts at the threshold, so new
/// evidence forwards immediately). The decision is snapshot-INDEPENDENT
/// — a degraded snapshot leg (refresh failing) must never stall
/// tombstone propagation, because the tombstones are what retire
/// removed identities on peers.
fn tombstone_round_due(unconfirmed: usize, ticks_since_send: u32) -> bool {
  unconfirmed > 0 && ticks_since_send >= SNAPSHOT_RESEND_TICKS
}

/// The peers of one round whose payload verdicts are still unresolved:
/// each plane's walk holds its own pending page, and the tombstone plane
/// holds its unconfirmed remainder, so an in-flight plane skips its
/// peers this round (their walk state is neither committed nor rewound
/// yet).
#[derive(Clone, Copy, Default)]
pub(crate) struct PeerPlanesInFlight {
  pub(crate) tombstones: bool,
  pub(crate) descriptors: bool,
  pub(crate) trust: bool,
}

/// Per-peer in-flight planes, consulted by the next round's dispatch.
pub(crate) type InFlightRounds = std::collections::BTreeMap<NodeId, PeerPlanesInFlight>;

/// The unsettled delivery verdicts of one dispatched membership round.
/// The round returns after handing every payload to the wire; the owner
/// settles it when the verdicts resolve — inline for the deterministic
/// seam (the `RunSyncRound` command), detached for the periodic driver,
/// whose next round harvests the effects without holding the tick open
/// for the slowest peer's ack.
pub(crate) struct MembershipPendingRound {
  tombstone_acks: Vec<(
    NodeId,
    u64,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )>,
  page_acks: Vec<(
    NodeId,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )>,
  trust_acks: Vec<(
    NodeId,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )>,
}

impl MembershipPendingRound {
  /// The peers with unresolved verdicts and their planes: the skip set
  /// the next round's dispatch must respect (a plane's walk holds its
  /// pending page until the verdict settles it).
  pub(crate) fn in_flight(&self) -> InFlightRounds {
    let mut in_flight = InFlightRounds::new();
    for (peer, ..) in &self.tombstone_acks {
      in_flight.entry(peer.clone()).or_default().tombstones = true;
    }
    for (peer, _) in &self.page_acks {
      in_flight.entry(peer.clone()).or_default().descriptors = true;
    }
    for (peer, _) in &self.trust_acks {
      in_flight.entry(peer.clone()).or_default().trust = true;
    }
    in_flight
  }

  /// Awaits every verdict (concurrently per plane) and folds them into
  /// the round's cursor effects.
  pub(crate) async fn settle(self) -> MembershipRoundEffects {
    // Delivery verdicts resolve concurrently: one unreachable peer must
    // not serialize the settlement behind its ack wait (that would make
    // the convergence bound liveness teardown, not the anti-entropy
    // cadence).
    let (tombstone_verdicts, page_verdicts, trust_verdicts) = futures_util::future::join3(
      futures_util::future::join_all(self.tombstone_acks.into_iter().map(
        |(peer, digest, ack)| async move {
          (
            peer,
            digest,
            crate::sync_common::delivered_within_bound(ack).await,
          )
        },
      )),
      futures_util::future::join_all(self.page_acks.into_iter().map(|(peer, ack)| async move {
        (peer, crate::sync_common::delivered_within_bound(ack).await)
      })),
      futures_util::future::join_all(self.trust_acks.into_iter().map(|(peer, ack)| async move {
        (peer, crate::sync_common::delivered_within_bound(ack).await)
      })),
    )
    .await;
    MembershipRoundEffects {
      tombstone_verdicts,
      page_verdicts,
      trust_verdicts,
    }
  }
}

/// The verdict effects of one dispatched round, ready to apply to the
/// cursors.
pub(crate) struct MembershipRoundEffects {
  tombstone_verdicts: Vec<(NodeId, u64, bool)>,
  page_verdicts: Vec<(NodeId, bool)>,
  trust_verdicts: Vec<(NodeId, bool)>,
}

/// Applies one settled round's verdict effects to the cursors: a page
/// verdict settles its walk (delivered commits the marks and boundary,
/// undelivered rewinds to the page's scan start), a delivered tombstone
/// confirms its digest (never re-forwarded), and a fully delivered
/// tombstone round re-arms the resend cadence. An undelivered page
/// resets nothing beyond the rewind, so the next tick retries exactly
/// that range.
pub(crate) fn apply_round_effects(
  cursors: &mut MembershipSyncCursors, effects: MembershipRoundEffects,
) {
  for (peer, digest, delivered) in effects.tombstone_verdicts {
    if let Some(state) = cursors.peers.get_mut(&peer)
      && delivered
    {
      if state.confirmed_tombstones.len() >= TOMBSTONE_CONFIRMED_CAP {
        state.confirmed_tombstones.clear();
      }
      state.confirmed_tombstones.insert(digest);
      state.ticks_since_tombstone_send = 0;
    }
  }
  for (peer, delivered) in effects.page_verdicts {
    if let Some(state) = cursors.peers.get_mut(&peer)
      && let Some(settled) = state.descriptors.settle_outcome(delivered)
      && settled.refreshed
    {
      crate::audit::membership_watermarks_refreshed(peer.as_str());
    }
  }
  for (peer, delivered) in effects.trust_verdicts {
    if let Some(state) = cursors.peers.get_mut(&peer) {
      let settled = state.trust.settle_outcome(delivered);
      if settled.is_some_and(|outcome| outcome.refreshed) {
        crate::audit::membership_watermarks_refreshed(peer.as_str());
      }
      if settled.is_some_and(|outcome| outcome.advanced) {
        // New binding evidence reached this peer: any tombstone it
        // skipped for a not-yet-known binding may apply now, so its
        // confirmations expire and the next cadence round re-forwards
        // the set (the common admitted-but-not-applied heal). A page
        // whose marks were all already known advances nothing and
        // leaves the confirmations alone.
        state.confirmed_tombstones.clear();
      }
    }
  }
}

/// The deterministic-seam consumption of one dispatched round: settle it
/// inline and apply the effects — the unit tests' consumption, with
/// settled cursor state on return. (The driver's `RunSyncRound` arm
/// settles through the harvested join handle instead: one mechanism,
/// two consumption policies.)
#[cfg(test)]
pub(crate) async fn settle_round(
  pending: MembershipPendingRound, cursors: &mut MembershipSyncCursors,
) {
  apply_round_effects(cursors, pending.settle().await);
}

/// The outcome of one per-peer membership round: the admission receivers
/// for every dispatched payload (grouped per plane so each lane's commit
/// is verdict-gated by the tick aggregator), and whether any payload
/// dispatched at all (a rejected dispatch fails the peer for this
/// round).
struct MembershipPeerRound {
  /// The round's tombstone payloads' digests paired with their admission
  /// receivers: a delivered digest confirms against the peer's set.
  tombstone_acks: Vec<(
    u64,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )>,
  /// The descriptor page's admission receiver: its verdict settles the
  /// peer's descriptor walk. A `None` beside dispatched bytes means the
  /// wire rejected the page: no pending entry landed, and the walk
  /// re-emits the same range next round.
  page_ack: Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  /// The trust page's admission receiver: its verdict settles the peer's
  /// trust walk.
  trust_ack: Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  dispatched: bool,
}

/// One dispatch prepared by a plane's walk: the encoded payload bytes
/// paired with the walk bookkeeping the delivery verdict settles.
struct PendingDispatch<K> {
  bytes: Vec<u8>,
  boundary: Option<K>,
  marks: Vec<(Vec<u8>, u64)>,
}

/// One per-peer membership anti-entropy step, mirroring the resource
/// lane's `resource_sync_tick_peer`: each plane's watermark walk decides
/// its own round — a quiet walk dispatches nothing at all (an unchanged
/// catalog, an unchanged binding set, a fully confirmed tombstone set),
/// and a due walk emits the next bounded diff page carrying only the
/// rows the peer is missing. The delivery verdicts are aggregated (and
/// walk commits gated) by the tick's caller.
#[allow(clippy::too_many_arguments)]
async fn membership_sync_tick_peer(
  catalog: &(dyn crate::provider::StoreSnapshot + '_), entropy: &Arc<dyn Entropy>,
  runtime: &RuntimeClient, peer: &NodeId, state: &mut PeerSyncState, protocol: &ProtocolTag,
  snapshot: Option<&crate::identity::trust::TrustSnapshotV1>, tombstones: &[(u64, Vec<u8>)],
  planes: PeerPlanesInFlight,
) -> Result<MembershipPeerRound> {
  // The tombstone cadence advances every tick — independent of the page
  // planes' (possibly multi-tick) passes — and is pulled back to zero
  // only by delivered tombstone verdicts in the tick's aggregator, so
  // an undelivered round retries on the cadence instead of waiting out
  // a full resend interval.
  state.ticks_since_tombstone_send = state.ticks_since_tombstone_send.saturating_add(1);
  state.tombstone_ticks = state.tombstone_ticks.saturating_add(1);

  // ---- the descriptor plane: one diff page over the catalog ----
  let mut page_dispatch: Option<PendingDispatch<Vec<u8>>> = None;
  if planes.descriptors {
    state.descriptors.quiet_tick();
  } else if state.descriptors.pass_due() {
    let emission = page_sync::emit_page_filtered_from_snapshot(
      catalog,
      state.descriptors.cursor().map(|value| value.as_slice()),
      DEFAULT_PAGE_LIMIT,
      crate::sync_common::SCAN_BUDGET_PER_TICK,
      state.descriptors.watermarks(),
    )
    .await?;
    match emission.page {
      Some(page) => {
        tracing::debug!(
          peer = %peer,
          descriptors = page.descriptors().len(),
          "membership diff page emitted"
        );
        crate::audit::membership_page_emitted(page.descriptors().len());
        page_dispatch = Some(PendingDispatch {
          bytes: SyncPayload::Page(ByteVec::from(page.encode()?)).encode()?,
          boundary: emission.walk_cursor,
          marks: emission.marks,
        });
      }
      None => {
        // Nothing to deliver in this step: either the scan reached the
        // catalog end (the pass completes, the cadence restarts, and the
        // refresh counter advances) or a budget window closed
        // change-free mid-catalog (the pass continues from its boundary
        // next tick — closing there would strand every record behind
        // the window until the peer's state resets).
        if state.descriptors.step_quiet(emission.walk_cursor) {
          crate::audit::membership_watermarks_refreshed(peer.as_str());
        }
      }
    }
  } else {
    state.descriptors.quiet_tick();
  }

  // ---- the trust plane: one diff page over the issuer binding set ----
  // Bindings are append-only and adopted per record, so a diff page
  // never implies a removal (removals retire through the tombstone
  // planes) — the digest filter is exact over the binding set.
  let mut trust_dispatch: Option<PendingDispatch<NodeId>> = None;
  if planes.trust {
    state.trust.quiet_tick();
  } else if let Some(snapshot) = snapshot
    && state.trust.pass_due()
  {
    let emission = snapshot.filtered_page_after(
      state.trust.cursor(),
      TRUST_BINDINGS_PAGE_LIMIT,
      crate::sync_common::SCAN_BUDGET_PER_TICK,
      state.trust.watermarks(),
    );
    match emission.page {
      Some(page) => {
        tracing::debug!(
          peer = %peer,
          revision = snapshot.revision(),
          bindings = page.bindings().len(),
          "trust diff page emitted"
        );
        trust_dispatch = Some(PendingDispatch {
          bytes: SyncPayload::Snapshot(ByteVec::from(page.encode()?)).encode()?,
          boundary: emission.boundary,
          marks: emission.marks,
        });
      }
      None => {
        if state.trust.step_quiet(emission.boundary) {
          crate::audit::membership_watermarks_refreshed(peer.as_str());
        }
      }
    }
  } else {
    state.trust.quiet_tick();
  }

  // ---- the tombstone plane: only the peer's unconfirmed records ----
  // A degraded snapshot leg (refresh failing) never stalls this plane:
  // tombstone forwarding is snapshot-independent by contract.
  // The confirmation-expiry roll first: after
  // TOMBSTONE_CONFIRM_REFRESH_TICKS the confirmed set expires (admission
  // is not application — a receiver skips a tombstone whose bindings
  // have not converged yet — so the set re-forwards on a slow roll; see
  // `confirmed_tombstones`), which re-arms the round below with the
  // whole bounded set.
  if !planes.tombstones && state.tombstone_ticks >= TOMBSTONE_CONFIRM_REFRESH_TICKS {
    state.tombstone_ticks = 0;
    state.confirmed_tombstones.clear();
  }
  let unconfirmed: Vec<(u64, &[u8])> = if planes.tombstones {
    Vec::new()
  } else {
    tombstones
      .iter()
      .filter(|(digest, _)| !state.confirmed_tombstones.contains(digest))
      .map(|(digest, bytes)| (*digest, bytes.as_slice()))
      .collect()
  };
  let tombstone_payloads: Vec<&[u8]> =
    if tombstone_round_due(unconfirmed.len(), state.ticks_since_tombstone_send) {
      unconfirmed.iter().map(|(_, bytes)| *bytes).collect()
    } else {
      Vec::new()
    };

  // A round with nothing due on any plane dispatches nothing at all:
  // the planes' own triggers (a diff row, an unconfirmed tombstone, the
  // detection cadence) are the only reasons anything goes on the wire.
  if page_dispatch.is_none() && trust_dispatch.is_none() && tombstone_payloads.is_empty() {
    return Ok(MembershipPeerRound {
      tombstone_acks: Vec::new(),
      page_ack: None,
      trust_ack: None,
      dispatched: false,
    });
  }
  let (tombstone_ack_options, page_ack, trust_ack) = dispatch_to_peer(
    peer,
    trust_dispatch
      .as_ref()
      .map(|dispatch| dispatch.bytes.as_slice()),
    &tombstone_payloads,
    page_dispatch
      .as_ref()
      .map(|dispatch| dispatch.bytes.as_slice()),
    runtime,
    entropy,
    protocol,
  )
  .await;
  // The tombstone receivers pair with their digests by dispatch order:
  // a payload the queue rejected has no receiver and stays unconfirmed
  // for the next round.
  let tombstone_acks: Vec<(
    u64,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )> = unconfirmed
    .into_iter()
    .zip(tombstone_ack_options)
    .filter_map(|((digest, _), ack)| ack.map(|ack| (digest, ack)))
    .collect();
  // Each pending page lands in its walk only on an accepted dispatch: a
  // rejected dispatch never entered the walk (nothing to settle) — the
  // walk's cursor still sits at this step's scan start and its cadence
  // counter was never reset, so the next tick re-emits exactly the same
  // range.
  let page_ack = match (page_dispatch, page_ack) {
    (Some(dispatch), Some(ack)) => {
      state
        .descriptors
        .dispatched(dispatch.boundary, dispatch.marks);
      Some(ack)
    }
    (Some(_), None) => {
      crate::audit::membership_page_rewound(peer.as_str());
      None
    }
    (None, ack) => ack,
  };
  let trust_ack = match (trust_dispatch, trust_ack) {
    (Some(dispatch), Some(ack)) => {
      state.trust.dispatched(dispatch.boundary, dispatch.marks);
      Some(ack)
    }
    (Some(_), None) => {
      crate::audit::membership_page_rewound(peer.as_str());
      None
    }
    (None, ack) => ack,
  };
  Ok(MembershipPeerRound {
    tombstone_acks,
    page_ack,
    trust_ack,
    dispatched: true,
  })
}

/// One anti-entropy tick: publish the local descriptor, refresh the issuer
/// snapshot when this node is the creator, and push a bounded page plus the
/// latest snapshot over every authenticated session. The work per tick is
/// bounded: one page and one snapshot per session, nothing paged to
/// exhaustion. A snapshot refresh failure (an issuer binding set that
/// overflows the single-record control bound) skips only that round's
/// snapshot send: the descriptor-page and tombstone anti-entropy below
/// keeps running, so a large membership degrades the snapshot leg instead
/// of stalling every sync lane.
///
/// The tick returns after handing every due payload to the wire — the
/// delivery verdicts come back as the [`MembershipPendingRound`] the
/// caller settles (inline for the deterministic seam, detached for the
/// periodic driver). Peers listed in `in_flight` skip their in-flight
/// planes this round: their previous dispatch's cursors are not settled
/// yet.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>, sessions: &SessionTable,
  runtime: &RuntimeClient, local_endpoints: &[crate::Endpoint],
  cursors: &mut MembershipSyncCursors, in_flight: &InFlightRounds,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
) -> Result<Option<MembershipPendingRound>> {
  let store = context.store();
  // Nothing to advertise at startup: the supervisor publishes the local
  // descriptor (with endpoints) when a query or listener first needs it,
  // so the anti-entropy loop never races a transient empty endpoint set
  // into a revision bump.
  if !local_endpoints.is_empty() {
    ensure_local_descriptor(context, entropy, local_endpoints.to_vec(), events, revision).await?;
  }
  // Before any member is admitted the node's store writes are quiescent
  // (the supervisor's lazy paths publish the local descriptor on the first
  // public query), keeping the admission commit sequence deterministic for
  // fault-injecting providers.
  // Cheap membership probe: an early-exit bounded read instead of a
  // whole-population map on every tick.
  let has_members = trust_store::has_more_than_bindings(store, 1).await?;
  if !has_members {
    // No membership yet: no descriptors exist to anti-entropize.
    return Ok(None);
  }
  // A snapshot refresh or encode failure (a binding set that overflows
  // the single-record control bound) must not fail the whole tick: every
  // round would fail identically and descriptor-page, resource, and
  // tombstone anti-entropy would stall permanently. Log and skip this
  // round's snapshot send; the page plane below runs unchanged and the
  // cursor keeps its existing semantics (no revision recorded, the
  // resend cadence untouched while refresh fails).
  let snapshot = match refresh_issuer_snapshot(context, entropy).await {
    Ok(snapshot) => snapshot,
    Err(error) => {
      tracing::warn!(
        kind = ?error.kind(),
        "issuer snapshot refresh failed; skipping this round's snapshot send"
      );
      None
    }
  };
  // Removal tombstones (leave, cleanup) ride the same anti-entropy plane:
  // forward the known (bounded) sets whenever a snapshot round sends, so a
  // lost delivery heals on the resend cadence.
  let leave_records =
    crate::identity::leave::known_leave_records_ctx(store, LEAVE_RESEND_CAP).await?;
  let cleanup_records =
    crate::identity::cleanup::known_cleanup_records_ctx(store, LEAVE_RESEND_CAP).await?;
  let revocation_records =
    crate::identity::revocation::known_revocation_records_ctx(store, LEAVE_RESEND_CAP).await?;
  let local_checkpoint = crate::identity::cleanup::latest_checkpoint_millis_ctx(store)
    .await?
    .map(|watermark| {
      crate::identity::cleanup::CleanupCheckpointV1::new(
        watermark,
        context.identity().node().clone(),
      )
    });
  let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
  let peers = crate::sync_common::alive_peers(sessions)?;
  if peers.is_empty() {
    // Nothing can be delivered with no live sessions. Dropping the
    // per-peer state means a returning peer is caught up in full —
    // including everything written while it was unreachable — on its
    // first tick back.
    cursors.peers.clear();
    cursors.rotation = None;
    gc_collected_tombstones(store, entropy).await;
    return Ok(None);
  }
  cursors.peers.retain(|peer, _| peers.contains(peer));
  // One round serves a bounded, fair window of the alive set: per-round
  // dispatch cost is independent of the node's connection degree, so a
  // dense mesh cannot starve the runtime's shared task; the cursor keeps
  // every unserved peer's state so the next round resumes after this
  // window's last peer.
  let (window, rotation) = crate::sync_common::rotation_window(
    &peers,
    cursors.rotation.as_ref(),
    crate::sync_common::SYNC_PEERS_PER_ROUND,
  );
  cursors.rotation = rotation.cloned();
  // One snapshot per tick, shared by every per-peer round: a hub
  // catching up a hundred leaves pays one scan, not a hundred.
  let catalog = store.snapshot().await?;
  // A local store write since the last tick (a caller write, an applied
  // page, a persisted tombstone, a snapshot refresh) arms every peer's
  // walks and the tombstone cadence: the changed rows push within one
  // tick per hop instead of one detection cadence per hop — the
  // push-per-change that keeps multi-hop convergence from growing
  // linearly with path length. The watermark filters keep the pushed
  // pages diff-shaped, and a quiet steady state (no writes) walks
  // nothing between passes.
  let epoch = store.register_epoch();
  if epoch != cursors.install_epoch {
    cursors.install_epoch = epoch;
    for state in cursors.peers.values_mut() {
      state.descriptors.arm();
      state.trust.arm();
      state.ticks_since_tombstone_send = SNAPSHOT_RESEND_TICKS;
    }
  }
  // Tombstone wire bytes are peer-independent: encode once, digest
  // once. The per-peer rounds filter them through the peer's confirmed
  // set. The bytes are snapshot-INDEPENDENT: a failed refresh must
  // never stall this lane (the tombstones are what retire removed
  // identities on peers).
  let tombstones: Vec<(u64, Vec<u8>)> = {
    let mut out = Vec::with_capacity(
      leave_records.len() + cleanup_records.len() + revocation_records.len() + 1,
    );
    for record in &leave_records {
      let bytes = SyncPayload::Leave(ByteVec::from(record.encode()?)).encode()?;
      out.push((crate::sync_common::row_digest(&bytes), bytes));
    }
    for record in &cleanup_records {
      let bytes = SyncPayload::Cleanup(ByteVec::from(record.encode()?)).encode()?;
      out.push((crate::sync_common::row_digest(&bytes), bytes));
    }
    for record in &revocation_records {
      let bytes = SyncPayload::Revocation(ByteVec::from(record.encode()?)).encode()?;
      out.push((crate::sync_common::row_digest(&bytes), bytes));
    }
    if let Some(checkpoint) = &local_checkpoint {
      let bytes = SyncPayload::Checkpoint(ByteVec::from(checkpoint.encode()?)).encode()?;
      out.push((crate::sync_common::row_digest(&bytes), bytes));
    }
    out
  };
  if !leave_records.is_empty() || !cleanup_records.is_empty() {
    tracing::debug!(
      leave = leave_records.len(),
      cleanup = cleanup_records.len(),
      send = !tombstones.is_empty(),
      "removal tombstones considered for forwarding"
    );
  }
  let mut pending_tombstone_acks: Vec<(
    NodeId,
    u64,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )> = Vec::new();
  let mut pending_page_acks: Vec<(
    NodeId,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )> = Vec::new();
  let mut pending_trust_acks: Vec<(
    NodeId,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )> = Vec::new();
  for peer in window.iter().copied() {
    let state = cursors.peers.entry(peer.clone()).or_default();
    let round = membership_sync_tick_peer(
      catalog.as_ref(),
      entropy,
      runtime,
      peer,
      state,
      &protocol,
      snapshot.as_ref(),
      &tombstones,
      in_flight.get(peer).copied().unwrap_or_default(),
    )
    .await?;
    if !round.dispatched {
      // A quiet round with nothing due: the peer state already advanced.
      continue;
    }
    let MembershipPeerRound {
      tombstone_acks,
      page_ack,
      trust_ack,
      ..
    } = round;
    if tombstone_acks.is_empty() && page_ack.is_none() && trust_ack.is_none() {
      // Nothing was queued (the routing queue rejected outright): the
      // round never left this node. A rejected page never entered its
      // walk, so the next round re-emits the same range.
      continue;
    }
    pending_tombstone_acks.extend(
      tombstone_acks
        .into_iter()
        .map(|(digest, ack)| (peer.clone(), digest, ack)),
    );
    if let Some(ack) = page_ack {
      pending_page_acks.push((peer.clone(), ack));
    }
    if let Some(ack) = trust_ack {
      pending_trust_acks.push((peer.clone(), ack));
    }
  }
  gc_collected_tombstones(store, entropy).await;
  if pending_tombstone_acks.is_empty()
    && pending_page_acks.is_empty()
    && pending_trust_acks.is_empty()
  {
    return Ok(None);
  }
  Ok(Some(MembershipPendingRound {
    tombstone_acks: pending_tombstone_acks,
    page_acks: pending_page_acks,
    trust_acks: pending_trust_acks,
  }))
}

/// One dispatch attempt with the lane's shared rejection diagnostics: a
/// rejected payload resolves to `None` (the round's verdict aggregator
/// rewinds the lane), the failure lands in the debug log once, in one
/// place.
async fn dispatch_or_log(
  peer: &NodeId, payload: &[u8], runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>,
  protocol: &ProtocolTag,
) -> Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>> {
  match crate::sync_common::send_payload(runtime, entropy, peer, protocol, payload).await {
    Ok(ack) => Some(ack),
    Err(error) => {
      tracing::debug!(kind = ?error.kind(), "sync payload dispatch failed");
      None
    }
  }
}

/// The per-tick fan-out to one peer: sends every due payload in order
/// and returns their admission receivers — the tombstone receivers
/// aligned with the input payloads (a payload the queue rejected has
/// `None` at its slot and stays unconfirmed for the next round), the
/// trust page's receiver, and the descriptor page's receiver, so each
/// plane's commit is gated on its own delivery verdict. A payload
/// swallowed by a session that still looks alive never resolves its
/// receiver, which is exactly the signal the caller needs to re-deliver
/// from scratch.
async fn dispatch_to_peer(
  peer: &NodeId, trust_page: Option<&[u8]>, tombstones: &[&[u8]], page: Option<&[u8]>,
  runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>, protocol: &ProtocolTag,
) -> (
  Vec<Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>>,
  Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
) {
  let trust_ack = match trust_page {
    Some(payload) => dispatch_or_log(peer, payload, runtime, entropy, protocol).await,
    None => None,
  };
  let mut tombstone_acks = Vec::with_capacity(tombstones.len());
  for payload in tombstones {
    tombstone_acks.push(dispatch_or_log(peer, payload, runtime, entropy, protocol).await);
  }
  let page_ack = match page {
    Some(payload) => dispatch_or_log(peer, payload, runtime, entropy, protocol).await,
    None => None,
  };
  (tombstone_acks, page_ack, trust_ack)
}

/// The post-round checkpoint GC: collect the
/// leave/cleanup tombstones at or before the local checkpoint watermark.
/// Hygiene only — a failure is logged and retried next round.
async fn gc_collected_tombstones(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
) {
  if let Err(error) =
    crate::identity::cleanup::collect_collected_tombstones_ctx(store, entropy.as_ref()).await
  {
    tracing::debug!(kind = ?error.kind(), "checkpoint gc pass failed");
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Every sync payload kind round-trips through the canonical wire,
  /// including the additive leave-applied receipt: the leaver correlates
  /// by subject, so the subject must survive the encoding exactly.
  #[test]
  fn sync_payload_kinds_round_trip() {
    let payloads = vec![
      SyncPayload::LeaveApplied { node: node(1) },
      SyncPayload::LeaveApplied { node: node(2) },
    ];
    for payload in payloads {
      let encoded = payload.encode().unwrap();
      assert_eq!(SyncPayload::decode(&encoded).unwrap(), payload);
    }
  }

  fn node(seed: u8) -> NodeId {
    NodeId::parse(&format!("node-{seed:021}")).unwrap()
  }

  fn node_at(seed: u64) -> NodeId {
    NodeId::parse(&format!("node-{seed:021}")).unwrap()
  }

  fn key_at(value: u64) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value);
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  // The tombstone decision is snapshot-independent: with the snapshot
  // leg degraded (refresh failing), unconfirmed tombstones still
  // forward on the slow cadence alone.
  #[test]
  fn tombstones_forward_on_the_slow_cadence_without_a_snapshot() {
    // Unconfirmed tombstones present and the resend cadence reached:
    // due.
    assert!(tombstone_round_due(3, SNAPSHOT_RESEND_TICKS));
    // Before the cadence: quiet.
    assert!(!tombstone_round_due(3, 0));
    // Nothing unconfirmed (a fresh peer, or everything confirmed):
    // nothing to forward, cadence or not.
    assert!(!tombstone_round_due(0, SNAPSHOT_RESEND_TICKS));
  }

  /// Regression: a snapshot refresh failure used to fail the whole sync
  /// tick every round — an issuer binding set over the single-record
  /// store bound cannot encode (past the 16 384-entry collection cap of
  /// the 1 MiB store body), so descriptor and tombstone anti-entropy
  /// stalled permanently. The oversized issuer refresh fails in
  /// isolation, the tick still returns success, and the page plane keeps
  /// advancing (round dispatched, resend cadence armed) while no snapshot
  /// revision is ever recorded.
  #[tokio::test]
  async fn sync_tick_survives_snapshot_refresh_overflow() {
    use crate::{
      identity::{
        lifecycle,
        records::{IdentityBindingV1, identity_binding_key},
        testing::{ScriptedKeys, SequenceEntropy, inject_entry},
      },
      storage::contract::{ReferenceFactory, required_capabilities},
    };

    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let factory: Arc<dyn crate::provider::StorageFactory> = reference.clone();
    let keys = ScriptedKeys::full();
    let entropy: Arc<dyn Entropy> = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      lifecycle::open_local_identity(
        &factory,
        Some(&keys.as_provider()),
        entropy.as_ref(),
        std::time::Duration::from_secs(10),
      )
      .await
      .unwrap(),
    );
    // Oversize the issuer's binding set past the snapshot wire bounds
    // (16 384 collection entries inside the 1 MiB store body): the
    // issuer's own snapshot can no longer encode. The entries are
    // injected straight into the reference store — committing this many
    // adoptions one by one is far too slow for the suite, and the
    // refresh path only scans the identity-binding family, which is
    // exactly what is injected. Keys repeat; only node identity is
    // unique per binding.
    let shared_key = key_at(0);
    for index in 0..16_385_u64 {
      let node = node_at(index);
      let (namespace, key) = identity_binding_key(&node).unwrap();
      let binding = IdentityBindingV1::new(node, shared_key.clone());
      inject_entry(&reference, (namespace, key), binding.encode().unwrap());
    }
    // The injection is real: the issuer refresh fails on its own.
    let error = refresh_issuer_snapshot(&context, &entropy)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);

    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let (packet, _received) = tokio::sync::mpsc::channel(16);
    let routes: crate::routing::RouteTable =
      Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let runtime = RuntimeClient::routing_only(packet, routes);
    let endpoints = vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()];
    let mut cursors = MembershipSyncCursors::default();

    // The tick succeeds despite the failed snapshot leg, and the page
    // round dispatches (to zero live sessions here).
    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap();
    assert!(
      cursors.peers.is_empty(),
      "no snapshot revision recorded while refresh fails (no live sessions)"
    );
    // A quiet second tick: the stored page fingerprint arms the resend
    // cadence instead of the tick failing again.
    sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap();
    assert!(
      cursors.peers.is_empty(),
      "still no snapshot revision recorded"
    );
  }

  /// The leave-applied receipt carries one subject only: the applying
  /// peer sends it to the record's leaver, and the leaver's consumer
  /// consumes it exactly when the subject is the local node. The signal
  /// itself is permit-based: one bump releases exactly one waiter.
  #[tokio::test]
  async fn leave_applied_signal_releases_one_waiter_per_bump() {
    use std::time::Duration;

    let signal = LeaveAppliedSignal::default();
    signal.bump();
    // A stored permit resolves the first wait immediately.
    tokio::time::timeout(Duration::from_millis(50), signal.wait())
      .await
      .expect("the stored permit resolves the first wait");
    // Without a fresh bump the next wait parks.
    assert!(
      tokio::time::timeout(Duration::from_millis(50), signal.wait())
        .await
        .is_err(),
      "without a fresh bump the next wait parks"
    );
  }

  /// Regression: a receiver-side leave persist failure used to surface
  /// nowhere — the `?` propagated a silent error while the sender kept
  /// forwarding, so an audit stall (leaver still Active everywhere) could
  /// not be attributed from the log. The apply site now logs the typed
  /// failure and propagates it; this lane pins both halves: the payload
  /// errors, and the store stays without the leave record.
  #[tokio::test]
  async fn leave_persist_failure_is_logged_and_propagated_at_the_apply_site() {
    use crate::identity::{
      leave::{LeaveRecordV1, sign_leave_record},
      records::{IdentityBindingV1, identity_binding_key},
      testing::{ScriptedKeys, SequenceEntropy, fresh_reference, inject_entry, open_context},
    };

    // The receiver: a clean reference store whose context applies the
    // payload; the leaver: an independent identity signing its own record.
    let (_receiver_reference, receiver_factory) = fresh_reference();
    let receiver_keys = ScriptedKeys::full_at(9_100);
    let receiver_entropy = Arc::new(SequenceEntropy::default());
    let receiver = Arc::new(
      open_context(&receiver_factory, &receiver_keys, &receiver_entropy)
        .await
        .unwrap(),
    );
    let (_leaver_reference, leaver_factory) = fresh_reference();
    let leaver_keys = ScriptedKeys::full_at(9_200);
    let leaver_entropy = Arc::new(SequenceEntropy::default());
    let leaver = Arc::new(
      open_context(&leaver_factory, &leaver_keys, &leaver_entropy)
        .await
        .unwrap(),
    );
    let record = sign_leave_record(&leaver, &leaver_keys.as_provider())
      .await
      .unwrap();

    // The accept path's precondition: the receiver holds the leaver's
    // trusted binding, so the record passes verification gating and the
    // failure must come from the persist site, not earlier.
    let (namespace, key) = identity_binding_key(record.node()).unwrap();
    let binding = IdentityBindingV1::new(record.node().clone(), record.public_key().clone());
    inject_entry(
      &_receiver_reference,
      (namespace, key),
      binding.encode().unwrap(),
    );

    // A divergent body (garbage signature over the recorded node and
    // key) passes the binding gate and fails inside the persist call:
    // exactly the failure the apply site must make attributable.
    let divergent = LeaveRecordV1::new(
      record.node().clone(),
      record.public_key().clone(),
      record.timestamp_millis(),
      crate::Signature::from_bytes([0x5A; 64]),
    );
    let payload = SyncPayload::Leave(minicbor::bytes::ByteVec::from(divergent.encode().unwrap()));

    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let (packet, _received) = tokio::sync::mpsc::channel(16);
    let routes: crate::routing::RouteTable =
      Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let runtime = RuntimeClient::routing_only(packet, routes);
    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    let leave_applied = LeaveAppliedSignal::new();

    let error = accept_payload(
      &receiver,
      Arc::clone(&receiver_entropy) as Arc<dyn Entropy>,
      &events,
      &revision,
      &leave_applied,
      &sessions,
      &runtime,
      record.node(),
      &payload,
    )
    .await
    .expect_err("the failed persist must fail the payload");
    assert_ne!(
      error.kind(),
      crate::ErrorKind::Internal,
      "the failure is the persist site's typed error, not an internal fault"
    );
    // Nothing landed: the store holds no leave record for the leaver.
    assert!(
      !crate::identity::leave::is_left_ctx(receiver.store(), record.node())
        .await
        .unwrap(),
      "the failed persist must not leave a leave record behind"
    );
  }

  /// Regression: the trust snapshot cursor commits on the trust page's
  /// OWN delivery verdict, never on a peer-level OR over the round. A
  /// round dispatches several payloads per peer (trust page, tombstones,
  /// descriptor page); when the trust page's admission fails while the
  /// descriptor page's ack resolves, the cursor must stay put and the
  /// page must retry on the next tick — under the peer-level commit the
  /// cursor jumped past the undelivered page and the missing bindings
  /// stayed missing until the peer's session dropped.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn the_trust_cursor_commits_only_on_its_own_page_verdict() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_util::StreamExt as _;

    use crate::{
      identity::{
        lifecycle,
        records::{IdentityBindingV1, identity_binding_key},
        testing::{ScriptedKeys, SequenceEntropy, inject_entry},
      },
      storage::contract::{ReferenceFactory, required_capabilities},
    };

    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let factory: Arc<dyn crate::provider::StorageFactory> = reference.clone();
    let keys = ScriptedKeys::full();
    let entropy: Arc<dyn Entropy> = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      lifecycle::open_local_identity(
        &factory,
        Some(&keys.as_provider()),
        entropy.as_ref(),
        std::time::Duration::from_secs(10),
      )
      .await
      .unwrap(),
    );
    // Two injected bindings so the tick's membership probe passes and
    // the issuer snapshot carries a paged grant set.
    let shared_key = key_at(0);
    for index in 101..=102_u64 {
      let bound = node_at(index);
      let (namespace, key) = identity_binding_key(&bound).unwrap();
      let binding = IdentityBindingV1::new(bound, shared_key.clone());
      inject_entry(&reference, (namespace, key), binding.encode().unwrap());
    }

    let peer = node(2);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let (entry, _rx) = crate::session::stream::test_entry(entropy.as_ref());
    sessions.lock().unwrap().insert(peer.clone(), entry);
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(64);
    let routes: crate::routing::RouteTable =
      Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let runtime = RuntimeClient::routing_only(packet_tx, routes);
    // The harness fails exactly the trust snapshot payloads (their
    // admission channel is dropped: the immediate failed verdict of a
    // peer that never admits) while the descriptor page admits normally.
    let admit_snapshots = Arc::new(std::sync::Mutex::new(false));
    let snapshot_dispatches = Arc::new(AtomicUsize::new(0));
    let drainer_snapshots = Arc::clone(&snapshot_dispatches);
    let drainer_admit = Arc::clone(&admit_snapshots);
    let drainer_peer = peer.clone();
    tokio::spawn(async move {
      while let Some(mut request) = packet_rx.recv().await {
        let mut bytes = Vec::new();
        while let Some(chunk) = request.body.as_mut().next().await {
          bytes.extend_from_slice(&chunk.unwrap());
        }
        let payload = SyncPayload::decode(&bytes).unwrap();
        if matches!(payload, SyncPayload::Snapshot(_)) {
          drainer_snapshots.fetch_add(1, Ordering::SeqCst);
          if !*drainer_admit.lock().unwrap() {
            continue;
          }
        }
        let _ = request.ack_notify.send(Ok(crate::packet::RoutedAck {
          by: drainer_peer.clone(),
          admitted_at: std::time::SystemTime::now(),
        }));
      }
    });

    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    let endpoints = vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()];
    let mut cursors = MembershipSyncCursors::default();

    // Round 1: the trust diff page dispatches (the fresh peer's walk is
    // due) and its admission fails while the descriptor page admits;
    // nothing commits — the walk's marks stay empty and its cursor
    // stays at scratch.
    if let Some(pending) = sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap()
    {
      settle_round(pending, &mut cursors).await;
    }
    assert_eq!(
      snapshot_dispatches.load(Ordering::SeqCst),
      1,
      "the trust page dispatched"
    );
    assert!(
      cursors
        .peers
        .get(&peer)
        .unwrap()
        .trust
        .watermarks()
        .is_empty(),
      "a failed trust page verdict must not commit its marks"
    );

    // Round 2: the undelivered page retries on the next tick (the
    // walk's cadence counter was never reset by the failed round) and
    // still commits nothing.
    if let Some(pending) = sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap()
    {
      settle_round(pending, &mut cursors).await;
    }
    assert_eq!(
      snapshot_dispatches.load(Ordering::SeqCst),
      2,
      "the undelivered trust page retried on the next tick"
    );
    assert!(
      cursors
        .peers
        .get(&peer)
        .unwrap()
        .trust
        .watermarks()
        .is_empty()
    );

    // Round 3: the trust page's own verdict resolves as delivered; the
    // marks commit and the pass completes (the page walked to the set's
    // end).
    *admit_snapshots.lock().unwrap() = true;
    if let Some(pending) = sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap()
    {
      settle_round(pending, &mut cursors).await;
    }
    assert_eq!(snapshot_dispatches.load(Ordering::SeqCst), 3);
    let state = cursors.peers.get(&peer).unwrap();
    assert!(
      !state.trust.watermarks().is_empty(),
      "the delivered trust page commits its binding marks"
    );
    assert_eq!(
      state.trust.cursor(),
      None,
      "the completed pass closes the walk"
    );

    // Round 4: the converged walk is quiet — no snapshot payload at
    // all, even on the detection cadence.
    if let Some(pending) = sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap()
    {
      settle_round(pending, &mut cursors).await;
    }
    assert_eq!(
      snapshot_dispatches.load(Ordering::SeqCst),
      3,
      "a converged binding walk emits nothing"
    );
  }

  /// The trust walk's diff shape: after one converged pass, an added
  /// binding dispatches ALONE (one binding row on the wire, not the
  /// whole grant set), the walk completes on that single-row page, and
  /// an armed next pass emits nothing. This is the trust plane's half
  /// of the anti-redundancy contract: a one-binding change costs one
  /// binding row per peer per hop, never a whole-set re-page — the
  /// trust equivalent of the descriptor fingerprint cascade the
  /// 2026-10 audit removed.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn the_trust_walk_dispatches_only_the_binding_diff() {
    use std::sync::{Arc, Mutex};

    use futures_util::StreamExt as _;

    use crate::{
      identity::{
        lifecycle,
        records::{IdentityBindingV1, identity_binding_key},
        testing::{ScriptedKeys, SequenceEntropy, inject_entry},
      },
      storage::contract::{ReferenceFactory, required_capabilities},
    };

    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let factory: Arc<dyn crate::provider::StorageFactory> = reference.clone();
    let keys = ScriptedKeys::full();
    let entropy: Arc<dyn Entropy> = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      lifecycle::open_local_identity(
        &factory,
        Some(&keys.as_provider()),
        entropy.as_ref(),
        std::time::Duration::from_secs(10),
      )
      .await
      .unwrap(),
    );
    // Two injected bindings: a small, stable grant set.
    let shared_key = key_at(0);
    for index in 101..=102_u64 {
      let bound = node_at(index);
      let (namespace, key) = identity_binding_key(&bound).unwrap();
      let binding = IdentityBindingV1::new(bound, shared_key.clone());
      inject_entry(&reference, (namespace, key), binding.encode().unwrap());
    }

    let peer = node(2);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let (entry, _rx) = crate::session::stream::test_entry(entropy.as_ref());
    sessions.lock().unwrap().insert(peer.clone(), entry);
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(64);
    let routes: crate::routing::RouteTable =
      Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let runtime = RuntimeClient::routing_only(packet_tx, routes);
    let page_sizes: Arc<Mutex<Vec<usize>>> = Arc::default();
    let drainer_peer = peer.clone();
    let drainer_sizes = Arc::clone(&page_sizes);
    tokio::spawn(async move {
      while let Some(mut request) = packet_rx.recv().await {
        let mut bytes = Vec::new();
        while let Some(chunk) = request.body.as_mut().next().await {
          bytes.extend_from_slice(&chunk.unwrap());
        }
        let payload = SyncPayload::decode(&bytes).unwrap();
        if let SyncPayload::Snapshot(encoded) = &payload {
          let page = crate::identity::trust::TrustSnapshotPage::decode(encoded.as_ref()).unwrap();
          drainer_sizes.lock().unwrap().push(page.bindings().len());
        }
        let _ = request.ack_notify.send(Ok(crate::packet::RoutedAck {
          by: drainer_peer.clone(),
          admitted_at: std::time::SystemTime::now(),
        }));
      }
    });

    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    let endpoints = vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()];
    let mut cursors = MembershipSyncCursors::default();

    // Round 1: the fresh peer's walk delivers the whole grant set in
    // one page and completes.
    if let Some(pending) = sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap()
    {
      settle_round(pending, &mut cursors).await;
    }
    let converged = cursors.peers.get(&peer).unwrap().trust.watermarks().len();
    assert!(converged >= 2, "the whole grant set committed its marks");
    assert_eq!(page_sizes.lock().unwrap().as_slice(), &[converged]);

    // One join: a third binding. The tick's refresh enumerates and
    // persists a new snapshot revision (a store write), which arms
    // every walk through the register epoch, and the next page carries
    // EXACTLY the new binding.
    let bound = node_at(103);
    let (namespace, key) = identity_binding_key(&bound).unwrap();
    let binding = IdentityBindingV1::new(bound, shared_key.clone());
    inject_entry(&reference, (namespace, key), binding.encode().unwrap());
    if let Some(pending) = sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap()
    {
      settle_round(pending, &mut cursors).await;
    }
    assert_eq!(
      page_sizes.lock().unwrap().as_slice(),
      &[converged, 1],
      "the join dispatched one binding row, not the whole grant set"
    );
    assert_eq!(
      cursors.peers.get(&peer).unwrap().trust.watermarks().len(),
      converged + 1,
      "the diff page's marks committed"
    );

    // The next pass — armed explicitly, past every cadence — emits
    // nothing: the converged walk is quiet.
    cursors.peers.get_mut(&peer).unwrap().trust.arm();
    if let Some(pending) = sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &InFlightRounds::new(),
      &events,
      &revision,
    )
    .await
    .unwrap()
    {
      settle_round(pending, &mut cursors).await;
    }
    assert_eq!(
      page_sizes.lock().unwrap().len(),
      2,
      "a converged binding walk emits nothing even when armed"
    );
  }

  /// The shared cadence-test harness: a local identity holding two
  /// injected bindings (the tick's membership probe passes, the issuer
  /// snapshot is stable at revision 1), one known leave record (the
  /// tombstone lane has evidence to forward), and one live peer whose
  /// payloads the drainer admits or fails per payload kind. The drainer
  /// drops a failed kind's admission channel — the immediate failed
  /// verdict of a peer that never admits.
  struct CadenceHarness {
    context: Arc<crate::identity::lifecycle::LocalIdentityContext>,
    entropy: Arc<dyn Entropy>,
    sessions: SessionTable,
    runtime: RuntimeClient,
    peer: NodeId,
    events: Arc<crate::node::EventHub>,
    revision: crate::node::MemberRevisionSignal,
    admit_all: Arc<std::sync::Mutex<bool>>,
    snapshot_dispatches: Arc<std::sync::atomic::AtomicUsize>,
    leave_dispatches: Arc<std::sync::atomic::AtomicUsize>,
    page_dispatches: Arc<std::sync::atomic::AtomicUsize>,
    /// The descriptor rows sent on the wire (the redundancy ledger's
    /// sent side: the ratio of this to the peer's adopted rows is the
    /// delivered-versus-useful traffic the watermark design bounds).
    page_rows: Arc<std::sync::atomic::AtomicUsize>,
    /// The typed reference factory behind the context's store: tests
    /// inject raw family entries straight into its shared state.
    reference: Arc<crate::storage::contract::ReferenceFactory>,
  }

  impl CadenceHarness {
    async fn build() -> Self {
      use std::sync::atomic::{AtomicUsize, Ordering};

      use futures_util::StreamExt as _;

      use crate::{
        StoreKey,
        identity::{
          lifecycle,
          records::{IdentityBindingV1, identity_binding_key},
          testing::{ScriptedKeys, SequenceEntropy, inject_entry},
        },
        storage::contract::{ReferenceFactory, required_capabilities},
      };

      let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
      let factory: Arc<dyn crate::provider::StorageFactory> = reference.clone();
      let keys = ScriptedKeys::full();
      let entropy: Arc<dyn Entropy> = Arc::new(SequenceEntropy::default());
      let context = Arc::new(
        lifecycle::open_local_identity(
          &factory,
          Some(&keys.as_provider()),
          entropy.as_ref(),
          std::time::Duration::from_secs(10),
        )
        .await
        .unwrap(),
      );
      let shared_key = key_at(0);
      for index in 101..=102_u64 {
        let bound = node_at(index);
        let (namespace, key) = identity_binding_key(&bound).unwrap();
        let binding = IdentityBindingV1::new(bound, shared_key.clone());
        inject_entry(&reference, (namespace, key), binding.encode().unwrap());
      }
      // One known leave record: the tombstone lane has evidence to
      // forward (a scan-time decode only; the dummy signature is never
      // verified on the send path).
      let leaver = node_at(77);
      let record = crate::identity::leave::LeaveRecordV1::new(
        leaver.clone(),
        key_at(3),
        1_000,
        crate::Signature::from_bytes([0_u8; 64]),
      );
      let leave_namespace =
        crate::storage::families::namespace(crate::storage::families::LEAVE_NAMESPACE).unwrap();
      inject_entry(
        &reference,
        (
          leave_namespace,
          StoreKey::new(std::sync::Arc::from(leaver.as_str().as_bytes().to_vec())),
        ),
        record.encode().unwrap(),
      );

      let peer = node(2);
      let sessions: SessionTable =
        Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
      let (entry, _rx) = crate::session::stream::test_entry(entropy.as_ref());
      sessions.lock().unwrap().insert(peer.clone(), entry);
      let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(64);
      let routes: crate::routing::RouteTable =
        Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
      let runtime = RuntimeClient::routing_only(packet_tx, routes);
      let admit_all = Arc::new(std::sync::Mutex::new(true));
      let snapshot_dispatches = Arc::new(AtomicUsize::new(0));
      let leave_dispatches = Arc::new(AtomicUsize::new(0));
      let page_dispatches = Arc::new(AtomicUsize::new(0));
      // The descriptor rows that actually went on the wire — the
      // redundancy ledger's sent side (the received side is what the
      // peer's store adopts).
      let page_rows = Arc::new(AtomicUsize::new(0));
      let drainer_admit = Arc::clone(&admit_all);
      let drainer_snapshots = Arc::clone(&snapshot_dispatches);
      let drainer_leaves = Arc::clone(&leave_dispatches);
      let drainer_pages = Arc::clone(&page_dispatches);
      let drainer_rows = Arc::clone(&page_rows);
      let drainer_peer = peer.clone();
      tokio::spawn(async move {
        while let Some(mut request) = packet_rx.recv().await {
          let mut bytes = Vec::new();
          while let Some(chunk) = request.body.as_mut().next().await {
            bytes.extend_from_slice(&chunk.unwrap());
          }
          match SyncPayload::decode(&bytes).unwrap() {
            SyncPayload::Snapshot(_) => {
              drainer_snapshots.fetch_add(1, Ordering::SeqCst);
            }
            SyncPayload::Leave(_) => {
              drainer_leaves.fetch_add(1, Ordering::SeqCst);
            }
            SyncPayload::Page(encoded) => {
              drainer_pages.fetch_add(1, Ordering::SeqCst);
              if let Ok(page) = MembershipPage::decode(encoded.as_ref()) {
                drainer_rows.fetch_add(page.descriptors().len(), Ordering::SeqCst);
              }
            }
            _ => {}
          }
          if *drainer_admit.lock().unwrap() {
            let _ = request.ack_notify.send(Ok(crate::packet::RoutedAck {
              by: drainer_peer.clone(),
              admitted_at: std::time::SystemTime::now(),
            }));
          }
        }
      });
      let events = Arc::new(crate::node::EventHub::new());
      let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
      Self {
        context,
        entropy,
        sessions,
        runtime,
        peer,
        events,
        revision: crate::node::MemberRevisionSignal::new(revision_tx),
        admit_all,
        snapshot_dispatches,
        leave_dispatches,
        page_dispatches,
        page_rows,
        reference,
      }
    }

    async fn tick(&self, cursors: &mut MembershipSyncCursors) {
      let endpoints = vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()];
      if let Some(pending) = sync_tick(
        &self.context,
        &self.entropy,
        &self.sessions,
        &self.runtime,
        &endpoints,
        cursors,
        &InFlightRounds::new(),
        &self.events,
        &self.revision,
      )
      .await
      .unwrap()
      {
        settle_round(pending, cursors).await;
      }
    }

    /// Injects one more identity binding into the shared store: the
    /// next tick's issuer refresh enumerates and persists a new
    /// snapshot revision — a real store write, which arms every walk
    /// through the register epoch exactly as a live join would.
    async fn inject_binding(&self, bound: NodeId) {
      use crate::identity::records::{IdentityBindingV1, identity_binding_key};
      let (namespace, key) = identity_binding_key(&bound).unwrap();
      let binding = IdentityBindingV1::new(bound, key_at(0));
      crate::identity::testing::inject_entry(
        &self.reference,
        (namespace, key),
        binding.encode().unwrap(),
      );
    }

    /// Injects one more known leave record: the tombstone plane's new
    /// unconfirmed evidence.
    async fn inject_leave(&self, leaver: NodeId) {
      let record = crate::identity::leave::LeaveRecordV1::new(
        leaver.clone(),
        key_at(9),
        2_000,
        crate::Signature::from_bytes([0_u8; 64]),
      );
      let leave_namespace =
        crate::storage::families::namespace(crate::storage::families::LEAVE_NAMESPACE).unwrap();
      crate::identity::testing::inject_entry(
        &self.reference,
        (
          leave_namespace,
          crate::StoreKey::new(std::sync::Arc::from(leaver.as_str().as_bytes().to_vec())),
        ),
        record.encode().unwrap(),
      );
    }
  }

  /// Regression: an undelivered round must retry on the NEXT tick, not
  /// after a full detection interval. The walks' cadence counters are
  /// reset only by delivery verdicts (a failed round consumed nothing);
  /// under the dispatch-time reset a single failed round silenced both
  /// lanes for the whole resend interval.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn an_undelivered_round_retries_on_the_next_tick_not_after_the_full_interval() {
    use std::sync::atomic::Ordering;

    let harness = CadenceHarness::build().await;
    let mut cursors = MembershipSyncCursors::default();

    // Round 1: the fresh peer's planes deliver the grant set, the
    // catalog, and the known tombstone. Disarm the tombstone cadence so
    // the diff setup below is deterministic; the tombstone plane's own
    // cadence and confirmation semantics are pinned by the sibling
    // tests.
    harness.tick(&mut cursors).await;
    let base_snapshot = harness.snapshot_dispatches.load(Ordering::SeqCst);
    let base_leave = harness.leave_dispatches.load(Ordering::SeqCst);
    let base_page = harness.page_dispatches.load(Ordering::SeqCst);
    let base_confirmed = cursors
      .peers
      .get(&harness.peer)
      .unwrap()
      .confirmed_tombstones
      .len();
    assert_eq!(base_snapshot, 1, "the grant set converged");
    assert!(base_leave >= 1, "the known tombstone converged");
    assert_eq!(base_page, 1, "the catalog converged");
    {
      let state = cursors.peers.get_mut(&harness.peer).unwrap();
      state.ticks_since_tombstone_send = 0;
    }

    // A new leave record and a new binding: both planes have a diff to
    // deliver (the refresh persist arms every walk through the register
    // epoch). Every dispatch fails: nothing commits.
    harness.inject_leave(node_at(78)).await;
    harness.inject_binding(node_at(104)).await;
    *harness.admit_all.lock().unwrap() = false;
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.snapshot_dispatches.load(Ordering::SeqCst),
      base_snapshot + 1,
      "the binding diff dispatched"
    );
    assert!(
      harness.leave_dispatches.load(Ordering::SeqCst) > base_leave,
      "the new tombstone dispatched"
    );
    assert_eq!(
      cursors
        .peers
        .get(&harness.peer)
        .unwrap()
        .confirmed_tombstones
        .len(),
      base_confirmed,
      "the failed tombstone round confirmed nothing"
    );

    // The next tick retries BOTH lanes with the same unconfirmed set:
    // the failed round consumed neither cadence.
    let failed_snapshot = harness.snapshot_dispatches.load(Ordering::SeqCst);
    let failed_leave = harness.leave_dispatches.load(Ordering::SeqCst);
    assert!(failed_leave > base_leave, "the new tombstone dispatched");
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.snapshot_dispatches.load(Ordering::SeqCst),
      failed_snapshot + 1,
      "the snapshot lane retried on the next tick"
    );
    assert_eq!(
      harness.leave_dispatches.load(Ordering::SeqCst),
      failed_leave + (failed_leave - base_leave),
      "the tombstone lane retried the same unconfirmed set on the next tick"
    );

    // Delivery heals both lanes: the marks and confirmations commit.
    *harness.admit_all.lock().unwrap() = true;
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.snapshot_dispatches.load(Ordering::SeqCst),
      failed_snapshot + 2,
      "the healed binding diff delivered"
    );
    assert_eq!(
      harness.leave_dispatches.load(Ordering::SeqCst),
      failed_leave + 2 * (failed_leave - base_leave),
      "the healed tombstone set delivered"
    );
    assert_eq!(harness.page_dispatches.load(Ordering::SeqCst), 1);
  }

  /// Regression: the tombstone plane's cadence advances on every tick
  /// — independent of the (possibly multi-tick) descriptor-page pass.
  /// Under quiet-round-only advancement a long descriptor pass froze
  /// the tombstone lane for the whole pass.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_long_descriptor_pass_does_not_stall_the_tombstone_lane() {
    use std::sync::atomic::Ordering;

    let harness = CadenceHarness::build().await;
    // A catalog far larger than one descriptor page: the walk runs a
    // multi-tick diff pass once the first tick records its boundary.
    let descriptor_namespace =
      crate::storage::families::namespace(crate::storage::families::NODE_DESCRIPTOR_NAMESPACE)
        .unwrap();
    for index in 0..200_u64 {
      let member = node_at(500 + index);
      let descriptor = crate::membership::NodeDescriptorV1::new(
        member.clone(),
        key_at(1),
        vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()],
        1,
        false,
        1,
      );
      crate::identity::testing::inject_entry(
        &harness.reference,
        (
          descriptor_namespace.clone(),
          crate::StoreKey::new(std::sync::Arc::from(member.as_str().as_bytes().to_vec())),
        ),
        descriptor.encode().unwrap(),
      );
    }

    let mut cursors = MembershipSyncCursors::default();

    // Tick 1: the fresh peer's round dispatches the first descriptor
    // page (the pass starts), the trust page, and the known tombstone;
    // everything delivers. The page walk is mid-pass. The trust page's
    // delivery expires the peer's tombstone confirmations, so tick 2
    // re-forwards the known tombstone beside the page pass.
    harness.tick(&mut cursors).await;
    assert!(harness.leave_dispatches.load(Ordering::SeqCst) >= 1);
    assert!(
      cursors
        .peers
        .get(&harness.peer)
        .unwrap()
        .descriptors
        .cursor()
        .is_some(),
      "the descriptor pass is in flight"
    );
    harness.tick(&mut cursors).await;
    let settled = harness.leave_dispatches.load(Ordering::SeqCst);
    assert!(settled >= 1, "the binding delivery re-forwarded the set");

    // A second tombstone arrives while the descriptor pass is still
    // mid-flight: its cadence is armed, so the next tick forwards it
    // beside the ongoing page pass — the tombstone lane never waits
    // for a quiet round.
    harness.inject_leave(node_at(78)).await;
    {
      let state = cursors.peers.get_mut(&harness.peer).unwrap();
      state.ticks_since_tombstone_send = SNAPSHOT_RESEND_TICKS;
    }
    harness.tick(&mut cursors).await;
    assert!(
      harness.leave_dispatches.load(Ordering::SeqCst) > settled,
      "the tombstone lane forwarded mid-pass"
    );
    assert!(
      cursors
        .peers
        .get(&harness.peer)
        .unwrap()
        .descriptors
        .cursor()
        .is_some(),
      "the descriptor pass is still in flight"
    );

    // The delivered tombstone round confirmed the records; with no new
    // binding progress, the lane goes quiet.
    let before = harness.leave_dispatches.load(Ordering::SeqCst);
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.leave_dispatches.load(Ordering::SeqCst),
      before,
      "the confirmed tombstones never re-forward"
    );
  }

  /// Regression (the redundant-edge re-emission storm, now the
  /// zero-emission steady state): a converged mesh dispatches NOTHING —
  /// not on the detection cadences, not when they are armed — and a
  /// real catalog change (a store write) pushes exactly one diff page
  /// on the next tick, alone. The old ride-along emitted the whole
  /// catalog beside every leg dispatch, so a converged mesh re-sent
  /// every descriptor at the legs' resend cadence forever; the
  /// watermark walks replaced that with quiet digest scans.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_converged_mesh_emits_nothing_until_a_real_change() {
    use std::sync::atomic::Ordering;

    let harness = CadenceHarness::build().await;
    let mut cursors = MembershipSyncCursors::default();

    // Run well past several detection cadences and confirmation-refresh
    // windows. The descriptor and trust planes converge on the first
    // round and NEVER emit again; the tombstone plane's only steady
    // traffic is its bounded confirmation refresh.
    for _ in 0..40 {
      harness.tick(&mut cursors).await;
    }
    assert_eq!(
      harness.page_dispatches.load(Ordering::SeqCst),
      1,
      "one page delivered the catalog; the descriptor plane never re-sends"
    );
    let converged_rows = harness.page_rows.load(Ordering::SeqCst);
    assert!(
      converged_rows >= 1,
      "the catalog delivered at least one row"
    );
    assert_eq!(
      harness.snapshot_dispatches.load(Ordering::SeqCst),
      1,
      "the converged binding walk emits nothing"
    );
    let converged_leaves = harness.leave_dispatches.load(Ordering::SeqCst);
    assert!(
      (1..=5).contains(&converged_leaves),
      "the tombstone plane's steady traffic is bounded to the refresh roll"
    );

    // Armed detection passes over a converged state are quiet scans: the
    // descriptor and trust planes put nothing on the wire and the row
    // count — the redundancy ledger — does not move.
    {
      let state = cursors.peers.get_mut(&harness.peer).unwrap();
      state.descriptors.arm();
      state.trust.arm();
    }
    harness.tick(&mut cursors).await;
    assert_eq!(harness.snapshot_dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(
      harness.page_dispatches.load(Ordering::SeqCst),
      1,
      "an armed quiet scan dispatches nothing"
    );
    assert_eq!(
      harness.page_rows.load(Ordering::SeqCst),
      converged_rows,
      "an armed quiet scan sends zero rows — the whole-catalog resend
      the fingerprint design performed on every cadence is gone"
    );

    // A real catalog change (a store-committed join) arms the walk
    // through the register epoch and pushes exactly one diff row on
    // the next tick, alone: one changed row costs one row on the wire,
    // not a catalog-sized page (the cascade's amplifier removed).
    let joined = node_at(600);
    let descriptor = crate::membership::NodeDescriptorV1::new(
      joined,
      key_at(1),
      vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()],
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(
      harness.context.store(),
      &crate::api::SystemEntropy,
      &descriptor,
    )
    .await
    .unwrap();
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.page_dispatches.load(Ordering::SeqCst),
      2,
      "a committed catalog change sends the diff page on the next tick"
    );
    assert_eq!(
      harness.page_rows.load(Ordering::SeqCst),
      converged_rows + 1,
      "one changed descriptor = exactly one row on the wire"
    );
    assert_eq!(harness.snapshot_dispatches.load(Ordering::SeqCst), 1);
    assert!(
      harness.leave_dispatches.load(Ordering::SeqCst) - converged_leaves <= 1,
      "a descriptor change does not amplify the tombstone plane"
    );
  }
}
