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
  membership::page::{MembershipPage, sync as page_sync},
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
/// five seconds, well inside the fixed authentication deadline's order of
/// magnitude.
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
    return Ok(());
  }
  tracing::debug!(peers = peers.len(), "leave announcement starting");
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
      crate::identity::leave::persist_leave_record_ctx(store, entropy.as_ref(), &record).await?;
      tracing::debug!(node = %record.node(), "leave record persisted on peer");
      member_changed(events, revision, record.node().clone());
      // The applied receipt: one durable-install
      // confirmation back to the leaver, best-effort and retried by the
      // announcement budget. Pre-receipt peers simply never send it.
      let receipt = SyncPayload::LeaveApplied {
        node: record.node().clone(),
      }
      .encode()?;
      let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
      // The applied receipt: one durable-install confirmation back to
      // the leaver, best-effort and retried by the announcement budget.
      // Pre-receipt peers simply never send it. The admission ack is
      // still observed (delivery truth, D2): the wait runs detached so
      // the pump never serializes behind it, and a failed admission is
      // diagnostics only — the receipt is a hint, never a trust
      // decision, and is never retried here.
      match crate::sync_common::send_payload(runtime, &entropy, source, &protocol, &receipt) {
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

/// One anti-entropy tick: publish the local descriptor, refresh the issuer
/// snapshot when this node is the creator, and push a bounded page plus the
/// latest snapshot over every authenticated session. The work per tick is
/// bounded: one page and one snapshot per session, nothing paged to
/// exhaustion. A snapshot refresh failure (an issuer binding set that
/// overflows the single-record control bound) skips only that round's
/// snapshot send: the descriptor-page and tombstone anti-entropy below
/// keeps running, so a large membership degrades the snapshot leg instead
/// of stalling every sync lane.
/// The driver's per-peer anti-entropy continuation state, tracked
/// separately for every alive peer: the state is dropped when a peer's
/// session is gone, so the returning peer's first round re-delivers
/// everything it missed — including writes made while it was
/// partitioned away.
#[derive(Debug, Default)]
pub(crate) struct MembershipSyncCursors {
  peers: std::collections::BTreeMap<NodeId, PeerSyncState>,
}

#[derive(Debug, Default)]
pub(crate) struct PeerSyncState {
  /// The last snapshot revision fully delivered to this peer, so
  /// unchanged grant sets are not re-sent every tick.
  snapshot_rev: u64,
  /// The keyset cursor into the issuer's binding set: the last delivered
  /// trust page's final binding, so a set larger than one wire page
  /// pages through across ticks.
  snapshot_cursor: Option<NodeId>,
  /// Ticks since this peer's last DELIVERED snapshot send: a lost
  /// delivery must be retried without waiting for the next grant-set
  /// change. The counter advances every tick — independent of the
  /// (possibly multi-tick) descriptor-page pass — and is pulled back to
  /// zero only by a delivered trust page's verdict (or the pass's
  /// closing tick), so an undelivered round retries on the next tick
  /// instead of after a full resend interval.
  ticks_since_snapshot_send: u32,
  /// Ticks since this peer's last DELIVERED tombstone send: lost removal
  /// evidence retries on the same slow cadence, independent of the
  /// (possibly multi-tick) trust-page pass and of the descriptor-page
  /// plane's state. The counter advances every tick and is pulled back
  /// to zero only by a fully delivered tombstone round.
  ticks_since_tombstone_send: u32,
  /// The shared page-plane continuation state (fingerprint, resend
  /// cadences, continuation cursor).
  page: crate::sync_common::PeerPageCursor,
}

/// The bounded number of known leave records forwarded per snapshot
/// round (anti-entropy healing without unbounded per-tick work).
const LEAVE_RESEND_CAP: usize = 64;

/// Snapshot deliveries are retried on this slow cadence even when the
/// grant set is unchanged, so a dropped payload heals instead of stalling
/// a peer forever (anti-entropy). The page cadences are single-sourced in
/// [`crate::sync_common::PeerPageCursor`].
const SNAPSHOT_RESEND_TICKS: u32 = 8;

/// The tombstone forwarding decision for one peer round: a revision
/// change forwards the accumulated tombstones once, and the slow
/// cadence heals lost ones. The decision is snapshot-INDEPENDENT — a
/// degraded snapshot leg (refresh failing) must never stall tombstone
/// propagation, because the tombstones are what retire removed
/// identities on peers.
fn tombstone_round_due(
  revision_advanced: bool, has_tombstones: bool, ticks_since_send: u32, snapshot_due: bool,
) -> bool {
  (revision_advanced || has_tombstones)
    && (ticks_since_send >= SNAPSHOT_RESEND_TICKS || snapshot_due)
}

/// One dispatched trust snapshot page: the keyset cursor it advances
/// paired with ITS OWN admission receiver. A round dispatches several
/// payloads per peer (trust page, tombstones, descriptor page), so the
/// cursor must commit on this payload's verdict alone — another
/// payload's ack says nothing about the trust page.
struct SnapshotPageDispatch {
  cursor: NodeId,
  ack: tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
}

/// The outcome of one per-peer membership round: the admission receivers
/// for every dispatched payload (grouped so each lane's cadence commit is
/// verdict-gated by the tick aggregator), the dispatched trust page if
/// any, and whether any payload dispatched at all (a rejected dispatch
/// fails the peer for this round).
struct MembershipPeerRound {
  /// The round's tombstone payloads' admission receivers: a fully
  /// delivered set re-arms the tombstone resend cadence.
  tombstone_acks: Vec<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  /// The descriptor page's admission receiver: the page rides every
  /// dispatched round, and its verdict feeds the peer-level failure set.
  page_ack: Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  snapshot_page: Option<SnapshotPageDispatch>,
  dispatched: bool,
}

/// One per-peer membership anti-entropy step, mirroring the resource
/// lane's `resource_sync_tick_peer`: emit the bounded descriptor page,
/// decide the snapshot/tombstone legs, dispatch one round, and advance
/// the peer's continuation state. The delivery verdicts are aggregated
/// (and cursor commits gated) by the tick's caller.
#[allow(clippy::too_many_arguments)]
async fn membership_sync_tick_peer(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>, runtime: &RuntimeClient,
  peer: &NodeId, state: &mut PeerSyncState, protocol: &ProtocolTag,
  snapshot: Option<&crate::identity::trust::TrustSnapshotV1>, tombstone_bytes: &[Vec<u8>],
) -> Result<MembershipPeerRound> {
  state.page.arm_full_pass();
  // The snapshot and tombstone resend cadences advance on every tick —
  // they are independent of the (possibly multi-tick) descriptor-page
  // pass — and are pulled back to zero only by delivery verdicts in the
  // tick's aggregator, so an undelivered round retries on the next tick
  // instead of waiting out the full resend interval.
  state.ticks_since_snapshot_send = state.ticks_since_snapshot_send.saturating_add(1);
  state.ticks_since_tombstone_send = state.ticks_since_tombstone_send.saturating_add(1);
  let page = page_sync::emit_page_ctx(
    store,
    state.page.continuation(),
    crate::membership::page::DEFAULT_PAGE_LIMIT,
  )
  .await?;
  let page_bytes = SyncPayload::Page(ByteVec::from(page.encode()?)).encode()?;
  // The page-round decision records the fingerprint against the emitted
  // page on starting rounds only: a stale recorded fingerprint would
  // mark every round as changed, keep the page due forever, and never
  // let the page plane go quiet between unchanged pages.
  let page_round = state.page.page_round(page.fingerprint());
  // A snapshot pass is due for this peer when its revision advanced past
  // what this peer last fully received, or on the slow resend cadence.
  // Tombstones ride their own cadence against the same revision marker:
  // a revision change forwards the accumulated tombstones once, and the
  // slow cadence heals lost ones. The cadence runs even while the
  // snapshot leg is degraded (refresh failing): tombstone forwarding is
  // snapshot-independent by contract.
  let revision_advanced = match snapshot {
    Some(snapshot) => snapshot.revision() != state.snapshot_rev,
    None => false,
  };
  let snapshot_due = revision_advanced
    || match snapshot {
      Some(_) => state.ticks_since_snapshot_send >= SNAPSHOT_RESEND_TICKS,
      None => false,
    };
  let tombstones_due = tombstone_round_due(
    revision_advanced,
    !tombstone_bytes.is_empty(),
    state.ticks_since_tombstone_send,
    snapshot_due,
  );
  match page_round {
    crate::sync_common::PageRound::Quiet if !snapshot_due && !tombstones_due => {
      state.page.quiet_tick();
      return Ok(MembershipPeerRound {
        tombstone_acks: Vec::new(),
        page_ack: None,
        snapshot_page: None,
        dispatched: false,
      });
    }
    crate::sync_common::PageRound::Quiet => {
      // The page is not due, but the snapshot/tombstone leg is: dispatch
      // that round without advancing the page cursor.
    }
    crate::sync_common::PageRound::Send => {
      state.page.record_send(page.cursor());
    }
  }
  // The trust snapshot leg pages through the issuer's binding set one
  // wire page per tick (keyset cursor per peer); the revision is only
  // marked fully delivered on the closing empty-page tick, so an
  // undelivered page leaves the pass due instead of truncated.
  let mut snapshot_page: Option<Vec<u8>> = None;
  let mut snapshot_page_cursor: Option<NodeId> = None;
  if snapshot_due && let Some(snapshot) = snapshot {
    let page = snapshot.page_after(state.snapshot_cursor.as_ref(), TRUST_BINDINGS_PAGE_LIMIT);
    if page.bindings().is_empty() {
      // The pass is complete for this revision: reset the cursor and
      // mark the peer fully delivered. No payload this round, so no
      // delivery verdict is needed to re-arm the snapshot cadence.
      state.snapshot_cursor = None;
      state.snapshot_rev = snapshot.revision();
      state.ticks_since_snapshot_send = 0;
    } else {
      snapshot_page_cursor = page.continuation().cloned();
      snapshot_page = Some(SyncPayload::Snapshot(ByteVec::from(page.encode()?)).encode()?);
    }
  }
  let mut tombstone_payloads: Vec<&[u8]> = Vec::new();
  if tombstones_due {
    tombstone_payloads.extend(tombstone_bytes.iter().map(Vec::as_slice));
  }
  let (tombstone_acks, page_ack, snapshot_ack) = dispatch_to_peer(
    peer,
    snapshot_page.as_deref(),
    &tombstone_payloads,
    &page_bytes,
    runtime,
    entropy,
    protocol,
  )
  .await;
  Ok(MembershipPeerRound {
    tombstone_acks,
    page_ack,
    snapshot_page: snapshot_ack
      .zip(snapshot_page_cursor)
      .map(|(ack, cursor)| SnapshotPageDispatch { cursor, ack }),
    dispatched: true,
  })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>, sessions: &SessionTable,
  runtime: &RuntimeClient, local_endpoints: &[crate::Endpoint],
  cursors: &mut MembershipSyncCursors, events: &Arc<crate::node::EventHub>,
  revision: &crate::node::MemberRevisionSignal,
) -> Result<()> {
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
    return Ok(());
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
    gc_collected_tombstones(store, entropy).await;
    return Ok(());
  }
  cursors.peers.retain(|peer, _| peers.contains(peer));
  // Tombstone wire bytes are peer-independent: encode once. The trust
  // snapshot legs are paged per peer (keyset cursor), so they cannot be
  // hoisted out of the loop. The bytes are snapshot-INDEPENDENT: a
  // failed refresh must never stall this lane (the tombstones are what
  // retire removed identities on peers).
  let tombstone_bytes: Vec<Vec<u8>> = {
    let mut out = Vec::with_capacity(
      leave_records.len() + cleanup_records.len() + revocation_records.len() + 1,
    );
    for record in &leave_records {
      out.push(SyncPayload::Leave(ByteVec::from(record.encode()?)).encode()?);
    }
    for record in &cleanup_records {
      out.push(SyncPayload::Cleanup(ByteVec::from(record.encode()?)).encode()?);
    }
    for record in &revocation_records {
      out.push(SyncPayload::Revocation(ByteVec::from(record.encode()?)).encode()?);
    }
    if let Some(checkpoint) = &local_checkpoint {
      out.push(SyncPayload::Checkpoint(ByteVec::from(checkpoint.encode()?)).encode()?);
    }
    out
  };
  if !leave_records.is_empty() || !cleanup_records.is_empty() {
    tracing::debug!(
      leave = leave_records.len(),
      cleanup = cleanup_records.len(),
      send = !tombstone_bytes.is_empty(),
      "removal tombstones considered for forwarding"
    );
  }
  let mut pending_tombstone_acks: Vec<(
    NodeId,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )> = Vec::new();
  let mut pending_page_acks: Vec<(
    NodeId,
    tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>,
  )> = Vec::new();
  let mut pending_trust_pages: Vec<(NodeId, SnapshotPageDispatch)> = Vec::new();
  let mut failed_peers: Vec<NodeId> = Vec::new();
  for peer in &peers {
    let state = cursors.peers.entry(peer.clone()).or_default();
    let round = membership_sync_tick_peer(
      store,
      entropy,
      runtime,
      peer,
      state,
      &protocol,
      snapshot.as_ref(),
      &tombstone_bytes,
    )
    .await?;
    if !round.dispatched {
      // A quiet round with nothing due: the peer state already advanced.
      continue;
    }
    let MembershipPeerRound {
      tombstone_acks,
      page_ack,
      snapshot_page,
      ..
    } = round;
    if tombstone_acks.is_empty() && page_ack.is_none() && snapshot_page.is_none() {
      // Nothing was queued (the routing queue rejected outright): the
      // round never left this node.
      failed_peers.push(peer.clone());
      continue;
    }
    state.page.count_round();
    if let Some(page) = snapshot_page {
      // The page dispatched: commit the trust cursor only after the
      // page's OWN delivery verdict (see below) — an unadmitted page
      // rewinds.
      pending_trust_pages.push((peer.clone(), page));
    }
    pending_tombstone_acks.extend(tombstone_acks.into_iter().map(|ack| (peer.clone(), ack)));
    if let Some(ack) = page_ack {
      pending_page_acks.push((peer.clone(), ack));
    }
  }
  // Delivery verdicts resolve concurrently: one unreachable peer must
  // not serialize the round behind its ack wait (that would make the
  // convergence bound liveness teardown, not the anti-entropy cadence).
  let (tombstone_verdicts, page_verdicts, trust_verdicts) = futures_util::future::join3(
    futures_util::future::join_all(pending_tombstone_acks.into_iter().map(
      |(peer, ack)| async move { (peer, crate::sync_common::delivered_within_bound(ack).await) },
    )),
    futures_util::future::join_all(pending_page_acks.into_iter().map(|(peer, ack)| async move {
      (peer, crate::sync_common::delivered_within_bound(ack).await)
    })),
    futures_util::future::join_all(pending_trust_pages.into_iter().map(
      |(peer, page)| async move {
        let delivered = crate::sync_common::delivered_within_bound(page.ack).await;
        (peer, page.cursor, delivered)
      },
    )),
  )
  .await;
  // A tombstone round re-arms its resend cadence only when EVERY
  // tombstone of the round was admitted; any lost one retries on the
  // next tick (the cadence counters kept advancing meanwhile).
  let mut tombstone_rounds: std::collections::BTreeMap<NodeId, bool> =
    std::collections::BTreeMap::new();
  for (peer, delivered) in tombstone_verdicts {
    if !delivered {
      failed_peers.push(peer.clone());
    }
    let entry = tombstone_rounds.entry(peer).or_insert(true);
    *entry &= delivered;
  }
  for (peer, delivered) in page_verdicts {
    if !delivered {
      failed_peers.push(peer);
    }
  }
  // The trust page resolves to its own verdict, never the peer-level OR
  // over the round: a round dispatches several payloads per peer (trust
  // page, tombstones, descriptor page), and another payload's ack says
  // nothing about the trust page.
  let mut trust_commits: Vec<(NodeId, NodeId)> = Vec::new();
  for (peer, cursor, delivered) in trust_verdicts {
    if delivered {
      trust_commits.push((peer, cursor));
    } else {
      failed_peers.push(peer);
    }
  }
  for peer in failed_peers {
    // An unadmitted payload means the peer may hold none of this round:
    // rewind to the failed page's start so the next tick re-sends exactly
    // that page (the snapshot stays due through its unrecorded revision).
    if let Some(state) = cursors.peers.get_mut(&peer) {
      state.page.discard_progress();
    }
  }
  // Verdict-gated cadence commits: a fully delivered tombstone round
  // re-arms the tombstone resend cadence, and a delivered trust page
  // re-arms the snapshot cadence while advancing the keyset cursor. An
  // undelivered round resets nothing, so the next tick retries it.
  for (peer, tombstones_delivered) in tombstone_rounds {
    if tombstones_delivered && let Some(state) = cursors.peers.get_mut(&peer) {
      state.ticks_since_tombstone_send = 0;
    }
  }
  for (peer, cursor) in trust_commits {
    if let Some(state) = cursors.peers.get_mut(&peer) {
      state.snapshot_cursor = Some(cursor);
      state.ticks_since_snapshot_send = 0;
    }
  }
  gc_collected_tombstones(store, entropy).await;
  Ok(())
}

/// The per-tick fan-out to one peer: sends every payload in order and
/// returns their admission receivers, grouped by lane so each cadence
/// commit can be gated on its own delivery verdict. The trust snapshot
/// page's receiver is kept separate from the rest so its own verdict —
/// not a peer-level OR over the round — gates the snapshot cursor
/// commit. A payload swallowed by a session that still looks alive never
/// resolves its receiver, which is exactly the signal the caller needs
/// to re-deliver from scratch.
async fn dispatch_to_peer(
  peer: &NodeId, snapshot_page: Option<&[u8]>, tombstones: &[&[u8]], page: &[u8],
  runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>, protocol: &ProtocolTag,
) -> (
  Vec<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
  Option<tokio::sync::oneshot::Receiver<crate::packet::RoutedAckOutcome>>,
) {
  let snapshot_ack = snapshot_page.and_then(|payload| {
    match crate::sync_common::send_payload(runtime, entropy, peer, protocol, payload) {
      Ok(ack) => Some(ack),
      Err(error) => {
        tracing::debug!(kind = ?error.kind(), "sync payload dispatch failed");
        None
      }
    }
  });
  let mut tombstone_acks = Vec::new();
  for payload in tombstones {
    match crate::sync_common::send_payload(runtime, entropy, peer, protocol, payload) {
      Ok(ack) => tombstone_acks.push(ack),
      Err(error) => {
        tracing::debug!(kind = ?error.kind(), "sync payload dispatch failed");
      }
    }
  }
  let page_ack = match crate::sync_common::send_payload(runtime, entropy, peer, protocol, page) {
    Ok(ack) => Some(ack),
    Err(error) => {
      tracing::debug!(kind = ?error.kind(), "sync payload dispatch failed");
      None
    }
  };
  (tombstone_acks, page_ack, snapshot_ack)
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
  // leg degraded (refresh failing, no revision signal), the slow
  // cadence alone keeps forwarding accumulated tombstones.
  #[test]
  fn tombstones_forward_on_the_slow_cadence_without_a_snapshot() {
    // No snapshot: revision_advanced and snapshot_due are both false.
    let revision_advanced = false;
    let snapshot_due = false;
    // Tombstones present and the resend cadence reached: due.
    assert!(tombstone_round_due(
      revision_advanced,
      true,
      SNAPSHOT_RESEND_TICKS,
      snapshot_due
    ));
    // Before the cadence: quiet.
    assert!(!tombstone_round_due(
      revision_advanced,
      true,
      0,
      snapshot_due
    ));
    // No tombstones: nothing to forward, cadence or not.
    assert!(!tombstone_round_due(
      revision_advanced,
      false,
      SNAPSHOT_RESEND_TICKS,
      snapshot_due
    ));
    // With a healthy snapshot, a revision advance forwards immediately.
    assert!(tombstone_round_due(true, true, 0, true));
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
        &keys.as_provider(),
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
        &keys.as_provider(),
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

    // Round 1: the trust page dispatches and its admission fails while
    // the descriptor page admits; the cursor must not advance.
    sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &events,
      &revision,
    )
    .await
    .unwrap();
    assert_eq!(
      snapshot_dispatches.load(Ordering::SeqCst),
      1,
      "the trust page dispatched"
    );
    assert!(
      cursors.peers.get(&peer).unwrap().snapshot_cursor.is_none(),
      "a failed trust page verdict must not advance the snapshot cursor"
    );

    // Round 2: the undelivered page retries on the next tick (the pass
    // is still due through its unrecorded revision) and still must not
    // commit past its failure.
    sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &events,
      &revision,
    )
    .await
    .unwrap();
    assert_eq!(
      snapshot_dispatches.load(Ordering::SeqCst),
      2,
      "the undelivered trust page retried on the next tick"
    );
    assert!(cursors.peers.get(&peer).unwrap().snapshot_cursor.is_none());

    // Round 3: the trust page's own verdict resolves as delivered; only
    // now the cursor commits.
    *admit_snapshots.lock().unwrap() = true;
    sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &events,
      &revision,
    )
    .await
    .unwrap();
    assert_eq!(snapshot_dispatches.load(Ordering::SeqCst), 3);
    assert!(
      cursors.peers.get(&peer).unwrap().snapshot_cursor.is_some(),
      "the delivered trust page commits its cursor"
    );

    // Round 4: the closing empty page completes the pass for this
    // revision.
    sync_tick(
      &context,
      &entropy,
      &sessions,
      &runtime,
      &endpoints,
      &mut cursors,
      &events,
      &revision,
    )
    .await
    .unwrap();
    let state = cursors.peers.get(&peer).unwrap();
    assert_eq!(state.snapshot_rev, 1, "the pass completed for revision 1");
    assert!(
      state.snapshot_cursor.is_none(),
      "the completed pass resets the cursor"
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
          &keys.as_provider(),
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
      let drainer_admit = Arc::clone(&admit_all);
      let drainer_snapshots = Arc::clone(&snapshot_dispatches);
      let drainer_leaves = Arc::clone(&leave_dispatches);
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
        reference,
      }
    }

    async fn tick(&self, cursors: &mut MembershipSyncCursors) {
      let endpoints = vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()];
      sync_tick(
        &self.context,
        &self.entropy,
        &self.sessions,
        &self.runtime,
        &endpoints,
        cursors,
        &self.events,
        &self.revision,
      )
      .await
      .unwrap();
    }
  }

  /// Regression: an undelivered round must retry on the NEXT tick, not
  /// after a full SNAPSHOT_RESEND_TICKS interval. The cadence counters
  /// advance every tick and are reset only by delivery verdicts; under
  /// the dispatch-time reset a single failed round consumed the cadence
  /// and silenced both lanes for the whole resend interval.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn an_undelivered_round_retries_on_the_next_tick_not_after_the_full_interval() {
    use std::sync::atomic::Ordering;

    let harness = CadenceHarness::build().await;
    let mut cursors = MembershipSyncCursors::default();

    // Converge one full snapshot pass first: round 1 delivers the trust
    // page (the tombstones ride the revision change), round 2 closes the
    // pass at revision 1. Round 3 is fully quiet.
    harness.tick(&mut cursors).await;
    harness.tick(&mut cursors).await;
    harness.tick(&mut cursors).await;
    let state = cursors.peers.get(&harness.peer).unwrap();
    assert_eq!(state.snapshot_rev, 1, "the snapshot pass completed");
    assert_eq!(harness.snapshot_dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(harness.leave_dispatches.load(Ordering::SeqCst), 2);

    // Arm both cadences, then fail a round completely: nothing may reset
    // the counters.
    {
      let state = cursors.peers.get_mut(&harness.peer).unwrap();
      state.ticks_since_snapshot_send = SNAPSHOT_RESEND_TICKS;
      state.ticks_since_tombstone_send = SNAPSHOT_RESEND_TICKS;
    }
    *harness.admit_all.lock().unwrap() = false;
    harness.tick(&mut cursors).await;
    let state = cursors.peers.get(&harness.peer).unwrap();
    assert!(
      state.snapshot_cursor.is_none(),
      "the failed round delivered nothing"
    );
    assert_eq!(harness.snapshot_dispatches.load(Ordering::SeqCst), 2);
    assert_eq!(harness.leave_dispatches.load(Ordering::SeqCst), 3);

    // The next tick retries BOTH lanes: the counters were not consumed
    // by the failed round.
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.snapshot_dispatches.load(Ordering::SeqCst),
      3,
      "the snapshot lane retried on the next tick"
    );
    assert_eq!(
      harness.leave_dispatches.load(Ordering::SeqCst),
      4,
      "the tombstone lane retried on the next tick"
    );
    assert!(
      cursors
        .peers
        .get(&harness.peer)
        .unwrap()
        .snapshot_cursor
        .is_none()
    );

    // Delivery heals both lanes: the verdict resets the cadences and
    // commits the cursor.
    *harness.admit_all.lock().unwrap() = true;
    harness.tick(&mut cursors).await;
    let state = cursors.peers.get(&harness.peer).unwrap();
    assert!(
      state.snapshot_cursor.is_some(),
      "the delivered trust page commits its cursor"
    );
    assert_eq!(harness.snapshot_dispatches.load(Ordering::SeqCst), 4);
    assert_eq!(harness.leave_dispatches.load(Ordering::SeqCst), 5);
  }

  /// Regression: the snapshot/tombstone cadence counters must advance on
  /// every tick — independent of the (possibly multi-tick)
  /// descriptor-page pass. Under quiet-round-only advancement a long
  /// descriptor pass froze the tombstone lane for the whole pass.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_long_descriptor_pass_does_not_stall_the_tombstone_lane() {
    use std::sync::atomic::Ordering;

    use crate::{StoreKey, identity::testing::inject_entry};

    let harness = CadenceHarness::build().await;
    // A catalog far larger than one descriptor page: the page plane runs
    // a multi-tick Send pass once the first tick records its cursor.
    let descriptor_namespace =
      crate::storage::families::namespace(crate::storage::families::NODE_DESCRIPTOR_NAMESPACE)
        .unwrap();
    for index in 0..100_u64 {
      let member = node_at(500 + index);
      let descriptor = crate::membership::NodeDescriptorV1::new(
        member.clone(),
        key_at(1),
        vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()],
        1,
        false,
        1,
      );
      inject_entry(
        &harness.reference,
        (
          descriptor_namespace.clone(),
          StoreKey::new(std::sync::Arc::from(member.as_str().as_bytes().to_vec())),
        ),
        descriptor.encode().unwrap(),
      );
    }

    let mut cursors = MembershipSyncCursors::default();
    // Pre-arm the tick state: the snapshot pass is already converged at
    // revision 1 (no revision signal), and the tombstone cadence is two
    // ticks from its resend threshold.
    cursors.peers.insert(
      harness.peer.clone(),
      PeerSyncState {
        snapshot_rev: 1,
        ticks_since_tombstone_send: SNAPSHOT_RESEND_TICKS - 2,
        ..PeerSyncState::default()
      },
    );

    // Tick 1: the descriptor page dispatches (the pass starts) but the
    // tombstone cadence is not reached yet.
    harness.tick(&mut cursors).await;
    assert_eq!(harness.leave_dispatches.load(Ordering::SeqCst), 0);
    // The page plane is mid-pass: its continuation cursor is set.
    assert!(
      cursors
        .peers
        .get(&harness.peer)
        .unwrap()
        .page
        .continuation()
        .is_some(),
      "the descriptor pass is in flight"
    );

    // Tick 2: still mid-pass, but the tombstone cadence elapsed — the
    // leave record must forward even though no round was quiet.
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.leave_dispatches.load(Ordering::SeqCst),
      1,
      "the tombstone lane forwarded mid-pass"
    );
    assert!(
      cursors
        .peers
        .get(&harness.peer)
        .unwrap()
        .page
        .continuation()
        .is_some(),
      "the descriptor pass is still in flight"
    );

    // The delivered tombstone round re-arms the cadence: no immediate
    // re-fire on the next tick.
    harness.tick(&mut cursors).await;
    assert_eq!(
      harness.leave_dispatches.load(Ordering::SeqCst),
      1,
      "the delivered round reset the tombstone cadence"
    );
  }
}
