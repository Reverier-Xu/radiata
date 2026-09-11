//! Session-carried membership sync.
//!
//! An authenticated session carries two bounded sync payloads in one
//! direction: a [`MembershipPage`] of node descriptors and the issuer
//! [`TrustSnapshotV1`] binding set. Entries are trusted through the
//! authenticated session that delivered them; decoding checks
//! only canonical wire rules and bounded capacities. Every node refreshes
//! its own snapshot when its binding set changes, and every member pages
//! its local descriptors, so reciprocal trust, exact descriptors, and
//! topology converge over the same authenticated sessions the facade
//! observes.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{
  Error, IncomingStream, NodeId, ProtocolTag, Result,
  api::{BoxFuture, Entropy},
  extension_registry::{PacketConsumer, ProtocolDefinition},
  identity::{
    lifecycle::LocalIdentityContext,
    trust::{TrustSnapshotV1, accept_snapshot, refresh_issuer_snapshot, store as trust_store},
  },
  membership::page::{MembershipPage, sync as page_sync},
  protocol::{decode_canonical_strict, encode_canonical},
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
  /// An encoded [`TrustSnapshotV1`].
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

#[derive(Encode, Decode)]
#[cbor(array)]
struct SyncPayloadWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  kind: u8,
  #[n(2)]
  payload: ByteVec,
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
    encode_canonical(
      &SyncPayloadWire {
        schema: SYNC_PAYLOAD_SCHEMA.to_owned(),
        kind,
        payload,
      },
      crate::protocol::CONTROL_CBOR_LIMITS,
    )
  }

  /// Decodes one payload, rejecting unknown schemas and kinds and any
  /// non-canonical encoding (fail closed).
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: SyncPayloadWire = decode_canonical_strict(
      bytes,
      crate::protocol::CONTROL_CBOR_LIMITS,
      "membership sync payload canonical form",
    )?;
    if wire.schema != SYNC_PAYLOAD_SCHEMA {
      return Err(Error::invalid_input("membership sync payload schema"));
    }
    match wire.kind {
      SYNC_KIND_PAGE => Ok(Self::Page(wire.payload)),
      SYNC_KIND_SNAPSHOT => Ok(Self::Snapshot(wire.payload)),
      SYNC_KIND_LEAVE => Ok(Self::Leave(wire.payload)),
      SYNC_KIND_CLEANUP => Ok(Self::Cleanup(wire.payload)),
      SYNC_KIND_REVOCATION => Ok(Self::Revocation(wire.payload)),
      SYNC_KIND_CHECKPOINT => Ok(Self::Checkpoint(wire.payload)),
      SYNC_KIND_LEAVE_APPLIED => Ok(Self::LeaveApplied {
        node: NodeId::parse(
          std::str::from_utf8(wire.payload.as_ref())
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
#[derive(Debug)]
pub(crate) struct MembershipSyncConsumer {
  // Held weakly so the registry shared with a live node handle never pins
  // the node's metadata store after shutdown; a packet arriving after the
  // runtime dropped is rejected as shutting down.
  context: std::sync::Weak<LocalIdentityContext>,
  entropy: Arc<dyn Entropy>,
  events: Arc<crate::node::EventHub>,
  revision: crate::node::MemberRevisionSignal,
  leave_applied: LeaveAppliedSignal,
}

impl MembershipSyncConsumer {
  pub(crate) fn new(
    context: Arc<LocalIdentityContext>, entropy: Arc<dyn Entropy>,
    events: Arc<crate::node::EventHub>, revision: crate::node::MemberRevisionSignal,
    leave_applied: LeaveAppliedSignal,
  ) -> Self {
    Self {
      context: Arc::downgrade(&context),
      entropy,
      events,
      revision,
      leave_applied,
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
    let (ack_notify, ack) = tokio::sync::oneshot::channel();
    let trace_id = crate::TraceId::generate(entropy.as_ref())?;
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
      routes.clone(),
      false,
      None,
      events.clone(),
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
  leave_applied: &LeaveAppliedSignal, runtime: &RuntimeClient, source: &NodeId,
  payload: &SyncPayload,
) -> Result<()> {
  let store = context.store();
  match payload {
    SyncPayload::Page(encoded) => {
      let page = MembershipPage::decode(encoded.as_ref())?;
      // Every newly installed descriptor is one member change.
      let installed = page_sync::apply_page_ctx(store, entropy.as_ref(), &page).await?;
      for node in installed {
        member_changed(events, revision, node);
      }
    }
    SyncPayload::Snapshot(encoded) => {
      let snapshot = TrustSnapshotV1::decode(encoded.as_ref())?;
      // The trust adoption policy lives in the trust module: issuer key
      // verification and per-binding adoption (a delivered snapshot is
      // never persisted; only the issuer's own refresh persists one).
      accept_snapshot(store, entropy.as_ref(), &snapshot).await?;
    }
    SyncPayload::Leave(encoded) => {
      // An owner-signed leave record is terminal evidence: verified
      // against the permanently retained binding
      // before any persistence. A record whose binding has not converged
      // yet is skipped; the resend cadence heals the ordering.
      let record = crate::identity::leave::LeaveRecordV1::decode(encoded.as_ref())?;
      let bindings = trust_store::trusted_bindings(store).await?;
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
      if let Err(error) =
        crate::sync_common::send_payload(runtime, &entropy, source, &protocol, &receipt).await
      {
        tracing::debug!(kind = ?error.kind(), "leave applied receipt skipped");
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
      let bindings = trust_store::trusted_bindings(store).await?;
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
      let bindings = trust_store::trusted_bindings(store).await?;
      if !bindings.contains_key(record.issuer()) || !bindings.contains_key(record.subject()) {
        tracing::debug!(subject = %record.subject(), "revocation record skipped: bindings unknown");
        return Ok(());
      }
      crate::identity::revocation::persist_revocation_ctx(store, entropy.as_ref(), &record).await?;
      events.emit(crate::NodeRevoked::new(record.subject().clone()));
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
  /// The last snapshot revision sent to this peer, so unchanged grant
  /// sets are not re-sent every tick.
  snapshot_rev: u64,
  /// Ticks since this peer's last snapshot send: a lost delivery must be
  /// retried without waiting for the next grant-set change.
  ticks_since_snapshot_send: u32,
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
  // Snapshot and tombstone wire bytes are peer-independent: encode once.
  let snapshot_bytes = snapshot
    .as_ref()
    .map(|snapshot| SyncPayload::Snapshot(ByteVec::from(snapshot.encode()?)).encode())
    .transpose()?;
  let tombstone_bytes: Vec<Vec<u8>> = if snapshot.is_some() {
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
  } else {
    Vec::new()
  };
  if !leave_records.is_empty() || !cleanup_records.is_empty() {
    tracing::debug!(
      leave = leave_records.len(),
      cleanup = cleanup_records.len(),
      send = !tombstone_bytes.is_empty(),
      "removal tombstones considered for forwarding"
    );
  }
  for peer in &peers {
    let state = cursors.peers.entry(peer.clone()).or_default();
    state.page.arm_full_pass();
    let page = page_sync::emit_page_ctx(
      store,
      state.page.continuation(),
      crate::membership::page::DEFAULT_PAGE_LIMIT,
    )
    .await?;
    let page_bytes = SyncPayload::Page(ByteVec::from(page.encode()?)).encode()?;
    // The page-round decision records the fingerprint against the
    // emitted page on starting rounds only: a stale recorded
    // fingerprint would mark every round as changed, keep the page due
    // forever, and starve the snapshot/tombstone resend cadence — the
    // quiet rounds between unchanged pages are what let
    // ticks_since_snapshot_send advance to its resend threshold.
    let page_round = state.page.page_round(page.fingerprint());
    // A snapshot is due for this peer when its revision advanced past
    // what this peer last received, or on the slow resend cadence.
    let snapshot_due = match &snapshot {
      Some(snapshot) => {
        snapshot.revision() != state.snapshot_rev
          || state.ticks_since_snapshot_send >= SNAPSHOT_RESEND_TICKS
      }
      None => false,
    };
    match page_round {
      crate::sync_common::PageRound::Quiet if !snapshot_due => {
        state.page.quiet_tick();
        state.ticks_since_snapshot_send = state.ticks_since_snapshot_send.saturating_add(1);
        continue;
      }
      crate::sync_common::PageRound::Quiet => {
        // The page is not due, but the snapshot leg is: dispatch the
        // snapshot round without advancing the page cursor.
      }
      crate::sync_common::PageRound::Send => {
        state.page.record_send(page.cursor());
      }
    }
    if snapshot_due {
      if let Some(snapshot) = &snapshot {
        state.snapshot_rev = snapshot.revision();
      }
      state.ticks_since_snapshot_send = 0;
    }
    let mut payloads: Vec<&[u8]> = Vec::new();
    if snapshot_due {
      if let Some(bytes) = &snapshot_bytes {
        payloads.push(bytes);
      }
      payloads.extend(tombstone_bytes.iter().map(Vec::as_slice));
    }
    payloads.push(&page_bytes);
    dispatch_to_peer(peer, &payloads, runtime, entropy, &protocol).await;
    state.page.count_round();
  }
  gc_collected_tombstones(store, entropy).await;
  Ok(())
}

/// The per-tick fan-out to one peer: sends every payload in order,
/// swallowing individual delivery failures (the snapshot and page resend
/// cadences heal lost payloads).
async fn dispatch_to_peer(
  peer: &NodeId, payloads: &[&[u8]], runtime: &RuntimeClient, entropy: &Arc<dyn Entropy>,
  protocol: &ProtocolTag,
) {
  for payload in payloads {
    let _ = crate::sync_common::send_payload(runtime, entropy, peer, protocol, payload).await;
  }
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
    NodeId::parse(&format!("node_{seed:021}")).unwrap()
  }

  fn node_at(seed: u64) -> NodeId {
    NodeId::parse(&format!("node_{seed:021}")).unwrap()
  }

  fn key_at(value: u64) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value);
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  /// Regression: a snapshot refresh failure used to fail the whole sync
  /// tick every round — an issuer binding set over the single-record
  /// control bound cannot encode (~870+ bindings), so descriptor and
  /// tombstone anti-entropy stalled permanently. The oversized issuer
  /// refresh fails in isolation, the tick still returns success, and the
  /// page plane keeps advancing (round dispatched, resend cadence armed)
  /// while no snapshot revision is ever recorded.
  #[tokio::test]
  async fn sync_tick_survives_snapshot_refresh_overflow() {
    use crate::{
      identity::{
        lifecycle,
        testing::{ScriptedKeys, SequenceEntropy},
      },
      storage::contract::{ReferenceFactory, required_capabilities},
    };

    let factory: Arc<dyn crate::provider::StorageFactory> =
      Arc::new(ReferenceFactory::new(required_capabilities()));
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
    // (1_024 collection entries inside the 64 KiB control body): the
    // issuer's own snapshot can no longer encode.
    for index in 0..1_200_u64 {
      trust_store::adopt_binding_ctx(
        context.store(),
        entropy.as_ref(),
        &node_at(index),
        &key_at(index),
      )
      .await
      .unwrap();
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
}
