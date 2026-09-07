//! Session-carried membership sync (G5-05/06 wiring, rebaselined by
//! ADR-0009).
//!
//! An authenticated session carries two bounded sync payloads in one
//! direction: a [`MembershipPage`] of node descriptors and the issuer
//! [`TrustSnapshotV1`] binding set. Entries are trusted through the
//! authenticated session that delivered them (ADR-0008); decoding checks
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
    trust::{TrustBinding, TrustSnapshotV1, store as trust_store},
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
/// sessions. Entries are trusted through the session that delivered them
/// (ADR-0008); decoding enforces canonical wire rules and bounded
/// capacities before install.
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

/// The bounded wait for the first leave-record admission acknowledgement
/// (ADR-0009 decision 3): five seconds, well inside the fixed
/// authentication deadline's order of magnitude.
const LEAVE_ACK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The bounded wait for flushing the record bodies after the first
/// acknowledgement. Deliberately a fresh budget, not the ack wait's
/// remainder: a slow acknowledgement must not shrink the flush window
/// toward zero, or the record body dies in the outbound queue when the
/// teardown retires the sessions (at-most-once loss of terminal
/// evidence).
const LEAVE_FLUSH_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The leave-plane announcement (ADR-0009 decision 3): injects the
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
      // Every newly installed descriptor is one member change (T-G09-07).
      let installed = page_sync::apply_page_ctx(store, entropy.as_ref(), &page).await?;
      for node in installed {
        member_changed(events, revision, node);
      }
    }
    SyncPayload::Snapshot(encoded) => {
      let snapshot = TrustSnapshotV1::decode(encoded.as_ref())?;
      // The issuer's declared key must match its locally trusted binding
      // when one exists: a substitution is conflicting evidence and fails
      // closed (ADR-0009: snapshots are per-issuer, trusted through the
      // authenticated session and the binding set they extend).
      let bindings = trust_store::trusted_bindings(store).await?;
      if let Some(known) = bindings.get(snapshot.issuer())
        && known != snapshot.issuer_key()
      {
        return Err(Error::not_trusted("trust snapshot issuer key"));
      }
      trust_store::persist_snapshot_ctx(store, entropy.as_ref(), &snapshot).await?;
      // Binding adoption is best effort per record: a transient store
      // contention on one binding must not abort the remaining bindings of
      // the snapshot; the next delivery retries what was skipped
      // (anti-entropy repair, SC-G05-P0-07).
      for binding in snapshot.bindings() {
        if let Err(error) =
          trust_store::persist_binding_ctx(store, entropy.as_ref(), binding.node(), binding.key())
            .await
        {
          tracing::debug!(node = %binding.node(), kind = ?error.kind(), "trust binding persist skipped");
          continue;
        }
        let _ =
          trust_store::adopt_binding_ctx(store, entropy.as_ref(), binding.node(), binding.key())
            .await;
      }
    }
    SyncPayload::Leave(encoded) => {
      // An owner-signed leave record is terminal evidence (ADR-0009
      // decision 3): verified against the permanently retained binding
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
      // The applied receipt (ADR-0009 decision 3): one durable-install
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
      // An issuer-signed cleanup tombstone is terminal evidence (ADR-0009
      // decision 4): verified against the retained issuer and subject
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
      // A revocation tombstone is convergent permanent evidence (ADR-0009
      // decision 6): verified against the retained issuer and subject
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
      // A cleanup checkpoint is unsigned hygiene knowledge (ADR-0009
      // decision 5): max-wins by watermark, never gating live entries or
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
/// endpoint candidates, so the anti-entropy tick can page it. Publishes a
/// revision bump when the endpoint set changes and the caller requests it.
pub(crate) async fn ensure_local_descriptor(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>, endpoints: Vec<crate::Endpoint>,
) -> Result<()> {
  let store = context.store();
  let node = context.identity().node().clone();
  let public_key = context.identity().public_key().clone();
  let existing = crate::membership::store::read_descriptor_ctx(store, &node).await?;
  if let Some(current) = &existing {
    let same_endpoints = current.endpoints().len() == endpoints.len()
      && current
        .endpoints()
        .iter()
        .zip(&endpoints)
        .all(|(left, right)| left == right);
    if same_endpoints {
      return Ok(());
    }
    // An empty candidate set never downgrades published endpoints: the
    // startup tick fires before any listener exists and must not bump the
    // revision (descriptor endpoint stability, SC-G05-P0-25).
    if endpoints.is_empty() {
      return Ok(());
    }
  }
  let revision = existing
    .as_ref()
    .map_or(1, |current| current.revision().saturating_add(1));
  let descriptor = crate::membership::NodeDescriptorV1::new(
    node.clone(),
    public_key,
    endpoints,
    revision,
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
      .map(|current| current.revision() >= revision)
      .unwrap_or(false);
    if !installed {
      return Err(error);
    }
  }
  Ok(())
}

/// Every node refreshes its own trust snapshot when its binding set
/// changed: enumerate the durable bindings at revision `latest + 1` and
/// persist. Returns the latest snapshot.
pub(crate) async fn refresh_issuer_snapshot(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>,
) -> Result<Option<TrustSnapshotV1>> {
  let store = context.store();
  let issuer = context.identity().node().clone();
  // Cheap short-circuit: bindings are append-only between merges, so an
  // unchanged count means an unchanged binding set; the full enumeration
  // runs only when a merge may have added one.
  let latest = trust_store::latest_snapshot_ctx(store, &issuer).await?;
  if let Some(latest) = &latest
    && !trust_store::has_more_than_bindings(store, latest.bindings().len()).await?
  {
    return Ok(Some(latest.clone()));
  }
  let bindings = trust_store::trusted_bindings(store).await?;
  let current: Vec<TrustBinding> = bindings
    .into_iter()
    .map(|(node, key)| TrustBinding::new(node, key))
    .collect();
  let revision = match &latest {
    Some(latest) if latest.bindings() != current.as_slice() => latest.revision().saturating_add(1),
    Some(latest) => return Ok(Some(latest.clone())),
    None => 1,
  };
  let snapshot = TrustSnapshotV1::new(
    revision,
    1,
    issuer,
    context.identity().public_key().clone(),
    current,
  );
  persist_snapshot_with_bindings(store, entropy, &snapshot).await?;
  Ok(Some(snapshot))
}

/// Persists one verified snapshot plus its binding observations, so the
/// issuer's own trust page and every receiver's page expose the exact
/// binding set (SC-G05-P0-25).
async fn persist_snapshot_with_bindings(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>, snapshot: &TrustSnapshotV1,
) -> Result<()> {
  trust_store::persist_snapshot_ctx(store, entropy.as_ref(), snapshot).await?;
  for binding in snapshot.bindings() {
    trust_store::persist_binding_ctx(store, entropy.as_ref(), binding.node(), binding.key())
      .await?;
  }
  Ok(())
}

/// One anti-entropy tick: publish the local descriptor, refresh the issuer
/// snapshot when this node is the creator, and push a bounded page plus the
/// latest snapshot over every authenticated session. The work per tick is
/// bounded: one page and one snapshot per session, nothing paged to
/// exhaustion (SC-G05-P0-06).
/// The driver's per-node anti-entropy continuation state.
#[derive(Default)]
pub(crate) struct SyncCursor {
  /// The last snapshot revision sent, so unchanged grant sets are not
  /// re-sent every tick.
  pub(crate) snapshot_rev: u64,
  /// Ticks since the last snapshot send: a lost delivery must be retried
  /// without waiting for the next grant-set change.
  pub(crate) ticks_since_snapshot_send: u32,
  /// Fingerprint of the last page sent, so an unchanged membership set
  /// costs no encode or per-peer delivery at all.
  pub(crate) page_fingerprint: u64,
  /// Fingerprint of the alive-peer set: a newly connected peer must
  /// receive the current pages immediately, changed set or not.
  pub(crate) peers_fingerprint: u64,
  /// Ticks since the last page send: a lost delivery must be retried on
  /// a slow cadence even when nothing changed.
  pub(crate) ticks_since_page_send: u32,
  /// The last membership page cursor, so descriptor sync continues across
  /// ticks and converges beyond a single page.
  pub(crate) page: Option<Vec<u8>>,
}

/// The bounded number of known leave records forwarded per snapshot
/// round (anti-entropy healing without unbounded per-tick work).
const LEAVE_RESEND_CAP: usize = 64;

/// Snapshot deliveries are retried on this slow cadence even when the
/// grant set is unchanged, so a dropped payload heals instead of stalling
/// a peer forever (anti-entropy, SC-G05-P0-07).
const SNAPSHOT_RESEND_TICKS: u32 = 8;
/// Page deliveries are retried on this slower cadence for the same reason.
const PAGE_RESEND_TICKS: u32 = 32;

pub(crate) async fn sync_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>, sessions: &SessionTable,
  runtime: &RuntimeClient, local_endpoints: &[crate::Endpoint], cursor: &mut SyncCursor,
) -> Result<()> {
  let store = context.store();
  // Nothing to advertise at startup: the supervisor publishes the local
  // descriptor (with endpoints) when a query or listener first needs it,
  // so the anti-entropy loop never races a transient empty endpoint set
  // into a revision bump.
  if !local_endpoints.is_empty() {
    ensure_local_descriptor(context, entropy, local_endpoints.to_vec()).await?;
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
  let snapshot = refresh_issuer_snapshot(context, entropy).await?;
  // Removal tombstones (leave, cleanup) ride the same anti-entropy plane:
  // forward the known (bounded) sets whenever a snapshot round sends, so a
  // lost delivery heals on the resend cadence (ADR-0009 decisions 3-4).
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
  let peers_fp = crate::sync_common::peers_fingerprint(&peers);
  // A paged anti-entropy round advances the cursor only while it is
  // sending; a steady state with an unchanged first page never turns the
  // cursor, so the page content (and its fingerprint) cannot change
  // between ticks and the quiet state costs no sends at all (T-G10-06
  // soak finding: an unconditional cursor turn re-sent every page every
  // tick, keeping one frame in flight permanently).
  let starting_round = cursor.page.is_none();
  let page = page_sync::emit_page_ctx(
    store,
    cursor.page.as_deref(),
    crate::membership::page::DEFAULT_PAGE_LIMIT,
  )
  .await?;
  let page_payload = SyncPayload::Page(ByteVec::from(page.encode()?));
  let page_bytes = page_payload.encode()?;
  // A round starts when the first page's content or the alive-peer set
  // changed, and is retried on a slow cadence otherwise (lost-delivery
  // healing, SC-G05-P0-07). Mid-round pages always send: they are the
  // continuation of an already-started round.
  let page_fp = page.fingerprint();
  let page_due = if starting_round {
    let due = page_fp != cursor.page_fingerprint
      || peers_fp != cursor.peers_fingerprint
      || cursor.ticks_since_page_send >= PAGE_RESEND_TICKS;
    cursor.page_fingerprint = page_fp;
    due
  } else {
    true
  };
  if page_due || !starting_round {
    cursor.page = page.cursor().map(|value| value.to_vec());
  }
  cursor.peers_fingerprint = peers_fp;
  // A snapshot is sent when its revision advanced, and retried on a slow
  // cadence even when unchanged: re-sending the same revision to every
  // session every tick floods the store with idempotent commits, but a
  // lost delivery must still heal (SC-G05-P0-07).
  let snapshot_payload = match &snapshot {
    Some(snapshot)
      if snapshot.revision() != cursor.snapshot_rev
        || cursor.ticks_since_snapshot_send >= SNAPSHOT_RESEND_TICKS =>
    {
      cursor.snapshot_rev = snapshot.revision();
      cursor.ticks_since_snapshot_send = 0;
      Some(SyncPayload::Snapshot(ByteVec::from(snapshot.encode()?)))
    }
    Some(_) => {
      cursor.ticks_since_snapshot_send = cursor.ticks_since_snapshot_send.saturating_add(1);
      None
    }
    None => None,
  };
  let snapshot_bytes = match &snapshot_payload {
    Some(payload) => Some(payload.encode()?),
    None => None,
  };
  let leave_bytes: Vec<Vec<u8>> = if snapshot_bytes.is_some() {
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
      send = !leave_bytes.is_empty(),
      "removal tombstones considered for forwarding"
    );
  }
  if page_due || !starting_round {
    cursor.ticks_since_page_send = 0;
    for peer in &peers {
      if let Some(bytes) = &snapshot_bytes {
        let _ = crate::sync_common::send_payload(runtime, entropy, peer, &protocol, bytes).await;
      }
      for bytes in &leave_bytes {
        let _ = crate::sync_common::send_payload(runtime, entropy, peer, &protocol, bytes).await;
      }
      let _ =
        crate::sync_common::send_payload(runtime, entropy, peer, &protocol, &page_bytes).await;
    }
    gc_collected_tombstones(store, entropy).await;
    return Ok(());
  }
  cursor.ticks_since_page_send = cursor.ticks_since_page_send.saturating_add(1);
  if let Some(bytes) = &snapshot_bytes {
    for peer in &peers {
      let _ = crate::sync_common::send_payload(runtime, entropy, peer, &protocol, bytes).await;
      for bytes in &leave_bytes {
        let _ = crate::sync_common::send_payload(runtime, entropy, peer, &protocol, bytes).await;
      }
    }
  }
  gc_collected_tombstones(store, entropy).await;
  Ok(())
}

/// The post-round checkpoint GC (ADR-0009 decision 5): collect the
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
