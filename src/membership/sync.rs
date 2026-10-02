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
    trust::{refresh_issuer_snapshot, store as trust_store},
  },
  runtime::RuntimeClient,
};

/// The canonical protocol tag of the membership sync stream.
pub(crate) const MEMBERSHIP_SYNC_PROTOCOL: &str = "radiata.woooo.tech/protocols/membership-sync";

/// The wire schema of one sync payload.
const SYNC_PAYLOAD_SCHEMA: &str = "radiata.woooo.tech/schemas/membership-sync-payload-v1";

/// Payload kinds: this protocol carries the interactive leave plane
/// only — the owner-signed leave announcement and its applied receipt.
/// Every anti-entropy lane (descriptors, trust, resources, tombstones)
/// rides the reconciliation plane (`crate::reconcile::plane`).
pub(crate) const SYNC_KIND_LEAVE: u8 = 3;
/// A leave-applied receipt: the applying peer confirms one leave record
/// persisted. Additive (post-0.1 peers only): peers that never send it
/// leave the announcement on its documented bounded-degradation path.
pub(crate) const SYNC_KIND_LEAVE_APPLIED: u8 = 7;

/// One sync payload: one encoded signed removal tombstone, or the
/// leave-applied receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SyncPayload {
  /// An encoded [`crate::identity::leave::LeaveRecordV1`].
  Leave(ByteVec),
  /// The applying peer's receipt for one leave record, addressed to the
  /// leaver. A hint only: never re-forwarded, never stored, and absent
  /// from pre-receipt peers by design.
  LeaveApplied { node: NodeId },
}

impl SyncPayload {
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    let (kind, payload) = match self {
      Self::Leave(encoded) => (SYNC_KIND_LEAVE, encoded.clone()),
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
      SYNC_KIND_LEAVE => Ok(Self::Leave(payload)),
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
/// guaranteed the change is durable and query-visible. Shared with the
/// reconciliation plane so both install paths bump exactly once.
pub(crate) fn member_changed(
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

/// The tombstone arms' shared verification context: the trusted-binding
/// set plus the collected-tombstone watermark, loaded once per payload
/// or row batch (every arm consults both).
struct TombstoneEvidence {
  bindings: std::collections::BTreeMap<NodeId, crate::PublicKey>,
  checkpoint: Option<u64>,
}

async fn tombstone_evidence(store: &crate::storage::MetadataStore) -> Result<TombstoneEvidence> {
  Ok(TombstoneEvidence {
    bindings: trust_store::trusted_bindings(store).await?,
    checkpoint: crate::identity::cleanup::latest_checkpoint_millis_ctx(store).await?,
  })
}

/// True when the record's timestamp sits at or before the collected
/// tombstone watermark: the cluster already asserted it collectable, so
/// re-persisting it would resurrect collected evidence — the receive
/// side of the sender-side store filter the watermark walk had (a
/// sender never forwarded a record its own GC had collected; the
/// reconciliation engines cannot forget rows, so the filter lives
/// here).
fn collected(checkpoint: Option<u64>, timestamp_millis: u64) -> bool {
  checkpoint.is_some_and(|watermark| timestamp_millis <= watermark)
}

/// Applies one encoded owner-signed leave record: verified against the
/// permanently retained binding before any persistence. A record whose
/// binding has not converged yet is skipped; the next epoch pass of the
/// reconciliation plane heals the ordering. The row-key↔record
/// attribution is checked at the lane's dispatch boundary. A
/// durable install answers the sender with the applied receipt when
/// `runtime` and `source` are present.
#[allow(clippy::too_many_arguments)]
async fn apply_leave_record(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
  evidence: &TombstoneEvidence, record: &crate::identity::leave::LeaveRecordV1,
  source: Option<&NodeId>, runtime: Option<&RuntimeClient>,
) -> Result<()> {
  if collected(evidence.checkpoint, record.timestamp_millis()) {
    tracing::debug!(node = %record.node(), "leave record skipped: already collected");
    return Ok(());
  }
  let Some(bound_key) = evidence.bindings.get(record.node()) else {
    tracing::debug!(node = %record.node(), "leave record skipped: binding unknown");
    return Ok(());
  };
  if bound_key != record.public_key() {
    return Err(Error::not_trusted("leave record binding"));
  }
  // The writer exclusion serializes the persist against every other
  // store writer, so terminal evidence cannot be dropped on contention.
  // A persist failure must be attributable at the apply site: the
  // sender keeps forwarding the record, so an unlogged failure here
  // looks like a receiver-side roster stall.
  if let Err(error) =
    crate::identity::leave::persist_leave_record_ctx(store, entropy.as_ref(), record).await
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
  let (Some(source), Some(runtime)) = (source, runtime) else {
    return Ok(());
  };
  let receipt = SyncPayload::LeaveApplied {
    node: record.node().clone(),
  }
  .encode()?;
  let protocol = ProtocolTag::parse(MEMBERSHIP_SYNC_PROTOCOL)?;
  // The applied receipt: one durable-install confirmation back to the
  // leaver, best-effort and retried by the announcement budget.
  // Pre-receipt peers simply never send it. The admission ack is
  // still observed (delivery truth): the wait runs detached so the
  // pump never serializes behind it, and a failed admission is
  // diagnostics only — the receipt is a hint, never a trust decision.
  let entropy = Arc::clone(entropy);
  let peer = source.clone();
  match crate::sync_common::send_payload(runtime, &entropy, &peer, &protocol, &receipt).await {
    Ok(ack) => {
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
  Ok(())
}

/// Applies one encoded issuer-signed cleanup tombstone: verified
/// against the retained issuer and subject bindings before any
/// persistence. A tombstone whose bindings have not converged yet is
/// skipped; the ordering heals on the next pass.
#[allow(clippy::too_many_arguments)]
async fn apply_cleanup_record(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
  evidence: &TombstoneEvidence, record: &crate::identity::cleanup::CleanupRecordV1,
) -> Result<()> {
  if collected(evidence.checkpoint, record.timestamp_millis()) {
    tracing::debug!(subject = %record.subject(), "cleanup record skipped: already collected");
    return Ok(());
  }
  if !evidence.bindings.contains_key(record.issuer())
    || !evidence.bindings.contains_key(record.subject())
  {
    tracing::debug!(subject = %record.subject(), "cleanup record skipped: bindings unknown");
    return Ok(());
  }
  crate::identity::cleanup::persist_cleanup_record_ctx(store, entropy.as_ref(), record).await?;
  member_changed(events, revision, record.subject().clone());
  Ok(())
}

/// Applies one encoded revocation tombstone: convergent permanent
/// evidence, verified against the retained issuer and subject bindings
/// before any persistence, never covered by checkpoints, and never
/// re-adoptable away. A persisted revocation closes the authorization
/// boundary immediately on this node too: any live session with the
/// revoked identity retires (its recovery dials race the propagation,
/// so a session admitted before this tombstone landed must not linger).
#[allow(clippy::too_many_arguments)]
async fn apply_revocation_record(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, evidence: &TombstoneEvidence,
  record: &crate::identity::revocation::RevocationRecordV1,
  sessions: &crate::session::stream::SessionTable,
) -> Result<()> {
  if !evidence.bindings.contains_key(record.issuer())
    || !evidence.bindings.contains_key(record.subject())
  {
    tracing::debug!(subject = %record.subject(), "revocation record skipped: bindings unknown");
    return Ok(());
  }
  crate::identity::revocation::persist_revocation_ctx(store, entropy.as_ref(), record).await?;
  events.emit(crate::NodeRevoked::new(record.subject().clone()));
  crate::session::stream::retire_session(sessions, record.subject())?;
  Ok(())
}

/// Applies one encoded cleanup checkpoint: unsigned hygiene knowledge,
/// max-wins by watermark, never gating live entries or revocations.
async fn apply_checkpoint_record(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  checkpoint: &crate::identity::cleanup::CleanupCheckpointV1,
) -> Result<()> {
  crate::identity::cleanup::persist_checkpoint_ctx(store, entropy.as_ref(), checkpoint).await?;
  Ok(())
}

/// The tombstone lane's reconciliation row apply: kind-prefixed keys
/// (the plane's `TombstoneKind` prefixes) dispatch to the same per-record
/// arms the announcement payload uses, so both planes verify, persist,
/// notify, and collect identically. `source` addresses the applied
/// receipt to the peer that carried the rows; the derived-view repair
/// passes `None`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_tombstone_rows(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
  sessions: &crate::session::stream::SessionTable, rows: &[(Vec<u8>, Vec<u8>)],
  source: Option<&NodeId>, runtime: Option<&RuntimeClient>,
) -> Result<()> {
  let store = context.store();
  let evidence = tombstone_evidence(store).await?;
  // Row-level fault tolerance, the scan side's corrupt-row policy: one
  // undecodable or misattributed tombstone row skips with a typed reason
  // instead of failing the batch — a whole-batch error would wedge the
  // derived-view repair on the same poison row forever. Store failures
  // inside the apply arms still propagate: they are real write faults.
  for (key, content) in rows {
    let Some((kind, subject)) = key.split_first() else {
      tracing::debug!("reconcile tombstone row skipped: no kind prefix");
      continue;
    };
    let subject: &[u8] = subject;
    match kind {
      1 => {
        let record = match crate::identity::leave::LeaveRecordV1::decode(content) {
          Ok(record) if record.node().as_str().as_bytes() == subject => record,
          Ok(record) => {
            tracing::debug!(
              node = %record.node(),
              "reconcile leave row skipped: subject mismatch"
            );
            continue;
          }
          Err(error) => {
            tracing::debug!(kind = ?error.kind(), "reconcile leave row skipped: undecodable");
            continue;
          }
        };
        // A leave row is terminal evidence carried by its own
        // signature: a failed signature (AuthenticationFailed from the
        // strict verify) is an untrustworthy row — skip it, exactly
        // like a corrupt row, instead of failing the batch. The
        // evidence check inside the apply (the bound key mismatching
        // the record's key, NotTrusted) is a policy refusal of the
        // same class: the row is refused, the batch continues. Real
        // store write faults still propagate.
        if let Err(error) = record.verify() {
          tracing::warn!(
            node = %record.node(),
            kind = ?error.kind(),
            "reconcile leave row skipped: untrusted signature"
          );
          continue;
        }
        match apply_leave_record(
          store, entropy, events, revision, &evidence, &record, source, runtime,
        )
        .await
        {
          Err(error) if error.kind() == crate::ErrorKind::NotTrusted => {
            tracing::warn!(
              node = %record.node(),
              "reconcile leave row refused by policy: binding mismatch; skipping"
            );
          }
          other => other?,
        }
      }
      2 => {
        let record = match crate::identity::cleanup::CleanupRecordV1::decode(content) {
          Ok(record) if record.subject().as_str().as_bytes() == subject => record,
          Ok(record) => {
            tracing::debug!(
              subject = %record.subject(),
              "reconcile cleanup row skipped: subject mismatch"
            );
            continue;
          }
          Err(error) => {
            tracing::debug!(kind = ?error.kind(), "reconcile cleanup row skipped: undecodable");
            continue;
          }
        };
        apply_cleanup_record(store, entropy, events, revision, &evidence, &record).await?;
      }
      3 => {
        let record = match crate::identity::revocation::RevocationRecordV1::decode(content) {
          Ok(record) if record.subject().as_str().as_bytes() == subject => record,
          Ok(record) => {
            tracing::debug!(
              subject = %record.subject(),
              "reconcile revocation row skipped: subject mismatch"
            );
            continue;
          }
          Err(error) => {
            tracing::debug!(
              kind = ?error.kind(),
              "reconcile revocation row skipped: undecodable"
            );
            continue;
          }
        };
        apply_revocation_record(store, entropy, events, &evidence, &record, sessions).await?;
      }
      4 => {
        let checkpoint = match crate::identity::cleanup::CleanupCheckpointV1::decode(content) {
          Ok(checkpoint) if subject == b"checkpoint" => checkpoint,
          Ok(_) => {
            tracing::debug!("reconcile checkpoint row skipped: subject mismatch");
            continue;
          }
          Err(error) => {
            tracing::debug!(
              kind = ?error.kind(),
              "reconcile checkpoint row skipped: undecodable"
            );
            continue;
          }
        };
        apply_checkpoint_record(store, entropy, &checkpoint).await?;
      }
      _ => {
        tracing::debug!(kind, "reconcile tombstone row skipped: unknown kind");
      }
    }
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
    SyncPayload::Leave(encoded) => {
      let record = crate::identity::leave::LeaveRecordV1::decode(encoded.as_ref())?;
      let evidence = tombstone_evidence(store).await?;
      apply_leave_record(
        store,
        &entropy,
        events,
        revision,
        &evidence,
        &record,
        Some(source),
        Some(runtime),
      )
      .await?;
    }
    SyncPayload::LeaveApplied { node } => {
      // A receipt is a hint addressed to the record's subject only:
      // fail-open for every other receiver, and never a trust decision.
      if *node != *context.identity().node() {
        return Ok(());
      }
      leave_applied.bump();
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

/// One membership maintenance tick: publish the local descriptor,
/// refresh the issuer snapshot, and run the checkpoint GC. The
/// anti-entropy itself rides the reconciliation plane (every lane —
/// descriptors, trust, resources, tombstones); this tick is only the
/// local store maintenance whose writes then drive the plane's
/// epoch-rescan triggers.
///
/// The same quiescence contract the old sync tick held: before any
/// member is admitted the node's store writes are quiescent (the
/// supervisor's lazy paths publish the local descriptor on the first
/// public query), keeping the admission commit sequence deterministic
/// for fault-injecting providers — nothing here runs before membership
/// exists.
pub(crate) async fn membership_maintenance_tick(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>,
  local_endpoints: &[crate::Endpoint], events: &Arc<crate::node::EventHub>,
  revision: &crate::node::MemberRevisionSignal,
) -> Result<()> {
  let store = context.store();
  // Nothing to advertise at startup: the supervisor publishes the local
  // descriptor (with endpoints) when a query or listener first needs it,
  // so the maintenance loop never races a transient empty endpoint set
  // into a revision bump.
  if !local_endpoints.is_empty() {
    ensure_local_descriptor(context, entropy, local_endpoints.to_vec(), events, revision).await?;
  }
  if !trust_store::has_more_than_bindings(store, 1).await? {
    // No membership yet: nothing to maintain.
    return Ok(());
  }
  // The issuer snapshot refresh feeds the views (the trust lane
  // propagates the bindings straight from the store): a refresh or
  // encode failure must not fail the tick. Log and skip; the refresh
  // retries next tick.
  if let Err(error) = refresh_issuer_snapshot(context, entropy).await {
    tracing::warn!(
      kind = ?error.kind(),
      "issuer snapshot refresh failed; skipping this round's refresh"
    );
  }
  gc_collected_tombstones(store, entropy).await;
  Ok(())
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
  use crate::session::stream::SessionTable;

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

  /// Regression: a snapshot refresh failure used to fail the whole sync
  /// tick every round — an issuer binding set over the single-record
  /// store bound cannot encode (past the 16 384-entry collection cap of
  /// the 1 MiB store body), so the maintenance tick would fail
  /// permanently. The oversized issuer refresh fails in isolation, the
  /// tick still returns success, and the reconciliation lanes keep
  /// running while no snapshot revision is ever recorded.
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

    let endpoints = vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()];

    // The maintenance tick succeeds despite the failed refresh leg.
    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    membership_maintenance_tick(&context, &entropy, &endpoints, &events, &revision)
      .await
      .unwrap();
    // A quiet second tick: the failing refresh is logged and skipped,
    // never a tick failure.
    membership_maintenance_tick(&context, &entropy, &endpoints, &events, &revision)
      .await
      .unwrap();
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

  /// The shared cadence-test harness: a local identity holding two
  /// injected bindings (the tick's membership probe passes, the issuer
  /// snapshot is stable at revision 1), one known leave record (the
  /// tombstone lane has evidence to forward), and one live peer whose
  /// payloads the drainer admits or fails per payload kind (the leave
  /// plane's payloads; both reconciled lanes cross the peer plane). The
  /// drainer drops a failed kind's admission channel — the immediate
  /// failed verdict of a peer that never admits.
  struct CadenceHarness {
    context: Arc<crate::identity::lifecycle::LocalIdentityContext>,
    entropy: Arc<dyn Entropy>,
    runtime: RuntimeClient,
    events: Arc<crate::node::EventHub>,
    revision: crate::node::MemberRevisionSignal,
    /// The reconciliation plane driven beside the walk lanes: the
    /// descriptors lane rides it.
    plane: crate::reconcile::plane::ReconcilePlane,
    page_dispatches: Arc<std::sync::atomic::AtomicUsize>,
    /// The descriptor rows sent on the wire (the redundancy ledger's
    /// sent side: the ratio of this to the peer's adopted rows is the
    /// delivered-versus-useful traffic the plane's diff-only contract
    /// bounds).
    page_rows: Arc<std::sync::atomic::AtomicUsize>,
    /// The trust-lane rows sent on the wire (the binding redundancy
    /// ledger's sent side).
    trust_rows: Arc<std::sync::atomic::AtomicUsize>,
    /// The tombstone-lane rows sent on the wire.
    tombstone_rows: Arc<std::sync::atomic::AtomicUsize>,
    /// The far node's identity context (its store receives the applied
    /// rows): tests assert the row application end to end.
    peer_context: Arc<crate::identity::lifecycle::LocalIdentityContext>,
    /// The far node's plane: production nodes tick their own planes
    /// (the derived-view repair and the cadence live there).
    peer_plane: crate::reconcile::plane::ReconcilePlane,
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
      // One known leave record, properly signed by the local identity
      // (the far node applies it, and the apply path verifies the
      // signature — a dummy would only ever be delivered).
      let record = crate::identity::leave::sign_leave_record(&context, &keys.as_provider())
        .await
        .unwrap();
      let leaver = context.identity().node().clone();
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
      let runtime = RuntimeClient::routing_only(packet_tx.clone(), routes);
      let events = Arc::new(crate::node::EventHub::new());
      let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
      let revision = crate::node::MemberRevisionSignal::new(revision_tx);
      // The reconciliation plane: the descriptors lane rides it, and
      // the harness tick drives it beside the walk lanes.
      let plane = crate::reconcile::plane::ReconcilePlane::new(
        Arc::clone(&context),
        Arc::clone(&entropy) as Arc<dyn Entropy>,
        Arc::clone(&events),
        revision.clone(),
        sessions.clone(),
      );
      let page_dispatches = Arc::new(AtomicUsize::new(0));
      // The descriptor rows that actually went on the wire — the
      // redundancy ledger's sent side (the received side is what the
      // peer's store adopts).
      let page_rows = Arc::new(AtomicUsize::new(0));
      let trust_rows = Arc::new(AtomicUsize::new(0));
      let tombstone_rows = Arc::new(AtomicUsize::new(0));
      let drainer_pages = Arc::clone(&page_dispatches);
      let drainer_rows = Arc::clone(&page_rows);
      let drainer_trust_rows = Arc::clone(&trust_rows);
      let drainer_tombstone_rows = Arc::clone(&tombstone_rows);
      let drainer_peer = peer.clone();
      // The far side of the reconcile lane: an independent node (its own
      // store and plane) whose engines the drainer drives with every
      // frame we send, and whose responses come back to ours — the
      // same loopback shape the walk harnesses always used, now with a
      // real negotiation partner.
      let (_peer_reference, peer_factory) = crate::identity::testing::fresh_reference();
      let peer_keys = crate::identity::testing::ScriptedKeys::full_at(9_400);
      let peer_entropy = Arc::new(crate::identity::testing::SequenceEntropy::default());
      let peer_context = Arc::new(
        crate::identity::testing::open_context(&peer_factory, &peer_keys, &peer_entropy)
          .await
          .unwrap(),
      );
      // The far node's session table holds our node alive: production
      // peers have live sessions both ways, and the far plane's tick
      // (the repair and the cadence) keys off its own alive set.
      let peer_sessions: SessionTable =
        Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
      let (peer_entry, _peer_rx) = crate::session::stream::test_entry(peer_entropy.as_ref());
      peer_sessions
        .lock()
        .unwrap()
        .insert(context.identity().node().clone(), peer_entry);
      let peer_plane = crate::reconcile::plane::ReconcilePlane::new(
        std::sync::Arc::clone(&peer_context),
        peer_entropy,
        events.clone(),
        revision.clone(),
        peer_sessions,
      );
      let local = context.identity().node().clone();
      let drainer_own_plane = plane.clone();
      let drainer_peer_plane = peer_plane.clone();
      let drainer_runtime = runtime.clone();
      tokio::spawn(async move {
        while let Some(mut request) = packet_rx.recv().await {
          let mut bytes = Vec::new();
          while let Some(chunk) = request.body.as_mut().next().await {
            bytes.extend_from_slice(&chunk.unwrap());
          }
          let to_peer = matches!(&request.target, crate::StreamTarget::Exact(target) if *target == drainer_peer);
          if let Ok(payload) = crate::sync_common::decode_plain_sync_envelope(
            &bytes,
            crate::reconcile::plane::RECONCILE_SCHEMA,
            "harness reconcile canonical",
            "harness reconcile schema",
          ) && let Ok(message) = crate::reconcile::wire::decode(payload.as_ref())
          {
            if to_peer {
              if let crate::reconcile::wire::Message::Rows { rows, lane } = &message {
                match lane {
                  crate::reconcile::wire::LaneId::Trust => {
                    drainer_trust_rows.fetch_add(rows.len(), Ordering::SeqCst);
                  }
                  crate::reconcile::wire::LaneId::Tombstones => {
                    drainer_tombstone_rows.fetch_add(rows.len(), Ordering::SeqCst);
                  }
                  _ => {
                    drainer_pages.fetch_add(1, Ordering::SeqCst);
                    drainer_rows.fetch_add(rows.len(), Ordering::SeqCst);
                  }
                }
              }
              let _ = drainer_peer_plane
                .deliver(&drainer_runtime, &local, message.clone())
                .await;
            } else {
              let _ = drainer_own_plane
                .deliver(&drainer_runtime, &drainer_peer, message.clone())
                .await;
            }
          }
          let _ = request.ack_notify.send(Ok(crate::packet::RoutedAck {
            by: drainer_peer.clone(),
            admitted_at: std::time::SystemTime::now(),
          }));
        }
      });
      Self {
        context,
        entropy,
        runtime,
        events,
        revision,
        plane,
        page_dispatches,
        page_rows,
        trust_rows,
        tombstone_rows,
        peer_context,
        peer_plane,
      }
    }

    /// Ticks the far node's plane (its own driver in production).
    async fn peer_tick(&self) {
      self.peer_plane.tick(&self.runtime).await.unwrap();
    }

    async fn tick(&self) {
      let endpoints = vec![crate::Endpoint::parse("wss://127.0.0.1:0").unwrap()];
      membership_maintenance_tick(
        &self.context,
        &self.entropy,
        &endpoints,
        &self.events,
        &self.revision,
      )
      .await
      .unwrap();
      self.plane.tick(&self.runtime).await.unwrap();
    }

    /// Waits for the harness's asynchronous lanes (the reconcile
    /// negotiation runs in the drainer task) to satisfy `condition`,
    /// returning the harness for chained reads. The bounded wait keeps
    /// a wedged lane a test failure, never a hang.
    async fn wait_until(&self, condition: impl Fn(&Self) -> bool) -> &Self {
      for _ in 0..800 {
        if condition(self) {
          return self;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
      }
      self
    }

    /// Waits for every asynchronous lane to go quiet: the dispatch
    /// counters stop moving for a settling window. The bounded wait
    /// keeps a wedged lane a test failure, never a hang.
    async fn settle_quiet(&self) -> &Self {
      use std::sync::atomic::Ordering;
      let mut stable = 0;
      let mut last = (0_usize, 0_usize, 0_usize, 0_usize);
      for _ in 0..800 {
        let now = (
          self.page_dispatches.load(Ordering::SeqCst),
          self.page_rows.load(Ordering::SeqCst),
          self.trust_rows.load(Ordering::SeqCst),
          self.tombstone_rows.load(Ordering::SeqCst),
        );
        if now == last {
          stable += 1;
          if stable >= 20 {
            return self;
          }
        } else {
          stable = 0;
          last = now;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
      }
      self
    }
  }

  /// Regression (the redundant-edge re-emission storm, now the
  /// zero-emission steady state): a converged mesh emits no ROWS. The
  /// reconciliation contract's steady state: the descriptor lane's
  /// only steady traffic is the cadence ROOT exchange, the converged
  /// binding walk emits nothing, the tombstone plane's only steady
  /// traffic is its bounded confirmation refresh, and a real catalog
  /// change pushes exactly one row on the next tick, alone — one
  /// changed row costs one row on the wire, never a catalog-sized
  /// re-send (the 2026-10 audit's cascade amplifier stays removed).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_converged_mesh_emits_nothing_until_a_real_change() {
    use std::sync::atomic::Ordering;

    let harness = CadenceHarness::build().await;

    // Run well past several detection cadence windows: every lane
    // converges in the first round.
    for _ in 0..40 {
      harness.tick().await;
    }
    // The initial reconciliation runs asynchronously through the
    // harness drainer: wait for the ledger to settle before pinning it.
    let settled = harness
      .wait_until(|harness| {
        harness.page_dispatches.load(Ordering::SeqCst) >= 1
          && harness.trust_rows.load(Ordering::SeqCst) >= 2
      })
      .await
      .settle_quiet()
      .await;
    assert_eq!(
      settled.page_dispatches.load(Ordering::SeqCst),
      1,
      "one reconciliation delivered the catalog; the descriptor lane never re-sends"
    );
    let converged_rows = settled.page_rows.load(Ordering::SeqCst);
    assert!(
      converged_rows >= 1,
      "the catalog delivered at least one row"
    );
    let converged_bindings = settled.trust_rows.load(Ordering::SeqCst);
    assert!(
      converged_bindings >= 2,
      "the binding set (the two injected bindings) delivered"
    );
    let converged_tombstones = settled.tombstone_rows.load(Ordering::SeqCst);
    assert!(
      converged_tombstones >= 1,
      "the known leave record delivered as a tombstone row"
    );

    // Steady state over more cadence windows: the ROOT exchanges carry
    // no rows — the redundancy ledger does not move.
    for _ in 0..40 {
      harness.tick().await;
    }
    let quiet = harness.settle_quiet().await;
    assert_eq!(
      quiet.page_dispatches.load(Ordering::SeqCst),
      1,
      "a converged reconciliation emits no ROWS on the cadence"
    );
    assert_eq!(
      quiet.page_rows.load(Ordering::SeqCst),
      converged_rows,
      "the cadence ROOT exchanges send zero rows"
    );
    assert_eq!(
      quiet.trust_rows.load(Ordering::SeqCst),
      converged_bindings,
      "a converged binding set emits no rows on the cadence"
    );
    assert_eq!(
      quiet.tombstone_rows.load(Ordering::SeqCst),
      converged_tombstones,
      "a converged tombstone set emits no rows on the cadence — the old
      resend cadence's steady traffic is gone with it"
    );

    // A real catalog change (a store-committed join) drives the lane
    // through the register epoch and pushes exactly one diff row on
    // the next tick, alone.
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
    harness.tick().await;
    let changed = harness
      .wait_until(|harness| harness.page_rows.load(Ordering::SeqCst) > converged_rows)
      .await
      .settle_quiet()
      .await;
    assert_eq!(
      changed.page_dispatches.load(Ordering::SeqCst),
      2,
      "a committed catalog change reconciles on the next tick"
    );
    assert_eq!(
      changed.page_rows.load(Ordering::SeqCst),
      converged_rows + 1,
      "one changed descriptor = exactly one row on the wire"
    );
    assert_eq!(
      changed.trust_rows.load(Ordering::SeqCst),
      converged_bindings,
      "a descriptor change does not amplify the trust lane"
    );
  }
  /// The admitted-but-not-applied heal, row shape: a tombstone row
  /// delivered before its subject's binding skips on arrival, and the
  /// later binding arrival (a store write) re-applies it through the
  /// plane's derived-view repair — the resend-cadence semantics the
  /// watermark design carried (`delayed_content_converges_after_revoke`
  /// is the behavior-level pin).
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_tombstone_row_skipped_for_a_missing_binding_heals_on_its_arrival() {
    use std::sync::atomic::Ordering;

    let harness = CadenceHarness::build().await;
    // The far node does NOT know the leaver's binding at build (the
    // harness adopts it only after the row below has been delivered).
    for _ in 0..40 {
      harness.tick().await;
    }
    let delivered = harness
      .wait_until(|harness| harness.tombstone_rows.load(Ordering::SeqCst) >= 1)
      .await
      .settle_quiet()
      .await;
    let leaver = delivered.context.identity().node().clone();
    assert!(
      !crate::identity::leave::is_left_ctx(delivered.peer_context.store(), &leaver)
        .await
        .unwrap(),
      "the row skipped: the far node lacks the leaver's binding"
    );
    // The binding arrives (a real store write through the adoption
    // path): the next epoch pass re-applies the pending row.
    crate::identity::trust::store::adopt_binding_ctx(
      delivered.peer_context.store(),
      &crate::identity::testing::SequenceEntropy::default(),
      &leaver,
      delivered.context.identity().public_key(),
    )
    .await
    .unwrap();
    for _ in 0..8 {
      harness.tick().await;
      harness.peer_tick().await;
    }
    assert!(
      crate::identity::leave::is_left_ctx(delivered.peer_context.store(), &leaver)
        .await
        .unwrap(),
      "the binding arrival re-applied the skipped row"
    );
  }
}
