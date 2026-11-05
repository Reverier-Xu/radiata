//! The tombstone lifecycle: the terminal evidence of a member's
//! departure, and the arms that install it.
//!
//! Four record families share one lifecycle — the owner-signed leave
//! record, the issuer-signed cleanup tombstone, the issuer-signed
//! revocation, and the unsigned cleanup checkpoint watermark. Every arm
//! verifies against the permanently retained bindings before it
//! persists, refuses evidence the cluster already collected instead of
//! resurrecting it, and reports a real transition through the paired
//! member-set notification. The same arms serve both planes: the
//! interactive leave payload on an authenticated session and the
//! reconciliation lane's kind-prefixed rows, so both verify, persist,
//! notify, and collect identically.

use std::sync::Arc;

use super::sync::{MEMBERSHIP_SYNC_PROTOCOL, SyncPayload, member_changed};
use crate::{
  Error, NodeId, ProtocolTag, Result,
  api::Entropy,
  identity::{lifecycle::LocalIdentityContext, trust::store as trust_store},
  runtime::RuntimeClient,
};

/// The tombstone arms' shared verification context: the trusted-binding
/// set plus the collected-tombstone watermark, loaded once per payload
/// or row batch (every arm consults both).
pub(super) struct TombstoneEvidence {
  bindings: std::collections::BTreeMap<NodeId, crate::PublicKey>,
  checkpoint: Option<u64>,
}

pub(super) async fn tombstone_evidence(
  store: &crate::storage::MetadataStore,
) -> Result<TombstoneEvidence> {
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
pub(super) async fn apply_leave_record(
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
  let install =
    crate::identity::cleanup::persist_cleanup_record_ctx(store, entropy.as_ref(), record).await?;
  // Only a real install changes the member set: an exact replay or a
  // legitimate losing record is a no-op success, not a notification.
  if install == crate::identity::records::TerminalInstall::Installed {
    member_changed(events, revision, record.subject().clone());
  }
  Ok(())
}

/// Applies one encoded revocation tombstone: convergent permanent
/// evidence, verified against the retained issuer and subject bindings
/// before any persistence, never covered by checkpoints, and never
/// re-adoptable away. A persisted revocation closes the authorization
/// boundary immediately on this node too — the same boundary the local
/// revoke effect holds: any live session with
/// the revoked identity retires, and a handshake already in flight is
/// refused at its final publication (its recovery dials race the
/// propagation, so a session admitted before this tombstone landed must
/// not linger either). Session retirement is independent of the
/// evidence verdict; the paired session-and-revocation notification
/// (the same pair, in the same order, the local revoke effect emits)
/// fires only for a first revocation, never for a canonical evidence
/// replacement or an unchanged replay.
#[allow(clippy::too_many_arguments)]
async fn apply_revocation_record(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, evidence: &TombstoneEvidence,
  record: &crate::identity::revocation::RevocationRecordV1,
  sessions: &crate::session::stream::SessionTable,
  authorization: &crate::session::stream::AuthorizationBoundary,
) -> Result<()> {
  if !evidence.bindings.contains_key(record.issuer())
    || !evidence.bindings.contains_key(record.subject())
  {
    tracing::debug!(subject = %record.subject(), "revocation record skipped: bindings unknown");
    return Ok(());
  }
  // The same exclusive section the local revoke effect holds: the durable
  // tombstone install, the ledger record, and the session retirement run as ONE
  // section against session publication. A handshake whose admission predated
  // this tombstone either published before the section ran (the retirement
  // below removes it) or re-checks the ledger after the section and
  // refuses to publish — the remote lane closes the in-flight window
  // exactly like the local one. The section is short and touches no
  // network negotiation.
  let mut revoked = authorization.section().await;
  let transition =
    crate::identity::revocation::persist_revocation_ctx(store, entropy.as_ref(), record).await?;
  revoked.record(record.subject());
  crate::session::stream::retire_session(sessions, record.subject())?;
  drop(revoked);
  // The paired notification the local revoke effect emits: the
  // retirement above removed the session-table entry, so the session
  // task's own exit path cannot report the change — this lane reports
  // it, SessionChanged first, then NodeRevoked.
  if transition.changed_authorization() {
    events.emit(crate::SessionChanged::new(record.subject().clone()));
    events.emit(crate::NodeRevoked::new(record.subject().clone()));
  }
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

/// One decoded reconciliation row, tagged with the kind its key prefix
/// named: the decode phase has already checked the record's own subject
/// against the key it arrived under (and, for a leave row, that the
/// record's signature verifies), so the apply phase dispatches on the
/// kind alone and never re-derives the attribution.
enum TombstoneRow {
  Leave(crate::identity::leave::LeaveRecordV1),
  Cleanup(crate::identity::cleanup::CleanupRecordV1),
  Revocation(crate::identity::revocation::RevocationRecordV1),
  Checkpoint(crate::identity::cleanup::CleanupCheckpointV1),
}

/// Decodes one reconciliation row into the evidence of its kind: the key
/// prefix names the kind, the record must decode, its own subject must
/// match the key it arrived under, and a leave row must carry a signature
/// that verifies. `None` means the row is skipped with its typed reason
/// already logged — never an error, because one poison row must not wedge
/// the batch.
fn decode_tombstone_row(key: &[u8], content: &[u8]) -> Option<TombstoneRow> {
  let Some((prefix, subject)) = key.split_first() else {
    tracing::debug!("reconcile tombstone row skipped: no kind prefix");
    return None;
  };
  // The typed kind decoder the scan side builds row keys with: one
  // closed mapping on the wire contract, so the apply dispatch and
  // the scan cannot drift apart.
  let kind = match crate::reconcile::wire::TombstoneKind::from_prefix(*prefix) {
    Some(kind) => kind,
    None => {
      tracing::debug!(
        kind = prefix,
        "reconcile tombstone row skipped: unknown kind"
      );
      return None;
    }
  };
  match kind {
    crate::reconcile::wire::TombstoneKind::Leave => {
      let record = match crate::identity::leave::LeaveRecordV1::decode(content) {
        Ok(record) if record.node().as_str().as_bytes() == subject => record,
        Ok(record) => {
          tracing::debug!(
            node = %record.node(),
            "reconcile leave row skipped: subject mismatch"
          );
          return None;
        }
        Err(error) => {
          tracing::debug!(kind = ?error.kind(), "reconcile leave row skipped: undecodable");
          return None;
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
        return None;
      }
      Some(TombstoneRow::Leave(record))
    }
    crate::reconcile::wire::TombstoneKind::Cleanup => {
      let record = match crate::identity::cleanup::CleanupRecordV1::decode(content) {
        Ok(record) if record.subject().as_str().as_bytes() == subject => record,
        Ok(record) => {
          tracing::debug!(
            subject = %record.subject(),
            "reconcile cleanup row skipped: subject mismatch"
          );
          return None;
        }
        Err(error) => {
          tracing::debug!(kind = ?error.kind(), "reconcile cleanup row skipped: undecodable");
          return None;
        }
      };
      Some(TombstoneRow::Cleanup(record))
    }
    crate::reconcile::wire::TombstoneKind::Revocation => {
      let record = match crate::identity::revocation::RevocationRecordV1::decode(content) {
        Ok(record) if record.subject().as_str().as_bytes() == subject => record,
        Ok(record) => {
          tracing::debug!(
            subject = %record.subject(),
            "reconcile revocation row skipped: subject mismatch"
          );
          return None;
        }
        Err(error) => {
          tracing::debug!(
            kind = ?error.kind(),
            "reconcile revocation row skipped: undecodable"
          );
          return None;
        }
      };
      Some(TombstoneRow::Revocation(record))
    }
    crate::reconcile::wire::TombstoneKind::Checkpoint => {
      let checkpoint = match crate::identity::cleanup::CleanupCheckpointV1::decode(content) {
        Ok(checkpoint) if subject == b"checkpoint" => checkpoint,
        Ok(_) => {
          tracing::debug!("reconcile checkpoint row skipped: subject mismatch");
          return None;
        }
        Err(error) => {
          tracing::debug!(
            kind = ?error.kind(),
            "reconcile checkpoint row skipped: undecodable"
          );
          return None;
        }
      };
      Some(TombstoneRow::Checkpoint(checkpoint))
    }
  }
}

/// Applies one decoded leave row: the record-level apply plus the row's
/// refusal policy — a NotTrusted answer is the permanently retained
/// binding disagreeing with the record's key, a refused row the batch
/// continues past, while real store faults propagate. `receipt` is the
/// applied receipt's target, the peer that carried the row and the client
/// that reaches it, present together or not at all.
async fn apply_leave_row(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
  evidence: &TombstoneEvidence, record: &crate::identity::leave::LeaveRecordV1,
  receipt: Option<(&NodeId, &RuntimeClient)>,
) -> Result<()> {
  let (source, runtime) = receipt.unzip();
  match apply_leave_record(
    store, entropy, events, revision, evidence, record, source, runtime,
  )
  .await
  {
    Err(error) if error.kind() == crate::ErrorKind::NotTrusted => {
      tracing::warn!(
        node = %record.node(),
        "reconcile leave row refused by policy: binding mismatch; skipping"
      );
      Ok(())
    }
    other => other,
  }
}

/// Applies one decoded cleanup row: a forged signature
/// (AuthenticationFailed from the strict verify), a policy refusal
/// (NotTrusted issuer or subject binding), or a divergent stored record
/// over a different binding (Conflict) refuses the row — the batch
/// continues, so one divergent record can never wedge the tombstone lane.
/// Real store faults still propagate.
async fn apply_cleanup_row(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
  evidence: &TombstoneEvidence, record: &crate::identity::cleanup::CleanupRecordV1,
) -> Result<()> {
  match apply_cleanup_record(store, entropy, events, revision, evidence, record).await {
    Err(error)
      if matches!(
        error.kind(),
        crate::ErrorKind::Conflict
          | crate::ErrorKind::NotTrusted
          | crate::ErrorKind::AuthenticationFailed
      ) =>
    {
      tracing::warn!(
        subject = %record.subject(),
        kind = ?error.kind(),
        "reconcile cleanup row refused: divergent or untrusted evidence; skipping"
      );
      Ok(())
    }
    other => other,
  }
}

/// Applies one decoded revocation row under the same refusal policy as the
/// cleanup row — a forged signature, a policy refusal, or a divergent
/// stored record refuses the row and the batch continues — while real
/// store faults propagate.
async fn apply_revocation_row(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, evidence: &TombstoneEvidence,
  record: &crate::identity::revocation::RevocationRecordV1,
  sessions: &crate::session::stream::SessionTable,
  authorization: &crate::session::stream::AuthorizationBoundary,
) -> Result<()> {
  match apply_revocation_record(
    store,
    entropy,
    events,
    evidence,
    record,
    sessions,
    authorization,
  )
  .await
  {
    Err(error)
      if matches!(
        error.kind(),
        crate::ErrorKind::Conflict
          | crate::ErrorKind::NotTrusted
          | crate::ErrorKind::AuthenticationFailed
      ) =>
    {
      tracing::warn!(
        subject = %record.subject(),
        kind = ?error.kind(),
        "reconcile revocation row refused: divergent or untrusted evidence; skipping"
      );
      Ok(())
    }
    other => other,
  }
}

/// The tombstone lane's reconciliation row apply: kind-prefixed keys
/// (the wire contract's [`crate::reconcile::wire::TombstoneKind`]
/// prefixes) dispatch to the same per-record
/// arms the announcement payload uses, so both planes verify, persist,
/// notify, and collect identically. `source` addresses the applied
/// receipt to the peer that carried the rows; the derived-view repair
/// passes `None`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_tombstone_rows(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>,
  events: &Arc<crate::node::EventHub>, revision: &crate::node::MemberRevisionSignal,
  sessions: &crate::session::stream::SessionTable,
  authorization: &crate::session::stream::AuthorizationBoundary, rows: &[(Vec<u8>, Vec<u8>)],
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
    let Some(row) = decode_tombstone_row(key, content) else {
      continue;
    };
    match row {
      TombstoneRow::Leave(record) => {
        apply_leave_row(
          store,
          entropy,
          events,
          revision,
          &evidence,
          &record,
          source.zip(runtime),
        )
        .await?;
      }
      TombstoneRow::Cleanup(record) => {
        apply_cleanup_row(store, entropy, events, revision, &evidence, &record).await?;
      }
      TombstoneRow::Revocation(record) => {
        apply_revocation_row(
          store,
          entropy,
          events,
          &evidence,
          &record,
          sessions,
          authorization,
        )
        .await?;
      }
      TombstoneRow::Checkpoint(checkpoint) => {
        apply_checkpoint_record(store, entropy, &checkpoint).await?;
      }
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::session::stream::SessionTable;

  fn node_at(seed: u64) -> NodeId {
    NodeId::parse(&format!("node-{seed:021}")).unwrap()
  }

  fn key_at(value: u64) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value);
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  /// Drains one subscription's currently available events.
  fn event_count<E: crate::Event>(subscription: &mut crate::EventSubscription<E>) -> usize {
    drained_events(subscription).len()
  }

  /// Drains one subscription's currently available events, keeping the
  /// items so payload parity can be pinned alongside the counts.
  fn drained_events<E: crate::Event>(subscription: &mut crate::EventSubscription<E>) -> Vec<E> {
    let mut drained = Vec::new();
    loop {
      match subscription.try_recv().unwrap() {
        crate::EventReceive::Item(item) => drained.push(item),
        crate::EventReceive::Empty | crate::EventReceive::Closed => return drained,
        crate::EventReceive::Lagged { .. } => panic!("test subscription lagged"),
      }
    }
  }

  /// Regression (audit #14): re-delivered terminal evidence is a no-op
  /// success, not a change notification. The member revision and the
  /// revocation event move only for a real transition: an exact replay
  /// notifies nothing, a cleanup evidence replacement notifies once (the
  /// member evidence changed), and a revocation evidence replacement
  /// over an already-revoked binding fires no second revocation. Session
  /// retirement stays independent of the evidence verdict: an
  /// already-revoked identity's live session still retires.
  ///
  /// Regression: a revocation that changes
  /// authorization through the sync lane reports the session change too
  /// — one `SessionChanged` pairing with the one `NodeRevoked`, both for
  /// the revoked subject, in the same branch — exactly the pair the local
  /// revoke effect emits. The per-type subscriptions of the hub expose
  /// counts and payloads, not a cross-type total order (the documented
  /// parity contract of `tests/event_parity.rs`); the emission order is
  /// pinned by the source mirroring the local path. Neither event fires
  /// on the replay, the cleanup replacement, or the evidence-only
  /// revocation replacement, even when a live session retires there.
  #[tokio::test]
  async fn replayed_tombstone_rows_notify_only_real_transitions() {
    use ed25519_dalek::Signer as _;

    use crate::identity::{
      cleanup::CleanupRecordV1,
      revocation::{REVOCATION_RECORD_DOMAIN, RevocationRecordV1, revoked_key_ctx},
      signature::signature_message,
      testing::{ScriptedKeys, SequenceEntropy, fresh_reference, open_context},
    };

    let (_reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full_at(9_900);
    let scripted_entropy = Arc::new(SequenceEntropy::default());
    let entropy: Arc<dyn Entropy> = scripted_entropy.clone();
    let context = Arc::new(
      open_context(&factory, &keys, &scripted_entropy)
        .await
        .unwrap(),
    );
    let store = context.store();

    let subject = node_at(9_910);
    let subject_key = key_at(9_911);
    let issuer = node_at(9_920);
    let issuer_signing = crate::identity::testing::scripted_signing(9_921);
    let other_issuer = node_at(9_930);
    let other_signing = crate::identity::testing::scripted_signing(9_931);
    for (node, key) in [
      (issuer.clone(), key_at(9_921)),
      (other_issuer.clone(), key_at(9_931)),
      (subject.clone(), subject_key.clone()),
    ] {
      crate::identity::trust::store::adopt_binding_ctx(store, entropy.as_ref(), &node, &key)
        .await
        .unwrap();
    }

    let revocation = |issuer: &NodeId, signing: &ed25519_dalek::SigningKey| {
      let body = RevocationRecordV1::encode_signed_body(&subject, &subject_key, issuer).unwrap();
      let signature = signing.sign(&signature_message(REVOCATION_RECORD_DOMAIN, &body));
      RevocationRecordV1::new(
        subject.clone(),
        subject_key.clone(),
        issuer.clone(),
        crate::Signature::from_bytes(signature.to_bytes()),
      )
    };
    let cleanup = |stamp: u64| {
      let body =
        CleanupRecordV1::encode_signed_body(&subject, &subject_key, &issuer, stamp).unwrap();
      let signature = issuer_signing.sign(&signature_message(
        crate::identity::cleanup::CLEANUP_RECORD_DOMAIN,
        &body,
      ));
      CleanupRecordV1::new(
        subject.clone(),
        subject_key.clone(),
        issuer.clone(),
        stamp,
        crate::Signature::from_bytes(signature.to_bytes()),
      )
    };
    // The second delivery is the canonical winner by construction, so the
    // revocation replacement branch is pinned regardless of byte layout.
    let first = revocation(&issuer, &issuer_signing);
    let second = revocation(&other_issuer, &other_signing);
    let (winner, loser) = if first.encode().unwrap() < second.encode().unwrap() {
      (first, second)
    } else {
      (second, first)
    };
    let winner_bytes = winner.encode().unwrap();

    let row = |kind: u8, subject: &NodeId, encoded: Vec<u8>| {
      let mut key = Vec::with_capacity(1 + subject.as_str().len());
      key.push(kind);
      key.extend_from_slice(subject.as_str().as_bytes());
      (key, encoded)
    };
    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    // The boundary the production wiring shares between the tombstone
    // lane and session publication.
    let authorization = crate::session::stream::AuthorizationBoundary::default();
    let mut revoked_events = events.subscribe::<crate::NodeRevoked>(crate::EventOptions::new());
    let mut member_events = events.subscribe::<crate::MemberChanged>(crate::EventOptions::new());
    let mut session_events = events.subscribe::<crate::SessionChanged>(crate::EventOptions::new());

    // The first delivery is the real transition: one revocation event,
    // one paired session event (parity with the local revoke path),
    // and one member revision for the cleanup install.
    let first_rows = vec![
      row(3, &subject, loser.encode().unwrap()),
      row(2, &subject, cleanup(9_000).encode().unwrap()),
    ];
    apply_tombstone_rows(
      &context,
      &entropy,
      &events,
      &revision,
      &sessions,
      &authorization,
      &first_rows,
      None,
      None,
    )
    .await
    .unwrap();
    let revoked_seen = drained_events(&mut revoked_events);
    assert_eq!(revoked_seen.len(), 1);
    assert_eq!(revoked_seen[0].subject(), &subject);
    let session_seen = drained_events(&mut session_events);
    assert_eq!(session_seen.len(), 1);
    assert_eq!(session_seen[0].peer(), &subject);
    assert_eq!(event_count(&mut member_events), 1);
    assert_eq!(*revision_rx.borrow(), 1);

    // An exact replay notifies nothing and bumps nothing.
    apply_tombstone_rows(
      &context,
      &entropy,
      &events,
      &revision,
      &sessions,
      &authorization,
      &first_rows,
      None,
      None,
    )
    .await
    .unwrap();
    assert_eq!(event_count(&mut revoked_events), 0);
    assert_eq!(event_count(&mut session_events), 0);
    assert_eq!(event_count(&mut member_events), 0);
    assert_eq!(*revision_rx.borrow(), 1);

    // A canonical cleanup replacement is a real member-evidence install:
    // exactly one notification.
    let replacement_rows = vec![row(2, &subject, cleanup(5_000).encode().unwrap())];
    apply_tombstone_rows(
      &context,
      &entropy,
      &events,
      &revision,
      &sessions,
      &authorization,
      &replacement_rows,
      None,
      None,
    )
    .await
    .unwrap();
    assert_eq!(event_count(&mut revoked_events), 0);
    assert_eq!(event_count(&mut session_events), 0);
    assert_eq!(event_count(&mut member_events), 1);
    assert_eq!(*revision_rx.borrow(), 2);

    // The surely-already-revoked identity's live session still retires on
    // an evidence-only replacement, while no second revocation fires.
    let (entry, _frames) = crate::session::stream::test_entry(&crate::api::SystemEntropy);
    sessions.lock().unwrap().insert(subject.clone(), entry);
    let replacement_rows = vec![row(3, &subject, winner_bytes.clone())];
    apply_tombstone_rows(
      &context,
      &entropy,
      &events,
      &revision,
      &sessions,
      &authorization,
      &replacement_rows,
      None,
      None,
    )
    .await
    .unwrap();
    assert_eq!(event_count(&mut revoked_events), 0);
    assert_eq!(event_count(&mut session_events), 0);
    assert!(
      sessions.lock().unwrap().get(&subject).is_none(),
      "a revoked identity's session retires even when only the evidence changed"
    );
    assert_eq!(
      store_revocation_bytes(store, &subject).await,
      winner_bytes,
      "the canonical winner replaced the stored evidence"
    );
    assert_eq!(
      revoked_key_ctx(store, &subject).await.unwrap(),
      Some(subject_key)
    );
  }

  /// The stored revocation encoding for `subject`.
  async fn store_revocation_bytes(
    store: &crate::storage::MetadataStore, subject: &NodeId,
  ) -> Vec<u8> {
    let snapshot = store.snapshot().await.unwrap();
    snapshot
      .get(
        &crate::storage::families::namespace(crate::storage::families::REVOCATION_NAMESPACE)
          .unwrap(),
        &crate::StoreKey::new(Arc::from(subject.as_str().as_bytes())),
      )
      .await
      .unwrap()
      .expect("the stored revocation record")
      .as_bytes()
      .to_vec()
  }

  /// Regression: one divergent terminal record must never
  /// abort a tombstone batch — the cleanup and revocation arms refuse the
  /// row (warn + continue) exactly like the leave arm, a same-binding
  /// divergent cleanup row merges to its canonical winner instead of
  /// conflicting, and rows ordered after a refused row still apply in
  /// the same pass. A `?` on the apply arms would wedge the
  /// derived-view repair on the same poison row every epoch.
  #[tokio::test]
  async fn divergent_tombstone_rows_refuse_row_wise_and_never_abort_the_batch() {
    use ed25519_dalek::Signer as _;

    use crate::identity::{
      cleanup::{CleanupRecordV1, known_cleanup_records_ctx, persist_cleanup_record_ctx},
      leave::{LeaveRecordV1, is_left_ctx},
      revocation::{RevocationRecordV1, persist_revocation_ctx, revoked_key_ctx},
      signature::signature_message,
      testing::{ScriptedKeys, SequenceEntropy, fresh_reference, open_context},
    };

    let (_reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full_at(9_700);
    let scripted_entropy = Arc::new(SequenceEntropy::default());
    let entropy: Arc<dyn Entropy> = scripted_entropy.clone();
    let context = Arc::new(
      open_context(&factory, &keys, &scripted_entropy)
        .await
        .unwrap(),
    );
    let store = context.store();

    // The shared issuer of the terminal evidence and the subjects: the
    // revoked subject's binding pins the stored revocation's key (the
    // poison row pins a different one, so the apply is refused by
    // policy), and the cleaned subject's binding is the merge row's.
    let issuer = node_at(9_710);
    let issuer_signing = crate::identity::testing::scripted_signing(9_711);
    let issuer_key = key_at(9_711);
    let revoked = node_at(9_720);
    let revoked_key = key_at(9_721);
    let cleaned = node_at(9_730);
    let cleaned_key = key_at(9_731);
    let leaver = node_at(9_740);
    let leaver_key = key_at(9_741);
    for (node, key) in [
      (issuer.clone(), issuer_key),
      (revoked.clone(), revoked_key.clone()),
      (cleaned.clone(), cleaned_key.clone()),
      (leaver.clone(), leaver_key.clone()),
    ] {
      crate::identity::trust::store::adopt_binding_ctx(store, entropy.as_ref(), &node, &key)
        .await
        .unwrap();
    }

    let revocation_of = |subject_key: &crate::PublicKey| {
      let body = RevocationRecordV1::encode_signed_body(&revoked, subject_key, &issuer).unwrap();
      let signature = issuer_signing.sign(&signature_message(
        crate::identity::revocation::REVOCATION_RECORD_DOMAIN,
        &body,
      ));
      RevocationRecordV1::new(
        revoked.clone(),
        subject_key.clone(),
        issuer.clone(),
        crate::Signature::from_bytes(signature.to_bytes()),
      )
    };
    let cleanup_of = |subject_key: &crate::PublicKey, stamp: u64| {
      let body =
        CleanupRecordV1::encode_signed_body(&cleaned, subject_key, &issuer, stamp).unwrap();
      let signature = issuer_signing.sign(&signature_message(
        crate::identity::cleanup::CLEANUP_RECORD_DOMAIN,
        &body,
      ));
      CleanupRecordV1::new(
        cleaned.clone(),
        subject_key.clone(),
        issuer.clone(),
        stamp,
        crate::Signature::from_bytes(signature.to_bytes()),
      )
    };

    // The stored evidence the arriving rows diverge from.
    persist_revocation_ctx(store, entropy.as_ref(), &revocation_of(&revoked_key))
      .await
      .unwrap();
    persist_cleanup_record_ctx(store, entropy.as_ref(), &cleanup_of(&cleaned_key, 9_000))
      .await
      .unwrap();

    // The leaver's own signed record: its row must apply in the same
    // pass as the refused rows ahead of it.
    let leave_body = LeaveRecordV1::encode_signed_body(&leaver, &leaver_key, 1_000).unwrap();
    let leave_signature = crate::identity::testing::scripted_signing(9_741).sign(
      &signature_message(crate::identity::leave::LEAVE_RECORD_DOMAIN, &leave_body),
    );
    let leave = LeaveRecordV1::new(
      leaver.clone(),
      leaver_key.clone(),
      1_000,
      crate::Signature::from_bytes(leave_signature.to_bytes()),
    );

    let row = |kind: u8, subject: &NodeId, encoded: Vec<u8>| {
      let mut key = Vec::with_capacity(1 + subject.as_str().len());
      key.push(kind);
      key.extend_from_slice(subject.as_str().as_bytes());
      (key, encoded)
    };
    let rows = vec![
      // The poison rows: pinned keys that diverge from the stored
      // records' bindings, refused by policy instead of aborting the
      // batch — one per terminal family.
      row(3, &revoked, revocation_of(&key_at(9_799)).encode().unwrap()),
      row(
        2,
        &cleaned,
        cleanup_of(&key_at(9_798), 5_000).encode().unwrap(),
      ),
      // The merge row: a same-binding divergent cleanup record, earlier
      // stamp — it converges instead of conflicting.
      row(
        2,
        &cleaned,
        cleanup_of(&cleaned_key, 5_000).encode().unwrap(),
      ),
      // The leave row behind the poison rows applies in the same pass.
      row(1, &leaver, leave.encode().unwrap()),
    ];

    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let authorization = crate::session::stream::AuthorizationBoundary::default();

    apply_tombstone_rows(
      &context,
      &entropy,
      &events,
      &revision,
      &sessions,
      &authorization,
      &rows,
      None,
      None,
    )
    .await
    .expect("one divergent record must never abort the batch");

    // The refused row left the stored revocation untouched.
    assert_eq!(
      revoked_key_ctx(store, &revoked).await.unwrap(),
      Some(revoked_key)
    );
    // The merge row replaced the stored cleanup record with the
    // earliest-stamp winner.
    let cleaned_records = known_cleanup_records_ctx(store, 64).await.unwrap();
    assert_eq!(
      cleaned_records
        .iter()
        .find(|record| record.subject() == &cleaned)
        .expect("the cleaned subject keeps exactly one record")
        .timestamp_millis(),
      5_000
    );
    // The leave row ordered after the poison rows applied in the same
    // pass — the batch did not abort.
    assert!(is_left_ctx(store, &leaver).await.unwrap());
  }

  /// The tombstone lane records its revocations in the shared
  /// authorization boundary: a subject whose
  /// remote tombstone landed through sync must be refused at session
  /// publication exactly like a locally revoked one. A fresh install and
  /// an unchanged replay both leave the subject in the ledger (both
  /// leave it durably revoked), and a row skipped for unknown bindings
  /// records nothing.
  #[tokio::test]
  async fn revocation_rows_record_the_shared_authorization_boundary() {
    use ed25519_dalek::Signer as _;

    use crate::identity::{
      revocation::{REVOCATION_RECORD_DOMAIN, RevocationRecordV1},
      signature::signature_message,
      testing::{ScriptedKeys, SequenceEntropy, fresh_reference, open_context},
    };

    let (_reference, factory) = fresh_reference();
    let keys = ScriptedKeys::full_at(9_950);
    let scripted_entropy = Arc::new(SequenceEntropy::default());
    let entropy: Arc<dyn Entropy> = scripted_entropy.clone();
    let context = Arc::new(
      open_context(&factory, &keys, &scripted_entropy)
        .await
        .unwrap(),
    );
    let store = context.store();

    let subject = node_at(9_951);
    let subject_key = key_at(9_952);
    let stranger = node_at(9_953);
    let stranger_key = key_at(9_954);
    let issuer = node_at(9_955);
    let issuer_signing = crate::identity::testing::scripted_signing(9_956);
    for (node, key) in [
      (issuer.clone(), key_at(9_956)),
      (subject.clone(), subject_key.clone()),
    ] {
      crate::identity::trust::store::adopt_binding_ctx(store, entropy.as_ref(), &node, &key)
        .await
        .unwrap();
    }
    // The stranger stays unbound: its row must skip without touching
    // the ledger.

    let revocation = |subject: &NodeId, key: &crate::PublicKey| {
      let body = RevocationRecordV1::encode_signed_body(subject, key, &issuer).unwrap();
      let signature = issuer_signing.sign(&signature_message(REVOCATION_RECORD_DOMAIN, &body));
      RevocationRecordV1::new(
        subject.clone(),
        key.clone(),
        issuer.clone(),
        crate::Signature::from_bytes(signature.to_bytes()),
      )
    };
    let row = |kind: u8, subject: &NodeId, encoded: Vec<u8>| {
      let mut key = Vec::with_capacity(1 + subject.as_str().len());
      key.push(kind);
      key.extend_from_slice(subject.as_str().as_bytes());
      (key, encoded)
    };
    let events = Arc::new(crate::node::EventHub::new());
    let (revision_tx, _revision_rx) = tokio::sync::watch::channel(0_u64);
    let revision = crate::node::MemberRevisionSignal::new(revision_tx);
    let sessions: SessionTable = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let authorization = crate::session::stream::AuthorizationBoundary::default();

    let rows = vec![
      row(
        3,
        &subject,
        revocation(&subject, &subject_key).encode().unwrap(),
      ),
      row(
        3,
        &stranger,
        revocation(&stranger, &stranger_key).encode().unwrap(),
      ),
    ];
    apply_tombstone_rows(
      &context,
      &entropy,
      &events,
      &revision,
      &sessions,
      &authorization,
      &rows,
      None,
      None,
    )
    .await
    .unwrap();
    assert!(
      authorization.section().await.contains(&subject),
      "the landed tombstone must gate session publication for its subject"
    );
    assert!(
      !authorization.section().await.contains(&stranger),
      "a skipped row must not record its subject"
    );

    // An unchanged replay leaves the subject durably revoked: the
    // ledger keeps recording it, mirroring the local revoke effect's
    // fresh-commit-and-replay alike.
    apply_tombstone_rows(
      &context,
      &entropy,
      &events,
      &revision,
      &sessions,
      &authorization,
      &rows,
      None,
      None,
    )
    .await
    .unwrap();
    assert!(authorization.section().await.contains(&subject));
  }
}
