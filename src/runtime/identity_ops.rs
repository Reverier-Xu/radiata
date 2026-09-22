//! The identity operations plane: the admission-authority and lifecycle
//! transitions over the signed stores — revocation, cleanup tombstones,
//! local purges, checkpoint epochs, the acknowledged active leave, and
//! the operator's frozen-journal resolution.

use tracing::debug;

use super::supervisor::Supervisor;
use crate::{Error, NodeId, Result, identity::lifecycle::LocalIdentityContext};

impl Supervisor {
  /// Revokes one exact subject binding's connection and admission
  /// authority (`RevokeNode`): the revocation commits
  /// conditionally first, then the revoked identity's sessions close and
  /// its new sessions, admissions, and operations are rejected. Stored
  /// metadata is never erased or reinterpreted.
  /// Issues one convergent issuer-signed cleanup tombstone:
  /// the record persists locally and converges through the sync plane.
  pub(super) async fn cleanup_node(&mut self, subject: NodeId) -> Result<()> {
    self.require_unblocked()?;
    let context = self.context()?;
    if &subject == context.identity().node() {
      // Self-removal is the explicit leave path, never a self-cleanup.
      return Err(Error::invalid_input("cleanup subject"));
    }
    let record =
      crate::identity::cleanup::sign_cleanup_record(&context, context.keys(), &subject).await?;
    crate::identity::cleanup::persist_cleanup_record_ctx(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &record,
    )
    .await?;
    self
      .dependencies
      .events
      .emit(crate::MemberChanged::new(subject));
    self.dependencies.member_revision.bump();
    Ok(())
  }

  /// Clears the local revocation record for one subject:
  /// local-only, idempotent, deliberate.
  pub(super) async fn purge_revocation(&mut self, subject: NodeId) -> Result<()> {
    self.require_unblocked()?;
    let context = self.context()?;
    crate::identity::revocation::purge_revocation_ctx(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &subject,
    )
    .await
  }

  /// Starts a new checkpoint GC epoch at the current wall clock. The
  /// convergence precondition is enforced here, not by the caller: the
  /// watermark converges through the sync plane, collected tombstones are
  /// swept after sync rounds, and a member still owed tombstones must be
  /// connected before any epoch may start.
  pub(super) async fn issue_cleanup_checkpoint(&mut self) -> Result<u64> {
    self.require_unblocked()?;
    let context = self.context()?;
    self.require_members_connected(&context).await?;
    crate::identity::cleanup::issue_checkpoint_ctx(&context, self.dependencies.entropy.as_ref())
      .await
  }

  /// The checkpoint issue precondition: every known member other than
  /// self whose removal record is not terminal (left or cleaned) must
  /// hold at least one live authenticated session — the crate's own
  /// any-one-route connectivity contract. A non-terminal member is still
  /// owed tombstone deliveries, so an epoch issued while it is unreachable
  /// could collect records it has not received yet; a member with a
  /// terminal removal record is exactly what the epoch may collect and
  /// never blocks. A singleton cluster passes trivially (no other
  /// member).
  async fn require_members_connected(&self, context: &LocalIdentityContext) -> Result<()> {
    // Snapshot the live-session peers under the lock, then release it
    // before any await so the supervisor future stays `Send`.
    let live: std::collections::BTreeSet<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .iter()
      .filter(|(_, entry)| entry.alive())
      .map(|(peer, _)| peer.clone())
      .collect();
    let store = context.store();
    let departed = self.departed_exclusions(store).await?;
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
          debug!(kind = ?error.kind(), "checkpoint guard skipped an undecodable descriptor");
          continue;
        }
      };
      let node = descriptor.node();
      if descriptor.removed()
        || node == context.identity().node()
        || departed.status(node) != crate::MemberStatus::Active
      {
        continue;
      }
      if !live.contains(node) {
        unreachable += 1;
      }
    }
    if unreachable > 0 {
      debug!(
        unreachable,
        "cleanup checkpoint refused: non-terminal members without a live session"
      );
      return Err(Error::not_ready("cleanup checkpoint"));
    }
    Ok(())
  }

  pub(super) async fn revoke_node(
    &mut self, subject: NodeId, expected_key: crate::PublicKey,
  ) -> Result<crate::RevokeOutcome> {
    self.require_unblocked()?;
    let context = self.context()?;
    let local = context.identity().node();
    if &subject == local {
      // Self-removal is the explicit leave path, never a self-revoke.
      return Err(Error::invalid_input("revoke subject"));
    }
    // The tombstone is issuer-signed and converges through the sync plane:
    // any member may expel a compromised binding
    // cluster-wide, and the record is permanent until an explicit local
    // purge.
    let record = crate::identity::revocation::sign_revocation_record(
      &context,
      context.keys(),
      &subject,
      &expected_key,
    )
    .await?;
    let outcome = crate::identity::revocation::revoke_binding_ctx(
      context.store(),
      self.dependencies.entropy.as_ref(),
      &record,
    )
    .await?;
    let was_already_revoked = matches!(
      outcome,
      crate::identity::revocation::RevokeStoreOutcome::AlreadyRevoked
    );
    if !was_already_revoked {
      // After the known-committed transition: close the exact identity's
      // active sessions. Redial is impossible by construction — the
      // revoked binding is gone, so neither recovery candidates nor an
      // inbound handshake can admit this identity again.
      crate::session::stream::retire_session(&self.dependencies.sessions, &subject)?;
      self
        .dependencies
        .events
        .emit(crate::SessionChanged::new(subject.clone()));
      self
        .dependencies
        .events
        .emit(crate::NodeRevoked::new(subject.clone()));
    }
    Ok(crate::RevokeOutcome::new(subject, was_already_revoked))
  }

  /// Executes one acknowledged active leave (`LeaveCluster`):
  /// tears down listeners and sessions, replaces the identity, wipes the
  /// old identity's local core metadata, and deletes the old key — all
  /// through the journaled, crash-recoverable leave phases. The caller's
  /// outcome is reported, then the control loop shuts the runtime down
  /// with `ShutdownReason::ActiveLeave`.
  pub(super) async fn leave_cluster(
    &mut self, acknowledgement: crate::ReplaceIdentityAndDeleteOldCoreMetadata,
  ) -> Result<crate::LeaveOutcome> {
    self.require_unblocked()?;
    // The acknowledgement is a proof-of-construction marker: only the
    // deliberate constructor produces it.
    if !acknowledgement.is_acknowledged() {
      return Err(Error::invalid_input("leave acknowledgement"));
    }
    let context = self.context()?;

    // Crash-retryable ordering: journal the intent
    // and the signed record before any network effect, announce with the
    // journaled record, then rotate. A crash anywhere before rotation
    // resumes at startup with the same journaled record, so the leave is
    // never forgotten and never diverges from what peers may already
    // hold. A receipt-less budget expires into the documented silent
    // leave, which the cleanup path covers.
    let journaled = crate::identity::leave::journal_leave(
      &context,
      context.keys(),
      self.dependencies.entropy.as_ref(),
    )
    .await?;
    crate::membership::sync::announce_leave(
      &context,
      &self.dependencies.entropy,
      &journaled.record,
      &self.dependencies.sessions,
      &self.dependencies.routes,
      &self.dependencies.events,
      &self.dependencies.leave_applied,
    )
    .await?;

    // Network teardown first: no new sessions or inbound metadata while
    // the identity is replaced and the old metadata is wiped.
    let listener_ids: Vec<crate::identity::ListenerId> = self.listeners.keys().cloned().collect();
    for listener in listener_ids {
      self.stop_listener(&listener).await?;
    }
    let peers: Vec<NodeId> = self
      .dependencies
      .sessions
      .lock()
      .map_err(Error::session_table)?
      .keys()
      .cloned()
      .collect();
    for peer in peers {
      crate::session::stream::retire_session(&self.dependencies.sessions, &peer)?;
    }

    crate::identity::leave::run_leave(
      context.store(),
      context.keys(),
      self.dependencies.entropy.as_ref(),
      &journaled.stored,
      &journaled.intent,
    )
    .await?;
    let (former, replacement) = (
      journaled.intent.former_node().clone(),
      journaled.intent.replacement_node().clone(),
    );
    self.dependencies.events.emit(crate::IdentityReplaced::new(
      former.clone(),
      replacement.clone(),
    ));
    Ok(crate::LeaveOutcome::new(former, replacement))
  }

  /// Executes one operator-acknowledged frozen-journal resolution
  /// (`ResolveFrozenJournal`): resolves the store's frozen pending
  /// journal as uncommitted and unfreezes the store. The store's blocked
  /// state is this command's precondition, so the `require_unblocked`
  /// gate that refuses admission-sensitive commands while frozen
  /// deliberately does not apply here. The command deliberately does not
  /// queue on the store's writer exclusion: on a frozen store the
  /// background anti-entropy writers park inside that exclusion on the
  /// commit-slot refusal and would starve the operator command forever.
  /// The frozen slot itself is the writer gate — every normal commit
  /// path refuses while frozen — and operator commands serialize on the
  /// supervisor's control loop, so the slot's fate keeps a single
  /// writer.
  pub(super) async fn resolve_frozen_journal(
    &mut self, acknowledgement: crate::DeclareInterruptedTransactionUncommitted,
  ) -> Result<()> {
    // The acknowledgement is a proof-of-construction marker: only the
    // deliberate constructor produces it.
    if !acknowledgement.is_acknowledged() {
      return Err(Error::invalid_input("frozen journal acknowledgement"));
    }
    let context = self.context()?;
    let operation = crate::TransactionId::generate(self.dependencies.entropy.as_ref())?;
    context
      .store()
      .resolve_frozen_journal_uncommitted(operation)
      .await
  }
}
