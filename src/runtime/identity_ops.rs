//! The identity operations plane: the admission-authority and lifecycle
//! transitions over the signed stores — the acknowledged active leave.
//! The revocation, cleanup, purge, checkpoint, and frozen-journal bodies
//! migrated to the task manager's effect plane
//! ([`super::task_effects`]).

use super::supervisor::Supervisor;
use crate::{Error, NodeId, Result};

impl Supervisor {
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
    let listener_ids: Vec<crate::identity::ListenerId> = self
      .dependencies
      .listeners
      .lock()
      .map_err(|_| Error::internal("listener registry"))?
      .keys()
      .cloned()
      .collect();
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
}
