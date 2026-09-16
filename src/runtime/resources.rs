//! The resource write plane: signed candidate commits for puts and
//! removals behind the shared bounded commit-race retry, the shared
//! post-commit outcome mapping, and the writer's monotonic
//! resource-write stamp clock.

use super::supervisor::Supervisor;
use crate::{Error, Result};

/// The commit-race retry budget for the resource write paths.
const RESOURCE_COMMIT_RACE_ATTEMPTS: u32 = 3;

/// One resource-write attempt's outcome under the shared bounded retry:
/// a lost register race is retried with a fresh attempt while the budget
/// lasts (the conflict error surfaces once it is spent); anything else —
/// success, the register rejecting the candidate, or any other error —
/// is final.
enum CommitRace<T> {
  Raced(crate::Error),
  Final(Result<T>),
}

/// The bounded retry shared by the resource put and remove commit paths:
/// a snapshot-exact CAS can lose a race against a concurrent internal
/// committer (anti-entropy convergence, the descriptor ensure) that
/// moved the base revision between the snapshot and the commit. That
/// refusal says nothing about the candidate itself, so the attempt
/// closure re-runs (fresh stamp, fresh register read) while the race
/// budget lasts; past the budget the surfaced conflict is the register's
/// own rejection, not a lost bookkeeping race.
async fn with_commit_race_retry<T, Fut>(
  context: &'static str, mut attempt: impl FnMut() -> Fut,
) -> Result<T>
where
  Fut: std::future::Future<Output = std::result::Result<CommitRace<T>, crate::Error>> + Send, {
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    match attempt().await {
      // A non-race failure inside the attempt (the `?` residual) is
      // always final: only the commit's own Conflict is retried.
      Err(error) => return Err(error),
      Ok(CommitRace::Raced(error)) if attempts < RESOURCE_COMMIT_RACE_ATTEMPTS => {
        tracing::debug!(
          attempts,
          kind = ?error.kind(),
          context,
          "lost the resource commit race; retrying"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10 * u64::from(attempts))).await;
      }
      Ok(CommitRace::Raced(error)) => return Err(error),
      Ok(CommitRace::Final(result)) => return result,
    }
  }
}

impl Supervisor {
  /// Issues the next resource-write stamp for this node: strictly
  /// greater than every stamp this writer has issued before, riding
  /// through host wall-clock regressions. The issued stamp is folded
  /// back into the issue clock so a third write inside the millisecond
  /// that produced the second cannot reuse the same candidate stamp.
  fn issue_resource_stamp(&self) -> u64 {
    issue_write_stamp(&self.resource_write_clock)
  }

  /// Commits one resource write intent as a signed candidate record
  /// (`PutResource`): the supervisor stamps the host wall-clock
  /// tuple, signs through the node's key provider, and commits the whole
  /// record in one conditional transaction. With an `expected` version
  /// the commit installs only while the stored winner equals it exactly
  /// — a raced read-modify-write is an explicit conflict (D7). A
  /// committed winner emits exactly one [`crate::ResourceChanged`] after
  /// durability; an accepted but superseded candidate emits nothing, and
  /// an indeterminate commit reports `CommitUnknown` without an event.
  pub(super) async fn put_resource(
    &mut self, write: crate::ResourceWrite, expected: Option<crate::ResourceVersion>,
  ) -> Result<crate::ResourceMutationView> {
    self.require_unblocked()?;
    let context = self.context()?;
    // The writer's descriptor anchors the record's signature: publish it
    // before the commit so peers can verify this candidate as soon as it
    // arrives (a writing member that never listens must still propagate).
    self.ensure_self_descriptor().await?;
    let writer = context.identity().node().clone();
    let labels = write.labels().clone();
    // Shared reborrows so the retry closure can capture by reference and
    // stay callable (FnMut) across attempts.
    let write = &write;
    let labels = &labels;
    let writer = &writer;
    let expected = &expected;
    let this = &*self;
    let context = &context;
    let (accepted, name, outcome) = with_commit_race_retry("resource put", || {
      Box::pin(async move {
        // The caller's expected version is the only authority on which
        // register state the write may replace: a mismatch is final and
        // never retried (the CAS race guard below covers only the
        // snapshot-commit window, re-running this check per attempt).
        if let Some(expected) = expected {
          let stored = crate::resource::store::read_record_ctx(context.store(), write.name())
            .await?
            .ok_or_else(|| Error::not_found("resource"))?;
          if !expected.matches_record(&stored) {
            return Ok(CommitRace::Final(Err(Error::conflict("resource version"))));
          }
        }
        let timestamp_millis = this.issue_resource_stamp();
        let record = crate::resource::ResourceRecordV1::sign_with_provider(
          write.name().clone(),
          labels.resource_type().clone(),
          labels.uri().clone(),
          labels.custom_labels().clone(),
          timestamp_millis,
          writer.clone(),
          0,
          false,
          &this.dependencies.keys,
          context.identity().handle(),
        )
        .await?;
        let accepted = crate::resource::select::resource_view(&record);
        match crate::resource::store::commit_record_ctx(
          context.store(),
          this.dependencies.entropy.as_ref(),
          &record,
        )
        .await
        {
          // A lost register race is the only retryable outcome; every
          // other error inside the attempt is final.
          Err(error) if error.kind() == crate::ErrorKind::Conflict => Ok(CommitRace::Raced(error)),
          Err(error) => Err(error),
          Ok(outcome) => Ok(CommitRace::Final(Ok((
            accepted,
            record.name().clone(),
            outcome,
          )))),
        }
      })
    })
    .await?;
    // A preconditioned write that lost the tuple can no longer be
    // replacing the expected version: the register moved past it, so the
    // precondition surfaces as an explicit conflict (D7) instead of a
    // silently accepted loser.
    let superseded = if expected.is_some() {
      None
    } else {
      Some(crate::ResourceMutationView::new(accepted.clone(), false))
    };
    Self::resource_mutation_outcome(
      &self.dependencies.events,
      &name,
      outcome,
      crate::ResourceMutationView::new(accepted, true),
      superseded,
    )
  }

  /// The shared post-commit mapping for one resource mutation: a
  /// committed install emits exactly one change event and wins; a
  /// superseded mutation reports the accepted loser (plain put) or
  /// conflicts (a preconditioned write or a removal whose register
  /// moved); an indeterminate commit is never guessed into an outcome.
  fn resource_mutation_outcome(
    events: &crate::node::EventHub, name: &crate::ResourceName,
    outcome: crate::resource::store::ResourceCommitOutcome, winner: crate::ResourceMutationView,
    superseded: Option<crate::ResourceMutationView>,
  ) -> Result<crate::ResourceMutationView> {
    match outcome {
      crate::resource::store::ResourceCommitOutcome::Installed(_) => {
        events.emit(crate::ResourceChanged::new(name.clone()));
        Ok(winner)
      }
      crate::resource::store::ResourceCommitOutcome::Superseded(_) => superseded
        .map(Ok)
        .unwrap_or_else(|| Err(Error::conflict("resource version"))),
      crate::resource::store::ResourceCommitOutcome::Indeterminate { .. } => Err(Error::provider(
        crate::ProviderErrorKind::CommitUnknown,
        crate::ProviderErrorContext::StorageCommit,
      )),
    }
  }

  /// Creates signed removal evidence for one resource (`RemoveResource`):
  /// only when the stored winner still equals the caller's
  /// observed version exactly and the removal strictly wins the tuple.
  /// The removal record carries the winner's labels (removal evidence
  /// stays comparable), and the operation touches core metadata only —
  /// the resource URI is never followed and no caller object is deleted.
  pub(super) async fn remove_resource(
    &mut self, name: crate::ResourceName, expected: crate::ResourceVersion,
  ) -> Result<crate::ResourceMutationView> {
    self.require_unblocked()?;
    let context = self.context()?;
    // The writer's descriptor anchors the removal's signature for the
    // same propagation reason as a put.
    self.ensure_self_descriptor().await?;
    let writer = context.identity().node().clone();
    // The snapshot-exact CAS can lose a race against a concurrent internal
    // committer, so the observation, signature, and commit re-run within
    // a bounded retry; the caller's `expected` stays the only authority
    // on which register state the removal may replace.
    // Shared reborrows so the retry closure can capture by reference and
    // stay callable (FnMut) across attempts; the outer `name` is cloned
    // per attempt and re-bound to the helper's result afterwards.
    let writer = &writer;
    let expected = &expected;
    let this = &*self;
    let context = &context;
    let name = &name;
    with_commit_race_retry("resource removal", || {
      Box::pin(async move {
        let store = context.store();
        let stored = crate::resource::store::read_record_ctx(store, name)
          .await?
          .ok_or_else(|| Error::not_found("resource"))?;
        if !expected.matches_record(&stored) {
          // A stale observation never becomes a newer wall-clock winner:
          // the caller's expected version is final, never retried.
          return Ok(CommitRace::Final(Err(Error::conflict("resource version"))));
        }
        if stored.removed() {
          // The exact removal already won: idempotent, no new transition
          // (and no event — only a fresh install emits).
          return Ok(CommitRace::Final(Ok(crate::ResourceMutationView::new(
            crate::resource::select::resource_view(&stored),
            true,
          ))));
        }
        // The removal rides the same monotonic issue clock as a put, so a
        // writer removing its own fresh record always outranks it, and a
        // rolled-back host clock cannot issue a stale-looking stamp.
        let timestamp_millis = this.issue_resource_stamp();
        // A synced record may legally carry the maximum rank; a saturated
        // register cannot host a further removal and fails closed instead
        // of wrapping the rank order.
        let removal_rank = stored
          .removal_rank()
          .checked_add(1)
          .ok_or_else(|| Error::conflict("resource removal rank"))?;
        // The removal signs through the same single sign-and-seal path as
        // a put (`removed = true`): one canonical encode, one digest, and
        // no second body construction inside `seal`.
        let removal = crate::resource::ResourceRecordV1::sign_with_provider(
          name.clone(),
          stored.resource_type().clone(),
          stored.resource_uri().clone(),
          stored.labels().clone(),
          timestamp_millis,
          writer.clone(),
          removal_rank,
          true,
          &this.dependencies.keys,
          context.identity().handle(),
        )
        .await?;
        if !removal.wins_over(&stored) {
          // A rolled-back host clock cannot pose as a newer winner: the
          // removal is refused and the live record stays.
          return Ok(CommitRace::Final(Err(Error::conflict(
            "resource removal clock",
          ))));
        }
        match crate::resource::store::commit_removal_ctx(
          store,
          this.dependencies.entropy.as_ref(),
          &removal,
          &stored,
        )
        .await
        {
          // A lost register race is the only retryable outcome.
          Err(error) if error.kind() == crate::ErrorKind::Conflict => Ok(CommitRace::Raced(error)),
          Err(error) => Err(error),
          Ok(outcome) => {
            // A committed removal emits exactly one event after
            // durability; the raced/moved/indeterminate arms below never
            // reach the emit as successes. A removal has no accepted-
            // loser report: a register move conflicts (D7).
            Ok(CommitRace::Final(Self::resource_mutation_outcome(
              &this.dependencies.events,
              name,
              outcome,
              crate::ResourceMutationView::new(
                crate::resource::select::resource_view(&removal),
                true,
              ),
              None,
            )))
          }
        }
      })
    })
    .await
  }
}

/// Issues the next resource-write stamp from the writer's issue clock:
/// strictly greater than every stamp previously issued through this
/// clock, and never below the observed wall clock. The issued stamp is
/// folded back into the clock, so successive issues inside one
/// millisecond keep advancing by one instead of colliding on
/// `previous + 1` and falling to the register's digest tie-break.
fn issue_write_stamp(clock: &std::sync::atomic::AtomicU64) -> u64 {
  issue_write_stamp_since(clock, crate::time::now_millis())
}

/// [`issue_write_stamp`] against an injected observation, so the
/// same-millisecond collision the fold prevents stays deterministic to
/// test.
fn issue_write_stamp_since(clock: &std::sync::atomic::AtomicU64, observed: u64) -> u64 {
  let previous = clock.fetch_max(observed, std::sync::atomic::Ordering::Relaxed);
  let stamp = previous.saturating_add(1).max(observed);
  clock.fetch_max(stamp, std::sync::atomic::Ordering::Relaxed);
  stamp
}

#[cfg(test)]
mod resource_stamp_tests {
  use super::issue_write_stamp_since;

  #[test]
  fn stamps_advance_inside_one_millisecond() {
    let clock = std::sync::atomic::AtomicU64::new(0);
    // Three issues inside the same observed millisecond: the second
    // issue advances past the first without moving the clock, so the
    // fold-back is what keeps the third from reusing the second's stamp.
    let first = issue_write_stamp_since(&clock, 1_000);
    let second = issue_write_stamp_since(&clock, 1_000);
    let third = issue_write_stamp_since(&clock, 1_000);
    assert_eq!(first, 1_000);
    assert_eq!(second, 1_001);
    assert_eq!(third, 1_002);
  }

  #[test]
  fn stamps_ride_through_wall_clock_regressions() {
    let clock = std::sync::atomic::AtomicU64::new(0);
    let _ = issue_write_stamp_since(&clock, 5_000);
    // A rolled-back observation issues above the last stamp, never below.
    let next = issue_write_stamp_since(&clock, 4_000);
    assert_eq!(next, 5_001);
    assert!(clock.load(std::sync::atomic::Ordering::Relaxed) >= next);
  }
}
