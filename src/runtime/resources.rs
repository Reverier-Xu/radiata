//! The resource write plane's shared machinery: the bounded commit-race
//! retry, the post-commit outcome mapping, and the writer's monotonic
//! resource-write stamp clock. The put and removal effects themselves
//! live in [`super::task_effects`] (`reconcile_put_resource`,
//! `reconcile_delete_resource`) and compose these helpers exactly the
//! way the old supervisor methods did.

use crate::{Error, Result, node::EventHub};

/// The commit-race retry budget for the resource write paths.
const RESOURCE_COMMIT_RACE_ATTEMPTS: u32 = 3;

/// One resource-write attempt's outcome under the shared bounded retry:
/// a lost register race is retried with a fresh attempt while the budget
/// lasts (the conflict error surfaces once it is spent); anything else —
/// success, the register rejecting the candidate, or any other error —
/// is final.
pub(super) enum CommitRace<T> {
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
pub(super) async fn with_commit_race_retry<T, Fut>(
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

/// The shared post-commit mapping for one resource mutation: a
/// committed install emits exactly one change event and wins; a
/// superseded mutation reports the accepted loser (plain put) or
/// conflicts (a preconditioned write or a removal whose register
/// moved); an indeterminate commit is never guessed into an outcome.
pub(super) fn resource_mutation_outcome(
  events: &EventHub, name: &crate::ResourceName,
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

/// The writer's issue clock for resource-write stamps: a writer's own
/// successive writes must strictly outrank their predecessor, so the
/// issue clock advances at least one millisecond per write and rides
/// through wall-clock regressions (a same-millisecond stamp would fall
/// to the digest tie-break, and the writer's own second write could
/// lose to its first). Both the put and the removal paths issue through
/// this clock.
pub(crate) type ResourceWriteClock = std::sync::Arc<std::sync::atomic::AtomicU64>;

/// Issues the next resource-write stamp from the writer's issue clock:
/// strictly greater than every stamp previously issued through this
/// clock, and never below the observed wall clock. The issued stamp is
/// folded back into the clock, so successive issues inside one
/// millisecond keep advancing by one instead of colliding on
/// `previous + 1` and falling to the register's digest tie-break.
pub(super) fn issue_write_stamp(clock: &ResourceWriteClock) -> u64 {
  issue_write_stamp_since(clock, crate::time::now_millis())
}

/// [`issue_write_stamp`] against an injected observation, so the
/// same-millisecond collision the fold prevents stays deterministic to
/// test.
fn issue_write_stamp_since(clock: &ResourceWriteClock, observed: u64) -> u64 {
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
    let clock = std::sync::Arc::new(clock);
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
    let clock = std::sync::Arc::new(clock);
    let _ = issue_write_stamp_since(&clock, 5_000);
    // A rolled-back observation issues above the last stamp, never below.
    let next = issue_write_stamp_since(&clock, 4_000);
    assert_eq!(next, 5_001);
    assert!(clock.load(std::sync::atomic::Ordering::Relaxed) >= next);
  }
}
