//! The node's membership revision: a monotonically increasing counter
//! that bumps exactly when the member set changes, in the same order as
//! the [`crate::MemberChanged`] events. Unlike the transient event bus,
//! the revision is state: a watcher that subscribes before acting can
//! never miss a bump, and a late subscriber observes the current
//! revision immediately. It exists so hosts and tests can await member
//! changes deterministically instead of polling pages with wall-clock
//! sleeps.

use tokio::sync::watch;

use crate::Error;

/// The node-side half of the membership revision: bumps the counter.
/// Clone-scoped like the event hub; every bump pairs one-to-one with a
/// `MemberChanged` emission after the underlying persist lands.
#[derive(Clone, Debug)]
pub(crate) struct MemberRevisionSignal {
  revision: watch::Sender<u64>,
}

impl MemberRevisionSignal {
  pub(crate) const fn new(revision: watch::Sender<u64>) -> Self {
    Self { revision }
  }

  /// Records one member-set change. Called immediately after the paired
  /// `MemberChanged` emission, so a watcher released by this bump is
  /// guaranteed the state change is already durable and observable
  /// through the paged member queries.
  pub(crate) fn bump(&self) {
    self.revision.send_modify(|revision| *revision += 1);
  }
}

/// The observer half handed out through
/// [`crate::NodeHandle::member_revision`]: watch the member-set revision
/// and await changes instead of polling the member pages.
#[derive(Clone, Debug)]
pub struct MemberRevision {
  revision: watch::Receiver<u64>,
}

impl MemberRevision {
  pub(crate) const fn new(revision: watch::Receiver<u64>) -> Self {
    Self { revision }
  }

  /// The current member-set revision. Compare before and after an action
  /// to detect that this node observed a change at all.
  pub fn current(&self) -> u64 {
    *self.revision.borrow()
  }

  /// Waits for the next member-set change and returns the new revision.
  /// Fails with `ShuttingDown` once the node (and every sender) is gone.
  /// The wait is value-based: bumps that fire between the action and
  /// this call are captured, never lost.
  pub async fn changed(&mut self) -> crate::Result<u64> {
    self
      .revision
      .changed()
      .await
      .map(|()| *self.revision.borrow())
      .map_err(|_| Error::shutting_down("member revision"))
  }
}
