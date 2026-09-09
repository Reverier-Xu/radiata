use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

#[cfg(test)]
use self::receipt::HostWallClock;
use self::receipt::{PreparedTransaction, WallClock};
use crate::{
  CommitOutcome, CommitReceipt, Digest, Error, ErrorKind, ProviderErrorContext, ProviderErrorKind,
  ReconcileOutcome, Result, StoreRequirements, TransactionId,
  provider::{Storage, StorageFactory, StoreSnapshot},
};

/// The bounded wait for the single commit slot: internal committers are
/// short, so an entry wait queues a concurrent caller instead of surfacing
/// the transient refusal. Keep it well under any caller-facing deadline.
const ENTRY_WAIT_BOUND: Duration = Duration::from_secs(5);
/// The commit-slot wait backstop: finish paths notify parked waiters
/// directly, so the backoff only bounds a lost-wakeup path.
const ENTRY_WAIT_BACKOFF: Duration = Duration::from_millis(10);

/// The process-wide writer exclusion for one [`MetadataStore`]: at most
/// one task may hold a read-decide-commit section at a time, so base
/// revisions observed inside the section cannot move before the commit
/// lands. Task-reentrant: a task that already holds the section acquires
/// a no-op permit, so journaled flows can span nested helper calls
/// without threading the permit through signatures.
#[derive(Debug)]
struct WriterLock {
  /// The holder's task id, if the holder runs inside a spawned task;
  /// [`None`] when the holder runs in a root future outside any task
  /// (e.g. a unit test body). Root-context holders are inherently
  /// sequential, so a shared pseudo-identity is sound there.
  holder: Mutex<Option<Option<tokio::task::Id>>>,
  /// Wakes parked acquirers when the section is released.
  released: tokio::sync::Notify,
}

impl WriterLock {
  /// Poisoning cannot lose the holder record in a recoverable way, so a
  /// poisoned lock resolves to its inner value: the writer exclusion must
  /// stay observable after a panicking holder unwinds.
  fn slot(&self) -> std::sync::MutexGuard<'_, Option<Option<tokio::task::Id>>> {
    match self.holder.lock() {
      Ok(slot) => slot,
      Err(poisoned) => poisoned.into_inner(),
    }
  }

  fn holder(&self) -> Option<Option<tokio::task::Id>> {
    *self.slot()
  }

  async fn acquire(&self) -> WriterPermit<'_> {
    let me = tokio::task::try_id();
    if self.holder() == Some(me) {
      return WriterPermit {
        lock: self,
        holder: me,
        nested: true,
      };
    }
    loop {
      // Register interest before re-checking the holder: the enable-
      // check ordering closes the lost-wakeup window between seeing a
      // held section and parking.
      let notified = self.released.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      if self.holder().is_none() {
        let mut slot = self.slot();
        if slot.is_none() {
          *slot = Some(me);
          return WriterPermit {
            lock: self,
            holder: me,
            nested: false,
          };
        }
      }
      notified.await;
    }
  }

  fn release(&self, holder: Option<tokio::task::Id>) {
    let mut slot = self.slot();
    if *slot == Some(holder) {
      *slot = None;
    }
    self.released.notify_waiters();
  }
}

/// The held writer section; releases on drop.
#[derive(Debug)]
pub(crate) struct WriterPermit<'a> {
  lock: &'a WriterLock,
  holder: Option<tokio::task::Id>,
  nested: bool,
}

impl Drop for WriterPermit<'_> {
  fn drop(&mut self) {
    if !self.nested {
      self.lock.release(self.holder);
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingCommit {
  transaction: TransactionId,
  digest: Digest,
  journal_proven: bool,
}

#[derive(Debug)]
enum CommitState {
  Ready,
  Frozen {
    pending: PendingCommit,
    provider_call_active: bool,
  },
}

#[derive(Debug)]
pub(crate) struct MetadataStore {
  provider: Box<dyn Storage>,
  state: Mutex<CommitState>,
  /// The writer exclusion: serializes every read-decide-commit section
  /// (see [`WriterLock`]).
  writer_lock: WriterLock,
  /// Wakes commit-slot waiters when the state returns to Ready (or an
  /// awaitable frozen outcome lands), so entry waits park instead of
  /// polling. The backoff sleep stays as a lost-wakeup backstop.
  ready_notify: tokio::sync::Notify,
  clock: Arc<dyn WallClock>,
  receipt_retention: Duration,
}

struct ProviderCall<'a> {
  state: &'a Mutex<CommitState>,
  active: bool,
}

impl ProviderCall<'_> {
  fn complete(mut self) {
    self.active = false;
  }
}

impl Drop for ProviderCall<'_> {
  fn drop(&mut self) {
    if !self.active {
      return;
    }
    if let Ok(mut state) = self.state.lock()
      && let CommitState::Frozen {
        provider_call_active,
        ..
      } = &mut *state
    {
      *provider_call_active = false;
    }
  }
}

impl MetadataStore {
  /// Opens a fresh (or existing, plain-ready) metadata store. Test-only
  /// today: production opens go through the journal-backed recovered and
  /// pending-recovery paths instead.
  #[cfg(test)]
  pub(crate) async fn open(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration,
  ) -> Result<Self> {
    Self::open_with_clock(factory, receipt_retention, Arc::new(HostWallClock)).await
  }

  #[cfg(test)]
  pub(crate) async fn open_recovered(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, transaction: TransactionId,
    digest: Digest,
  ) -> Result<Self> {
    Self::open_recovered_with_clock(
      factory,
      receipt_retention,
      transaction,
      digest,
      Arc::new(HostWallClock),
    )
    .await
  }

  /// The clock-injected open used by the storage contract suite and the
  /// unit tests, so deterministic clocks drive commit-timestamp behavior.
  #[cfg(any(test, fuzzing))]
  async fn open_with_clock(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, clock: Arc<dyn WallClock>,
  ) -> Result<Self> {
    Self::open_with_state(factory, receipt_retention, clock, CommitState::Ready).await
  }

  #[cfg(test)]
  async fn open_recovered_with_clock(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, transaction: TransactionId,
    digest: Digest, clock: Arc<dyn WallClock>,
  ) -> Result<Self> {
    Self::open_with_state(
      factory,
      receipt_retention,
      clock,
      CommitState::Frozen {
        pending: PendingCommit {
          transaction,
          digest,
          journal_proven: false,
        },
        provider_call_active: false,
      },
    )
    .await
  }

  async fn open_with_state(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, clock: Arc<dyn WallClock>,
    state: CommitState,
  ) -> Result<Self> {
    let requirements = StoreRequirements::metadata();
    let provider = factory.open(requirements).await?;
    if !provider.capabilities().satisfies(&requirements) {
      return Err(Error::provider(
        ProviderErrorKind::UnsupportedCapability,
        ProviderErrorContext::StorageOpen,
      ));
    }
    // The opened store must sit inside the production schema chain
    // before anything reads or recovers it: a version outside the chain
    // fails closed without mutating anything, and a store behind the
    // target walks the explicit edge chain (which, while the chain has
    // no edges, writes nothing at all).
    migration::ensure_open_schema(provider.as_ref()).await?;
    Ok(Self {
      provider,
      state: Mutex::new(state),
      writer_lock: WriterLock {
        holder: Mutex::new(None),
        released: tokio::sync::Notify::new(),
      },
      ready_notify: tokio::sync::Notify::new(),
      clock,
      receipt_retention,
    })
  }

  /// Acquires the writer exclusion: while held, no other task can enter
  /// a read-decide-commit section on this store, so a snapshot taken
  /// under the permit stays authoritative until the caller's commit
  /// lands. Task-reentrant; see [`WriterLock`].
  pub(crate) async fn write_permit(&self) -> WriterPermit<'_> {
    self.writer_lock.acquire().await
  }

  pub(crate) async fn snapshot(&self) -> Result<Box<dyn StoreSnapshot>> {
    self.provider.snapshot().await
  }

  pub(crate) async fn commit(&self, transaction: PreparedTransaction) -> Result<CommitOutcome> {
    // The single-commit state machine refuses a second in-flight commit
    // with NotReady. Every internal committer (anti-entropy ticks,
    // descriptor ensures, key intents) is short and always restores the
    // Ready state, so a bounded entry wait turns the transient refusal
    // into queueing instead of pushing retry policy onto every caller.
    // A caller that truly cannot wait still observes NotReady after the
    // bound, and a user-visible Conflict/Aborted outcome is never masked:
    // only the entry refusal is retried, never the commit itself.
    let deadline = std::time::Instant::now() + ENTRY_WAIT_BOUND;
    let transaction = transaction.0;
    let pending = PendingCommit {
      transaction: transaction.id().clone(),
      digest: transaction.operation_digest().clone(),
      journal_proven: false,
    };
    let call = loop {
      match self.begin_commit(pending.clone()) {
        Ok(call) => break call,
        Err(error) if error.kind() == crate::ErrorKind::NotReady => {
          if std::time::Instant::now() >= deadline {
            return Err(error);
          }
          // Park until a finish path notifies, with the short backoff as
          // a lost-wakeup backstop; either way the loop re-checks the
          // state before waiting again.
          let notified = self.ready_notify.notified();
          tokio::pin!(notified);
          notified.as_mut().enable();
          tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep(ENTRY_WAIT_BACKOFF) => {}
          }
        }
        Err(error) => return Err(error),
      }
    };
    let result = self.provider.commit(transaction).await;

    match result {
      Ok(CommitOutcome::Committed(receipt)) => {
        self.validate_receipt(&pending, &receipt, ProviderErrorContext::StorageCommit)?;
        self.finish_ready(call)?;
        Ok(CommitOutcome::Committed(receipt))
      }
      Ok(CommitOutcome::Aborted) => {
        self.finish_ready(call)?;
        Ok(CommitOutcome::Aborted)
      }
      Ok(CommitOutcome::Conflict) => {
        self.finish_ready(call)?;
        Ok(CommitOutcome::Conflict)
      }
      Ok(CommitOutcome::Unknown {
        transaction,
        operation_digest,
      }) => {
        if transaction != pending.transaction || operation_digest != pending.digest {
          return Err(Error::provider(
            ProviderErrorKind::StorageCorrupt,
            ProviderErrorContext::StorageCommit,
          ));
        }
        self.finish_frozen(call)?;
        Ok(CommitOutcome::Unknown {
          transaction,
          operation_digest,
        })
      }
      Err(error) if error.kind() == ErrorKind::CommitUnknown => {
        self.finish_frozen(call)?;
        Err(error)
      }
      Err(error) => {
        self.finish_ready(call)?;
        Err(error)
      }
    }
  }

  pub(crate) async fn reconcile(&self) -> Result<ReconcileOutcome> {
    // The same bounded entry wait as commit: a reconcile racing an
    // in-flight commit waits for the Ready state instead of surfacing the
    // transient refusal to callers.
    let deadline = std::time::Instant::now() + ENTRY_WAIT_BOUND;
    let (pending, call) = loop {
      match self.begin_reconcile() {
        Ok(pair) => break pair,
        Err(error) if error.kind() == crate::ErrorKind::NotReady => {
          if std::time::Instant::now() >= deadline {
            return Err(error);
          }
          // Same parked entry wait as commit (see there).
          let notified = self.ready_notify.notified();
          tokio::pin!(notified);
          notified.as_mut().enable();
          tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep(ENTRY_WAIT_BACKOFF) => {}
          }
        }
        Err(error) => return Err(error),
      }
    };
    let outcome = self
      .provider
      .reconcile(&pending.transaction, &pending.digest)
      .await;
    match outcome {
      Ok(ReconcileOutcome::Committed(receipt)) => {
        self.validate_receipt(&pending, &receipt, ProviderErrorContext::StorageReconcile)?;
        self.finish_ready(call)?;
        Ok(ReconcileOutcome::Committed(receipt))
      }
      Ok(ReconcileOutcome::Aborted) => {
        if pending.journal_proven {
          // A recovered pending record proves the journaled transaction
          // committed atomically, so an aborted reconciliation contradicts
          // the durable journal and must fail closed.
          self.finish_frozen(call)?;
          return Err(Error::provider(
            ProviderErrorKind::StorageCorrupt,
            ProviderErrorContext::StorageReconcile,
          ));
        }
        self.finish_ready(call)?;
        Ok(ReconcileOutcome::Aborted)
      }
      Ok(ReconcileOutcome::DigestConflict) => {
        self.finish_frozen(call)?;
        Ok(ReconcileOutcome::DigestConflict)
      }
      Ok(ReconcileOutcome::Unknown) => {
        self.finish_frozen(call)?;
        Ok(ReconcileOutcome::Unknown)
      }
      Err(error) => {
        self.finish_frozen(call)?;
        Err(error)
      }
    }
  }

  fn begin_commit(&self, pending: PendingCommit) -> Result<ProviderCall<'_>> {
    let mut state = self.lock_state()?;
    if !matches!(*state, CommitState::Ready) {
      return Err(Error::not_ready("metadata storage commit"));
    }
    *state = CommitState::Frozen {
      pending,
      provider_call_active: true,
    };
    drop(state);
    Ok(ProviderCall {
      state: &self.state,
      active: true,
    })
  }

  fn begin_reconcile(&self) -> Result<(PendingCommit, ProviderCall<'_>)> {
    let mut state = self.lock_state()?;
    let pending = match &mut *state {
      CommitState::Ready => return Err(Error::not_ready("metadata storage reconcile")),
      CommitState::Frozen {
        pending,
        provider_call_active,
      } => {
        if *provider_call_active {
          return Err(Error::not_ready("metadata storage reconcile"));
        }
        *provider_call_active = true;
        pending.clone()
      }
    };
    drop(state);
    Ok((
      pending,
      ProviderCall {
        state: &self.state,
        active: true,
      },
    ))
  }

  fn finish_ready(&self, call: ProviderCall<'_>) -> Result<()> {
    *self.lock_state()? = CommitState::Ready;
    call.complete();
    self.ready_notify.notify_waiters();
    Ok(())
  }

  fn finish_frozen(&self, call: ProviderCall<'_>) -> Result<()> {
    let mut state = self.lock_state()?;
    let CommitState::Frozen {
      provider_call_active,
      ..
    } = &mut *state
    else {
      return Err(Error::internal("metadata storage commit state"));
    };
    *provider_call_active = false;
    drop(state);
    call.complete();
    self.ready_notify.notify_waiters();
    Ok(())
  }

  fn validate_receipt(
    &self, pending: &PendingCommit, receipt: &CommitReceipt, context: ProviderErrorContext,
  ) -> Result<()> {
    if receipt.transaction() != &pending.transaction
      || receipt.operation_digest() != &pending.digest
    {
      return Err(Error::provider(ProviderErrorKind::StorageCorrupt, context));
    }
    Ok(())
  }

  /// Freezes a ready store on a pending identity recovered from a durable
  /// journal by the caller.
  ///
  /// The journal record was committed atomically with the target
  /// transaction, so reconciliation must prove `Committed`. Recovering the
  /// same identity again is idempotent: an already frozen store keeps its
  /// pending identity and upgrades it to journal-proven so reconciliation
  /// can proceed after a healed provider.
  pub(crate) fn freeze_journaled(&self, identity: &receipt::ReceiptIdentity) -> Result<()> {
    let mut state = self.lock_state()?;
    match &mut *state {
      CommitState::Ready => {
        *state = CommitState::Frozen {
          pending: PendingCommit {
            transaction: identity.transaction().clone(),
            digest: identity.operation_digest().clone(),
            journal_proven: true,
          },
          provider_call_active: false,
        };
        Ok(())
      }
      CommitState::Frozen { pending, .. }
        if pending.transaction == *identity.transaction()
          && pending.digest == *identity.operation_digest() =>
      {
        pending.journal_proven = true;
        Ok(())
      }
      CommitState::Frozen { .. } => Err(Error::not_ready("metadata storage journal recovery")),
    }
  }

  /// Reconciles a frozen store back to ready, if it is frozen.
  ///
  /// A ready store is unchanged. A frozen store reconciles its exact pending
  /// identity once; `Committed` or `Aborted` clears the freeze while an
  /// unresolved or conflicting outcome keeps it and fails.
  pub(crate) async fn reconcile_if_frozen(&self) -> Result<()> {
    {
      let state = self.lock_state()?;
      if matches!(*state, CommitState::Ready) {
        return Ok(());
      }
    }
    match self.reconcile().await? {
      ReconcileOutcome::Committed(_) | ReconcileOutcome::Aborted => Ok(()),
      ReconcileOutcome::DigestConflict => Err(Error::provider(
        ProviderErrorKind::StorageCorrupt,
        ProviderErrorContext::StorageReconcile,
      )),
      ReconcileOutcome::Unknown => Err(Error::provider(
        ProviderErrorKind::CommitUnknown,
        ProviderErrorContext::StorageReconcile,
      )),
    }
  }

  /// Whether the store is blocked on an indeterminate outcome: frozen and
  /// no provider call in flight. A frozen state with an active provider
  /// call is an ordinary in-flight commit that will complete momentarily;
  /// it is not a block. While blocked, the runtime refuses new
  /// admission-sensitive operations (credential rotation, reuse, signing,
  /// and networking) until an authoritative reopen reconciles the exact
  /// transaction or proves absence.
  pub(crate) fn is_blocked(&self) -> Result<bool> {
    Ok(matches!(
      *self.lock_state()?,
      CommitState::Frozen {
        provider_call_active: false,
        ..
      }
    ))
  }

  fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, CommitState>> {
    self
      .state
      .lock()
      .map_err(|_| Error::internal("metadata storage commit state"))
  }
}
#[cfg(any(test, fuzzing))]
#[cfg_attr(fuzzing, allow(dead_code))]
pub(crate) mod test_util;

pub(crate) mod families;
#[cfg(feature = "json")]
pub(crate) mod json;
pub(crate) mod migration;

#[cfg(all(test, unix, feature = "json", feature = "redb"))]
pub(crate) mod mixed_e2e;
pub(crate) mod pending;
pub(crate) mod receipt;
#[cfg(feature = "redb")]
pub(crate) mod redb;

#[cfg(any(test, fuzzing))]
pub(crate) mod contract;

#[cfg(test)]
mod tests;
