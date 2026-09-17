use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

#[cfg(test)]
use self::receipt::HostWallClock;
use self::receipt::{
  PreparedTransaction, ReceiptReferenceToken, WallClock, build_pending_record_delete_operations,
  prepare_internal_transaction,
};
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
/// without threading the permit through signatures. Root-context holders
/// (no task id) share one pseudo-identity, so they must not
/// `tokio::join!` concurrent store operations: both legs would observe
/// "already holding" and run inside one exclusion at the same time.
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
  /// The register-install epoch: one monotonic bump per installed
  /// resource record commit (see [`Self::note_register_install`]), so
  /// the sync driver observes local catalog changes with one atomic
  /// load per tick instead of a catalog scan.
  register_epoch: std::sync::atomic::AtomicU64,
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
      register_epoch: std::sync::atomic::AtomicU64::new(0),
    })
  }

  /// Records one installed register entry: the sync driver reads the
  /// epoch once per tick ([`Self::register_epoch`]) and treats any
  /// advance as "some peer's diff may have changed", turning local
  /// writes into next-tick pushes instead of one detection-cadence wait
  /// per hop.
  pub(crate) fn note_register_install(&self) {
    use std::sync::atomic::Ordering;
    self.register_epoch.fetch_add(1, Ordering::Relaxed);
  }

  /// The current register-install epoch. `Relaxed` suffices: the value
  /// is a change detector across ticks, never a synchronization point.
  pub(crate) fn register_epoch(&self) -> u64 {
    use std::sync::atomic::Ordering;
    self.register_epoch.load(Ordering::Relaxed)
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

  /// The bounded entry wait shared by commit and reconcile: a transient
  /// `NotReady` refusal (a second in-flight state-machine entry) parks
  /// until a finish path notifies, with the short backoff as a
  /// lost-wakeup backstop; either way the entry is re-checked before
  /// waiting again. Past the bound the refusal surfaces instead of
  /// queueing forever, and any non-NotReady error is never retried.
  async fn wait_for_entry<R>(
    &self, deadline: std::time::Instant,
    mut begin: impl FnMut() -> std::result::Result<R, crate::Error>,
  ) -> std::result::Result<R, crate::Error> {
    loop {
      match begin() {
        Ok(value) => return Ok(value),
        Err(error) if error.kind() == crate::ErrorKind::NotReady => {
          if std::time::Instant::now() >= deadline {
            return Err(error);
          }
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
    }
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
    let transaction = transaction.0;
    let pending = PendingCommit {
      transaction: transaction.id().clone(),
      digest: transaction.operation_digest().clone(),
      journal_proven: false,
    };
    let deadline = std::time::Instant::now() + ENTRY_WAIT_BOUND;
    let call = self
      .wait_for_entry(deadline, || self.begin_commit(pending.clone()))
      .await?;
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
    // in-flight commit waits for the frozen slot instead of surfacing
    // the transient refusal to callers. A ready store, by contrast, has
    // no in-doubt commit at all: the refusal is semantic and final (no
    // state change can make this transaction reconcilable), so it
    // surfaces immediately instead of parking for the full bound.
    if matches!(*self.lock_state()?, CommitState::Ready) {
      return Err(Error::not_ready("metadata storage reconcile"));
    }
    let deadline = std::time::Instant::now() + ENTRY_WAIT_BOUND;
    let (pending, call) = self
      .wait_for_entry(deadline, || self.begin_reconcile())
      .await?;
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

  /// Resolves one purpose-scoped pending journal against durable provider
  /// evidence and returns whether a journal was recovered.
  ///
  /// The journal record is committed atomically with its transaction, so
  /// the provider's durable receipt — not this process's in-flight commit
  /// slot — is the recovery authority. Reading the evidence deliberately
  /// bypasses the slot state machine: the slot exists to order this
  /// process's in-flight commits, while a journal residue is either a
  /// crash leftover or another flow's live residue, and both resolve from
  /// the same authoritative source on a ready store.
  ///
  /// Outcomes: `Ok(true)` — the journal committed; the caller removes the
  /// residue with `cleanup_pending_exact`. `Ok(false)` — nothing to
  /// recover (absent, or the owning flow cleaned it while the evidence
  /// was being read). `Err` — the durable evidence contradicts the
  /// atomic journal: the store stays frozen and fails closed (the
  /// `is_blocked` gate refuses admission-sensitive operations until an
  /// authoritative reopen reconciles it).
  ///
  /// Precondition: the journaled flow calling this holds the store's
  /// writer permit (every identity-side entry holds it for the whole
  /// prologue→commit→cleanup flow). The unfreeze path mutates the commit
  /// state outside the commit path, so two concurrent resolvers could
  /// otherwise interleave their evidence reads and verdicts.
  pub(crate) async fn resolve_pending_journal(&self, purpose: &str) -> Result<bool> {
    let Some(identity) = self.recover_pending(purpose).await? else {
      return Ok(false);
    };
    let pending = PendingCommit {
      transaction: identity.transaction().clone(),
      digest: identity.operation_digest().clone(),
      journal_proven: true,
    };
    match self
      .provider
      .reconcile(identity.transaction(), identity.operation_digest())
      .await
    {
      Ok(ReconcileOutcome::Committed(receipt)) => {
        self.validate_receipt(&pending, &receipt, ProviderErrorContext::StorageReconcile)?;
        self.finish_journal_recovery(&pending)?;
        crate::audit::journal_resolved(purpose, true);
        Ok(true)
      }
      Ok(_) => {
        // The evidence shows no committed receipt for the journaled
        // identity — a contradiction with the atomic journal, unless the
        // owning flow cleaned the residue while the evidence was being
        // read. Re-read the journal: gone means already resolved; still
        // present means the durable state contradicts the journal, and
        // the store stays frozen and fails closed.
        if self.recover_pending(purpose).await?.is_none() {
          self.finish_journal_recovery(&pending)?;
          crate::audit::journal_resolved(purpose, false);
          return Ok(false);
        }
        Err(Error::provider(
          ProviderErrorKind::StorageCorrupt,
          ProviderErrorContext::StorageReconcile,
        ))
      }
      Err(error) => {
        // An evidence read failure is not a classification: the store
        // stays frozen (fail closed, `is_blocked` gates admission) and
        // the error surfaces. A retry of `resolve_pending_journal`
        // re-enters the same frozen identity.
        Err(error)
      }
    }
  }

  /// Returns a frozen store recovered on journal evidence back to ready.
  ///
  /// Permit-holding resolvers (see [`Self::resolve_pending_journal`])
  /// still own the frozen slot when they unfreeze, so the identity
  /// condition below always holds for them. The declared-uncommitted
  /// command runs outside the writer permit by design, so its unfreeze
  /// is conditioned on the slot still holding the exact resolved
  /// identity: a slot that moved on during the delete await (unfrozen by
  /// another resolver, or re-purposed by a new in-flight commit) keeps
  /// its state, because clobbering it would break the
  /// single-in-flight-commit invariant.
  fn finish_journal_recovery(&self, resolved: &PendingCommit) -> Result<()> {
    let mut state = self.lock_state()?;
    match &*state {
      CommitState::Frozen { pending, .. }
        if pending.transaction == resolved.transaction && pending.digest == resolved.digest => {}
      // The slot moved on while this resolver was reading durable
      // evidence: the resolution outcome is classified from durable
      // evidence either way, so only the state write is skipped.
      _ => return Ok(()),
    }
    *state = CommitState::Ready;
    drop(state);
    self.ready_notify.notify_waiters();
    Ok(())
  }

  /// Resolves a store frozen on a pending journal whose durable provider
  /// evidence permanently contradicts the journal (the record is present,
  /// but the provider proves no committed receipt for the journaled
  /// transaction), by declaring the interrupted transaction not durably
  /// committed. This is the operator-confirmed last resort for the
  /// permanent-contradiction freeze; restart-based reconciliation remains
  /// the first remedy and stays authoritative whenever the evidence
  /// resolves.
  ///
  /// The resolution deletes the pending journal record for the frozen
  /// purpose — paired, exactly as the normal pending cleanup pairs them,
  /// with removing the journal's receipt-reference token from the live
  /// target receipt — in one atomic, never-journaled transaction and
  /// only then unfreezes the store, so a crash at any point leaves the
  /// store either still frozen with its journal or cleanly unfrozen
  /// without one — never half-cleared. A restart after the delete
  /// reopens ready with no pending journal. The unfreeze is conditioned
  /// on the slot still holding the exact frozen identity (see
  /// [`Self::finish_journal_recovery`]): a slot that moved on during the
  /// delete await keeps its state, and the landed delete still stands.
  ///
  /// Writer gate: the frozen slot replaces the writer exclusion here.
  /// While frozen, every normal commit path refuses at the slot, so this
  /// direct provider commit is the only durable writer; operator
  /// commands serialize on the supervisor's control loop, and the slot's
  /// fate is mutated only under the state mutex through the same finish
  /// path the normal resolver uses. The delete is re-anchored to the
  /// still-frozen slot immediately before it commits.
  ///
  /// Typed rejections that change nothing: a ready store, an in-flight
  /// commit freeze, and a frozen slot matching no durable journal record
  /// reject with `Conflict`; a fresh evidence read proving the transaction
  /// committed or digest-conflicted rejects with `StorageCorrupt` (a
  /// committed journal resolves through restart instead); an evidence read
  /// failure propagates and keeps the store frozen.
  pub(crate) async fn resolve_frozen_journal_uncommitted(
    &self, operation: TransactionId,
  ) -> Result<()> {
    let pending = self.lock_frozen_slot()?;
    let purpose = {
      let snapshot = self.snapshot().await?;
      pending::discover_frozen_journal_purpose(
        snapshot.as_ref(),
        &pending.transaction,
        &pending.digest,
      )
      .await?
    };
    let Some(purpose) = purpose else {
      // No durable journal matches the frozen slot: the freeze is an
      // in-flight commit slot, not a recovered journal, and aborting it
      // has nothing to anchor on.
      return Err(Error::conflict("frozen journal resolution"));
    };
    // The delete is anchored to a fresh durable verdict: evidence of a
    // committed or digest-conflicted transaction contradicts the
    // declaration and keeps the store frozen, while a definitively
    // uncommitted or indeterminate verdict accepts the declaration. An
    // evidence failure is not a classification and changes nothing.
    match self
      .provider
      .reconcile(&pending.transaction, &pending.digest)
      .await
    {
      Ok(ReconcileOutcome::Aborted | ReconcileOutcome::Unknown) => {}
      Ok(ReconcileOutcome::Committed(_) | ReconcileOutcome::DigestConflict) => {
        return Err(storage_corrupt(ProviderErrorContext::StorageReconcile));
      }
      Err(error) => return Err(error),
    }
    let snapshot = self.snapshot().await?;
    let Some((stored, record)) = pending::discover_pending(snapshot.as_ref(), &purpose).await?
    else {
      // The journal vanished between reads: there is nothing left to
      // abort, and the frozen premise no longer holds.
      return Err(Error::conflict("frozen journal resolution"));
    };
    let identity = record.recover_identity(&stored)?;
    if identity.transaction() != &pending.transaction
      || identity.operation_digest() != &pending.digest
    {
      return Err(storage_corrupt(ProviderErrorContext::StorageSnapshot));
    }
    let base_revision = snapshot.revision().clone();
    // The delete is paired — in the same shape as the normal pending
    // cleanup — with removing the journal's receipt-reference token from
    // the live target receipt, so a receipt touched by a
    // declared-uncommitted transaction can anchor and be forgotten again
    // instead of staying permanently referenced. A forgotten target
    // receipt carries no reachable reference set, so the record delete
    // alone applies.
    let record_token = ReceiptReferenceToken::for_record(
      &pending::pending_namespace()?,
      &pending::pending_key(&purpose),
    );
    let delete_operations = build_pending_record_delete_operations(
      snapshot.as_ref(),
      &operation,
      &identity,
      &record_token,
      pending::pending_namespace()?,
      pending::pending_key(&purpose),
      stored.digest().clone(),
    )
    .await?;
    drop(snapshot);
    // The slot must still be the exact frozen journal: nothing else may
    // unfreeze between the evidence read and the delete, and a flipped
    // slot means the premise broke while this resolution was reading.
    let frozen_now = self.lock_frozen_slot()?;
    if frozen_now.transaction != pending.transaction || frozen_now.digest != pending.digest {
      return Err(Error::conflict("frozen journal resolution"));
    }
    drop(frozen_now);
    let delete_id = operation.clone();
    let prepared = prepare_internal_transaction(operation, base_revision, delete_operations)?;
    let delete_digest = prepared.operation_digest().clone();
    // The delete bypasses the commit slot's state machine on purpose:
    // the machine refuses any commit while frozen, and this delete is
    // the resolution that ends the freeze. The frozen slot itself gates
    // the writers: every normal commit path refuses while frozen.
    match self.provider.commit(prepared.0).await {
      Ok(CommitOutcome::Committed(receipt)) => {
        self.validate_receipt(
          &PendingCommit {
            transaction: delete_id,
            digest: delete_digest,
            journal_proven: false,
          },
          &receipt,
          ProviderErrorContext::StorageCommit,
        )?;
      }
      Ok(CommitOutcome::Unknown {
        transaction,
        operation_digest,
      }) => {
        if transaction != delete_id || operation_digest != delete_digest {
          return Err(storage_corrupt(ProviderErrorContext::StorageCommit));
        }
        // Classify the unknown by the journal's presence, the same
        // evidence read the resolver classifies by: gone means the delete
        // landed; still present means it did not and the contradiction
        // stands, so a retry re-enters the same resolution.
        if self.recover_pending(&purpose).await?.is_some() {
          return Err(Error::conflict("frozen journal resolution"));
        }
      }
      // The conditional delete definitively did not land: the record's
      // expected digest no longer matches, so the frozen premise broke.
      Ok(CommitOutcome::Aborted | CommitOutcome::Conflict) => {
        return Err(Error::conflict("frozen journal resolution"));
      }
      Err(error) => return Err(error),
    }
    self.finish_journal_recovery(&pending)?;
    crate::audit::journal_declared_uncommitted(&purpose);
    tracing::info!(
      purpose = %purpose,
      transaction = %pending.transaction.as_str(),
      "frozen journal resolved as uncommitted"
    );
    Ok(())
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

  /// Clones the frozen slot's pending identity while the slot is a
  /// settled freeze (no provider call in flight); every other state is
  /// not a resolvable frozen journal.
  fn lock_frozen_slot(&self) -> Result<PendingCommit> {
    let state = self.lock_state()?;
    match &*state {
      CommitState::Frozen {
        pending,
        provider_call_active: false,
      } => Ok(pending.clone()),
      _ => Err(Error::conflict("frozen journal resolution")),
    }
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

/// The one `StorageCorrupt` constructor for the storage domain: every
/// "on-disk state violates an invariant" failure carries the kind plus
/// the caller's error context, so the corruption surface cannot fork per
/// backend (receipt bookkeeping, json generations, redb tables).
pub(crate) fn storage_corrupt(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::StorageCorrupt, context)
}

/// Derives a deterministic transaction-id value (single source for the
/// storage domain): the domain-separated SHA-256 over the ordered parts,
/// truncated to the first 16 bytes and read big-endian. Callers freeze
/// their own domain constants (the migration chain, the receipt
/// retention sweep), so a retried operation replays the same idempotent
/// identity while no other transaction can collide with it.
pub(crate) fn deterministic_transaction_value(domain: &[u8], parts: &[&[u8]]) -> Result<u128> {
  use sha2::{Digest as ShaDigest, Sha256};
  let mut hasher = Sha256::new();
  hasher.update(domain);
  for part in parts {
    hasher.update(part);
  }
  let hashed = hasher.finalize();
  let bytes: [u8; 16] = hashed[..16]
    .try_into()
    .map_err(|_| crate::Error::internal("deterministic transaction value"))?;
  Ok(u128::from_be_bytes(bytes))
}
