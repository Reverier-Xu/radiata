//! The redb production storage adapter implementing the backend-neutral
//! storage SPI.
//!
//! Logical layout: one `&[u8] -> &[u8]` entries table keyed by
//! `namespace-tag ++ 0x00 ++ key`, one receipts table keyed by transaction
//! text, and one meta table holding the strictly increasing generation
//! counter as the store revision. Every commit fsyncs
//! (`Durability::Immediate`), so a receipt survives process and OS
//! crashes. Read transactions are provider-owned immutable snapshots;
//! scans stream one ordered redb range without materializing the namespace.

use std::{fmt, path::PathBuf, sync::Arc};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, DurabilityLevel, Error, ProviderErrorContext,
  ProviderErrorKind, ReconcileOutcome, Result, StoreCapabilities, StoreEntry, StoreKey,
  StoreNamespace, StoreOperation, StoreRequirements, StoreRevision, StoreTransaction, StoreValue,
  TransactionId,
  provider::{Storage, StorageFactory, StoreScan, StoreSnapshot},
};

// The `relay-*` table names are historical frozen names: they predate the
// metadata-family namespace split but are persisted inside existing redb
// files, so they must never change.
const ENTRIES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-entries-v1");
const DIGESTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-digests-v1");
const RECEIPTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-receipts-v1");
const VALUE_DIGEST_BYTES: usize = 32;
// Visible to the adapter's test module so corruption tests inject
// malformed rows through the real tables instead of restating the
// frozen names.
pub(super) const META_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-meta-v1");
pub(super) const REVISION_META_KEY: &[u8] = b"revision";
const RECEIPT_VALUE_BYTES: usize = 40;

/// Test-only crash injection for the subprocess durability matrix.
///
/// The hook table is compiled only into test builds; production code carries
/// an empty inlined stub. A child test process selects one commit boundary
/// through the environment and aborts when execution reaches it.
#[cfg(test)]
static CRASH_POINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
pub(crate) fn select_crash_point(point: u8) {
  CRASH_POINT.store(point, std::sync::atomic::Ordering::SeqCst);
}

/// First crash point at which the redb commit is already durable, so a
/// crash from here on reopens to the committed state and every earlier
/// point (`1..6`: after begin, after conditions, after mutations, after
/// the revision bump, after the receipt insert) to the old one. The
/// crash matrices import this instead of restating the boundary, so
/// renumbering a hook desyncs nothing. Must track the `crash_hook`
/// numbering in this module.
#[cfg(test)]
pub(crate) const FIRST_COMMITTED_POINT: u8 = 6;
/// Highest live `crash_hook` boundary of this commit path; the crash
/// matrices scan points `1..=LAST_POINT`. Must track the `crash_hook`
/// numbering in this module.
#[cfg(test)]
pub(crate) const LAST_POINT: u8 = 6;

#[cfg(test)]
fn crash_hook(point: u8) {
  if CRASH_POINT.load(std::sync::atomic::Ordering::SeqCst) == point {
    std::process::abort();
  }
}

#[cfg(not(test))]
#[inline(always)]
fn crash_hook(_point: u8) {}

/// Test-only deterministic landing hold for cancellation tests: when
/// armed, the commit blocks its blocking thread just before the durable
/// commit (the receipt row is staged but not yet durable), so a test can
/// observe the not-yet-landed state, cancel the caller, and then release
/// the landing. The reached set names every held transaction, so a
/// waiting test observes its own commit holding the landing even while
/// other tests' commits run concurrently (each holds its own entry until
/// the release clears the set). Mirrors the crash-hook pattern: test
/// builds only.
#[cfg(test)]
static HOLD_BEFORE_COMMIT_ARMED: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
static HOLD_BEFORE_COMMIT_REACHED: std::sync::Mutex<std::collections::BTreeSet<TransactionId>> =
  std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(test)]
pub(crate) fn arm_landing_hold() {
  HOLD_BEFORE_COMMIT_ARMED.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn landing_hold_reached_by(transaction: &TransactionId) -> bool {
  HOLD_BEFORE_COMMIT_REACHED
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
    .contains(transaction)
}

#[cfg(test)]
pub(crate) fn release_landing_hold() {
  HOLD_BEFORE_COMMIT_ARMED.store(false, std::sync::atomic::Ordering::Release);
  HOLD_BEFORE_COMMIT_REACHED
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
    .clear();
}

/// Serializes every armed hold across the whole test binary: the
/// park/release signal is global, so two concurrently armed holds
/// would release each other's parked commits and turn each test's
/// "still parked" window into a race. The guard is held for the
/// [`LandingHold`] struct's life — the test's armed window — and
/// released by its drop.
#[cfg(test)]
static LANDING_HOLD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII releaser for the landing hold: arms on construction and
/// releases on drop, so a panicking test cannot leave the hold armed
/// and wedge every later commit in the binary. Drop it explicitly at
/// the moment the landing should proceed. Construction takes the
/// test-binary-wide hold lock, so concurrently armed holds serialize
/// behind it instead of releasing each other's parked commits.
#[cfg(test)]
pub(crate) struct LandingHold {
  _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl LandingHold {
  pub(crate) fn arm() -> Self {
    let lock = LANDING_HOLD_TEST_LOCK
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    arm_landing_hold();
    LandingHold { _lock: lock }
  }
}

#[cfg(test)]
impl Drop for LandingHold {
  fn drop(&mut self) {
    release_landing_hold();
  }
}

#[cfg(test)]
fn hold_before_commit(transaction: &TransactionId) {
  if HOLD_BEFORE_COMMIT_ARMED.load(std::sync::atomic::Ordering::Acquire) {
    HOLD_BEFORE_COMMIT_REACHED
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .insert(transaction.clone());
    while HOLD_BEFORE_COMMIT_ARMED.load(std::sync::atomic::Ordering::Acquire) {
      std::thread::sleep(std::time::Duration::from_millis(1));
    }
  }
}

#[cfg(not(test))]
#[inline(always)]
fn hold_before_commit(_transaction: &TransactionId) {}

/// Test-only one-shot commit-failure injection for the final durable
/// commit (see [`commit_durable`]): armed as one entry per transaction
/// id, so concurrent tests' arms never overwrite each other and only
/// the armed transaction's final `write.commit()` fails. The registry
/// is global, so armed ids must be unique across the whole test binary
/// (the contract suite shares the `test_util::transaction_id` id
/// space). Mirrors the crash-hook and landing-hold pattern: test
/// builds only.
#[cfg(test)]
static COMMIT_FAILURE_FAULT: std::sync::Mutex<Vec<(TransactionId, redb::CommitError)>> =
  std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn arm_commit_failure(transaction: TransactionId, error: redb::CommitError) {
  COMMIT_FAILURE_FAULT
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
    .push((transaction, error));
}

#[cfg(test)]
fn take_commit_failure(transaction: &TransactionId) -> Option<redb::CommitError> {
  let mut fault = COMMIT_FAILURE_FAULT
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  let armed = fault
    .iter()
    .position(|(armed, _)| armed == transaction)
    .map(|index| fault.swap_remove(index));
  armed.map(|(_, error)| error)
}

/// Test-only scan-failure injection for the backfill regression (audit
/// 2026-10-23 P2-9): armed as the number of entries the scan may yield
/// before failing, and consumed one-shot by the first scan that reaches
/// the threshold, so the armed fault never leaks into a later open.
/// `usize::MAX` disarms. Mirrors the crash-hook and landing-hold
/// pattern: test builds only.
#[cfg(test)]
static BACKFILL_SCAN_FAULT_AFTER: std::sync::atomic::AtomicUsize =
  std::sync::atomic::AtomicUsize::new(usize::MAX);

#[cfg(test)]
pub(crate) fn arm_backfill_scan_fault(after: usize) {
  BACKFILL_SCAN_FAULT_AFTER.store(after, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn backfill_scan_fault(scanned: usize) -> Result<()> {
  use std::sync::atomic::Ordering;
  if scanned < BACKFILL_SCAN_FAULT_AFTER.load(Ordering::SeqCst) {
    return Ok(());
  }
  BACKFILL_SCAN_FAULT_AFTER.store(usize::MAX, Ordering::SeqCst);
  Err(Error::provider(
    ProviderErrorKind::Io,
    ProviderErrorContext::StorageOpen,
  ))
}

#[cfg(not(test))]
#[inline(always)]
fn backfill_scan_fault(_scanned: usize) -> Result<()> {
  Ok(())
}

/// A factory for redb stores rooted at one database file.
pub(crate) struct RedbStoreFactory {
  path: PathBuf,
}

impl RedbStoreFactory {
  pub(crate) fn new(path: PathBuf) -> Self {
    Self { path }
  }

  fn capabilities() -> StoreCapabilities {
    StoreCapabilities::full_metadata(DurabilityLevel::OsCrashDurable)
  }
}

impl fmt::Debug for RedbStoreFactory {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RedbStoreFactory")
      .finish_non_exhaustive()
  }
}

impl StorageFactory for RedbStoreFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    Box::pin(async move {
      let capabilities = Self::capabilities();
      if !capabilities.satisfies(&requirements) {
        return Err(Error::provider(
          ProviderErrorKind::UnsupportedCapability,
          ProviderErrorContext::StorageOpen,
        ));
      }
      let path = self.path.clone();
      let database = tokio::task::spawn_blocking(move || {
        Database::create(&path)
          .map_err(|error| map_database_error(error, ProviderErrorContext::StorageOpen))
      })
      .await
      .map_err(|_| internal(ProviderErrorContext::StorageOpen))??;
      let database = Arc::new(database);
      let init_database = Arc::clone(&database);
      tokio::task::spawn_blocking(move || {
        initialize(&init_database)?;
        backfill_value_digests(&init_database)
      })
      .await
      .map_err(|_| internal(ProviderErrorContext::StorageOpen))??;
      Ok(Box::new(RedbStorage {
        database,
        detached: Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
        settled: Arc::new(tokio::sync::Notify::new()),
        readers: Arc::new(SnapshotReaders::default()),
      }) as Box<dyn Storage>)
    })
  }
}

struct RedbStorage {
  database: Arc<Database>,
  /// The commit executions detached from a cancelled caller, keyed by
  /// transaction id: redb's `spawn_blocking` commit keeps running and
  /// lands durably even after the awaiting future is dropped. A
  /// reconciler of the same transaction waits on the entry's landing
  /// signal before reading receipts, so a cancelled commit is judged by
  /// its final receipt and never by a not-yet-landed absence (audit
  /// 2026-10-09 item 14). An empty map is half of the completion
  /// barrier [`Storage::flush`] awaits — the snapshot readers are the
  /// other half — so no in-flight execution still holds the database
  /// or is about to commit (audit 2026-10-23 P1-10).
  detached:
    Arc<std::sync::Mutex<std::collections::BTreeMap<TransactionId, Arc<tokio::sync::Notify>>>>,
  /// Fires whenever any detached execution ends (commit, failure, or
  /// panic): the wakeup edge behind [`Storage::flush`]'s drain wait.
  settled: Arc<tokio::sync::Notify>,
  /// The in-flight snapshot executions (audit 2026-10-27 B3): a
  /// snapshot's `spawn_blocking` read clones the database and the
  /// returned handle keeps the read transaction open, so a live slot
  /// pins the `Database` — and its file lock — exactly like a detached
  /// commit does. [`Storage::flush`] awaits the gate draining, so the
  /// barrier covers every execution that holds the database, not only
  /// commits.
  readers: Arc<SnapshotReaders>,
}

/// Counts the snapshot executions that still hold the database: one
/// slot per [`Storage::snapshot`] call, from the moment its blocking
/// read is admitted until the returned snapshot handle drops. The
/// detached-commit registry cannot see these executions (they never
/// register a transaction), yet empirically they held the last
/// `Arc<Database>` past the shutdown reply — a restart then lost the
/// race for the file lock and observed `StorageLocked` (audit
/// 2026-10-27 B3) — so the flush barrier drains this gate as well.
#[derive(Default)]
struct SnapshotReaders {
  live: std::sync::Mutex<usize>,
  settled: tokio::sync::Notify,
}

impl SnapshotReaders {
  fn acquire(self: &Arc<Self>) -> SnapshotReadGuard {
    *self
      .live
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
    SnapshotReadGuard {
      readers: Arc::clone(self),
    }
  }

  fn is_idle(&self) -> bool {
    *self
      .live
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      == 0
  }
}

/// Holds one [`SnapshotReaders`] slot: acquired before the snapshot's
/// blocking task is spawned, moved into the returned snapshot handle on
/// success, and dropped on every other exit path (read failure, task
/// panic, or an abandoned result), so the gate counts exactly the
/// executions that still pin the database.
struct SnapshotReadGuard {
  readers: Arc<SnapshotReaders>,
}

impl Drop for SnapshotReadGuard {
  fn drop(&mut self) {
    *self
      .readers
      .live
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner()) -= 1;
    self.readers.settled.notify_waiters();
  }
}

/// Fires one detached commit's landing signal and removes its registry
/// entry on every exit path of the execution — completion, error, or
/// panic — so a reconciler never waits on a finished execution. The
/// signal fires strictly after the blocking commit returned, so a woken
/// reconciler reads final durable evidence. The guard is constructed
/// INSIDE the blocking closure that performs the durable work (audit
/// 2026-10-23 P1-10): its drop is the commit's own end, so no outer
/// async task's teardown can fire the signal or drop the registry entry
/// while the durable write is still in flight. The shared `settled`
/// notify wakes the flush barrier the same way.
struct DetachedLandingGuard {
  registry:
    Arc<std::sync::Mutex<std::collections::BTreeMap<TransactionId, Arc<tokio::sync::Notify>>>>,
  id: TransactionId,
  landed: Arc<tokio::sync::Notify>,
  settled: Arc<tokio::sync::Notify>,
}

impl Drop for DetachedLandingGuard {
  fn drop(&mut self) {
    self
      .registry
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .remove(&self.id);
    self.landed.notify_waiters();
    self.settled.notify_waiters();
  }
}

impl fmt::Debug for RedbStorage {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RedbStorage")
      .finish_non_exhaustive()
  }
}

impl Storage for RedbStorage {
  fn capabilities(&self) -> StoreCapabilities {
    RedbStoreFactory::capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    let database = Arc::clone(&self.database);
    let readers = Arc::clone(&self.readers);
    Box::pin(async move {
      // `begin_read` takes the database's internal file lock and can
      // block behind a durable commit, so the open (and the revision
      // read it seeds) runs on the blocking pool: write pressure can
      // never stall the async runtime thread. The reader slot is taken
      // before the task is admitted and rides the returned handle
      // (audit 2026-10-27 B3): the blocking task clones the database,
      // so an execution the awaiting future abandoned still pins the
      // `Database` — and its file lock — until the handle drops, and
      // the flush barrier must see it.
      let guard = readers.acquire();
      let snapshot = tokio::task::spawn_blocking(move || {
        let transaction = database
          .begin_read()
          .map_err(|error| map_transaction_error(error, ProviderErrorContext::StorageSnapshot))?;
        let revision = snapshot_revision(&transaction)?;
        Ok::<RedbSnapshot, Error>(RedbSnapshot {
          transaction,
          revision,
          _readers: guard,
        })
      })
      .await
      .map_err(|_| internal(ProviderErrorContext::StorageSnapshot))??;
      Ok(Box::new(snapshot) as Box<dyn StoreSnapshot>)
    })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    let registry = Arc::clone(&self.detached);
    let settled = Arc::clone(&self.settled);
    let database = Arc::clone(&self.database);
    // The execution is registered and spawned eagerly, before the
    // returned future is ever polled: the commit still lands durably
    // when the caller is cancelled (or never polls), and a reconcile of
    // the same transaction observes the in-flight landing from the
    // moment commit is called — no drop window can hide it (audit
    // 2026-10-09 item 14). The completion guard rides the blocking
    // commit itself (audit 2026-10-23 P1-10): it lives and drops inside
    // the `spawn_blocking` closure, so the registry entry and the
    // landing signal track the true durable operation rather than any
    // async task that happens to be awaiting it.
    let id = transaction.id().clone();
    let landed = Arc::new(tokio::sync::Notify::new());
    registry
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .insert(id.clone(), Arc::clone(&landed));
    let execution = tokio::task::spawn_blocking(move || {
      let _landing = DetachedLandingGuard {
        registry,
        id,
        landed,
        settled,
      };
      commit_blocking(&database, transaction)
    });
    Box::pin(async move {
      execution
        .await
        .map_err(|_| internal(ProviderErrorContext::StorageCommit))?
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    let registry = Arc::clone(&self.detached);
    let transaction = transaction.clone();
    let digest = digest.clone();
    Box::pin(async move {
      // A detached execution of THIS transaction may still land: wait
      // for it before reading durable evidence, so a commit whose caller
      // was cancelled is judged by its final receipt, never by a
      // not-yet-landed absence (audit 2026-10-09 item 14).
      loop {
        let landed = registry
          .lock()
          .unwrap_or_else(|poisoned| poisoned.into_inner())
          .get(&transaction)
          .cloned();
        let Some(landed) = landed else { break };
        let notified = landed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // Re-check under the registration the enable observed: a landing
        // that fired between the lookup and the enable removed the
        // entry, and its receipt is already durable to read.
        if !registry
          .lock()
          .unwrap_or_else(|poisoned| poisoned.into_inner())
          .contains_key(&transaction)
        {
          break;
        }
        notified.await;
      }
      let read = self
        .database
        .begin_read()
        .map_err(|error| map_transaction_error(error, ProviderErrorContext::StorageReconcile))?;
      let receipts = read
        .open_table(RECEIPTS_TABLE)
        .map_err(|error| map_table_error(error, ProviderErrorContext::StorageReconcile))?;
      let receipt = read_receipt(&receipts, &transaction)?;
      Ok(crate::provider::classify_receipt(receipt, &digest))
    })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    // The completion barrier, deliberately distinct from the durability
    // guarantee: every commit already fsyncs (`Durability::Immediate`),
    // so a landed transaction needs no second flush — what a shutdown
    // caller must additionally know is that no in-flight execution
    // still holds the database or is about to commit. This awaits the
    // detached registry draining to empty, so every registered
    // execution has ended (committed, failed, or rolled back) before
    // the caller resumes (audit 2026-10-23 P1-10), and then the
    // snapshot readers draining to idle (audit 2026-10-27 B3): a
    // snapshot execution — its blocking read still running or its
    // handle still held — pins the database exactly like a commit
    // does, and leaving it outside the barrier let the file lock
    // outlive the shutdown reply. Sequencing is sound because the
    // barrier runs only after every runtime plane is torn down, so no
    // new execution of either kind can be admitted behind it.
    let registry = Arc::clone(&self.detached);
    let settled = Arc::clone(&self.settled);
    let readers = Arc::clone(&self.readers);
    Box::pin(async move {
      loop {
        if registry
          .lock()
          .unwrap_or_else(|poisoned| poisoned.into_inner())
          .is_empty()
        {
          break;
        }
        let notified = settled.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // Re-check under the registration the enable observed: an
        // execution that landed between the empty check and the enable
        // already removed its entry, and the drain is already complete.
        if registry
          .lock()
          .unwrap_or_else(|poisoned| poisoned.into_inner())
          .is_empty()
        {
          break;
        }
        notified.await;
      }
      loop {
        if readers.is_idle() {
          return Ok(());
        }
        // A caller that leaks a snapshot handle holds the barrier open;
        // surface the wait instead of hanging the shutdown silently.
        tracing::debug!("storage flush waiting for snapshot readers to drain");
        let notified = readers.settled.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // Re-check under the slot accounting the enable observed: a
        // handle dropped between the idle check and the enable already
        // released its slot, and the gate is already idle.
        if readers.is_idle() {
          return Ok(());
        }
        notified.await;
      }
    })
  }
}

struct RedbSnapshot {
  transaction: redb::ReadTransaction,
  revision: StoreRevision,
  /// The reader slot this snapshot holds (see [`SnapshotReadGuard`]):
  /// dropping the handle — not the blocking read's return — is what
  /// releases the database, so the barrier waits for handles too.
  /// Drop-only, like the landing hold's `_lock`.
  _readers: SnapshotReadGuard,
}

impl fmt::Debug for RedbSnapshot {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RedbSnapshot")
      .field("revision", &self.revision)
      .finish_non_exhaustive()
  }
}

impl StoreSnapshot for RedbSnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    Box::pin(async move {
      let entries = self
        .transaction
        .open_table(ENTRIES_TABLE)
        .map_err(|error| map_table_error(error, ProviderErrorContext::StorageSnapshot))?;
      let composite = composite_key(namespace, key);
      let stored = entries
        .get(&*composite)
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageSnapshot))?;
      let Some(guard) = stored else {
        return Ok(None);
      };
      // Reads trust the persisted digest: the commit path wrote both
      // sides in one atomic transaction, so a missing row is corruption.
      let persisted = self
        .transaction
        .open_table(DIGESTS_TABLE)
        .map_err(|error| map_table_error(error, ProviderErrorContext::StorageSnapshot))?
        .get(&*composite)
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageSnapshot))?
        .ok_or_else(|| super::super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
      let digest_bytes: [u8; VALUE_DIGEST_BYTES] = persisted
        .value()
        .try_into()
        .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
      Ok(Some(StoreValue::from_parts(
        Arc::from(guard.value()),
        Digest::from_bytes(digest_bytes),
      )))
    })
  }

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    self.scan_from(namespace, prefix, None)
  }

  fn scan_from<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8], from: Option<&'a [u8]>,
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    Box::pin(async move {
      let entries = self
        .transaction
        .open_table(ENTRIES_TABLE)
        .map_err(|error| map_table_error(error, ProviderErrorContext::StorageScan))?;
      let digests = self
        .transaction
        .open_table(DIGESTS_TABLE)
        .map_err(|error| map_table_error(error, ProviderErrorContext::StorageScan))?;
      // The composite key is `namespace-tag ++ 0x00 ++ user key` in the
      // exact scan order: one lower bound starts the range at the prefix
      // (or, positioned, strictly past `from`), and `next` ends the scan
      // at the first key outside the composite prefix, keeping
      // out-of-bounds starts empty.
      let prefix_bound = composite_prefix(namespace, prefix);
      let positioned_start = from.map(|from| composite_prefix(namespace, from));
      let lower = match positioned_start.as_deref() {
        None => std::ops::Bound::Included(prefix_bound.as_slice()),
        // A `from` exactly on the prefix start excludes that exact key.
        Some(start) if start == prefix_bound.as_slice() => {
          std::ops::Bound::Excluded(prefix_bound.as_slice())
        }
        // Positioning only ever moves the bound forward: a `from` beyond
        // the prefix start positions strictly past it, a `from` before
        // it keeps the inclusive prefix start (the range must not begin
        // inside keys the prefix filter would end the scan on).
        Some(start) if start > prefix_bound.as_slice() => std::ops::Bound::Excluded(start),
        Some(_) => std::ops::Bound::Included(prefix_bound.as_slice()),
      };
      let range = entries
        .range::<&[u8]>((lower, std::ops::Bound::Unbounded))
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageScan))?;
      let digest_range = digests
        .range::<&[u8]>((lower, std::ops::Bound::Unbounded))
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageScan))?;
      Ok(Box::new(RedbScan {
        range,
        digest_range,
        namespace: namespace.clone(),
        prefix: prefix_bound,
        base_len: namespace.as_str().len() + 1,
      }) as Box<dyn StoreScan + 'a>)
    })
  }
}

struct RedbScan {
  range: redb::Range<'static, &'static [u8], &'static [u8]>,
  // The digest sidecar iterates in lockstep: both tables carry the same
  // composite keys, written and removed in the same transactions.
  digest_range: redb::Range<'static, &'static [u8], &'static [u8]>,
  namespace: StoreNamespace,
  prefix: Vec<u8>,
  base_len: usize,
}

impl fmt::Debug for RedbScan {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_struct("RedbScan").finish_non_exhaustive()
  }
}

impl StoreScan for RedbScan {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    Box::pin(async move {
      // The range starts at the composite prefix bound, so the first
      // non-matching key ends the ordered scan without materializing the
      // namespace.
      match (self.range.next(), self.digest_range.next()) {
        (Some(Ok((key, value))), Some(Ok((digest_key, digest)))) => {
          let bytes = key.value();
          if bytes != digest_key.value() {
            return Err(super::super::storage_corrupt(
              ProviderErrorContext::StorageScan,
            ));
          }
          if !bytes.starts_with(&self.prefix) {
            return Ok(None);
          }
          let user_key = &bytes[self.base_len..];
          let digest_bytes: [u8; VALUE_DIGEST_BYTES] = digest
            .value()
            .try_into()
            .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageScan))?;
          let entry = StoreEntry::new(
            self.namespace.clone(),
            StoreKey::new(Arc::from(user_key)),
            StoreValue::from_parts(Arc::from(value.value()), Digest::from_bytes(digest_bytes)),
          );
          Ok(Some(entry))
        }
        (Some(Err(error)), _) | (_, Some(Err(error))) => {
          Err(map_storage_error(error, ProviderErrorContext::StorageScan))
        }
        (None, None) => Ok(None),
        _ => Err(super::super::storage_corrupt(
          ProviderErrorContext::StorageScan,
        )),
      }
    })
  }
}

fn internal(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::Internal, context)
}

/// A persisted digest sidecar row is missing or malformed: the commit
/// path maintains both sides atomically, so this is storage corruption.
fn composite_key(namespace: &StoreNamespace, key: &StoreKey) -> Vec<u8> {
  composite_prefix(namespace, key.as_bytes())
}

fn composite_prefix(namespace: &StoreNamespace, prefix: &[u8]) -> Vec<u8> {
  let mut bytes = Vec::with_capacity(namespace.as_str().len() + 1 + prefix.len());
  bytes.extend_from_slice(namespace.as_str().as_bytes());
  bytes.push(0);
  bytes.extend_from_slice(prefix);
  bytes
}

fn owned_value(bytes: &[u8]) -> StoreValue {
  StoreValue::new(Arc::from(bytes))
}

fn current_generation(
  meta: &impl ReadableTable<&'static [u8], &'static [u8]>, context: ProviderErrorContext,
) -> Result<u64> {
  let stored = meta
    .get(REVISION_META_KEY)
    .map_err(|error| map_storage_error(error, context))?;
  Ok(match stored {
    Some(guard) => decode_revision(guard.value(), context)?,
    None => 0,
  })
}

/// Decodes the persisted 8-byte big-endian generation counter. The
/// bytes come from the on-disk revision row (or a receipt tail), never
/// from the caller, so any other shape is storage corruption that
/// fails closed rather than invalid input.
fn decode_revision(bytes: &[u8], context: ProviderErrorContext) -> Result<u64> {
  let raw: [u8; 8] = bytes
    .try_into()
    .map_err(|_| super::super::storage_corrupt(context))?;
  Ok(u64::from_be_bytes(raw))
}

fn encode_receipt(digest: &Digest, generation: u64) -> Vec<u8> {
  let mut bytes = Vec::with_capacity(RECEIPT_VALUE_BYTES);
  bytes.extend_from_slice(digest.as_bytes());
  bytes.extend_from_slice(&generation.to_be_bytes());
  bytes
}

fn read_receipt(
  receipts: &impl ReadableTable<&'static [u8], &'static [u8]>, transaction: &TransactionId,
) -> Result<Option<CommitReceipt>> {
  let stored = receipts
    .get(transaction.as_str().as_bytes())
    .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageReconcile))?;
  Ok(match stored {
    Some(guard) => {
      let bytes = guard.value();
      if bytes.len() != RECEIPT_VALUE_BYTES {
        return Err(Error::provider(
          ProviderErrorKind::StorageCorrupt,
          ProviderErrorContext::StorageReconcile,
        ));
      }
      let (digest_bytes, revision_bytes) = bytes.split_at(32);
      let digest_digest: [u8; 32] = digest_bytes
        .try_into()
        .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageReconcile))?;
      let generation = decode_revision(revision_bytes, ProviderErrorContext::StorageReconcile)?;
      Some(CommitReceipt::new(
        transaction.clone(),
        Digest::from_bytes(digest_digest),
        StoreRevision::new(Arc::from(generation.to_be_bytes()))?,
      ))
    }
    None => None,
  })
}

fn snapshot_revision(transaction: &redb::ReadTransaction) -> Result<StoreRevision> {
  let meta = transaction
    .open_table(META_TABLE)
    .map_err(|error| map_table_error(error, ProviderErrorContext::StorageSnapshot))?;
  let generation = current_generation(&meta, ProviderErrorContext::StorageSnapshot)?;
  StoreRevision::new(Arc::from(generation.to_be_bytes()))
}

fn initialize(database: &Database) -> Result<()> {
  let mut write = database
    .begin_write()
    .map_err(|error| map_transaction_error(error, ProviderErrorContext::StorageOpen))?;
  write
    .set_durability(Durability::Immediate)
    .map_err(|error| map_durability_error(error, ProviderErrorContext::StorageOpen))?;
  {
    let mut meta = write
      .open_table(META_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageOpen))?;
    if meta
      .get(REVISION_META_KEY)
      .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageOpen))?
      .is_none()
    {
      meta
        .insert(REVISION_META_KEY, 0_u64.to_be_bytes().as_slice())
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageOpen))?;
    }
    write
      .open_table(ENTRIES_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageOpen))?;
    write
      .open_table(DIGESTS_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageOpen))?;
    write
      .open_table(RECEIPTS_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageOpen))?;
  }
  write
    .commit()
    .map_err(|error| map_commit_error(error, ProviderErrorContext::StorageOpen))?;
  Ok(())
}

/// Backfills persisted value digests for entries written before the
/// digest table existed. One write transaction over the whole table: a
/// legacy file upgrades transparently on its first open, and a crash
/// leaves the file at the complete old or new state. Fresh files find
/// nothing to backfill.
fn backfill_value_digests(database: &Database) -> Result<()> {
  let mut write = database
    .begin_write()
    .map_err(|error| map_transaction_error(error, ProviderErrorContext::StorageOpen))?;
  write
    .set_durability(Durability::Immediate)
    .map_err(|error| map_durability_error(error, ProviderErrorContext::StorageOpen))?;
  {
    let entries = write
      .open_table(ENTRIES_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageOpen))?;
    let mut digests = write
      .open_table(DIGESTS_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageOpen))?;
    let mut pending: Vec<(Vec<u8>, Digest)> = Vec::new();
    let mut cursor = entries
      .iter()
      .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageOpen))?;
    let mut scanned = 0_usize;
    // A failing iterator is the open's failure, never a silent early
    // EOF: the loop surfaces every error before the write transaction
    // commits, so a partial backfill can never pose as a completed
    // upgrade (audit 2026-10-23 P2-9).
    loop {
      backfill_scan_fault(scanned)?;
      let entry = cursor
        .next()
        .transpose()
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageOpen))?;
      let Some((key, value)) = entry else {
        break;
      };
      scanned += 1;
      if digests
        .get(key.value())
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageOpen))?
        .is_none()
      {
        pending.push((
          key.value().to_vec(),
          owned_value(value.value()).digest().clone(),
        ));
      }
    }
    for (key, digest) in pending {
      digests
        .insert(key.as_slice(), digest.as_bytes().as_slice())
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
    }
  }
  write
    .commit()
    .map_err(|error| map_commit_error(error, ProviderErrorContext::StorageOpen))?;
  Ok(())
}

/// Drives the final durable commit of [`commit_blocking`]: production
/// calls [`redb::WriteTransaction::commit`]; a test build first
/// consults the one-shot fault armed for exactly this transaction (see
/// [`COMMIT_FAILURE_FAULT`]) and surfaces that failure instead. The
/// fault path never runs the real commit, so the staged transaction
/// rolls back deterministically and the injected failure exercises the
/// outcome classification below.
#[cfg_attr(not(test), allow(unused_variables))]
fn commit_durable(
  write: redb::WriteTransaction, transaction: &TransactionId,
) -> std::result::Result<(), redb::CommitError> {
  #[cfg(test)]
  if let Some(error) = take_commit_failure(transaction) {
    return Err(error);
  }
  write.commit()
}

fn commit_blocking(database: &Database, transaction: StoreTransaction) -> Result<CommitOutcome> {
  let mut write = database
    .begin_write()
    .map_err(|error| map_transaction_error(error, ProviderErrorContext::StorageCommit))?;
  crash_hook(1);
  write
    .set_durability(Durability::Immediate)
    .map_err(|error| map_durability_error(error, ProviderErrorContext::StorageCommit))?;

  let receipt = {
    let mut entries = write
      .open_table(ENTRIES_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageCommit))?;
    let mut digests = write
      .open_table(DIGESTS_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageCommit))?;
    let mut receipts = write
      .open_table(RECEIPTS_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageCommit))?;
    let mut meta = write
      .open_table(META_TABLE)
      .map_err(|error| map_table_error(error, ProviderErrorContext::StorageCommit))?;

    // Idempotent replay: an existing receipt for the same transaction is
    // authoritative; a different digest for that identity fails closed.
    // The base check is the only reader of the current generation and it
    // must run strictly between the receipt replay and the condition
    // loop, so the apply phase reuses the value the check closure stored.
    let mut generation_slot = None;
    if let Some(outcome) = crate::provider::commit_precheck(
      &transaction,
      |id: &TransactionId| read_receipt(&receipts, id),
      || {
        let generation = current_generation(&meta, ProviderErrorContext::StorageCommit)?;
        generation_slot = Some(generation);
        StoreRevision::new(Arc::from(generation.to_be_bytes()))
      },
      |namespace: &StoreNamespace, key: &StoreKey| {
        let composite = composite_key(namespace, key);
        let stored = entries
          .get(&*composite)
          .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
        if stored.is_none() {
          return Ok(None);
        }
        // The commit path keeps every entry's digest row current in the
        // same transaction, so a missing row is storage corruption.
        let persisted = digests
          .get(&*composite)
          .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?
          .ok_or_else(|| super::super::storage_corrupt(ProviderErrorContext::StorageCommit))?;
        let bytes: [u8; VALUE_DIGEST_BYTES] = persisted
          .value()
          .try_into()
          .map_err(|_| super::super::storage_corrupt(ProviderErrorContext::StorageCommit))?;
        Ok(Some(Digest::from_bytes(bytes)))
      },
    )? {
      return Ok(outcome);
    }
    let generation = generation_slot.ok_or_else(|| Error::internal("redb generation"))?;
    let next_generation = generation.checked_add(1).ok_or_else(|| {
      Error::provider(
        ProviderErrorKind::ResourceExhausted,
        ProviderErrorContext::StorageCommit,
      )
    })?;
    crash_hook(2);
    for operation in transaction.operations() {
      match operation {
        StoreOperation::Check { .. } => {}
        StoreOperation::Put {
          namespace,
          key,
          value,
          ..
        } => {
          let composite = composite_key(namespace, key);
          entries
            .insert(&*composite, value.as_bytes())
            .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
          digests
            .insert(&*composite, value.digest().as_bytes().as_slice())
            .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
        }
        StoreOperation::Delete { namespace, key, .. } => {
          let composite = composite_key(namespace, key);
          entries
            .remove(&*composite)
            .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
          digests
            .remove(&*composite)
            .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
        }
        StoreOperation::ForgetReceipt {
          transaction: forgotten,
          ..
        } => {
          receipts
            .remove(forgotten.as_str().as_bytes())
            .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
        }
      }
    }
    crash_hook(3);
    meta
      .insert(REVISION_META_KEY, next_generation.to_be_bytes().as_slice())
      .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
    crash_hook(4);
    let receipt = CommitReceipt::new(
      transaction.id().clone(),
      transaction.operation_digest().clone(),
      StoreRevision::new(Arc::from(next_generation.to_be_bytes()))?,
    );
    receipts
      .insert(
        transaction.id().as_str().as_bytes(),
        encode_receipt(transaction.operation_digest(), next_generation).as_slice(),
      )
      .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageCommit))?;
    crash_hook(5);
    receipt
  };
  hold_before_commit(transaction.id());
  // The final durable commit is the one outcome-unknown boundary: a
  // failure here is classified rather than blanket-mapped, because a
  // failed write-out can leave the durable state indeterminate instead
  // of provably rolled back (audit finding #12).
  if let Err(error) = commit_durable(write, transaction.id()) {
    return classify_commit_failure(error, &transaction);
  }
  crash_hook(6);
  Ok(CommitOutcome::Committed(receipt))
}

fn map_database_error(error: redb::DatabaseError, context: ProviderErrorContext) -> Error {
  match error {
    redb::DatabaseError::DatabaseAlreadyOpen => {
      Error::provider(ProviderErrorKind::StorageLocked, context)
    }
    redb::DatabaseError::UpgradeRequired(_) => {
      Error::provider(ProviderErrorKind::UnsupportedSchema, context)
    }
    redb::DatabaseError::Storage(storage) => map_storage_error(storage, context),
    redb::DatabaseError::RepairAborted | redb::DatabaseError::TransactionInProgress => {
      Error::provider(ProviderErrorKind::Io, context)
    }
    _ => Error::provider(ProviderErrorKind::Io, context),
  }
}

fn map_storage_error(error: redb::StorageError, context: ProviderErrorContext) -> Error {
  let kind = match &error {
    redb::StorageError::Corrupted(_) => ProviderErrorKind::StorageCorrupt,
    redb::StorageError::ValueTooLarge(_) => ProviderErrorKind::ResourceExhausted,
    redb::StorageError::Io(io_error) => match io_error.kind() {
      std::io::ErrorKind::PermissionDenied => ProviderErrorKind::PermissionDenied,
      _ => ProviderErrorKind::Io,
    },
    redb::StorageError::PreviousIo => ProviderErrorKind::Io,
    _ => ProviderErrorKind::Internal,
  };
  Error::provider(kind, context)
}

fn map_commit_error(error: redb::CommitError, context: ProviderErrorContext) -> Error {
  match error {
    redb::CommitError::Storage(storage) => map_storage_error(storage, context),
    _ => Error::provider(ProviderErrorKind::Io, context),
  }
}

/// Classifies a failed final durable commit ([`commit_durable`]). An
/// I/O failure during the write-out — or the sticky [`PreviousIo`]
/// aftermath of a prior one — can neither prove the transaction landed
/// nor prove it rolled back, so the in-doubt identity surfaces as
/// [`CommitOutcome::Unknown`] and the metadata store freezes on
/// reconcile evidence instead of unfreezing and retrying as if nothing
/// landed. Every other commit failure is provably not committed
/// (`TransactionPoisoned`, a closed database, ...) and stays a
/// definite-abort error through [`map_commit_error`]. Deliberately
/// narrow per the audit: only these two indeterminate variants freeze
/// the store, and pre-mutation begin/table failures upstream of the
/// commit are definite aborts by construction.
///
/// [`PreviousIo`]: redb::StorageError::PreviousIo
fn classify_commit_failure(
  error: redb::CommitError, transaction: &StoreTransaction,
) -> Result<CommitOutcome> {
  if matches!(
    &error,
    redb::CommitError::Storage(redb::StorageError::Io(_))
      | redb::CommitError::Storage(redb::StorageError::PreviousIo)
  ) {
    tracing::warn!(
      transaction = %transaction.id(),
      "redb durable commit failed with an indeterminate outcome; deferring to reconcile evidence"
    );
    return Ok(CommitOutcome::Unknown {
      transaction: transaction.id().clone(),
      operation_digest: transaction.operation_digest().clone(),
    });
  }
  Err(map_commit_error(error, ProviderErrorContext::StorageCommit))
}

fn map_durability_error(error: redb::SetDurabilityError, context: ProviderErrorContext) -> Error {
  match error {
    redb::SetDurabilityError::PersistentSavepointModified => {
      Error::provider(ProviderErrorKind::StorageCorrupt, context)
    }
    _ => Error::provider(ProviderErrorKind::Io, context),
  }
}

fn map_transaction_error(error: redb::TransactionError, context: ProviderErrorContext) -> Error {
  match error {
    redb::TransactionError::Storage(storage) => map_storage_error(storage, context),
    _ => Error::provider(ProviderErrorKind::Internal, context),
  }
}

fn map_table_error(error: redb::TableError, context: ProviderErrorContext) -> Error {
  match error {
    redb::TableError::TableDoesNotExist(_)
    | redb::TableError::TableTypeMismatch { .. }
    | redb::TableError::TypeDefinitionChanged { .. } => super::super::storage_corrupt(context),
    redb::TableError::Storage(storage) => map_storage_error(storage, context),
    redb::TableError::TableIsMultimap(_)
    | redb::TableError::TableIsNotMultimap(_)
    | redb::TableError::TableExists(_) => Error::provider(ProviderErrorKind::Io, context),
    _ => Error::provider(ProviderErrorKind::Io, context),
  }
}

/// The adapter-local regression lanes for the 2026-10-23 follow-ups:
/// the backfill scan's error contract (P2-9) and the flush completion
/// barrier (P1-10). Every test drives the real factory open and the
/// real commit path; the only injections are the module's established
/// test-only fault hooks.
#[cfg(test)]
mod followup_tests {
  use std::sync::Arc;

  use redb::{ReadableDatabase, ReadableTableMetadata};
  use tempfile::TempDir;

  use super::{
    DIGESTS_TABLE, ENTRIES_TABLE, LandingHold, RedbStoreFactory, arm_backfill_scan_fault,
    composite_prefix, landing_hold_reached_by,
  };
  use crate::{
    CommitOutcome, ErrorKind, ReconcileOutcome, StoreExpectation, StoreOperation,
    StoreRequirements, StoreTransaction, StoreValue,
    provider::{Storage, StorageFactory},
    storage::test_util,
  };

  /// A failing backfill scan is the open's failure — never a silent
  /// early EOF that commits a partial digest upgrade and reports the
  /// open successful (audit 2026-10-23 P2-9): the injected iterator
  /// error fails the open typed, the digest table stays empty (no
  /// partial upgrade was committed), and a later open completes the
  /// whole backfill instead of resuming a mislabeled "finished" one.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn backfill_scan_failure_fails_the_open_and_commits_nothing() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("store.redb");
    // A legacy file: two entries whose digest sidecar rows are absent
    // (written through the real entries table the way pre-digest files
    // were), keyed with the composite prefix the scan iterates.
    let namespace = test_util::namespace("redb-backfill-fault");
    let legacy: [(&[u8], &[u8]); 2] = [(b"legacy-a", b"value-a"), (b"legacy-b", b"value-b")];
    {
      let database = redb::Database::create(&path).unwrap();
      let write = database.begin_write().unwrap();
      {
        let mut entries = write.open_table(ENTRIES_TABLE).unwrap();
        for (key, value) in legacy {
          let composite = composite_prefix(&namespace, key);
          entries.insert(composite.as_slice(), value).unwrap();
        }
      }
      write.commit().unwrap();
    }

    // The scan fails after the first legacy entry: the open must fail
    // with the mapped iterator error instead of succeeding over a
    // partial scan.
    arm_backfill_scan_fault(1);
    let factory = RedbStoreFactory::new(path.clone());
    let error = factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(error.context(), "storage open");

    // No partial upgrade was committed: the digest table is exactly as
    // empty as the legacy file left it.
    {
      let database = redb::Database::create(&path).unwrap();
      let read = database.begin_read().unwrap();
      let digests = read.open_table(DIGESTS_TABLE).unwrap();
      assert_eq!(
        digests.len().unwrap(),
        0,
        "a failed backfill must not commit partial digests"
      );
    }

    // The retry completes the whole upgrade: both entries read back
    // with their persisted digest sidecars through the public snapshot.
    let factory = RedbStoreFactory::new(path);
    let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
    let snapshot = storage.snapshot().await.unwrap();
    for (key, value) in legacy {
      let stored = snapshot
        .get(&namespace, &test_util::key(key))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the entry {:?} must survive the backfill", key));
      assert_eq!(stored.as_bytes(), value);
    }
  }
  /// Prepares one absent-put transaction over the store's current
  /// revision: the barrier tests need a real committed-eligible shape.
  async fn put(
    storage: &Arc<dyn Storage>, index: u64, key: &[u8], value: &[u8],
  ) -> StoreTransaction {
    let namespace = test_util::namespace("redb-flush-barrier");
    let base = storage.snapshot().await.unwrap().revision().clone();
    StoreTransaction::new(
      test_util::transaction_id(index),
      base,
      vec![StoreOperation::Put {
        namespace,
        key: test_util::key(key),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(value)),
      }],
    )
    .unwrap()
  }

  /// `flush` is the execution completion barrier (audit 2026-10-23
  /// P1-10): while a commit is parked just before its durable landing,
  /// flush must not resolve — the immediate `Ok(())` it used to return
  /// is exactly the shutdown race the finding names — and once the
  /// execution ends, flush resolves and the parked commit has landed.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn flush_waits_for_an_in_flight_execution_to_end() {
    let directory = TempDir::new().unwrap();
    let factory = RedbStoreFactory::new(directory.path().join("store.redb"));
    let storage: Arc<dyn Storage> = factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap()
      .into();
    let transaction = put(&storage, 61, b"barrier", b"lands").await;
    let id = transaction.id().clone();

    // Park the commit just before its durable landing.
    let hold = LandingHold::arm();
    let commit = tokio::spawn({
      let storage = Arc::clone(&storage);
      async move { storage.commit(transaction).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      while !landing_hold_reached_by(&id) {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("the landing hold is reached within the box");

    // The barrier holds while the execution is mid-commit.
    let flush = tokio::spawn({
      let storage = Arc::clone(&storage);
      async move { storage.flush().await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
      !flush.is_finished(),
      "flush must not resolve while an execution is still mid-commit"
    );

    // The execution ends and the barrier resolves behind it.
    drop(hold);
    flush.await.unwrap().unwrap();
    assert!(matches!(
      commit.await.unwrap().unwrap(),
      CommitOutcome::Committed(_)
    ));
  }

  /// The barrier covers the detached case the shutdown path actually
  /// meets: the commit's caller is cancelled mid-flight, the execution
  /// keeps running, and flush still waits for the true landing before
  /// resolving — then the durable evidence is there to read.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn flush_waits_for_a_cancelled_callers_detached_execution() {
    let directory = TempDir::new().unwrap();
    let factory = RedbStoreFactory::new(directory.path().join("store.redb"));
    let storage: Arc<dyn Storage> = factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap()
      .into();
    let transaction = put(&storage, 62, b"detached-barrier", b"lands").await;
    let id = transaction.id().clone();
    let digest = transaction.operation_digest().clone();

    let hold = LandingHold::arm();
    let commit = tokio::spawn({
      let storage = Arc::clone(&storage);
      async move { storage.commit(transaction).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
      while !landing_hold_reached_by(&id) {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("the landing hold is reached within the box");
    // The caller is cancelled; the blocking execution keeps running.
    commit.abort();
    assert!(commit.await.unwrap_err().is_cancelled());

    let flush = tokio::spawn({
      let storage = Arc::clone(&storage);
      async move { storage.flush().await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
      !flush.is_finished(),
      "flush must not resolve behind a cancelled caller's still-running execution"
    );

    drop(hold);
    flush.await.unwrap().unwrap();
    assert!(matches!(
      storage.reconcile(&id, &digest).await.unwrap(),
      ReconcileOutcome::Committed(_)
    ));
  }

  /// The barrier also covers the read side (audit 2026-10-27 B3): a
  /// snapshot handle still held — or a snapshot blocking task still
  /// running — clones and pins the `Database` past the shutdown reply,
  /// and a restart on the same factory then raced the file-lock release
  /// and observed `StorageLocked`. While a snapshot handle is alive,
  /// flush must not resolve; when the handle drops, flush resolves.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn flush_waits_for_an_outstanding_snapshot_execution() {
    let directory = TempDir::new().unwrap();
    let factory = RedbStoreFactory::new(directory.path().join("store.redb"));
    let storage: Arc<dyn Storage> = factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap()
      .into();

    // The snapshot's blocking read has already returned, but the
    // handle keeps the reader slot — exactly the shape the shutdown
    // path leaves behind when a plane's snapshot outlives the barrier.
    let snapshot = storage.snapshot().await.unwrap();
    let flush = tokio::spawn({
      let storage = Arc::clone(&storage);
      async move { storage.flush().await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
      !flush.is_finished(),
      "flush must not resolve while a snapshot handle still pins the database"
    );

    // Dropping the handle releases the slot; the barrier resolves
    // behind it, and — the shutdown contract this guards — the factory
    // can reopen the same file immediately afterwards.
    drop(snapshot);
    flush.await.unwrap().unwrap();
    drop(storage);
    factory.open(StoreRequirements::metadata()).await.unwrap();
  }
}
