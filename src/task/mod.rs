//! The task entity: the admitted-operation model behind the declarative
//! verb surface. A task is the *observation* of one admitted mutating
//! intent — a printable ordered id, a closed kind set (plus
//! caller-registered extension kinds), a phase machine with typed error
//! and output payloads, and the cloneable caller handle [`Task`] over
//! the shared in-memory task table.
//!
//! The table is deliberately in-memory: durable desired state remains
//! exactly each effect's existing durable footprint (leave intent,
//! resource candidates, revocation/cleanup records). A crash loses only
//! the observation of intent, never more state than the synchronous
//! verb would have lost.

use std::{
  collections::{BTreeMap, hash_map::DefaultHasher},
  hash::{Hash, Hasher},
  marker::PhantomData,
  panic::AssertUnwindSafe,
  sync::{Arc, Mutex},
  time::SystemTime,
};

use futures_util::FutureExt;
use tokio::sync::{mpsc, watch};

use crate::{
  BoxFuture, Error, ErrorKind, IssuedMergeCredential, NodeId, QualifiedTag, Result, TaskId,
  view::{
    LeaveOutcome, ListenerView, MemberView, MergeView, ReceiptRetentionReport, RecoveryView,
    ResourceMutationView, RevokeOutcome,
  },
};

/// The closed set of core task kinds plus caller-registered extension
/// kinds (a qualified tag under the caller's own domain).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskKind {
  Join,
  Leave,
  Connect,
  Disconnect,
  Revoke,
  PurgeRevocation,
  Cleanup,
  IssueCleanupCheckpoint,
  ResolveFrozenJournal,
  Listen,
  StopListener,
  PutResource,
  DeleteResource,
  PatchNodeMetadata,
  IssueCredential,
  RotateCredential,
  StartRecovery,
  ApplyReceiptRetention,
  SyncRound,
  /// A caller-registered kind: the tag is the registration key of the
  /// caller's registered task reconciler and must live under a
  /// caller-owned domain, never the builtin one.
  Extension(QualifiedTag),
}

impl TaskKind {
  /// Whether the kind's effect is awaited to its terminal phase during
  /// node shutdown instead of being cancelled on the manager's cancel
  /// watch: the journaled/store-atomic kinds whose outcome must settle
  /// before teardown completes. Every other kind's effect may exit
  /// mid-flight, leaving the task non-terminal for the process.
  pub(crate) const fn drains_on_shutdown(&self) -> bool {
    matches!(self, Self::Leave | Self::ResolveFrozenJournal)
  }

  /// The execution-slot channel the kind's effect draws from: the
  /// network dials (join/connect), which can hold a slot for a whole
  /// dial deadline, draw from their own channel so local work
  /// (resource writes, credentials, maintenance) never queues behind a
  /// wedged dial, and the caller-registered extension kinds draw from
  /// their own channel so a workflow awaiting core verbs through its
  /// handle never occupies the local capacity its own child operations
  /// need. The two core budgets live in
  /// [`NodeConfig::with_task_reconcile_slots`](crate::NodeConfig::with_task_reconcile_slots);
  /// the extension channel's budget is the task manager's own constant.
  pub(crate) const fn slot_class(&self) -> SlotClass {
    match self {
      Self::Join | Self::Connect => SlotClass::Network,
      Self::Extension(_) => SlotClass::Extension,
      _ => SlotClass::Local,
    }
  }
}

/// Which of the task manager's execution-slot channels a kind draws
/// from. Each class keeps its own budget so one class's wedged work can
/// never starve the operations whose latency the caller owns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotClass {
  /// Join and connect dials: bounded by the configured dial deadline
  /// (seconds), so they are the only core kinds that can pin a slot
  /// for a transport-observable span.
  Network,
  /// The core's own node-local work (resource writes, credentials,
  /// leave, recovery, retention, sync, listener and metadata
  /// maintenance): effects whose latency is this node's own.
  Local,
  /// Caller-registered extension workflows: their own channel, because
  /// an extension reconciler is the one effect class that routinely
  /// awaits *other* admitted tasks through its public handle — drawing
  /// from the local channel would let a workflow occupy the very
  /// capacity its child writes need (with one local slot, the first
  /// such workflow deadlocks on itself). Recursive waiting is bounded
  /// per class: code running inside one class's effect may await tasks
  /// of other classes, but awaiting another task of the *same* class
  /// (an extension reconciler awaiting an extension task) can
  /// self-deadlock on that class's bounded budget, so reconcile code
  /// must never do it.
  Extension,
}

/// The task phase machine. `Succeeded` and `Failed` are terminal; no
/// transition ever leaves a terminal state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TaskPhase {
  Pending,
  Running,
  Succeeded,
  Failed,
}

impl TaskPhase {
  /// Whether no further transition can occur. Terminal phases carry
  /// the task's final output or error.
  pub const fn is_terminal(self) -> bool {
    matches!(self, TaskPhase::Succeeded | TaskPhase::Failed)
  }
}

/// One task's typed failure surface: the effect's terminal error as the
/// stable kind plus its redacted context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskError {
  kind: ErrorKind,
  context: &'static str,
}

impl TaskError {
  pub(crate) fn from_error(error: Error) -> Self {
    Self {
      kind: error.kind(),
      context: error.context(),
    }
  }

  /// The stable, secret-safe error category.
  pub const fn kind(&self) -> ErrorKind {
    self.kind
  }

  /// The redacted error context (the same `&'static str` surface the
  /// crate's [`Error`] carries; never a message with interpolated
  /// caller data).
  pub fn as_str(&self) -> &'static str {
    self.context
  }

  pub(crate) fn to_error(self) -> Error {
    Error::from_parts(self.kind, self.context)
  }
}

/// The non-secret observation of one issued credential generation: the
/// expiry instant of the generation the task issued or rotated. The
/// credential secret itself is delivered exactly once, to the first
/// [`Task::wait`] caller — an issued credential is a value to hand out
/// once, not an observation to keep re-reading, so it never resides in
/// the repeatedly readable table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialIssued {
  expires_at: SystemTime,
}

impl CredentialIssued {
  pub(crate) const fn new(expires_at: SystemTime) -> Self {
    Self { expires_at }
  }

  /// The instant after which the issued generation is invalid.
  pub const fn expires_at(&self) -> SystemTime {
    self.expires_at
  }
}

/// The verb-specific success payload, stored on the task so late
/// `wait()` callers can read the outcome after the fact from the
/// bounded terminal history. The two credential variants carry the
/// [`CredentialIssued`] observation only — the secret is collected once
/// through the typed handle (see [`CredentialIssued`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskOutput {
  Join(MergeView),
  Leave(LeaveOutcome),
  Connect(NodeId),
  Disconnect(()),
  Revoke(RevokeOutcome),
  PurgeRevocation(()),
  Cleanup(()),
  IssueCleanupCheckpoint(u64),
  ResolveFrozenJournal(()),
  Listen(ListenerView),
  StopListener(()),
  PutResource(ResourceMutationView),
  DeleteResource(ResourceMutationView),
  PatchNodeMetadata(MemberView),
  IssueCredential(CredentialIssued),
  RotateCredential(CredentialIssued),
  StartRecovery(RecoveryView),
  ApplyReceiptRetention(ReceiptRetentionReport),
  SyncRound(()),
  Extension(()),
}

/// The cheap status snapshot: the live phase, the attempt count, and
/// the terminal error once one exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskStatus {
  phase: TaskPhase,
  attempts: u32,
  error: Option<TaskError>,
}

impl TaskStatus {
  pub(crate) const fn new(phase: TaskPhase, attempts: u32, error: Option<TaskError>) -> Self {
    Self {
      phase,
      attempts,
      error,
    }
  }

  pub const fn phase(&self) -> TaskPhase {
    self.phase
  }

  /// The number of reconcile attempts spent so far (1 once running).
  pub const fn attempts(&self) -> u32 {
    self.attempts
  }

  /// The typed terminal error; `None` while non-terminal or succeeded.
  pub const fn error(&self) -> Option<TaskError> {
    self.error
  }
}

/// The full status record carried by each task's watch channel: the
/// [`TaskStatus`] triple plus the observability timestamps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TaskStatusRecord {
  pub(crate) phase: TaskPhase,
  pub(crate) attempts: u32,
  pub(crate) error: Option<TaskError>,
  /// Host wall clock at admission (observability only).
  pub(crate) created: SystemTime,
  /// Host wall clock at the first reconcile spawn (observability only).
  pub(crate) started: Option<SystemTime>,
  /// Host wall clock at the terminal transition (observability only).
  pub(crate) finished: Option<SystemTime>,
}

impl TaskStatusRecord {
  pub(crate) const fn pending(created: SystemTime) -> Self {
    Self {
      phase: TaskPhase::Pending,
      attempts: 0,
      error: None,
      created,
      started: None,
      finished: None,
    }
  }

  pub(crate) const fn status(&self) -> TaskStatus {
    TaskStatus::new(self.phase, self.attempts, self.error)
  }
}

/// One task-table entry: the kind, the per-task status watch, and the
/// terminal payloads. `secret` holds an issued credential exactly until
/// the first typed `wait()` collects it; eviction and shutdown drop the
/// entry, and the secret's own zeroizing drop does the rest.
pub(crate) struct TaskEntry {
  pub(crate) kind: TaskKind,
  pub(crate) status: watch::Sender<TaskStatusRecord>,
  pub(crate) output: Option<TaskOutput>,
  pub(crate) secret: Option<IssuedMergeCredential>,
}

impl std::fmt::Debug for TaskEntry {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // No payload or credential material: the record alone.
    formatter
      .debug_struct("TaskEntry")
      .field("kind", &self.kind)
      .field("status", &self.status)
      .finish_non_exhaustive()
  }
}

/// The shared in-memory task table: admission-ordered by [`TaskId`],
/// readable without a runtime round trip, and mutated only by the task
/// manager's admission and reconcile futures.
#[derive(Clone, Debug, Default)]
pub(crate) struct TaskTable {
  entries: Arc<Mutex<BTreeMap<TaskId, TaskEntry>>>,
}

impl TaskTable {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  fn lock(
    &self,
  ) -> std::result::Result<std::sync::MutexGuard<'_, BTreeMap<TaskId, TaskEntry>>, Error> {
    self.entries.lock().map_err(Error::task_table)
  }

  /// Inserts one admitted task's `Pending` entry. `false` when the id
  /// already exists (an admission invariant violation, never a caller
  /// path).
  pub(crate) fn insert_pending(&self, id: &TaskId, kind: TaskKind, created: SystemTime) -> bool {
    let Ok(mut entries) = self.lock() else {
      return false;
    };
    if entries.contains_key(id) {
      return false;
    }
    let (status, _) = watch::channel(TaskStatusRecord::pending(created));
    entries.insert(
      id.clone(),
      TaskEntry {
        kind,
        status,
        output: None,
        secret: None,
      },
    );
    true
  }

  /// The per-task status watch, when the id is live or inside the
  /// bounded terminal history.
  pub(crate) fn watch(&self, id: &TaskId) -> Option<watch::Receiver<TaskStatusRecord>> {
    self
      .lock()
      .ok()
      .and_then(|entries| entries.get(id).map(|entry| entry.status.subscribe()))
  }

  /// The kind and current cheap status of one task.
  pub(crate) fn status(&self, id: &TaskId) -> Option<(TaskKind, TaskStatus)> {
    self.lock().ok().and_then(|entries| {
      entries
        .get(id)
        .map(|entry| (entry.kind.clone(), entry.status.borrow().status()))
    })
  }

  /// One task's full observation view (the never-secret surface: the
  /// consumed-once credential slot is deliberately unread here), when
  /// the id is live or inside the bounded terminal history.
  pub(crate) fn view(&self, id: &TaskId) -> Option<crate::view::TaskView> {
    self.lock().ok().and_then(|entries| {
      entries.get(id).map(|entry| {
        crate::view::TaskView::from_record(
          id.clone(),
          entry.kind.clone(),
          &entry.status.borrow(),
          entry.output.clone(),
        )
      })
    })
  }

  /// Pages the task views in canonical id order (= admission order,
  /// newest last), keyset-paginated on the id like every other view.
  pub(crate) fn page_views(&self, cursor: Option<&[u8]>, limit: usize) -> crate::view::TaskPage {
    let entries = self.lock().ok();
    let mut views = Vec::new();
    let mut next = None;
    let Some(entries) = entries else {
      return crate::view::TaskPage::new(views, None);
    };
    for (id, entry) in entries.iter() {
      // The cursor is the last delivered id: everything after it, in
      // id order, is the next page.
      if let Some(cursor) = cursor
        && id.as_str().as_bytes() <= cursor
      {
        continue;
      }
      if views.len() >= limit {
        // The boundary entry is *not* delivered on this page, so the
        // cursor must name the last delivered id — naming the boundary
        // entry would skip it on the continuation page.
        next = views
          .last()
          .map(|view| view.id().as_str().as_bytes().to_vec());
        break;
      }
      views.push(crate::view::TaskView::from_record(
        id.clone(),
        entry.kind.clone(),
        &entry.status.borrow(),
        entry.output.clone(),
      ));
    }
    let next = next
      .map(std::sync::Arc::from)
      .map(crate::PageCursor::new)
      .transpose();
    match next {
      Ok(next) => crate::view::TaskPage::new(views, next),
      Err(_) => crate::view::TaskPage::new(views, None),
    }
  }

  /// Runs one mutation over the entry: the single lock discipline for
  /// the manager's transitions. `Ok(None)` when the id is unknown
  /// (evicted); a poisoned lock is the typed internal error.
  pub(crate) fn update<R>(
    &self, id: &TaskId, mutate: impl FnOnce(&mut TaskEntry) -> R,
  ) -> Result<Option<R>> {
    let mut entries = self.lock()?;
    Ok(entries.get_mut(id).map(mutate))
  }

  /// Evicts oldest-terminal entries beyond `keep` (the bounded
  /// terminal history), dropping each evicted entry's consumed-once
  /// secret with it. Id order is admission order, so the first terminal
  /// entries encountered are the oldest; non-terminal entries are never
  /// evicted. Called by the manager's retention pass after each
  /// terminal transition.
  pub(crate) fn retain_terminal_history(&self, keep: usize) {
    let Ok(mut entries) = self.lock() else {
      return;
    };
    let excess = entries
      .values()
      .filter(|entry| entry.status.borrow().phase.is_terminal())
      .count()
      .saturating_sub(keep);
    if excess == 0 {
      return;
    }
    let evicted: Vec<TaskId> = entries
      .iter()
      .filter(|(_, entry)| entry.status.borrow().phase.is_terminal())
      .map(|(id, _)| id.clone())
      .take(excess)
      .collect();
    for id in evicted {
      entries.remove(&id);
    }
  }

  /// The number of live non-terminal entries of one slot class: the
  /// manager's admission bound counts these (a class whose non-terminal
  /// count reaches its bound refuses further admissions typed), so slow
  /// effects plus a stream of distinct intents can never accumulate
  /// unbounded admitted work — entries, captured effects, and waiting
  /// workers are each bounded by it. Terminal entries (the bounded
  /// history) never count: they are observations, not work.
  pub(crate) fn non_terminal_count(&self, class: SlotClass) -> usize {
    self.lock().map_or(0, |entries| {
      entries
        .values()
        .filter(|entry| {
          entry.kind.slot_class() == class && !entry.status.borrow().phase.is_terminal()
        })
        .count()
    })
  }
}

/// The caller's observation half over the shared task table: the table
/// plus the manager's stop signal, carried by every [`Task`] handle.
/// The submission half lives with the manager
/// (`runtime::task_manager::TaskClient`).
#[derive(Clone, Debug)]
pub(crate) struct TaskObserver {
  pub(crate) table: TaskTable,
  /// The manager's stop signal: `true` once the manager stopped
  /// admitting and reconciling (node shutdown).
  pub(crate) stop: watch::Receiver<bool>,
}

impl TaskObserver {
  /// The watch/shutdown arbitration every wait composes — the typed
  /// [`Task::wait`] and the node api's id-based wait: resolves with the
  /// terminal status record once the id terminalizes (value-based: an
  /// already-terminal id resolves immediately, so there is no
  /// missed-transition race), and with the typed shutdown failure
  /// once the manager's terminal publication can no longer arrive
  /// (the status watch closed, or the stop signal reached a kind the
  /// shutdown drain does not await). A kind the drain awaits to
  /// terminality (the journaled leave and frozen-journal resolution)
  /// still resolves with its real outcome: the manager publishes it
  /// before the drain completes.
  pub(crate) async fn await_terminal(
    &self, id: &TaskId, kind: &TaskKind,
  ) -> Result<TaskStatusRecord> {
    let Some(mut status) = self.table.watch(id) else {
      return Err(Error::not_found("task"));
    };
    let mut stop = self.stop.clone();
    loop {
      let record = status.borrow().clone();
      if record.phase.is_terminal() {
        return Ok(record);
      }
      // The task will never terminalize once either watch closes, or
      // once the stop signal reaches a kind the drain does not await.
      let stopped = tokio::select! {
        changed = status.changed() => changed.is_err(),
        changed = stop.changed() => changed.is_err() || !kind.drains_on_shutdown(),
      };
      if stopped {
        // The terminal publication can land in the same wake as the
        // stop signal (the manager publishes before it stops), so the
        // outcome is still read before the typed shutdown failure.
        let record = status.borrow().clone();
        if record.phase.is_terminal() {
          return Ok(record);
        }
        return Err(Error::shutting_down("task wait"));
      }
    }
  }
}

/// The sealed bound behind every typed task handle: it maps a stored
/// [`TaskOutput`] variant to the verb's historical return type, once
/// per verb output, and only this crate can implement it.
mod private {
  pub(crate) trait Sealed {}
}

pub(crate) trait TaskResult: private::Sealed + Sized + Send + 'static {
  /// Builds the verb's success value from the stored output. The
  /// `secret` slot is the consumed-once credential payload: the first
  /// collector receives `Some`, every later caller `None` (a typed
  /// invalid-input error for credential kinds, ignored by the rest).
  fn from_output(output: TaskOutput, secret: Option<IssuedMergeCredential>) -> Result<Self>;
}

/// The mismatch error for every wrong-variant mapping: the handle's
/// type and the task's kind drifted, which only a crate bug can cause.
const OUTPUT_MISMATCH: &str = "task output";

impl TaskResult for MergeView {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::Join(view) => Ok(view),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for LeaveOutcome {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::Leave(outcome) => Ok(outcome),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for NodeId {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::Connect(peer) => Ok(peer),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for () {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::Disconnect(())
      | TaskOutput::PurgeRevocation(())
      | TaskOutput::Cleanup(())
      | TaskOutput::ResolveFrozenJournal(())
      | TaskOutput::StopListener(())
      | TaskOutput::SyncRound(())
      | TaskOutput::Extension(()) => Ok(()),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for RevokeOutcome {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::Revoke(outcome) => Ok(outcome),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for u64 {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::IssueCleanupCheckpoint(watermark) => Ok(watermark),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for ListenerView {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::Listen(view) => Ok(view),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for ResourceMutationView {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::PutResource(view) | TaskOutput::DeleteResource(view) => Ok(view),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for MemberView {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::PatchNodeMetadata(view) => Ok(view),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for RecoveryView {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::StartRecovery(view) => Ok(view),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for ReceiptRetentionReport {
  fn from_output(output: TaskOutput, _secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::ApplyReceiptRetention(report) => Ok(report),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for IssuedMergeCredential {
  fn from_output(output: TaskOutput, secret: Option<IssuedMergeCredential>) -> Result<Self> {
    match output {
      TaskOutput::IssueCredential(_) | TaskOutput::RotateCredential(_) => {
        secret.ok_or_else(|| Error::invalid_input("task output already collected"))
      }
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl private::Sealed for MergeView {}
impl private::Sealed for LeaveOutcome {}
impl private::Sealed for NodeId {}
impl private::Sealed for () {}
impl private::Sealed for RevokeOutcome {}
impl private::Sealed for u64 {}
impl private::Sealed for ListenerView {}
impl private::Sealed for ResourceMutationView {}
impl private::Sealed for MemberView {}
impl private::Sealed for RecoveryView {}
impl private::Sealed for ReceiptRetentionReport {}
impl private::Sealed for IssuedMergeCredential {}

/// One admitted operation: the caller's proof of acceptance and its
/// observation surface. Cheap to clone; `wait` consumes.
///
/// The value-based wait contract: an already-terminal task resolves
/// immediately (no missed-transition race), and a non-terminal task
/// fails with [`ErrorKind::ShuttingDown`] once the node stops before
/// the effect settles. For the credential kinds the *first* `wait()`
/// collects the issued secret; later waits (and the status views)
/// observe only the expiry — an issued credential is handed out once.
#[derive(Clone, Debug)]
pub struct Task<T> {
  id: TaskId,
  kind: TaskKind,
  observer: TaskObserver,
  _output: PhantomData<fn() -> T>,
}

#[allow(private_bounds)]
impl<T: TaskResult> Task<T> {
  pub(crate) fn from_parts(id: TaskId, kind: TaskKind, observer: TaskObserver) -> Self {
    Self {
      id,
      kind,
      observer,
      _output: PhantomData,
    }
  }

  pub fn id(&self) -> &TaskId {
    &self.id
  }

  /// The admitted task's kind (captured at admission; coalesced
  /// submissions share it by construction).
  pub fn kind(&self) -> &TaskKind {
    &self.kind
  }

  /// The current status snapshot, read locally from the shared table
  /// without a runtime round trip. An id outside the live table and the
  /// bounded terminal history (evicted long after terminalizing) reads
  /// as a fresh admission snapshot; the typed wait surfaces eviction as
  /// a typed not-found instead.
  pub fn status(&self) -> TaskStatus {
    self.observer.table.status(&self.id).map_or_else(
      || TaskStatus::new(TaskPhase::Pending, 0, None),
      |(_, status)| status,
    )
  }

  /// Resolves when the task reaches a terminal phase: `Ok(T)` on
  /// `Succeeded`, the typed effect error on `Failed`, and
  /// [`ErrorKind::ShuttingDown`] if the node stops before the effect
  /// settles. A kind the shutdown drain awaits to terminality (the
  /// journaled leave and frozen-journal resolution) still resolves with
  /// its real outcome: the manager publishes it before the drain
  /// completes.
  pub async fn wait(self) -> Result<T> {
    let record = self.observer.await_terminal(&self.id, &self.kind).await?;
    resolve_terminal::<T>(record, &self.id, &self.observer.table)
  }
}

/// Maps one terminal status record to its result: the success path
/// takes (consumes) the secret slot and maps the stored output through
/// [`TaskResult`]; the failure path rebuilds the typed error.
fn resolve_terminal<T: TaskResult>(
  record: TaskStatusRecord, id: &TaskId, table: &TaskTable,
) -> Result<T> {
  match record.phase {
    TaskPhase::Succeeded => {
      let collected = table.update(id, |entry| (entry.output.clone(), entry.secret.take()));
      match collected {
        // A `Succeeded` entry always carries its output; the missing
        // shapes are internal invariant violations, never caller data.
        Ok(Some((Some(output), secret))) => T::from_output(output, secret),
        Ok(Some((None, _))) => Err(Error::internal(OUTPUT_MISMATCH)),
        Ok(None) => Err(Error::not_found("task")),
        Err(error) => Err(error),
      }
    }
    TaskPhase::Failed => Err(
      record
        .error
        .map_or_else(|| Error::internal("task failure"), TaskError::to_error),
    ),
    // The arbitration resolves only at a terminal phase, so a
    // non-terminal record here is an internal invariant violation.
    TaskPhase::Pending | TaskPhase::Running => Err(Error::internal("task terminal phase")),
  }
}

/// Admission-time and post-commit observation hooks for resource writes.
///
/// Hooks registered through
/// [`ExtensionRegistry::register_resource_hook`](crate::ExtensionRegistry::register_resource_hook)
/// run in canonical tag order. `validate` and `mutate` run on the
/// caller's admission path, before any IO; `observed` runs on the
/// node's bounded observation lanes after this node's own commit
/// lands, off the write task's execution slot.
pub trait ResourceHook: std::fmt::Debug + Send + Sync + 'static {
  /// Rejects a write at admission, before any IO runs. The first
  /// rejection in tag order wins and the verb fails typed with it.
  fn validate(&self, _write: &crate::ResourceWrite) -> Result<()> {
    Ok(())
  }

  /// Defaults or normalizes the write at admission; the hooks compose
  /// left to right in canonical tag order, and the composed result is
  /// the intent the effect signs.
  fn mutate(&self, write: crate::ResourceWrite) -> Result<crate::ResourceWrite> {
    Ok(write)
  }

  /// Fires after this node's own commit lands: the local observation of
  /// the put or delete, never a cluster-convergence promise (cluster
  /// visibility stays the reconcile plane's domain, observable through
  /// [`crate::ResourceChanged`]). The observation runs on the node's
  /// bounded observation lanes (a crate-private facility), off the
  /// write task's execution slot and after the commit lands;
  /// scheduling does not await the observer, so an error or a panic is
  /// a diagnostic and never fails, delays, or blocks the task or its
  /// shutdown.
  fn observed<'a>(&'a self, _view: &'a crate::ResourceView) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

/// Observer over one task's phase transitions.
///
/// Hooks registered through
/// [`ExtensionRegistry::register_action_hook`](crate::ExtensionRegistry::register_action_hook)
/// observe each transition sequentially in canonical tag order, in the
/// task's own spawned observation task — never on the manager task and
/// never on one of the manager's execution slots. One task's
/// observations run in transition order (each awaits its predecessor);
/// different tasks never observe through each other. They observe only:
/// an error or a panic is a `tracing` diagnostic, so no hook can fail,
/// wedge, or delay a task, its slot, or its shutdown drain.
pub trait ActionHook: std::fmt::Debug + Send + Sync + 'static {
  fn on_transition<'a>(&'a self, _transition: &'a TaskTransition) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

/// One observed phase transition of one task.
pub struct TaskTransition {
  id: TaskId,
  kind: TaskKind,
  from: TaskPhase,
  to: TaskPhase,
}

impl TaskTransition {
  /// The task that transitioned.
  pub const fn id(&self) -> &TaskId {
    &self.id
  }

  /// The task's kind (immutable for its lifetime).
  pub const fn kind(&self) -> &TaskKind {
    &self.kind
  }

  /// The phase the task held before this transition.
  pub const fn from(&self) -> TaskPhase {
    self.from
  }

  /// The phase the task holds now.
  pub const fn to(&self) -> TaskPhase {
    self.to
  }

  pub(crate) const fn new(id: TaskId, kind: TaskKind, from: TaskPhase, to: TaskPhase) -> Self {
    Self { id, kind, from, to }
  }
}

impl std::fmt::Debug for TaskTransition {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("TaskTransition")
      .field("id", &self.id)
      .field("kind", &self.kind)
      .field("from", &self.from)
      .field("to", &self.to)
      .finish()
  }
}

/// Runs one transition's action hooks sequentially in canonical tag
/// order (the registry's own order). Called from one of the node's
/// [`ObservationLanes`] runners, never on the manager task and never on
/// an execution slot: a hook error is a warn diagnostic, and a hook
/// panic is contained right here (also a warn diagnostic) — an observer
/// can never fail, retry, wedge, or delay the task it observes.
pub(crate) async fn notify_action_hooks(
  hooks: &[Arc<dyn ActionHook>], transition: &TaskTransition,
) {
  for hook in hooks {
    match AssertUnwindSafe(hook.on_transition(transition))
      .catch_unwind()
      .await
    {
      Ok(Ok(())) => {}
      Ok(Err(error)) => tracing::warn!(kind = ?error.kind(), "action hook failed"),
      Err(_panic) => tracing::warn!(
        task = %transition.id(),
        "action hook panicked while observing a transition"
      ),
    }
  }
}

/// How many observations may run their hooks concurrently: one
/// spawned runner task per lane. Observations are diagnostics-grade
/// caller code that must never delay a task, so the budget is the
/// facility's own — deliberately small, independent of the execution
/// slot budgets — and a wedged hook parks at most one lane.
pub(crate) const TASK_OBSERVATION_LANES: usize = 4;

/// Each lane's inbox depth: the queued-observation bound. A lane whose
/// runner is wedged accumulates at most this many queued observations;
/// the next one is dropped with a warn (the explicit overload
/// behavior — observations are best-effort diagnostics, never
/// load-bearing work), so caller hook code can never accumulate
/// unbounded parked tasks.
pub(crate) const TASK_OBSERVATION_INBOX: usize = 32;

/// One scheduled observation: the diagnostics label, the subject the
/// observation belongs to (the task id, or the resource name), and the
/// boxed observer work.
struct Observation {
  label: &'static str,
  subject: String,
  observation: BoxFuture<'static, ()>,
}

/// The node's bounded facility for running observer code — the action
/// hooks behind task transitions and the resource hooks behind
/// committed writes. The manager owns one `ObservationLanes` per
/// incarnation: a fixed set of lanes, each one spawned runner task over
/// a bounded inbox, and dropping it aborts every runner, so a wedged
/// observation is cancelled at shutdown instead of surviving the
/// incarnation as detached work. The shareable half is the
/// [`ObservationScheduler`] clone the manager hands to the operation
/// deps, so the resource-write effects schedule onto the same lanes.
/// One observation's lane is a deterministic function of its subject
/// (the task id, or the resource name), and each lane is consumed by
/// exactly one runner, so one task's observations always run in
/// transition order (and one resource's in commit order) without
/// per-subject bookkeeping and without detached predecessor chains.
pub(crate) struct ObservationLanes {
  scheduler: ObservationScheduler,
  runners: Vec<tokio::task::JoinHandle<()>>,
}

impl ObservationLanes {
  /// Spawns the lanes' runner tasks. The returned value keeps every
  /// runner handle, so its drop is the shutdown cancellation point.
  pub(crate) fn new() -> Self {
    let mut inboxes = Vec::with_capacity(TASK_OBSERVATION_LANES);
    let mut runners = Vec::with_capacity(TASK_OBSERVATION_LANES);
    for _ in 0..TASK_OBSERVATION_LANES {
      let (inbox, mut received) = mpsc::channel::<Observation>(TASK_OBSERVATION_INBOX);
      let runner = tokio::spawn(async move {
        while let Some(observation) = received.recv().await {
          // Panics are the scheduled work's own to contain
          // (`notify_action_hooks` and `notify_resource_observers`
          // catch each hook); this is the backstop of the generic
          // facility, so a panicking observation still never takes the
          // lane down.
          if let Err(_panic) = AssertUnwindSafe(observation.observation)
            .catch_unwind()
            .await
          {
            tracing::warn!(
              observation = observation.label,
              subject = %observation.subject,
              "an observation panicked and was contained"
            );
          }
        }
      });
      inboxes.push(inbox);
      runners.push(runner);
    }
    Self {
      scheduler: ObservationScheduler {
        inboxes: Arc::new(inboxes),
      },
      runners,
    }
  }

  /// The shareable scheduling half: a clone carrying no runner
  /// handles, so holding it never pins the runners' lifetime.
  pub(crate) fn scheduler(&self) -> ObservationScheduler {
    self.scheduler.clone()
  }

  /// Schedules one observation on its subject's pinned lane (see
  /// [`ObservationScheduler::schedule`]).
  pub(crate) fn schedule(
    &self, pin: &str, label: &'static str, observation: BoxFuture<'static, ()>,
  ) {
    self.scheduler.schedule(pin, label, observation);
  }
}

impl Drop for ObservationLanes {
  /// The shutdown cancellation: abort every runner, so an observation
  /// wedged mid-hook is dropped — wedged observer code never outlives
  /// the incarnation that scheduled it.
  fn drop(&mut self) {
    for runner in &self.runners {
      runner.abort();
    }
  }
}

/// The scheduling half of the [`ObservationLanes`]: the clone the
/// manager installs on the operation deps, so effects (the
/// resource-write commits) schedule their observations onto the same
/// bounded lanes the manager owns and cancels.
#[derive(Clone)]
pub(crate) struct ObservationScheduler {
  inboxes: Arc<Vec<mpsc::Sender<Observation>>>,
}

impl ObservationScheduler {
  /// Schedules one observation on its subject's pinned lane.
  /// Scheduling never blocks and never fails the caller: a full inbox
  /// drops the observation with a warn (the explicit overload behavior
  /// — the observation is diagnostics, and the task it belongs to has
  /// already moved on), and a closed inbox only means the lanes are
  /// already shutting down.
  pub(crate) fn schedule(
    &self, pin: &str, label: &'static str, observation: BoxFuture<'static, ()>,
  ) {
    match self.inboxes[lane_of(pin)].try_send(Observation {
      label,
      subject: pin.to_owned(),
      observation,
    }) {
      Ok(()) => {}
      Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
        observation = label,
        subject = pin,
        "the observation lane's inbox is full; dropping the observation"
      ),
      Err(mpsc::error::TrySendError::Closed(_)) => tracing::debug!(
        observation = label,
        subject = pin,
        "the observation lanes are shutting down; dropping the observation"
      ),
    }
  }
}

/// The lane one subject's observations run on: a deterministic function
/// of the pin string (the task id, or the resource name), so every
/// observation of one subject lands on the same lane's FIFO in order —
/// no per-subject assignment map, no predecessor chains.
fn lane_of(pin: &str) -> usize {
  let mut hasher = DefaultHasher::new();
  pin.hash(&mut hasher);
  (hasher.finish() % TASK_OBSERVATION_LANES as u64) as usize
}

/// Runs one write's admission hooks on the caller's task, in canonical
/// tag order: every `validate` runs first (the first rejection wins and
/// fails the verb with that error), then the `mutate`s compose
/// left-to-right, so the composed result is the intent the effect signs.
/// A panic in a hook aborts the caller's future only — the node is
/// unaffected (the same isolation class as any panicking caller code).
pub(crate) fn apply_resource_hooks(
  hooks: &[Arc<dyn ResourceHook>], mut write: crate::ResourceWrite,
) -> Result<crate::ResourceWrite> {
  for hook in hooks {
    hook.validate(&write)?;
  }
  for hook in hooks {
    write = hook.mutate(write)?;
  }
  Ok(write)
}

/// Schedules one write's post-commit observations on the node's
/// bounded observation lanes: each write's hooks run sequentially in
/// canonical tag order inside one lane runner, pinned to the resource
/// so one resource's observations keep their commit order, off the
/// write task's execution slot. Awaiting the call only performs the
/// scheduling, so the write task never waits on observer code: an
/// error or a panic in an observer is a `tracing` diagnostic that
/// never fails, delays, or blocks anything — and a wedged observer
/// parks its lane, further observations drop with a warn once the
/// inbox fills, and the runners are aborted at shutdown with the
/// lanes' owner.
pub(crate) async fn notify_resource_observers(
  lanes: &ObservationScheduler, hooks: &[Arc<dyn ResourceHook>], view: &crate::ResourceView,
) {
  if hooks.is_empty() {
    return;
  }
  let hooks = hooks.to_vec();
  let view = view.clone();
  // The pin is the resource name, so one resource's observations stay
  // in commit order on their lane; it is owned before the move into
  // the scheduled observation.
  let pin = view.name().as_str().to_owned();
  lanes.schedule(
    &pin,
    "resource hook observation",
    Box::pin(async move {
      for hook in hooks {
        match AssertUnwindSafe(hook.observed(&view)).catch_unwind().await {
          Ok(Ok(())) => {}
          Ok(Err(error)) => tracing::warn!(kind = ?error.kind(), "resource hook failed"),
          Err(_panic) => tracing::warn!(
            resource = %view.name(),
            "resource hook panicked while observing the commit"
          ),
        }
      }
    }),
  );
}

/// The caller-supplied effect behind one custom task kind: the
/// reconcile half of [`TaskKind::Extension`]. Registered through
/// [`ExtensionRegistry::register_task_reconciler`](crate::ExtensionRegistry::register_task_reconciler)
/// under a caller-owned tag and dispatched by the `tasks().submit`
/// admission.
///
/// A reconciler runs on the extension slot channel: it may freely await
/// core verbs (the local and network classes) through its handle, but
/// must never await another extension-kind task — the extension
/// channel's bounded budget is not reentrant, and same-class recursive
/// waiting can self-deadlock (see `SlotClass`).
pub trait TaskReconciler: std::fmt::Debug + Send + Sync + 'static {
  /// Produces the effect for one attempt. `Ok(Succeeded)` completes the
  /// task, `Ok(Retry)` re-arms the retry schedule without progress, and
  /// `Err` retries (bounded) before failing the task with that error.
  fn reconcile<'a>(&'a self, ctx: ReconcileContext) -> BoxFuture<'a, Result<ReconcileDecision>>;
}

/// What one reconcile attempt decided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileDecision {
  /// The effect completed: the task terminalizes `Succeeded`.
  Succeeded,
  /// The effect made no progress: re-arm the retry schedule.
  Retry,
}

/// The owned context of one reconcile attempt.
///
/// The handle is the ordinary public node surface — reads, watches,
/// `send`, `open_stream`: a custom kind is a caller workflow over the
/// crate's public contract, never privileged core access (no store, no
/// sessions, no supervisor internals).
#[derive(Clone)]
pub struct ReconcileContext {
  pub handle: crate::NodeHandle,
  pub spec: CustomTaskSpec,
  pub attempt: u32,
  pub last_error: Option<TaskError>,
}

impl std::fmt::Debug for ReconcileContext {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("ReconcileContext")
      .field("spec", &self.spec)
      .field("attempt", &self.attempt)
      .field("last_error", &self.last_error)
      .field("handle", &"NodeHandle")
      .finish()
  }
}

/// One caller-registered custom task submission: the kind tag (the
/// registry key of the caller's [`TaskReconciler`]) plus the caller's
/// labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomTaskSpec {
  kind: QualifiedTag,
  labels: crate::LabelSet,
}

impl CustomTaskSpec {
  pub fn new(kind: QualifiedTag, labels: crate::LabelSet) -> Self {
    Self { kind, labels }
  }

  pub const fn kind(&self) -> &QualifiedTag {
    &self.kind
  }

  pub const fn labels(&self) -> &crate::LabelSet {
    &self.labels
  }
}

#[cfg(test)]
mod tests {
  use std::{
    sync::{
      Arc,
      atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
  };

  use tokio::sync::watch;

  use super::{
    ActionHook, CredentialIssued, CustomTaskSpec, ObservationLanes, ResourceHook,
    TASK_OBSERVATION_INBOX, Task, TaskError, TaskKind, TaskObserver, TaskOutput, TaskPhase,
    TaskResult, TaskStatusRecord, TaskTable, TaskTransition, lane_of, notify_resource_observers,
  };
  use crate::{
    Error, ErrorKind, IssuedMergeCredential, MergeView, NodeId, QualifiedTag, Result, TaskId,
    identity::testing::SequenceEntropy,
  };

  struct Harness {
    table: TaskTable,
    observer: TaskObserver,
    stop: watch::Sender<bool>,
    next: u64,
  }

  impl Harness {
    fn new() -> Self {
      let table = TaskTable::new();
      let (stop, stop_rx) = watch::channel(false);
      Self {
        observer: TaskObserver {
          table: table.clone(),
          stop: stop_rx,
        },
        table,
        stop,
        next: 1,
      }
    }

    fn admit(&mut self, kind: TaskKind) -> TaskId {
      let id = TaskId::compose(0, self.next).expect("composition");
      self.next += 1;
      assert!(self.table.insert_pending(&id, kind, SystemTime::UNIX_EPOCH));
      id
    }

    fn set_running(&self, id: &TaskId, attempts: u32) {
      self
        .table
        .update(id, |entry| {
          let mut record = entry.status.borrow().clone();
          record.phase = TaskPhase::Running;
          record.attempts = attempts;
          record.started = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(attempts)));
          entry.status.send_replace(record);
        })
        .expect("update")
        .expect("entry");
    }

    fn finish(&self, id: &TaskId, phase: TaskPhase, output: Option<TaskOutput>) {
      self
        .table
        .update(id, |entry| {
          let mut record = entry.status.borrow().clone();
          record.phase = phase;
          record.finished = Some(SystemTime::UNIX_EPOCH);
          if let Some(output) = output {
            entry.output = Some(output);
          }
          if phase == TaskPhase::Failed {
            record.error = Some(TaskError::from_error(Error::not_found("peer binding")));
          }
          entry.status.send_replace(record);
        })
        .expect("update")
        .expect("entry");
    }
  }

  fn node(suffix: char) -> NodeId {
    let text = format!("node-00000000000000000000{suffix}");
    NodeId::parse(&text).expect("node id")
  }

  fn merge_view() -> MergeView {
    MergeView::new(node('a'), node('b'))
  }

  /// The P2-1 regression at the facility level: a wedged observation
  /// parks its lane's runner, the lane's inbox bounds how much further
  /// work may queue behind it, the next observation is dropped with the
  /// overload diagnostic, and dropping the lanes aborts the parked
  /// runner — wedged observer code is cancelled at shutdown instead of
  /// surviving as detached work.
  #[tokio::test]
  async fn observation_lanes_bound_a_parked_lane_drop_on_overflow_and_abort_on_drop() {
    // Two ids pinned to the same lane: with 64 ids over the lane count
    // the pigeonhole principle guarantees a pair.
    let ids: Vec<TaskId> = (0..64)
      .map(|counter| TaskId::compose(0, counter).expect("id"))
      .collect();
    let (parker, queued) = ids
      .iter()
      .enumerate()
      .find_map(|(index, id)| {
        ids[..index]
          .iter()
          .find(|other| lane_of(other.as_str()) == lane_of(id.as_str()))
          .map(|other| (other.clone(), id.clone()))
      })
      .expect("two ids share a lane");

    let lanes = ObservationLanes::new();
    // Park the shared lane's runner: this observation sets `started`,
    // then never settles, holding the alive guard until it is dropped.
    let started = Arc::new(AtomicBool::new(false));
    let alive = Arc::new(AtomicBool::new(true));
    let wedge_started = Arc::clone(&started);
    let wedge_alive = Arc::clone(&alive);
    struct Held(Arc<AtomicBool>);
    impl Drop for Held {
      fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
      }
    }
    lanes.schedule(
      parker.as_str(),
      "wedging observation",
      Box::pin(async move {
        wedge_started.store(true, Ordering::SeqCst);
        let _held = Held(wedge_alive);
        let () = std::future::pending().await;
      }),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !started.load(Ordering::SeqCst) {
      assert!(
        std::time::Instant::now() < deadline,
        "the wedging observation never started"
      );
      tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Fill the parked lane's inbox with instant observations for the
    // mate: they queue behind the wedged one, never running.
    let queued_ran = Arc::new(AtomicUsize::new(0));
    for _ in 0..TASK_OBSERVATION_INBOX {
      let ran = Arc::clone(&queued_ran);
      lanes.schedule(
        queued.as_str(),
        "queued observation",
        Box::pin(async move {
          ran.fetch_add(1, Ordering::SeqCst);
        }),
      );
    }
    // The next observation is the explicit overload behavior: the
    // runner is parked, the inbox is full, so the observation is
    // dropped with a warn instead of accumulating.
    let overflow_ran = Arc::new(AtomicBool::new(false));
    let overflow = Arc::clone(&overflow_ran);
    lanes.schedule(
      queued.as_str(),
      "overflow observation",
      Box::pin(async move {
        overflow.store(true, Ordering::SeqCst);
      }),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
      !overflow_ran.load(Ordering::SeqCst),
      "the overflow observation was dropped, never queued"
    );
    assert_eq!(
      queued_ran.load(Ordering::SeqCst),
      0,
      "the parked runner never reached the queued observations"
    );

    // Shutdown cancellation: dropping the facility aborts the parked
    // runner, which drops the wedged observation's state. Under the
    // old detached-spawn design the wedged observation survived the
    // facility (and the whole incarnation) forever.
    drop(lanes);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while alive.load(Ordering::SeqCst) {
      assert!(
        std::time::Instant::now() < deadline,
        "the wedged observation outlived the observation lanes"
      );
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!overflow_ran.load(Ordering::SeqCst));
  }

  /// The P2-1 resource-observer half: awaiting
  /// [`notify_resource_observers`] only schedules onto the lanes — the
  /// write task never waits on observer code — and one resource's
  /// observations keep their commit order on the resource's pinned
  /// lane.
  #[tokio::test]
  async fn notify_resource_observers_schedules_one_resources_hooks_in_commit_order() {
    #[derive(Debug)]
    struct RecordingHook {
      calls: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl ResourceHook for RecordingHook {
      fn observed<'a>(&'a self, view: &'a crate::ResourceView) -> crate::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
          self
            .calls
            .lock()
            .expect("hook calls")
            .push(view.labels().uri().as_str().to_owned());
          Ok(())
        })
      }
    }

    let name = crate::ResourceName::parse("radiata.woooo.tech/resources/hook-001").expect("name");
    let commit = |uri: &str| {
      crate::ResourceView::new(
        name.clone(),
        crate::ResourceLabels::new(
          crate::LabelValue::parse("document").expect("type"),
          crate::ResourceUri::parse(uri).expect("uri"),
        ),
        crate::ResourceVersion::from_parts(
          SystemTime::UNIX_EPOCH,
          node('a'),
          false,
          crate::Digest::from_bytes([1; 32]),
        ),
      )
    };
    let first = commit("file:///commit-one");
    let second = commit("file:///commit-two");
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hook: Arc<dyn ResourceHook> = Arc::new(RecordingHook {
      calls: Arc::clone(&calls),
    });

    let lanes = ObservationLanes::new();
    notify_resource_observers(&lanes.scheduler(), &[Arc::clone(&hook)], &first).await;
    notify_resource_observers(&lanes.scheduler(), &[Arc::clone(&hook)], &second).await;
    // Awaiting the call performed only the scheduling: on this test's
    // single-threaded runtime the lane runners have not been polled,
    // so neither observation has run — the write task moved on.
    assert!(
      calls.lock().expect("hook calls").is_empty(),
      "scheduling awaited an observer"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while calls.lock().expect("hook calls").len() < 2 {
      assert!(
        std::time::Instant::now() < deadline,
        "the scheduled observations never ran"
      );
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Both commits of the one resource landed on its pinned lane, so
    // the hooks observed them in commit order.
    assert_eq!(
      *calls.lock().expect("hook calls"),
      vec![
        "file:///commit-one".to_owned(),
        "file:///commit-two".to_owned()
      ]
    );
  }

  #[test]
  fn resource_hook_defaults_are_no_ops() {
    #[derive(Debug)]
    struct NoopHook;

    impl ResourceHook for NoopHook {}

    let hook = NoopHook;
    let name = crate::ResourceName::parse("radiata.woooo.tech/resources/hook-001").expect("name");
    let labels = crate::ResourceLabels::new(
      crate::LabelValue::parse("document").expect("type"),
      crate::ResourceUri::parse("file:///hook").expect("uri"),
    );
    let write = crate::ResourceWrite::new(name.clone(), labels.clone());
    assert!(hook.validate(&write).is_ok());
    let mutated = hook.mutate(write).expect("default mutate");
    assert_eq!(mutated.name(), &name);
    assert_eq!(mutated.labels(), &labels);
  }

  #[tokio::test]
  async fn action_hook_default_ignores_the_transition() {
    #[derive(Debug)]
    struct NoopHook;

    impl ActionHook for NoopHook {}

    let id = TaskId::compose(0, 1).expect("composition");
    let transition = TaskTransition::new(
      id.clone(),
      TaskKind::Join,
      TaskPhase::Pending,
      TaskPhase::Running,
    );
    assert_eq!(transition.id(), &id);
    assert_eq!(transition.kind(), &TaskKind::Join);
    assert_eq!(transition.from(), TaskPhase::Pending);
    assert_eq!(transition.to(), TaskPhase::Running);
    assert!(NoopHook.on_transition(&transition).await.is_ok());
    assert!(format!("{} {transition:?}", transition.id()).contains("TaskTransition"));
  }

  #[test]
  fn custom_task_spec_keeps_its_kind_and_labels() {
    let kind = QualifiedTag::parse("example.com/tasks/rotate-secret").expect("tag");
    let labels = crate::LabelSet::new()
      .insert(
        crate::LabelKey::parse("example.com/labels/lane").expect("key"),
        crate::LabelValue::parse("one").expect("value"),
      )
      .expect("labels");
    let spec = CustomTaskSpec::new(kind.clone(), labels.clone());
    assert_eq!(spec.kind(), &kind);
    assert_eq!(spec.labels(), &labels);
  }

  #[test]
  fn task_kind_orders_variants_then_extension_tags() {
    let alpha =
      TaskKind::Extension(crate::QualifiedTag::parse("example.com/tasks/alpha").expect("tag"));
    let beta =
      TaskKind::Extension(crate::QualifiedTag::parse("example.com/tasks/beta").expect("tag"));
    // The closed set sorts ahead of extension kinds, and extensions
    // sort by their tag.
    assert!(TaskKind::SyncRound < alpha);
    assert!(TaskKind::Join < alpha);
    assert!(alpha < beta);
    let mut kinds = vec![
      TaskKind::SyncRound,
      TaskKind::Join,
      beta.clone(),
      TaskKind::Leave,
      alpha.clone(),
    ];
    kinds.sort();
    assert_eq!(
      kinds,
      vec![
        TaskKind::Join,
        TaskKind::Leave,
        TaskKind::SyncRound,
        alpha,
        beta,
      ]
    );
  }

  #[test]
  fn task_kind_slot_classes_split_the_dials_from_local_work() {
    use super::SlotClass;
    // The network channel is exactly the dial kinds: they can hold a
    // slot for a whole dial deadline.
    assert_eq!(TaskKind::Join.slot_class(), SlotClass::Network);
    assert_eq!(TaskKind::Connect.slot_class(), SlotClass::Network);
    // Caller-registered extension kinds draw their own channel: a
    // workflow awaiting core verbs through its handle must never
    // occupy the local capacity its children need.
    assert_eq!(
      TaskKind::Extension(QualifiedTag::parse("example.com/tasks/v1/x").expect("tag")).slot_class(),
      SlotClass::Extension
    );
    // Everything else — resource writes, credentials, leave, and the
    // maintenance kinds — draws from the local channel.
    for kind in [
      TaskKind::Leave,
      TaskKind::Disconnect,
      TaskKind::Revoke,
      TaskKind::PurgeRevocation,
      TaskKind::Cleanup,
      TaskKind::IssueCleanupCheckpoint,
      TaskKind::ResolveFrozenJournal,
      TaskKind::Listen,
      TaskKind::StopListener,
      TaskKind::PutResource,
      TaskKind::DeleteResource,
      TaskKind::PatchNodeMetadata,
      TaskKind::IssueCredential,
      TaskKind::RotateCredential,
      TaskKind::StartRecovery,
      TaskKind::ApplyReceiptRetention,
      TaskKind::SyncRound,
    ] {
      assert_eq!(kind.slot_class(), SlotClass::Local, "{kind:?}");
    }
  }

  #[test]
  fn task_phase_terminality_is_total() {
    assert!(!TaskPhase::Pending.is_terminal());
    assert!(!TaskPhase::Running.is_terminal());
    assert!(TaskPhase::Succeeded.is_terminal());
    assert!(TaskPhase::Failed.is_terminal());
    assert!(TaskPhase::Pending < TaskPhase::Running);
    assert!(TaskPhase::Running < TaskPhase::Succeeded);
    assert!(TaskPhase::Succeeded < TaskPhase::Failed);
  }

  #[test]
  fn task_error_keeps_the_redacted_kind_and_context() {
    let error = TaskError::from_error(Error::conflict("resource version"));
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(error.as_str(), "resource version");
    let rebuilt = error.to_error();
    assert_eq!(rebuilt.kind(), ErrorKind::Conflict);
    assert_eq!(rebuilt.context(), "resource version");
  }

  #[test]
  fn credential_observation_carries_only_the_expiry() {
    let issued = issued_credential();
    let observation = CredentialIssued::new(issued.expires_at());
    assert_eq!(observation.expires_at(), issued.expires_at());
  }

  #[test]
  fn task_result_maps_each_payload_to_its_verb_type() {
    let view = merge_view();
    assert_eq!(
      MergeView::from_output(TaskOutput::Join(view.clone()), None).ok(),
      Some(view)
    );
    assert_eq!(
      <() as TaskResult>::from_output(TaskOutput::SyncRound(()), None).ok(),
      Some(())
    );
    assert_eq!(
      u64::from_output(TaskOutput::IssueCleanupCheckpoint(7), None).ok(),
      Some(7)
    );
    let mismatch = <u64 as TaskResult>::from_output(TaskOutput::SyncRound(()), None).unwrap_err();
    assert_eq!(mismatch.kind(), ErrorKind::Internal);
    assert_eq!(mismatch.context(), "task output");
  }

  #[test]
  fn credential_secret_is_collected_exactly_once() {
    let issued = issued_credential();
    let expires_at = issued.expires_at();
    let observation = TaskOutput::IssueCredential(CredentialIssued::new(expires_at));
    let first =
      IssuedMergeCredential::from_output(observation.clone(), Some(issued)).expect("first");
    assert_eq!(first.expires_at(), expires_at);
    let second = IssuedMergeCredential::from_output(observation, None).unwrap_err();
    assert_eq!(second.kind(), ErrorKind::InvalidInput);
    assert_eq!(second.context(), "task output already collected");
    // A non-credential mapping never touches the secret slot.
    assert_eq!(
      <() as TaskResult>::from_output(TaskOutput::SyncRound(()), None).ok(),
      Some(())
    );
  }

  fn issued_credential() -> IssuedMergeCredential {
    let entropy = SequenceEntropy::default();
    let mut issuer = crate::identity::credential::MergeCredentialIssuer::new();
    issuer
      .issue(&entropy, SystemTime::UNIX_EPOCH + Duration::from_secs(600))
      .expect("issued credential")
  }

  #[tokio::test]
  async fn wait_resolves_only_at_terminal_and_is_value_based() {
    let mut harness = Harness::new();
    let id = harness.admit(TaskKind::Join);
    let task: Task<MergeView> =
      Task::from_parts(id.clone(), TaskKind::Join, harness.observer.clone());

    assert_eq!(task.status().phase(), TaskPhase::Pending);
    assert_eq!(task.status().attempts(), 0);
    assert_eq!(task.kind(), &TaskKind::Join);
    harness.set_running(&id, 1);
    assert_eq!(task.status().phase(), TaskPhase::Running);
    assert_eq!(task.status().attempts(), 1);

    // An already-terminal task resolves immediately when awaited later
    // (the value-based contract: no missed-transition race).
    harness.finish(
      &id,
      TaskPhase::Succeeded,
      Some(TaskOutput::Join(merge_view())),
    );
    let view = task.wait().await.expect("terminal wait");
    assert_eq!(view, merge_view());
  }

  #[tokio::test]
  async fn wait_returns_the_typed_terminal_error() {
    let mut harness = Harness::new();
    let id = harness.admit(TaskKind::Connect);
    let task: Task<NodeId> =
      Task::from_parts(id.clone(), TaskKind::Connect, harness.observer.clone());
    harness.finish(&id, TaskPhase::Failed, None);
    let error = task.wait().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(error.context(), "peer binding");
    let status = Task::<NodeId>::from_parts(id, TaskKind::Connect, harness.observer).status();
    assert_eq!(
      status.error().map(|error| error.kind()),
      Some(ErrorKind::NotFound)
    );
  }

  #[tokio::test]
  async fn wait_fails_typed_when_the_manager_stops_first() {
    let mut harness = Harness::new();
    let id = harness.admit(TaskKind::Join);
    let task: Task<MergeView> =
      Task::from_parts(id.clone(), TaskKind::Join, harness.observer.clone());
    harness.stop.send_replace(true);
    let error = task.wait().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ShuttingDown);
    assert_eq!(error.context(), "task wait");
  }

  #[tokio::test]
  async fn wait_resolves_terminal_even_when_the_manager_stopped() {
    let mut harness = Harness::new();
    let id = harness.admit(TaskKind::Join);
    let task: Task<MergeView> =
      Task::from_parts(id.clone(), TaskKind::Join, harness.observer.clone());
    // The stop fired, but the task already terminalized: the terminal
    // value wins over the stop signal (the drain publishes before the
    // manager exits, and non-cancellable kinds always terminalize).
    harness.stop.send_replace(true);
    harness.finish(
      &id,
      TaskPhase::Succeeded,
      Some(TaskOutput::Join(merge_view())),
    );
    assert_eq!(task.wait().await.ok(), Some(merge_view()));
  }

  #[tokio::test]
  async fn wait_on_an_evicted_id_is_a_typed_not_found() {
    let harness = Harness::new();
    let id = TaskId::compose(0, 9_999).expect("composition");
    let task: Task<MergeView> = Task::from_parts(id, TaskKind::Join, harness.observer);
    let error = task.wait().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(error.context(), "task");
  }

  #[test]
  fn pending_entries_admit_in_id_order() -> Result<()> {
    let mut harness = Harness::new();
    let first = harness.admit(TaskKind::SyncRound);
    let second = harness.admit(TaskKind::SyncRound);
    assert!(first < second);
    let phases = harness.table.status(&first).map(|(_, status)| status.phase);
    assert_eq!(phases, Some(TaskPhase::Pending));
    let record = TaskStatusRecord::pending(SystemTime::UNIX_EPOCH);
    assert_eq!(record.status().phase(), TaskPhase::Pending);
    assert_eq!(record.status().attempts(), 0);
    Ok(())
  }

  #[test]
  fn page_views_walk_every_task_across_page_boundaries() {
    let mut harness = Harness::new();
    let ids = [
      harness.admit(TaskKind::SyncRound),
      harness.admit(TaskKind::SyncRound),
      harness.admit(TaskKind::SyncRound),
    ];
    for id in &ids {
      harness.finish(id, TaskPhase::Succeeded, Some(TaskOutput::SyncRound(())));
    }

    // Keyset pages must deliver every task exactly once: the cursor is
    // the last delivered id, so a page boundary never swallows its own
    // successor.
    let mut cursor: Option<Vec<u8>> = None;
    let mut walked = Vec::new();
    loop {
      let page = harness.table.page_views(cursor.as_deref(), 1);
      match page.next() {
        Some(next) => {
          assert_eq!(page.items().len(), 1, "a bounded page is full");
          cursor = Some(next.as_bytes().to_vec());
          walked.push(page.items()[0].id().clone());
        }
        None => {
          walked.extend(page.items().iter().map(|view| view.id().clone()));
          break;
        }
      }
    }
    assert_eq!(walked, ids.to_vec());
  }
}
