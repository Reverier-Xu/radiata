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
  collections::BTreeMap,
  marker::PhantomData,
  sync::{Arc, Mutex},
  time::SystemTime,
};

use tokio::sync::watch;

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
  /// settles. A kind the shutdown drain awaits to terminality
  /// ([`TaskKind::drains_on_shutdown`]) still resolves with its real
  /// outcome: the manager publishes it before the drain completes.
  pub async fn wait(self) -> Result<T> {
    let Some(mut status) = self.observer.table.watch(&self.id) else {
      return Err(Error::not_found("task"));
    };
    let mut stop = self.observer.stop.clone();
    loop {
      if let Some(result) = resolve_terminal::<T>(&self.id, &status, &self.observer.table) {
        return result;
      }
      // The task will never terminalize once either watch closes, or
      // once the stop signal reaches a kind the drain does not await.
      let stopped = tokio::select! {
        changed = status.changed() => changed.is_err(),
        changed = stop.changed() => changed.is_err() || !self.kind.drains_on_shutdown(),
      };
      if stopped {
        // The terminal publication can land in the same wake as the
        // stop signal (the manager publishes before it stops), so the
        // outcome is still read before the typed shutdown failure.
        if let Some(result) = resolve_terminal::<T>(&self.id, &status, &self.observer.table) {
          return result;
        }
        return Err(Error::shutting_down("task wait"));
      }
    }
  }
}

/// Maps one watch snapshot to a terminal result when the record says
/// terminal: the success path takes (consumes) the secret slot and maps
/// the stored output through [`TaskResult`]; the failure path rebuilds
/// the typed error.
fn resolve_terminal<T: TaskResult>(
  id: &TaskId, status: &watch::Receiver<TaskStatusRecord>, table: &TaskTable,
) -> Option<Result<T>> {
  let record = status.borrow().clone();
  match record.phase {
    TaskPhase::Succeeded => {
      let collected = table.update(id, |entry| (entry.output.clone(), entry.secret.take()));
      Some(match collected {
        // A `Succeeded` entry always carries its output; the missing
        // shapes are internal invariant violations, never caller data.
        Ok(Some((Some(output), secret))) => T::from_output(output, secret),
        Ok(Some((None, _))) => Err(Error::internal(OUTPUT_MISMATCH)),
        Ok(None) => Err(Error::not_found("task")),
        Err(error) => Err(error),
      })
    }
    TaskPhase::Failed => Some(Err(
      record
        .error
        .map_or_else(|| Error::internal("task failure"), TaskError::to_error),
    )),
    TaskPhase::Pending | TaskPhase::Running => None,
  }
}

/// Admission-time and post-commit observation hooks for resource writes.
///
/// Hooks registered through
/// [`ExtensionRegistry::register_resource_hook`](crate::ExtensionRegistry::register_resource_hook)
/// run in canonical tag order. `validate` and `mutate` run on the
/// caller's admission path, before any IO; `observed` runs inside the
/// write task's own future, after this node's own commit lands.
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

  /// Fires after this node's own commit lands and before the write task
  /// terminalizes: the local observation of the put or delete, never a
  /// cluster-convergence promise (cluster visibility stays the reconcile
  /// plane's domain, observable through [`crate::ResourceChanged`]). An
  /// error is a diagnostic and never fails or blocks the task.
  fn observed<'a>(&'a self, _view: &'a crate::ResourceView) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

/// Observer over one task's phase transitions.
///
/// Hooks registered through
/// [`ExtensionRegistry::register_action_hook`](crate::ExtensionRegistry::register_action_hook)
/// run sequentially in canonical tag order inside the task's own future
/// (never on the manager task). They observe only: an error is a
/// `tracing` diagnostic and the sequence continues, so no hook can wedge
/// a task or its shutdown drain.
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
/// order (the registry's own order). Called inside the task's own future:
/// a panic in a hook aborts that future and surfaces as the task's typed
/// internal failure, and a hook error is a diagnostic that never fails,
/// retries, or blocks the task.
pub(crate) async fn notify_action_hooks(
  hooks: &[Arc<dyn ActionHook>], transition: &TaskTransition,
) {
  for hook in hooks {
    if let Err(error) = hook.on_transition(transition).await {
      tracing::warn!(kind = ?error.kind(), "action hook failed");
    }
  }
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

/// Runs one write task's post-commit observations sequentially in
/// canonical tag order, inside the task's own future: an error is a
/// `tracing` diagnostic that never fails or blocks the task, and a panic
/// surfaces as the task's typed internal failure through the same path
/// as any other panicking effect code.
pub(crate) async fn notify_resource_observers(
  hooks: &[Arc<dyn ResourceHook>], view: &crate::ResourceView,
) {
  for hook in hooks {
    if let Err(error) = hook.observed(view).await {
      tracing::warn!(kind = ?error.kind(), "resource hook failed");
    }
  }
}

/// The caller-supplied effect behind one custom task kind: the
/// reconcile half of [`TaskKind::Extension`]. Registered through
/// [`ExtensionRegistry::register_task_reconciler`](crate::ExtensionRegistry::register_task_reconciler)
/// under a caller-owned tag and dispatched by the `tasks().submit`
/// admission.
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
  use std::time::{Duration, SystemTime};

  use tokio::sync::watch;

  use super::{
    ActionHook, CredentialIssued, CustomTaskSpec, ResourceHook, Task, TaskError, TaskKind,
    TaskObserver, TaskOutput, TaskPhase, TaskResult, TaskStatusRecord, TaskTable, TaskTransition,
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
