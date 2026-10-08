//! The task manager: the node-local reconcile plane behind the
//! declarative verb surface. One spawned manager owns admission (id
//! composition, dedup/coalescing, the `Pending` publication), one
//! bounded worker pool (a counting semaphore over the per-task
//! reconcile futures), the bounded retry schedule with per-kind
//! policies, and the shutdown drain (cancellable kinds exit on the
//! cancel watch; the journaled kinds are awaited to completion).
//!
//! Effects are crate-internal closures over the moved verb bodies
//! (`runtime::task_effects`, landed stage by stage with the verb
//! migrations); this module knows policies, ordering, and status —
//! never verb semantics. Each effect runs as its own spawned task
//! awaited by its task's worker future, so user-registered hook code
//! and reconcilers never run on the manager task, and a panicking
//! effect surfaces as the task's typed internal failure without
//! touching the manager.

use std::{collections::BTreeMap, pin::Pin, sync::Arc, time::Duration};

use tokio::{
  sync::{Semaphore, mpsc, oneshot, watch},
  time::{Instant, Sleep},
};

use crate::{
  BoxFuture, Error, ErrorKind, IssuedMergeCredential, NodeId, Result, TaskId, TaskKind, TaskOutput,
  TaskPhase,
  api::Entropy,
  task::{CredentialIssued, TaskError, TaskObserver, TaskTable},
  time::WallClock,
};

/// The submission channel width: mirrors the control channel's capacity
/// so one bound governs both admission ends.
pub(crate) const TASK_CHANNEL_CAPACITY: usize = 32;

/// The concurrent reconcile bound: one counting semaphore's permit
/// count. The two-vcpu-runner starvation precedents keep effects off
/// the supervision planes; this is not a config knob until evidence
/// demands one.
pub(crate) const TASK_RECONCILE_CONCURRENCY: usize = 4;

/// The bounded terminal history: the newest terminal tasks stay
/// readable through the observation surface; older ones are evicted
/// (oldest-terminal first) and read as absent.
pub(crate) const TASK_TERMINAL_HISTORY: usize = 256;

/// The idle retry timer: far enough out to never fire while the
/// schedule is empty, near enough to stay inside tokio's `Instant`
/// arithmetic.
const RETRY_TIMER_IDLE: Duration = Duration::from_secs(86_400 * 365);

/// The retry classification behind each kind's policy: which typed
/// error categories may retry. The taxonomy is the crate's own verbatim
/// — e.g. an unspread binding (`NotFound`) is a retryable convergence
/// state for a network dial, while `AuthenticationFailed`/`Revoked` are
/// the documented terminal dial contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryClass {
  /// Join/connect dials: convergence and transport transients retry.
  Network,
  /// Resource writes: only the snapshot-commit register race retries
  /// (the `RESOURCE_COMMIT_RACE_ATTEMPTS` precedent).
  Local,
  /// Everything else: one attempt, no retry.
  Once,
}

impl RetryClass {
  const fn retryable(self, kind: ErrorKind) -> bool {
    match self {
      RetryClass::Network => matches!(
        kind,
        ErrorKind::NotFound
          | ErrorKind::NotReady
          | ErrorKind::Io
          | ErrorKind::Overloaded
          | ErrorKind::RouteUnavailable
          | ErrorKind::StreamInterrupted
      ),
      RetryClass::Local => matches!(kind, ErrorKind::Conflict),
      RetryClass::Once => false,
    }
  }
}

/// One kind's bounded retry policy: attempt budget plus exponential
/// backoff (`initial * 4^(attempt-1)`, capped, no jitter — the
/// lockstep-slamming rationale behind the recovery plane's jitter does
/// not apply at these scales, and seeded jitter stays additive later).
pub(crate) struct RetryPolicy {
  pub(crate) max_attempts: u32,
  initial: Duration,
  max: Duration,
  class: RetryClass,
}

impl RetryPolicy {
  /// The backoff after the `failed_attempt`-th attempt (1-based).
  pub(crate) fn backoff(&self, failed_attempt: u32) -> Duration {
    let factor = 4_u32.saturating_pow(failed_attempt.saturating_sub(1));
    self.initial.saturating_mul(factor).min(self.max)
  }
}

/// Join and connect dials: four attempts, 100 ms → 10 s.
const NETWORK_RETRY: RetryPolicy = RetryPolicy {
  max_attempts: 4,
  initial: Duration::from_millis(100),
  max: Duration::from_secs(10),
  class: RetryClass::Network,
};

/// Resource writes: three attempts, 10 ms → 30 ms — the register
/// commit-race budget.
const LOCAL_RETRY: RetryPolicy = RetryPolicy {
  max_attempts: 3,
  initial: Duration::from_millis(10),
  max: Duration::from_millis(30),
  class: RetryClass::Local,
};

/// Everything else (leave, credentials, recovery, retention, the sync
/// round, frozen-journal resolution): one attempt.
const ONCE: RetryPolicy = RetryPolicy {
  max_attempts: 1,
  initial: Duration::ZERO,
  max: Duration::ZERO,
  class: RetryClass::Once,
};

/// The kind's retry policy (single classification site).
pub(crate) fn retry_policy(kind: &TaskKind) -> &'static RetryPolicy {
  match kind {
    TaskKind::Join | TaskKind::Connect => &NETWORK_RETRY,
    TaskKind::PutResource | TaskKind::DeleteResource => &LOCAL_RETRY,
    _ => &ONCE,
  }
}

/// Whether a kind's in-flight effect exits on the shutdown cancel
/// watch, or is awaited to its terminal phase by the shutdown drain.
/// `Leave` and `ResolveFrozenJournal` are journaled/store-atomic
/// operations whose outcome must settle before teardown completes.
pub(crate) fn cancellable(kind: &TaskKind) -> bool {
  !kind.drains_on_shutdown()
}

/// One reconcile attempt's terminal payload: the public output plus,
/// for the credential kinds, the consumed-once secret slot.
pub(crate) struct EffectOutcome {
  pub(crate) output: TaskOutput,
  pub(crate) secret: Option<IssuedMergeCredential>,
}

impl EffectOutcome {
  #[allow(dead_code)] // driven by the verb migration stage's effects
  pub(crate) fn new(output: TaskOutput) -> Self {
    Self {
      output,
      secret: None,
    }
  }

  /// The issue-credential effect's outcome: the observation carries the
  /// generation's expiry; the secret rides the consumed-once slot.
  #[allow(dead_code)] // driven by the verb migration stage's effects
  pub(crate) fn credential_issued(issued: IssuedMergeCredential) -> Self {
    Self {
      output: TaskOutput::IssueCredential(CredentialIssued::new(issued.expires_at())),
      secret: Some(issued),
    }
  }

  /// The rotate-credential effect's outcome (the same consumed-once
  /// rule).
  #[allow(dead_code)] // driven by the verb migration stage's effects
  pub(crate) fn credential_rotated(issued: IssuedMergeCredential) -> Self {
    Self {
      output: TaskOutput::RotateCredential(CredentialIssued::new(issued.expires_at())),
      secret: Some(issued),
    }
  }
}

/// One admitted task's effect: a factory called once per attempt with the
/// node-shared operation handles the manager owns. The verb admissions
/// build these closures over the moved verb bodies; the effect body is a
/// `reconcile_*` function in [`super::task_effects`].
pub(crate) type TaskEffect = Arc<
  dyn Fn(Arc<super::task_effects::OperationDeps>, u32) -> BoxFuture<'static, Result<EffectOutcome>>
    + Send
    + Sync,
>;

/// The payload the coalescing rules compare. The verb migrations (next
/// stage) extend the set with their verb inputs; today the effect
/// closure owns the whole verb input and the payload carries only the
/// coalescing subject.
#[allow(dead_code)] // constructed by the verb migration stage's admission paths and the manager tests
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TaskPayload {
  /// No coalescing subject: the kind never coalesces.
  None,
  /// The coalescing subject: the dialed peer for Connect/Disconnect,
  /// the acted-on node for Revoke/PurgeRevocation/Cleanup.
  Peer(NodeId),
}

/// One admitted task's immutable intent: the kind plus the payload the
/// coalescing rules compare. Coalescing is keyed on kind + subject and
/// accepts a coalesced submission only when the whole spec equals the
/// in-flight one, so a coalesced retry can never smuggle a different
/// intent silently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TaskSpec {
  kind: TaskKind,
  payload: TaskPayload,
}

impl TaskSpec {
  #[allow(dead_code)] // constructed by the verb migration stage's admission paths
  pub(crate) fn new(kind: TaskKind, payload: TaskPayload) -> Self {
    Self { kind, payload }
  }

  pub(crate) fn kind(&self) -> &TaskKind {
    &self.kind
  }

  /// Validates the spec shape: a coalescing kind must carry its subject
  /// (only crate-internal wiring builds specs, so a miss is the typed
  /// internal invariant, never caller data).
  pub(crate) fn check_shape(&self) -> Result<()> {
    let requires_subject = matches!(
      self.kind,
      TaskKind::Connect
        | TaskKind::Disconnect
        | TaskKind::Revoke
        | TaskKind::PurgeRevocation
        | TaskKind::Cleanup
    );
    if requires_subject && !matches!(self.payload, TaskPayload::Peer(_)) {
      return Err(Error::internal("task coalescing subject"));
    }
    Ok(())
  }

  /// The coalescing subject, when the kind coalesces.
  pub(crate) fn coalesce_key(&self) -> Option<NodeId> {
    match &self.kind {
      TaskKind::Connect
      | TaskKind::Disconnect
      | TaskKind::Revoke
      | TaskKind::PurgeRevocation
      | TaskKind::Cleanup => match &self.payload {
        TaskPayload::Peer(subject) => Some(subject.clone()),
        TaskPayload::None => None,
      },
      _ => None,
    }
  }
}

/// One submission through the bounded admission channel: the spec, the
/// effect, and the admission reply.
pub(crate) struct Submission {
  pub(crate) spec: TaskSpec,
  pub(crate) effect: TaskEffect,
  pub(crate) reply: oneshot::Sender<Result<TaskId>>,
}

/// The caller's submission half over the manager: the bounded admission
/// channel plus the shared observation surface carried by every task
/// handle.
#[derive(Clone)]
pub(crate) struct TaskClient {
  submit: mpsc::Sender<Submission>,
  pub(crate) observer: TaskObserver,
}

impl std::fmt::Debug for TaskClient {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("TaskClient")
      .field("observer", &self.observer)
      .finish_non_exhaustive()
  }
}

impl TaskClient {
  /// Submits one task and awaits its admission: pure validation and
  /// hooks have already run caller-side; this is id composition, the
  /// dedup/coalescing check, the `Pending` publication, and the first
  /// reconcile spawn. No IO ever runs on this path.
  #[allow(dead_code)] // submissions arrive with the verb migration stage
  pub(crate) async fn submit(&self, spec: TaskSpec, effect: TaskEffect) -> Result<TaskId> {
    let (reply, response) = oneshot::channel();
    self
      .submit
      .send(Submission {
        spec,
        effect,
        reply,
      })
      .await
      .map_err(|_| Error::shutting_down("task admission"))?;
    response
      .await
      .map_err(|_| Error::shutting_down("task admission"))?
  }
}

/// The supervisor's half: the cancel watch (begin_shutdown) and the
/// manager's join handle (drain awaits the journaled kinds).
#[allow(dead_code)] // driven by the supervisor's teardown; the wiring lands with the supervisor stages
pub(crate) struct TaskManagerHandle {
  cancel: watch::Sender<bool>,
  task: tokio::task::JoinHandle<()>,
}

impl TaskManagerHandle {
  /// Closes admissions (subsequent submissions fail typed) and
  /// broadcasts the cancel watch: cancellable kinds exit immediately,
  /// the journaled kinds keep running to their terminal phase.
  #[allow(dead_code)] // called by the supervisor's teardown; the wiring lands with the supervisor stages
  pub(crate) fn begin_shutdown(&self) {
    let _ = self.cancel.send(true);
  }

  /// Awaits the manager's exit: every spawned worker has settled
  /// (cancelled, or terminal for the journaled kinds) before this
  /// resolves.
  #[allow(dead_code)] // awaited by the supervisor's teardown; the wiring lands with the supervisor stages
  pub(crate) async fn drain(self) {
    let _ = self.task.await;
  }
}

/// Everything the manager machinery itself needs. The effect context
/// (identity, driver, sessions, listeners) joins with the verb
/// migrations; each stage extends this struct with exactly what its
/// effects read.
pub(crate) struct TaskManagerDeps {
  pub(crate) entropy: Arc<dyn Entropy>,
  pub(crate) clock: Arc<dyn WallClock>,
  /// The node-shared operation handles: every effect reads them, and the
  /// manager owns the only long-lived reference (a node handle keeps just
  /// the submit half, so holding a handle never keeps the metadata store
  /// locked past shutdown).
  pub(crate) operations: Arc<super::task_effects::OperationDeps>,
  /// The node's bound listeners, shared with the supervisor's views: the
  /// listen/stop effects mutate the same registry the pages read.
  pub(crate) listeners: super::supervisor::ListenerRegistry,
  /// The leave reconciler's completion signal to the supervisor
  /// ([`super::supervisor::spawn_runtime`] owns the receiving end). The
  /// manager sends it once the leave task's terminal publication landed,
  /// which is what starts the `ActiveLeave` shutdown.
  pub(crate) leave_complete: mpsc::Sender<()>,
}

/// The per-incarnation state shared with every worker future.
struct ManagerShared {
  table: TaskTable,
  clock: Arc<dyn WallClock>,
  /// The node-shared operation handles every effect reads.
  operations: Arc<super::task_effects::OperationDeps>,
  /// The shared listener registry, read by the listen/stop effects.
  #[allow(dead_code)] // read by the listener effects; that migration stage lands next
  listeners: super::supervisor::ListenerRegistry,
  /// The leave completion signal, sent once the leave task terminalized
  /// (the supervisor owns the receiver).
  #[allow(dead_code)] // sent by the leave verb's reconciliation; that stage lands next
  leave_complete: mpsc::Sender<()>,
  semaphore: Arc<Semaphore>,
}

impl ManagerShared {
  /// The typed event hub: every phase transition emits its
  /// [`crate::TaskChanged`] through it.
  fn events(&self) -> &Arc<crate::node::EventHub> {
    self.operations.events()
  }

  /// The node-local extension registry: the source of the registered
  /// action hooks (and, for the verb stages, the resource hooks and
  /// custom-kind reconcilers).
  fn extensions(&self) -> &Arc<crate::ExtensionRegistry> {
    self.operations.extensions()
  }
}

impl ManagerShared {
  /// Publishes one `Running` record (the running re-emission at each
  /// retry wake rides the attempt counter) plus its transition
  /// observation. Returns whether the entry was live; a missing entry
  /// (evicted) needs no further work.
  async fn publish_running(&self, id: &TaskId, kind: &TaskKind, attempt: u32) -> bool {
    let previous = self.table.update(id, |entry| {
      let from = entry.status.borrow().phase;
      let mut record = entry.status.borrow().clone();
      record.phase = TaskPhase::Running;
      record.attempts = attempt;
      if record.started.is_none() {
        record.started = Some(self.clock.now());
      }
      entry.status.send_replace(record);
      from
    });
    match previous {
      Ok(Some(from)) => {
        self.observe(id, kind, from, TaskPhase::Running).await;
        true
      }
      Ok(None) | Err(_) => false,
    }
  }

  /// Publishes the terminal success with its payloads and its transition
  /// observation.
  async fn publish_success(
    &self, id: &TaskId, kind: &TaskKind, output: TaskOutput, secret: Option<IssuedMergeCredential>,
  ) {
    let finished = self.clock.now();
    let previous = self.table.update(id, |entry| {
      let from = entry.status.borrow().phase;
      let mut record = entry.status.borrow().clone();
      record.phase = TaskPhase::Succeeded;
      record.finished = Some(finished);
      entry.output = Some(output);
      entry.secret = secret;
      entry.status.send_replace(record);
      from
    });
    if let Ok(Some(from)) = previous {
      self.observe(id, kind, from, TaskPhase::Succeeded).await;
    }
  }

  /// Publishes the terminal failure with its typed error and its
  /// transition observation.
  async fn publish_failure(&self, id: &TaskId, kind: &TaskKind, error: Error) {
    if let Some(from) = self.record_failure(id, error) {
      self.observe(id, kind, from, TaskPhase::Failed).await;
    }
  }

  /// Publishes the terminal failure of an attempt that panicked. The
  /// failure *is* uncontained user code, so the transition is emitted
  /// but the hooks are not re-run: hooks never observe their own
  /// failure. The table publication itself is crate code, so nothing a
  /// panicking hook could do remains on this path.
  fn publish_panicked(&self, id: &TaskId, kind: &TaskKind, error: Error) {
    if let Some(from) = self.record_failure(id, error) {
      self.events().emit(crate::TaskChanged::new(
        id.clone(),
        kind.clone(),
        TaskPhase::Failed,
      ));
      tracing::warn!(
        task = %id,
        from = ?from,
        "task failed after a panicking reconcile attempt"
      );
    } else {
      // The entry already terminalized: the panic landed in the terminal
      // transition's own observation (a hook panicking on `Succeeded`),
      // and terminality is monotone, so the phase stands.
      tracing::warn!(
        task = %id,
        "a reconcile attempt panicked after the task terminalized"
      );
    }
  }

  /// The table half of a terminal failure: the typed error, the finish
  /// instant, and the phase the entry held before. `None` when the entry
  /// is gone, or already terminal — no phase transition ever leaves a
  /// terminal state, so a failure publication never overwrites one.
  fn record_failure(&self, id: &TaskId, error: Error) -> Option<TaskPhase> {
    let failure = TaskError::from_error(error);
    let finished = self.clock.now();
    match self.table.update(id, |entry| {
      let from = entry.status.borrow().phase;
      if from.is_terminal() {
        return None;
      }
      let mut record = entry.status.borrow().clone();
      record.phase = TaskPhase::Failed;
      record.error = Some(failure);
      record.finished = Some(finished);
      entry.status.send_replace(record);
      Some(from)
    }) {
      Ok(Some(from)) => from,
      Ok(None) | Err(_) => None,
    }
  }

  /// The transition observation, in the design's order: the typed event
  /// first, then the registered action hooks in canonical tag order.
  /// Runs inside the task's own future, never on the manager task.
  async fn observe(&self, id: &TaskId, kind: &TaskKind, from: TaskPhase, to: TaskPhase) {
    self
      .events()
      .emit(crate::TaskChanged::new(id.clone(), kind.clone(), to));
    let transition = crate::task::TaskTransition::new(id.clone(), kind.clone(), from, to);
    crate::task::notify_action_hooks(&self.extensions().action_hooks(), &transition).await;
  }
}

/// Spawns the task manager. The startup id-base draw is the single new
/// startup entropy fill (pinned by the lifecycle entropy-sequence
/// test).
#[allow(dead_code)] // spawned beside the sync driver; the supervisor wiring lands with the supervisor stages
pub(crate) fn spawn_task_manager(deps: TaskManagerDeps) -> Result<(TaskClient, TaskManagerHandle)> {
  let base = TaskId::draw_base(deps.entropy.as_ref())?;
  let (submit, submissions) = mpsc::channel(TASK_CHANNEL_CAPACITY);
  let (cancel, cancel_rx) = watch::channel(false);
  let table = TaskTable::new();
  let observer = TaskObserver {
    table: table.clone(),
    stop: cancel_rx.clone(),
  };
  let shared = Arc::new(ManagerShared {
    table,
    clock: deps.clock,
    operations: deps.operations,
    listeners: deps.listeners,
    leave_complete: deps.leave_complete,
    semaphore: Arc::new(Semaphore::new(TASK_RECONCILE_CONCURRENCY)),
  });
  let (reports_tx, reports_rx) = mpsc::unbounded_channel();
  let task = tokio::spawn(run_manager(
    shared,
    submissions,
    reports_tx,
    reports_rx,
    base,
    cancel.clone(),
    cancel_rx,
  ));
  Ok((
    TaskClient { submit, observer },
    TaskManagerHandle { cancel, task },
  ))
}

/// One scheduled retry wake.
struct RetryTicket {
  id: TaskId,
  kind: TaskKind,
  effect: TaskEffect,
  attempt: u32,
}

/// One worker's completion report to the manager loop. Sent as the
/// worker's last action; the terminal publications themselves already
/// ran inside the worker's own future.
enum WorkerReport {
  /// The task terminalized (success or typed failure).
  Terminal(TaskId),
  /// The attempt failed retryably; re-spawn after the delay.
  Retry {
    id: TaskId,
    kind: TaskKind,
    effect: TaskEffect,
    attempt: u32,
    delay: Duration,
  },
  /// Shutdown cancelled a cancellable kind mid-flight; the task stays
  /// non-terminal and the table dies with the runtime.
  Cancelled,
}

/// A [`tokio::task::JoinHandle`] that aborts its task on drop: the
/// shutdown cancel path drops the guard when its select branch loses, so
/// no detached attempt task outlives its worker. (`JoinHandle` is
/// `Unpin`, so the delegation needs no pin projection.)
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
  fn drop(&mut self) {
    self.0.abort();
  }
}

impl<T> std::future::Future for AbortOnDrop<T> {
  type Output = std::result::Result<T, tokio::task::JoinError>;

  fn poll(
    mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Self::Output> {
    Pin::new(&mut self.0).poll(cx)
  }
}

/// The select-loop event: handlers carry plain data so no arm's future
/// borrows state a handler needs (the mutation happens after the
/// select, with every borrow released).
enum LoopEvent {
  Submission(Option<Submission>),
  RetryWake,
  Report(Option<WorkerReport>),
  Cancel,
}

/// The manager loop: admission, the retry schedule, worker reports,
/// and the shutdown drain.
async fn run_manager(
  shared: Arc<ManagerShared>, mut submissions: mpsc::Receiver<Submission>,
  reports_tx: mpsc::UnboundedSender<WorkerReport>,
  mut reports: mpsc::UnboundedReceiver<WorkerReport>, base: u128, cancel: watch::Sender<bool>,
  cancel_watch: watch::Receiver<bool>,
) {
  // A dedicated listener clone backs the select arm; the manager's own
  // sender clone lets the dropped-client path run the same shutdown
  // sequence as an explicit begin_shutdown.
  let mut cancel_listener = cancel_watch.clone();
  let mut retry_timer: Pin<Box<Sleep>> = Box::pin(tokio::time::sleep(RETRY_TIMER_IDLE));
  // The per-incarnation admission counter: id order == admission order.
  let mut counter: u64 = 0;
  // The retry schedule: deadline → due tickets (one shared timer at
  // the earliest deadline).
  let mut retries: BTreeMap<Instant, Vec<RetryTicket>> = BTreeMap::new();
  // Coalescing bookkeeping over non-terminal tasks: kind + subject.
  let mut coalescing: BTreeMap<(TaskKind, NodeId), (TaskId, TaskSpec)> = BTreeMap::new();
  // Leave exclusivity: one admitted leave per incarnation (the node
  // shuts down after it anyway).
  let mut leave_task: Option<TaskId> = None;
  let mut outstanding: usize = 0;
  let mut draining = false;
  loop {
    let event = tokio::select! {
      submission = submissions.recv(), if !draining => LoopEvent::Submission(submission),
      _ = &mut retry_timer, if !draining && !retries.is_empty() => LoopEvent::RetryWake,
      report = reports.recv(), if outstanding > 0 => LoopEvent::Report(report),
      _ = cancel_listener.changed(), if !draining => LoopEvent::Cancel,
    };
    match event {
      LoopEvent::Submission(Some(submission)) => {
        admit(
          &shared,
          &mut counter,
          &mut coalescing,
          &mut leave_task,
          &cancel_watch,
          base,
          submission,
          &reports_tx,
          &mut outstanding,
        );
      }
      LoopEvent::Submission(None) => {
        // Every client dropped: run the same stop sequence as an
        // explicit begin_shutdown, then exit with the workers.
        draining = true;
        let _ = cancel.send(true);
      }
      LoopEvent::RetryWake => {
        let now = Instant::now();
        let due_keys: Vec<Instant> = retries
          .range(..=now)
          .map(|(deadline, _)| *deadline)
          .collect();
        for key in due_keys {
          let Some(tickets) = retries.remove(&key) else {
            continue;
          };
          for ticket in tickets {
            spawn_worker(
              &shared,
              &cancel_watch,
              &reports_tx,
              &mut outstanding,
              ticket.id,
              ticket.kind,
              ticket.effect,
              ticket.attempt,
            );
          }
        }
      }
      LoopEvent::Report(Some(report)) => {
        outstanding -= 1;
        match report {
          WorkerReport::Terminal(id) => {
            coalescing.retain(|_, (in_flight, _)| in_flight != &id);
            if leave_task.as_ref() == Some(&id) {
              leave_task = None;
            }
            shared.table.retain_terminal_history(TASK_TERMINAL_HISTORY);
          }
          WorkerReport::Retry {
            id,
            kind,
            effect,
            attempt,
            delay,
          } => {
            // Only cancellable kinds retry; during the drain the wake is
            // dropped and the task stays non-terminal, exactly like a
            // mid-flight cancel.
            if !draining {
              retries
                .entry(Instant::now() + delay)
                .or_default()
                .push(RetryTicket {
                  id,
                  kind,
                  effect,
                  attempt,
                });
            }
          }
          WorkerReport::Cancelled => {}
        }
      }
      LoopEvent::Report(None) => {
        // Unreachable while outstanding > 0 (each live worker holds a
        // report sender); diagnosed rather than propagated.
        tracing::error!("task worker report channel closed with workers outstanding");
      }
      LoopEvent::Cancel => {
        draining = true;
        submissions.close();
        retries.clear();
      }
    }
    rearm_retry_timer(&mut retry_timer, &retries);
    if draining && outstanding == 0 {
      break;
    }
  }
}

/// The admission bookkeeping: shutdown gate, spec shape, coalescing,
/// leave exclusivity, id composition, the `Pending` publication, and
/// the first reconcile spawn. The admission reply always resolves —
/// a dropped reply means the caller went away.
#[allow(clippy::too_many_arguments)]
fn admit(
  shared: &Arc<ManagerShared>, counter: &mut u64,
  coalescing: &mut BTreeMap<(TaskKind, NodeId), (TaskId, TaskSpec)>,
  leave_task: &mut Option<TaskId>, cancel_watch: &watch::Receiver<bool>, base: u128,
  submission: Submission, reports: &mpsc::UnboundedSender<WorkerReport>, outstanding: &mut usize,
) {
  let Submission {
    spec,
    effect,
    reply,
  } = submission;
  let result = admit_inner(
    shared,
    counter,
    coalescing,
    leave_task,
    cancel_watch,
    base,
    &spec,
    effect,
    reports,
    outstanding,
  );
  let _ = reply.send(result);
}

#[allow(clippy::too_many_arguments)]
fn admit_inner(
  shared: &Arc<ManagerShared>, counter: &mut u64,
  coalescing: &mut BTreeMap<(TaskKind, NodeId), (TaskId, TaskSpec)>,
  leave_task: &mut Option<TaskId>, cancel_watch: &watch::Receiver<bool>, base: u128,
  spec: &TaskSpec, effect: TaskEffect, reports: &mpsc::UnboundedSender<WorkerReport>,
  outstanding: &mut usize,
) -> Result<TaskId> {
  if *cancel_watch.borrow() {
    return Err(Error::shutting_down("task admission"));
  }
  spec.check_shape()?;
  let kind = spec.kind().clone();
  // Coalescing: kind + subject, accepted only when the whole spec
  // equals the in-flight one.
  if let Some(subject) = spec.coalesce_key() {
    let key = (kind.clone(), subject);
    if let Some((existing, in_flight_spec)) = coalescing.get(&key)
      && *in_flight_spec == *spec
    {
      return Ok(existing.clone());
    }
    // A same-subject but different-intent submission conflicts while
    // the in-flight task runs.
    if coalescing.contains_key(&key) {
      return Err(Error::conflict("task in flight"));
    }
  }
  if matches!(kind, TaskKind::Leave) && leave_task.is_some() {
    return Err(Error::conflict("task in flight"));
  }
  let next = *counter;
  *counter = next
    .checked_add(1)
    .ok_or_else(|| Error::resource_exhausted("task admission"))?;
  let id = TaskId::compose(base, next)?;
  if !shared
    .table
    .insert_pending(&id, kind.clone(), shared.clock.now())
  {
    return Err(Error::internal("task admission"));
  }
  // The admission transition is an event only: the action hooks first
  // observe at `Running`, because no caller code ever runs on the
  // manager task (the admission is crate-side bookkeeping).
  shared.events().emit(crate::TaskChanged::new(
    id.clone(),
    kind.clone(),
    TaskPhase::Pending,
  ));
  if let Some(subject) = spec.coalesce_key() {
    coalescing.insert((kind.clone(), subject), (id.clone(), spec.clone()));
  }
  if matches!(kind, TaskKind::Leave) {
    *leave_task = Some(id.clone());
  }
  spawn_worker(
    shared,
    cancel_watch,
    reports,
    outstanding,
    id.clone(),
    kind,
    effect,
    1,
  );
  Ok(id)
}

/// One running reconcile attempt: pure crate code around the
/// caller-migrated effect (which runs as its own spawned task, so a
/// panicking effect aborts that task only).
struct Worker {
  shared: Arc<ManagerShared>,
  reports: mpsc::UnboundedSender<WorkerReport>,
  id: TaskId,
  kind: TaskKind,
  effect: TaskEffect,
  attempt: u32,
  cancel: watch::Receiver<bool>,
}

impl Worker {
  async fn run(self) {
    // The report is the worker's last action: keep a sender clone
    // because the attempt consumes the worker.
    let reports = self.reports.clone();
    let report = self.run_attempt().await;
    let _ = reports.send(report);
  }

  async fn run_attempt(mut self) -> WorkerReport {
    let cancellable = cancellable(&self.kind);
    if cancellable && *self.cancel.borrow() {
      return WorkerReport::Cancelled;
    }
    // The permit gate: a cancellable kind releases its queue slot on
    // shutdown instead of waiting out the concurrency bound.
    let permit = if cancellable {
      tokio::select! {
        permit = self.shared.semaphore.acquire() => permit,
        _ = self.cancel.changed() => return WorkerReport::Cancelled,
      }
    } else {
      self.shared.semaphore.acquire().await
    };
    let _permit = match permit {
      Ok(permit) => permit,
      Err(_) => {
        self
          .shared
          .publish_failure(
            &self.id,
            &self.kind,
            Error::internal("task reconcile permit"),
          )
          .await;
        return WorkerReport::Terminal(self.id);
      }
    };
    // The whole attempt body — the `Running` publication, its transition
    // observation (event plus action hooks), the effect, and the terminal
    // publication — runs as its own spawned task, so a panic anywhere in
    // it (including inside caller-registered hook code) surfaces as the
    // aborted join handled below, and the worker always reports back to
    // the manager. The abort-on-drop guard cancels the body when the
    // shutdown cancel wins the select.
    let mut body = AbortOnDrop(tokio::spawn(
      Attempt {
        shared: Arc::clone(&self.shared),
        id: self.id.clone(),
        kind: self.kind.clone(),
        effect: self.effect.clone(),
        attempt: self.attempt,
      }
      .run(),
    ));
    let joined = if cancellable {
      tokio::select! {
        joined = &mut body => joined,
        _ = self.cancel.changed() => return WorkerReport::Cancelled,
      }
    } else {
      body.await
    };
    match joined {
      Ok(AttemptOutcome::Terminal) => WorkerReport::Terminal(self.id),
      Ok(AttemptOutcome::Retry { delay }) => WorkerReport::Retry {
        id: self.id,
        kind: self.kind,
        effect: self.effect,
        // The wake runs the next attempt: the ticket carries the
        // incremented index, so the budget is spent monotonically and
        // the backoff schedule is keyed on the failed attempt.
        attempt: self.attempt + 1,
        delay,
      },
      Err(join_error) => {
        // The attempt body panicked (or was aborted from outside, which
        // nothing does): the typed internal terminal failure through the
        // task's own publication path.
        let failure = if join_error.is_panic() {
          Error::internal("reconciler panicked")
        } else {
          Error::internal("reconciler cancelled")
        };
        self.shared.publish_panicked(&self.id, &self.kind, failure);
        WorkerReport::Terminal(self.id)
      }
    }
  }
}

/// One attempt body, run as its own spawned task (see
/// [`Worker::run_attempt`]).
enum AttemptOutcome {
  /// The task terminalized (succeeded, or failed its last attempt).
  Terminal,
  /// The attempt failed retryably; the manager re-arms the delay.
  Retry { delay: Duration },
}

struct Attempt {
  shared: Arc<ManagerShared>,
  id: TaskId,
  kind: TaskKind,
  effect: TaskEffect,
  attempt: u32,
}

impl Attempt {
  async fn run(self) -> AttemptOutcome {
    if !self
      .shared
      .publish_running(&self.id, &self.kind, self.attempt)
      .await
    {
      // The entry is gone (evicted terminal history) or its lock is
      // poisoned: there is no state left to publish onto.
      return AttemptOutcome::Terminal;
    }
    match (self.effect)(Arc::clone(&self.shared.operations), self.attempt).await {
      Ok(EffectOutcome { output, secret }) => {
        self
          .shared
          .publish_success(&self.id, &self.kind, output, secret)
          .await;
        AttemptOutcome::Terminal
      }
      Err(error) => {
        let policy = retry_policy(&self.kind);
        if self.attempt < policy.max_attempts && policy.class.retryable(error.kind()) {
          AttemptOutcome::Retry {
            delay: policy.backoff(self.attempt),
          }
        } else {
          self
            .shared
            .publish_failure(&self.id, &self.kind, error)
            .await;
          AttemptOutcome::Terminal
        }
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
fn spawn_worker(
  shared: &Arc<ManagerShared>, cancel_watch: &watch::Receiver<bool>,
  reports: &mpsc::UnboundedSender<WorkerReport>, outstanding: &mut usize, id: TaskId,
  kind: TaskKind, effect: TaskEffect, attempt: u32,
) {
  *outstanding += 1;
  let worker = Worker {
    shared: Arc::clone(shared),
    reports: reports.clone(),
    id,
    kind,
    effect,
    attempt,
    cancel: cancel_watch.clone(),
  };
  tokio::spawn(worker.run());
}

/// Rearms the shared retry timer to the earliest pending deadline (or
/// the far-future idle when the schedule is empty).
fn rearm_retry_timer(timer: &mut Pin<Box<Sleep>>, retries: &BTreeMap<Instant, Vec<RetryTicket>>) {
  match retries.keys().next() {
    Some(deadline) => timer.as_mut().reset(*deadline),
    None => timer.as_mut().reset(Instant::now() + RETRY_TIMER_IDLE),
  }
}

#[cfg(test)]
mod tests {
  use std::{
    collections::VecDeque,
    sync::{
      Arc, Mutex,
      atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
  };

  use tokio::sync::{Notify, mpsc};

  use super::{
    EffectOutcome, TaskClient, TaskEffect, TaskManagerDeps, TaskPayload, TaskSpec,
    spawn_task_manager,
  };
  use crate::{
    ActionHook, BoxFuture, Error, ErrorKind, EventOptions, EventReceive, ExtensionRegistry,
    MergeView, NodeId, QualifiedTag, Result, TaskChanged, TaskId, TaskKind, TaskOutput, TaskPhase,
    TaskTransition, identity::testing::SequenceEntropy, task::Task, time::HostWallClock,
  };

  fn deps_with(
    events: Arc<crate::node::EventHub>, extensions: ExtensionRegistry,
  ) -> TaskManagerDeps {
    // The leave signal's receiver is the supervisor's in production; the
    // manager tests never admit a leave effect that sends it.
    let (leave_complete, _leave_signals) = mpsc::channel(1);
    TaskManagerDeps {
      entropy: Arc::new(SequenceEntropy::default()),
      clock: Arc::new(HostWallClock),
      operations: Arc::new(super::super::task_effects::OperationDeps::test_double(
        events,
        Arc::new(extensions),
      )),
      listeners: Default::default(),
      leave_complete,
    }
  }

  fn deps() -> TaskManagerDeps {
    deps_with(
      Arc::new(crate::node::EventHub::new()),
      ExtensionRegistry::new(),
    )
  }

  /// One recorded `(hook tag, from, to)` transition observation.
  type HookCall = (&'static str, TaskPhase, TaskPhase);

  /// An action hook recording every transition it observes, tagged so a
  /// test can assert the canonical tag order of the sequence.
  #[derive(Debug)]
  struct RecordingHook {
    tag: &'static str,
    calls: Arc<Mutex<Vec<HookCall>>>,
  }

  impl ActionHook for RecordingHook {
    fn on_transition<'a>(&'a self, transition: &'a TaskTransition) -> BoxFuture<'a, Result<()>> {
      Box::pin(async move {
        self
          .calls
          .lock()
          .expect("hook calls")
          .push((self.tag, transition.from(), transition.to()));
        Ok(())
      })
    }
  }

  /// An action hook that panics on every transition it observes.
  #[derive(Debug)]
  struct PanickingHook;

  impl ActionHook for PanickingHook {
    fn on_transition<'a>(&'a self, _transition: &'a TaskTransition) -> BoxFuture<'a, Result<()>> {
      Box::pin(async { panic!("scripted action hook panic") })
    }
  }

  /// An action hook that panics only on the terminal success transition.
  #[derive(Debug)]
  struct PanicOnSucceededHook;

  impl ActionHook for PanicOnSucceededHook {
    fn on_transition<'a>(&'a self, transition: &'a TaskTransition) -> BoxFuture<'a, Result<()>> {
      Box::pin(async move {
        assert_ne!(transition.to(), TaskPhase::Succeeded, "scripted hook panic");
        Ok(())
      })
    }
  }

  #[tokio::test]
  async fn action_hooks_run_in_canonical_tag_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut extensions = ExtensionRegistry::new();
    // Registered out of tag order: the registry's own order (not the
    // registration order) decides who observes first.
    extensions
      .register_action_hook(
        QualifiedTag::parse("example.com/hooks/zeta").expect("tag"),
        Arc::new(RecordingHook {
          tag: "zeta",
          calls: Arc::clone(&calls),
        }),
      )
      .expect("registration");
    extensions
      .register_action_hook(
        QualifiedTag::parse("example.com/hooks/alpha").expect("tag"),
        Arc::new(RecordingHook {
          tag: "alpha",
          calls: Arc::clone(&calls),
        }),
      )
      .expect("registration");
    let (client, _manager) = spawn_task_manager(deps_with(
      Arc::new(crate::node::EventHub::new()),
      extensions,
    ))
    .expect("manager");
    let id = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        ok_effect(TaskOutput::SyncRound(())),
      )
      .await
      .expect("admission");
    handle::<()>(&client, &id, TaskKind::SyncRound)
      .wait()
      .await
      .expect("terminal");
    assert_eq!(
      calls.lock().expect("hook calls").clone(),
      vec![
        ("alpha", TaskPhase::Pending, TaskPhase::Running),
        ("zeta", TaskPhase::Pending, TaskPhase::Running),
        ("alpha", TaskPhase::Running, TaskPhase::Succeeded),
        ("zeta", TaskPhase::Running, TaskPhase::Succeeded),
      ]
    );
  }

  #[tokio::test]
  async fn a_panicking_action_hook_fails_the_task_typed_and_the_manager_keeps_serving() {
    let mut extensions = ExtensionRegistry::new();
    extensions
      .register_action_hook(
        QualifiedTag::parse("example.com/hooks/boom").expect("tag"),
        Arc::new(PanickingHook),
      )
      .expect("registration");
    let (client, _manager) = spawn_task_manager(deps_with(
      Arc::new(crate::node::EventHub::new()),
      extensions,
    ))
    .expect("manager");
    for counter in 0..2 {
      let id = client
        .submit(
          TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
          ok_effect(TaskOutput::SyncRound(())),
        )
        .await
        .expect("admission");
      let error = handle::<()>(&client, &id, TaskKind::SyncRound)
        .wait()
        .await
        .expect_err("panicking hook");
      assert_eq!(error.kind(), ErrorKind::Internal);
      assert_eq!(error.context(), "reconciler panicked");
      assert_eq!(
        handle::<()>(&client, &id, TaskKind::SyncRound)
          .status()
          .phase(),
        TaskPhase::Failed,
        "submission {counter} terminalized"
      );
    }
  }

  #[tokio::test]
  async fn a_panicking_terminal_hook_leaves_the_succeeded_phase_standing() {
    let mut extensions = ExtensionRegistry::new();
    extensions
      .register_action_hook(
        QualifiedTag::parse("example.com/hooks/late-boom").expect("tag"),
        Arc::new(PanicOnSucceededHook),
      )
      .expect("registration");
    let (client, _manager) = spawn_task_manager(deps_with(
      Arc::new(crate::node::EventHub::new()),
      extensions,
    ))
    .expect("manager");
    let id = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        ok_effect(TaskOutput::SyncRound(())),
      )
      .await
      .expect("admission");
    // The effect succeeded and published `Succeeded`; the hook panicked
    // while observing that terminal transition. Terminality is monotone,
    // so the phase stands and the waiter still receives the outcome.
    handle::<()>(&client, &id, TaskKind::SyncRound)
      .wait()
      .await
      .expect("the terminal success stands");
    assert_eq!(
      handle::<()>(&client, &id, TaskKind::SyncRound)
        .status()
        .phase(),
      TaskPhase::Succeeded
    );
  }

  #[tokio::test]
  async fn every_transition_emits_its_task_changed_event() {
    let events = Arc::new(crate::node::EventHub::new());
    let mut subscription =
      events.subscribe::<TaskChanged>(EventOptions::new().capacity(16).expect("capacity"));
    let (client, _manager) =
      spawn_task_manager(deps_with(Arc::clone(&events), ExtensionRegistry::new()))
        .expect("manager");
    let id = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        ok_effect(TaskOutput::SyncRound(())),
      )
      .await
      .expect("admission");
    handle::<()>(&client, &id, TaskKind::SyncRound)
      .wait()
      .await
      .expect("terminal");
    let mut phases = Vec::new();
    while phases.len() < 3 {
      let EventReceive::Item(event) = subscription.recv().await.expect("event") else {
        panic!("unexpected subscription state");
      };
      assert_eq!(event.task(), &id);
      assert_eq!(event.kind(), &TaskKind::SyncRound);
      phases.push(event.phase());
    }
    assert_eq!(
      phases,
      vec![TaskPhase::Pending, TaskPhase::Running, TaskPhase::Succeeded]
    );
  }

  fn node(suffix: char) -> NodeId {
    NodeId::parse(&format!("node-00000000000000000000{suffix}")).expect("node id")
  }

  fn merge_view() -> MergeView {
    MergeView::new(node('a'), node('b'))
  }

  /// A freshly issued merge credential: the fixture's consumable secret.
  fn issued_credential() -> crate::IssuedMergeCredential {
    let entropy = SequenceEntropy::default();
    crate::identity::credential::MergeCredentialIssuer::new()
      .issue(
        &entropy,
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(600),
      )
      .expect("issued credential")
  }

  fn handle<T: crate::task::TaskResult>(
    client: &TaskClient, id: &TaskId, kind: TaskKind,
  ) -> Task<T> {
    Task::from_parts(id.clone(), kind, client.observer.clone())
  }

  /// An effect that always succeeds with one output.
  fn ok_effect(output: TaskOutput) -> TaskEffect {
    Arc::new(move |_deps, _attempt| {
      let output = output.clone();
      Box::pin(async move { Ok(EffectOutcome::new(output)) })
    })
  }

  /// An effect that never settles (a wedged effect under test).
  fn wedged_effect() -> TaskEffect {
    Arc::new(|_deps, _attempt| Box::pin(std::future::pending()))
  }

  /// A scripted effect: one queued step per attempt (the last step
  /// repeats for attempts past the script), recording every attempt
  /// number it was invoked with.
  enum Step {
    Ok(TaskOutput),
    Fail(ErrorKind, &'static str),
  }

  struct Scripted {
    steps: Mutex<VecDeque<Step>>,
    attempts: Mutex<Vec<u32>>,
  }

  impl Scripted {
    fn new(steps: Vec<Step>) -> Arc<Self> {
      Arc::new(Self {
        steps: Mutex::new(steps.into()),
        attempts: Mutex::new(Vec::new()),
      })
    }

    fn effect(self: &Arc<Self>) -> TaskEffect {
      let scripted = Arc::clone(self);
      Arc::new(move |_deps, attempt| {
        let scripted = Arc::clone(&scripted);
        Box::pin(async move {
          scripted.attempts.lock().expect("attempts").push(attempt);
          let mut steps = scripted.steps.lock().expect("steps");
          let step = match steps.len() {
            0 => Step::Ok(TaskOutput::SyncRound(())),
            1 => match &steps[0] {
              Step::Ok(output) => Step::Ok(output.clone()),
              Step::Fail(kind, context) => Step::Fail(*kind, context),
            },
            _ => steps.pop_front().expect("scripted step"),
          };
          match step {
            Step::Ok(output) => Ok(EffectOutcome::new(output)),
            Step::Fail(kind, context) => Err(Error::from_parts(kind, context)),
          }
        })
      })
    }

    fn attempts(&self) -> Vec<u32> {
      self.attempts.lock().expect("attempts").clone()
    }
  }

  #[tokio::test]
  async fn retry_exhaustion_terminalizes_with_the_last_error() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let scripted = Scripted::new(vec![Step::Fail(ErrorKind::NotFound, "peer binding")]);
    let id = client
      .submit(
        TaskSpec::new(TaskKind::Join, TaskPayload::None),
        scripted.effect(),
      )
      .await
      .expect("admission");
    let error = handle::<MergeView>(&client, &id, TaskKind::Join)
      .wait()
      .await
      .expect_err("exhausted");
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(error.context(), "peer binding");
    let status = handle::<MergeView>(&client, &id, TaskKind::Join).status();
    assert_eq!(status.attempts(), 4, "network budget");
    assert_eq!(scripted.attempts(), vec![1, 2, 3, 4]);
  }

  #[tokio::test]
  async fn terminal_dial_failures_never_retry() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let scripted = Scripted::new(vec![Step::Fail(
      ErrorKind::AuthenticationFailed,
      "member handshake",
    )]);
    let id = client
      .submit(
        TaskSpec::new(TaskKind::Join, TaskPayload::None),
        scripted.effect(),
      )
      .await
      .expect("admission");
    let error = handle::<MergeView>(&client, &id, TaskKind::Join)
      .wait()
      .await
      .expect_err("terminal dial contract");
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    let status = handle::<MergeView>(&client, &id, TaskKind::Join).status();
    assert_eq!(status.attempts(), 1);
    assert_eq!(scripted.attempts(), vec![1]);
  }

  #[tokio::test]
  async fn once_kinds_never_retry() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let scripted = Scripted::new(vec![Step::Fail(ErrorKind::NotFound, "anything")]);
    let id = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        scripted.effect(),
      )
      .await
      .expect("admission");
    let error = handle::<()>(&client, &id, TaskKind::SyncRound)
      .wait()
      .await
      .expect_err("once policy");
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(scripted.attempts(), vec![1]);
  }

  #[tokio::test]
  async fn local_conflicts_retry_until_the_budget_ends() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let scripted = Scripted::new(vec![Step::Fail(ErrorKind::Conflict, "resource version")]);
    let id = client
      .submit(
        TaskSpec::new(TaskKind::PutResource, TaskPayload::None),
        scripted.effect(),
      )
      .await
      .expect("admission");
    let error = handle::<crate::ResourceMutationView>(&client, &id, TaskKind::PutResource)
      .wait()
      .await
      .expect_err("local budget");
    assert_eq!(error.kind(), ErrorKind::Conflict);
    let status =
      handle::<crate::ResourceMutationView>(&client, &id, TaskKind::PutResource).status();
    assert_eq!(status.attempts(), 3, "local budget");
    assert_eq!(scripted.attempts(), vec![1, 2, 3]);
  }

  #[tokio::test]
  async fn coalescing_returns_the_in_flight_task_id() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let peer = node('p');
    let spec = TaskSpec::new(TaskKind::Connect, TaskPayload::Peer(peer.clone()));
    let first = client
      .submit(spec.clone(), wedged_effect())
      .await
      .expect("admission");
    // The same intent while in flight: the same task.
    let second = client
      .submit(spec, wedged_effect())
      .await
      .expect("coalesced admission");
    assert_eq!(first, second);
    // A different subject: a distinct task.
    let other = client
      .submit(
        TaskSpec::new(TaskKind::Connect, TaskPayload::Peer(node('q'))),
        wedged_effect(),
      )
      .await
      .expect("distinct admission");
    assert_ne!(first, other);
    // A distinct kind over the same subject never coalesces.
    let revoke = client
      .submit(
        TaskSpec::new(TaskKind::Revoke, TaskPayload::Peer(peer.clone())),
        wedged_effect(),
      )
      .await
      .expect("distinct kind");
    assert_ne!(first, revoke);
    // After the in-flight task terminalizes, a new submission is a new
    // task (the coalescing window closes with terminality).
    let quick = client
      .submit(
        TaskSpec::new(TaskKind::Connect, TaskPayload::Peer(node('z'))),
        ok_effect(TaskOutput::Connect(node('z'))),
      )
      .await
      .expect("admission");
    handle::<NodeId>(&client, &quick, TaskKind::Connect)
      .wait()
      .await
      .expect("terminal");
    let _ = first; // the wedged first task stays non-terminal for the rest of the test
  }

  #[tokio::test]
  async fn leave_is_exclusive_while_in_flight() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let spec = TaskSpec::new(TaskKind::Leave, TaskPayload::None);
    let first = client
      .submit(spec.clone(), wedged_effect())
      .await
      .expect("admission");
    let conflict = client
      .submit(spec, wedged_effect())
      .await
      .expect_err("leave exclusivity");
    assert_eq!(conflict.kind(), ErrorKind::Conflict);
    assert_eq!(conflict.context(), "task in flight");
    let _ = first;
  }

  #[tokio::test]
  async fn shutdown_cancels_cancellable_kinds_and_awaits_the_journaled_ones() {
    let (client, manager) = spawn_task_manager(deps()).expect("manager");
    // A cancellable kind wedged mid-effect.
    let wedged = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        wedged_effect(),
      )
      .await
      .expect("admission");
    // A journaled kind whose effect completes only when released.
    let release = Arc::new(Notify::new());
    let gate = release.clone();
    let journaled_effect: TaskEffect = Arc::new(move |_deps, _attempt| {
      let gate = gate.clone();
      Box::pin(async move {
        gate.notified().await;
        Ok(EffectOutcome::new(TaskOutput::ResolveFrozenJournal(())))
      })
    });
    let journaled = client
      .submit(
        TaskSpec::new(TaskKind::ResolveFrozenJournal, TaskPayload::None),
        journaled_effect,
      )
      .await
      .expect("admission");

    manager.begin_shutdown();
    // The cancellable task's wait resolves ShuttingDown without the
    // effect ever settling, and the task stays non-terminal.
    let error = handle::<()>(&client, &wedged, TaskKind::SyncRound)
      .wait()
      .await
      .expect_err("cancelled");
    assert_eq!(error.kind(), ErrorKind::ShuttingDown);
    assert_eq!(
      handle::<()>(&client, &wedged, TaskKind::SyncRound)
        .status()
        .phase(),
      TaskPhase::Running
    );

    // The drain does not complete until the journaled kind settles.
    let (drained, drained_rx) = tokio::sync::oneshot::channel::<()>();
    let drain = tokio::spawn(async move {
      manager.drain().await;
      let _ = drained.send(());
    });
    tokio::time::timeout(Duration::from_millis(50), drained_rx)
      .await
      .expect_err("the drain must wait for the journaled kind");
    release.notify_waiters();
    handle::<()>(&client, &journaled, TaskKind::ResolveFrozenJournal)
      .wait()
      .await
      .expect("journaled terminal");
    tokio::time::timeout(Duration::from_secs(5), drain)
      .await
      .expect("drain completes")
      .expect("drain join");
  }

  #[tokio::test]
  async fn submissions_after_shutdown_fail_typed() {
    let (client, manager) = spawn_task_manager(deps()).expect("manager");
    manager.begin_shutdown();
    let error = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        ok_effect(TaskOutput::SyncRound(())),
      )
      .await
      .expect_err("closed admission");
    assert_eq!(error.kind(), ErrorKind::ShuttingDown);
    assert_eq!(error.context(), "task admission");
    manager.drain().await;
  }

  #[tokio::test]
  async fn the_concurrency_bound_bounds_simultaneous_effects() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut ids = Vec::new();
    for index in 0..8 {
      let live = live.clone();
      let peak = peak.clone();
      let effect: TaskEffect = Arc::new(move |_deps, _attempt| {
        let live = live.clone();
        let peak = peak.clone();
        Box::pin(async move {
          let now = live.fetch_add(1, Ordering::SeqCst) + 1;
          peak.fetch_max(now, Ordering::SeqCst);
          tokio::time::sleep(Duration::from_millis(20)).await;
          live.fetch_sub(1, Ordering::SeqCst);
          Ok(EffectOutcome::new(TaskOutput::SyncRound(())))
        })
      });
      let id = client
        .submit(
          TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
          effect,
        )
        .await
        .expect("admission");
      ids.push((id, index));
    }
    for (id, _index) in ids {
      handle::<()>(&client, &id, TaskKind::SyncRound)
        .wait()
        .await
        .expect("terminal");
      let status = handle::<()>(&client, &id, TaskKind::SyncRound).status();
      assert_eq!(status.phase(), TaskPhase::Succeeded);
    }
    assert!(
      peak.load(Ordering::SeqCst) <= 4,
      "peak simultaneous effects: {}",
      peak.load(Ordering::SeqCst)
    );
  }

  #[tokio::test]
  async fn a_panicking_effect_fails_the_task_typed() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let panicking: TaskEffect = Arc::new(|_deps, _attempt| {
      Box::pin(async {
        panic!("scripted reconciler panic");
      })
    });
    let id = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        panicking,
      )
      .await
      .expect("admission");
    let error = handle::<()>(&client, &id, TaskKind::SyncRound)
      .wait()
      .await
      .expect_err("panic terminal");
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "reconciler panicked");
  }

  #[tokio::test]
  async fn the_terminal_history_is_bounded_and_evicts_oldest_first() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let total = super::TASK_TERMINAL_HISTORY + 44;
    let mut ids = Vec::new();
    for _ in 0..total {
      let id = client
        .submit(
          TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
          ok_effect(TaskOutput::SyncRound(())),
        )
        .await
        .expect("admission");
      ids.push(id);
    }
    // Await the newest task's terminal publication, then the manager's
    // retention pass (which runs on the terminal report, after the
    // watch publish) with a bounded re-read.
    handle::<()>(&client, ids.last().expect("newest"), TaskKind::SyncRound)
      .wait()
      .await
      .expect("terminal");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while client.observer.table.status(&ids[0]).is_some() && std::time::Instant::now() < deadline {
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
      client.observer.table.status(&ids[0]).is_none(),
      "the oldest terminal task is evicted"
    );
    let kept = ids
      .iter()
      .filter(|id| client.observer.table.status(id).is_some())
      .count();
    assert_eq!(kept, super::TASK_TERMINAL_HISTORY, "exactly the bound kept");
    assert!(
      client
        .observer
        .table
        .status(ids.last().expect("newest"))
        .is_some()
    );
  }

  #[tokio::test]
  async fn dropping_every_client_stops_the_manager() {
    let (client, manager) = spawn_task_manager(deps()).expect("manager");
    let wedged = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        wedged_effect(),
      )
      .await
      .expect("admission");
    let observer = client.observer.clone();
    drop(client);
    // The dropped-client path runs the same stop sequence: the cancel
    // watch fires, the cancellable wedged task releases (staying
    // non-terminal), and the manager exits.
    let mut stopped = observer.stop.clone();
    tokio::time::timeout(Duration::from_secs(5), stopped.changed())
      .await
      .expect("cancel signal")
      .expect("stop watch live");
    assert!(*stopped.borrow());
    let error = Task::<()>::from_parts(wedged, TaskKind::SyncRound, observer)
      .wait()
      .await
      .expect_err("stopped manager");
    assert_eq!(error.kind(), ErrorKind::ShuttingDown);
    manager.drain().await;
  }

  #[tokio::test]
  async fn the_success_path_publishes_pending_running_succeeded() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let id = client
      .submit(
        TaskSpec::new(TaskKind::SyncRound, TaskPayload::None),
        ok_effect(TaskOutput::SyncRound(())),
      )
      .await
      .expect("admission");
    handle::<()>(&client, &id, TaskKind::SyncRound)
      .wait()
      .await
      .expect("terminal");
    let status = handle::<()>(&client, &id, TaskKind::SyncRound).status();
    assert_eq!(status.phase(), TaskPhase::Succeeded);
    assert_eq!(status.attempts(), 1);
    assert_eq!(status.error(), None);
  }

  #[test]
  fn the_retry_policies_are_bounded_and_exponential() {
    let network = super::retry_policy(&TaskKind::Join);
    assert_eq!(network.max_attempts, 4);
    assert_eq!(network.backoff(1), Duration::from_millis(100));
    assert_eq!(network.backoff(2), Duration::from_millis(400));
    assert_eq!(network.backoff(3), Duration::from_millis(1_600));
    assert_eq!(network.backoff(4), Duration::from_millis(6_400));
    assert_eq!(network.backoff(5), Duration::from_secs(10), "capped");
    let local = super::retry_policy(&TaskKind::PutResource);
    assert_eq!(local.max_attempts, 3);
    assert_eq!(local.backoff(1), Duration::from_millis(10));
    assert_eq!(local.backoff(2), Duration::from_millis(30), "capped");
    let once = super::retry_policy(&TaskKind::Leave);
    assert_eq!(once.max_attempts, 1);
    assert_eq!(once.backoff(1), Duration::ZERO);
  }

  #[test]
  fn the_credential_outcome_keeps_the_observation_and_the_secret_apart() {
    let issued = issued_credential();
    let expires_at = issued.expires_at();
    let outcome = EffectOutcome::credential_issued(issued);
    match &outcome.output {
      TaskOutput::IssueCredential(observation) => assert_eq!(observation.expires_at(), expires_at),
      other => panic!("not a credential observation: {other:?}"),
    }
    assert!(outcome.secret.is_some(), "the secret rides the once slot");
  }

  #[tokio::test]
  async fn the_credential_secret_is_collected_once_through_the_manager() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    let issued = issued_credential();
    let expires_at = issued.expires_at();
    // The consume-once slot under test: a credential effect can only
    // hand its non-Clone secret out once.
    let slot = Arc::new(Mutex::new(Some(issued)));
    let effect: TaskEffect = Arc::new(move |_deps, _attempt| {
      let slot = Arc::clone(&slot);
      Box::pin(async move {
        let issued = slot
          .lock()
          .expect("credential slot")
          .take()
          .ok_or_else(|| Error::internal("credential effect"))?;
        Ok(EffectOutcome::credential_issued(issued))
      })
    });
    let id = client
      .submit(
        TaskSpec::new(TaskKind::IssueCredential, TaskPayload::None),
        effect,
      )
      .await
      .expect("admission");
    let collected = handle::<crate::IssuedMergeCredential>(&client, &id, TaskKind::IssueCredential)
      .wait()
      .await
      .expect("first collection");
    assert_eq!(collected.expires_at(), expires_at);
    let second = handle::<crate::IssuedMergeCredential>(&client, &id, TaskKind::IssueCredential)
      .wait()
      .await
      .expect_err("the slot is consumed");
    assert_eq!(second.kind(), ErrorKind::InvalidInput);
    assert_eq!(second.context(), "task output already collected");
    // The table keeps the terminal task and its expiry observation.
    let (kind, status) = client
      .observer
      .table
      .status(&id)
      .expect("the terminal entry stays readable");
    assert_eq!(kind, TaskKind::IssueCredential);
    assert_eq!(status.phase(), TaskPhase::Succeeded);
  }

  #[tokio::test]
  async fn retryable_failures_retry_then_succeed() {
    let (client, _manager) = spawn_task_manager(deps()).expect("manager");
    // A Join task under the network policy: NotFound (an unspread
    // binding) retries, then the dial succeeds with the verb's payload.
    let scripted = Scripted::new(vec![
      Step::Fail(ErrorKind::NotFound, "peer binding"),
      Step::Ok(TaskOutput::Join(merge_view())),
    ]);
    let spec = TaskSpec::new(TaskKind::Join, TaskPayload::None);
    let id = client
      .submit(spec, scripted.effect())
      .await
      .expect("admission");
    let view = handle::<MergeView>(&client, &id, TaskKind::Join)
      .wait()
      .await
      .expect("terminal");
    assert_eq!(view, merge_view());
    let status = handle::<MergeView>(&client, &id, TaskKind::Join).status();
    assert_eq!(status.attempts(), 2, "attempts: {:?}", scripted.attempts());
    assert_eq!(scripted.attempts(), vec![1, 2]);
  }
}
