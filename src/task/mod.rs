//! The task entity: the admitted-operation model behind the declarative
//! verb surface. A task is the *observation* of one admitted mutating
//! intent — a printable ordered id, a kind tag (a core verb's constant,
//! or a caller-registered tag under the caller's own domain), a phase
//! machine with typed error and encoded output payloads, and the
//! cloneable caller handle [`Task`] over the shared in-memory task
//! table.
//!
//! The table is deliberately in-memory: durable desired state remains
//! exactly each effect's existing durable footprint (leave intent,
//! resource candidates, revocation/cleanup records). A crash loses only
//! the observation of intent, never more state than the synchronous
//! verb would have lost.

use std::{
  borrow::Cow,
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

/// The canonical-CBOR payloads behind [`TaskOutput`].
pub(crate) mod output;

/// The tag identifying one admitted task's kind: a canonical qualified
/// tag. The core verbs are the associated constants under the builtin
/// domain; a caller-registered kind is any tag under a caller-owned
/// domain — exactly the registration key of the caller's reconciler.
/// The tag *is* the identity, so a caller-defined kind needs no crate
/// change to exist.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskKind(QualifiedTag);

impl TaskKind {
  /// The core verbs, in canonical tag order. Each is the tag the task
  /// surface reports for that verb and the key of the crate's own
  /// policy dispatch (the private core-kind table).
  pub const JOIN: Self = Self(QualifiedTag::from_static("radiata.woooo.tech/tasks/join"));
  pub const LEAVE: Self = Self(QualifiedTag::from_static("radiata.woooo.tech/tasks/leave"));
  pub const CONNECT: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/connect",
  ));
  pub const DISCONNECT: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/disconnect",
  ));
  pub const REVOKE: Self = Self(QualifiedTag::from_static("radiata.woooo.tech/tasks/revoke"));
  pub const PURGE_REVOCATION: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/purge-revocation",
  ));
  pub const CLEANUP: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/cleanup",
  ));
  pub const ISSUE_CLEANUP_CHECKPOINT: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/issue-cleanup-checkpoint",
  ));
  pub const RESOLVE_FROZEN_JOURNAL: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/resolve-frozen-journal",
  ));
  pub const LISTEN: Self = Self(QualifiedTag::from_static("radiata.woooo.tech/tasks/listen"));
  pub const STOP_LISTENER: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/stop-listener",
  ));
  pub const PUT_RESOURCE: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/put-resource",
  ));
  pub const DELETE_RESOURCE: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/delete-resource",
  ));
  pub const PATCH_NODE_METADATA: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/patch-node-metadata",
  ));
  pub const ISSUE_CREDENTIAL: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/issue-credential",
  ));
  pub const ROTATE_CREDENTIAL: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/rotate-credential",
  ));
  pub const START_RECOVERY: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/start-recovery",
  ));
  pub const APPLY_RECEIPT_RETENTION: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/apply-receipt-retention",
  ));
  pub const SYNC_ROUND: Self = Self(QualifiedTag::from_static(
    "radiata.woooo.tech/tasks/sync-round",
  ));

  /// Parses one kind tag: any canonical qualified tag. A tag outside the
  /// core set is a caller-defined kind and must live under a caller-owned
  /// domain to be registrable (see
  /// [`ExtensionRegistry::register_task_reconciler`](crate::ExtensionRegistry::register_task_reconciler)).
  pub fn parse(value: &str) -> Result<Self> {
    Ok(Self(QualifiedTag::parse(value)?))
  }

  /// The canonical tag text.
  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// The kind's qualified tag.
  pub const fn tag(&self) -> &QualifiedTag {
    &self.0
  }
}

impl From<QualifiedTag> for TaskKind {
  fn from(tag: QualifiedTag) -> Self {
    Self(tag)
  }
}

impl std::fmt::Display for TaskKind {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(self.as_str())
  }
}

impl std::fmt::Debug for TaskKind {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_tuple("TaskKind")
      .field(&self.as_str())
      .finish()
  }
}

/// The core verb set as a closed enum: the private dispatch key behind
/// every policy the crate itself owns (the retry class, the slot class,
/// the shutdown drain, and the coalescing rules). A tag outside the set
/// is a caller-defined kind and takes the extension policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreTaskKind {
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
}

/// Every core verb, in canonical tag order: the single source of the
/// closed set. [`CoreTaskKind::from_tag`] scans it, so a verb cannot be
/// added to [`TaskKind`]'s constants and forgotten here.
const CORE_TASK_KINDS: [CoreTaskKind; 19] = [
  CoreTaskKind::Join,
  CoreTaskKind::Leave,
  CoreTaskKind::Connect,
  CoreTaskKind::Disconnect,
  CoreTaskKind::Revoke,
  CoreTaskKind::PurgeRevocation,
  CoreTaskKind::Cleanup,
  CoreTaskKind::IssueCleanupCheckpoint,
  CoreTaskKind::ResolveFrozenJournal,
  CoreTaskKind::Listen,
  CoreTaskKind::StopListener,
  CoreTaskKind::PutResource,
  CoreTaskKind::DeleteResource,
  CoreTaskKind::PatchNodeMetadata,
  CoreTaskKind::IssueCredential,
  CoreTaskKind::RotateCredential,
  CoreTaskKind::StartRecovery,
  CoreTaskKind::ApplyReceiptRetention,
  CoreTaskKind::SyncRound,
];

impl CoreTaskKind {
  /// The core verb one tag names, or `None` for a caller-defined kind.
  pub(crate) fn from_tag(kind: &TaskKind) -> Option<Self> {
    CORE_TASK_KINDS
      .iter()
      .copied()
      .find(|core| core.tag() == *kind)
  }

  /// The verb's tag.
  pub(crate) const fn tag(self) -> TaskKind {
    match self {
      Self::Join => TaskKind::JOIN,
      Self::Leave => TaskKind::LEAVE,
      Self::Connect => TaskKind::CONNECT,
      Self::Disconnect => TaskKind::DISCONNECT,
      Self::Revoke => TaskKind::REVOKE,
      Self::PurgeRevocation => TaskKind::PURGE_REVOCATION,
      Self::Cleanup => TaskKind::CLEANUP,
      Self::IssueCleanupCheckpoint => TaskKind::ISSUE_CLEANUP_CHECKPOINT,
      Self::ResolveFrozenJournal => TaskKind::RESOLVE_FROZEN_JOURNAL,
      Self::Listen => TaskKind::LISTEN,
      Self::StopListener => TaskKind::STOP_LISTENER,
      Self::PutResource => TaskKind::PUT_RESOURCE,
      Self::DeleteResource => TaskKind::DELETE_RESOURCE,
      Self::PatchNodeMetadata => TaskKind::PATCH_NODE_METADATA,
      Self::IssueCredential => TaskKind::ISSUE_CREDENTIAL,
      Self::RotateCredential => TaskKind::ROTATE_CREDENTIAL,
      Self::StartRecovery => TaskKind::START_RECOVERY,
      Self::ApplyReceiptRetention => TaskKind::APPLY_RECEIPT_RETENTION,
      Self::SyncRound => TaskKind::SYNC_ROUND,
    }
  }

  /// Whether the verb's effect is awaited to its terminal phase during
  /// node shutdown (the journaled/store-atomic kinds whose outcome must
  /// settle before teardown completes). Declared onto the reconciler
  /// registration channel by `register_default` (see
  /// [`core_task_policies`]); never derived at dispatch time.
  pub(crate) const fn drains_on_shutdown(self) -> bool {
    matches!(self, Self::Leave | Self::ResolveFrozenJournal)
  }

  /// The execution-slot channel the verb draws from. Declared onto the
  /// reconciler registration channel by `register_default` (see
  /// [`core_task_policies`]); never derived at dispatch time. The match
  /// is exhaustive: a new core verb must declare its class here, so a
  /// forgotten entry is a compile error, never a silent default.
  pub(crate) const fn slot_class(self) -> SlotClass {
    match self {
      Self::Join | Self::Connect => SlotClass::Network,
      Self::Leave
      | Self::Disconnect
      | Self::Revoke
      | Self::PurgeRevocation
      | Self::Cleanup
      | Self::IssueCleanupCheckpoint
      | Self::ResolveFrozenJournal
      | Self::Listen
      | Self::StopListener
      | Self::PutResource
      | Self::DeleteResource
      | Self::PatchNodeMetadata
      | Self::IssueCredential
      | Self::RotateCredential
      | Self::StartRecovery
      | Self::ApplyReceiptRetention
      | Self::SyncRound => SlotClass::Local,
    }
  }

  /// The retry classification the verb's schedule rides. Declared onto
  /// the reconciler registration channel by `register_default` (see
  /// [`core_task_policies`]); never derived at dispatch time. The match
  /// is exhaustive: a new core verb must declare its class here, so a
  /// forgotten entry is a compile error, never a silent degradation to
  /// one-attempt-no-retry.
  pub(crate) const fn retry_class(self) -> RetryClass {
    match self {
      Self::Join | Self::Connect => RetryClass::Network,
      Self::Leave
      | Self::Disconnect
      | Self::Revoke
      | Self::PurgeRevocation
      | Self::Cleanup
      | Self::IssueCleanupCheckpoint
      | Self::ResolveFrozenJournal
      | Self::Listen
      | Self::StopListener
      | Self::PutResource
      | Self::DeleteResource
      | Self::PatchNodeMetadata
      | Self::IssueCredential
      | Self::RotateCredential
      | Self::StartRecovery
      | Self::ApplyReceiptRetention
      | Self::SyncRound => RetryClass::Once,
    }
  }

  /// The coalescing rule the verb's admission applies. Declared onto the
  /// reconciler registration channel by `register_default` (see
  /// [`core_task_policies`]); never derived at dispatch time. The match
  /// is exhaustive: a new core verb must declare its rule here, so a
  /// forgotten entry is a compile error, never a silent degradation to
  /// no-coalescing (or a coalescing shape the admission never checks).
  pub(crate) const fn coalescing(self) -> Coalescing {
    match self {
      Self::Connect => Coalescing::PeerDial,
      Self::Disconnect | Self::PurgeRevocation | Self::Cleanup => Coalescing::Peer,
      Self::Revoke => Coalescing::RevokeKey,
      Self::Join
      | Self::Leave
      | Self::IssueCleanupCheckpoint
      | Self::ResolveFrozenJournal
      | Self::Listen
      | Self::StopListener
      | Self::PutResource
      | Self::DeleteResource
      | Self::PatchNodeMetadata
      | Self::IssueCredential
      | Self::RotateCredential
      | Self::StartRecovery
      | Self::ApplyReceiptRetention
      | Self::SyncRound => Coalescing::None,
    }
  }

  /// The verb's full declared execution policy: the single record the
  /// registration channel installs (see [`core_task_policies`]) and the
  /// admission resolves.
  pub(crate) const fn policy(self) -> TaskReconcilePolicy {
    TaskReconcilePolicy {
      slot_class: self.slot_class(),
      drains_on_shutdown: self.drains_on_shutdown(),
      retry_class: self.retry_class(),
      coalescing: self.coalescing(),
    }
  }
}

/// The retry classification behind a kind's bounded schedule: which
/// typed error categories may retry. The taxonomy is the crate's own
/// verbatim — e.g. an unspread binding (`NotFound`) is a retryable
/// convergence state for a network dial, while
/// `AuthenticationFailed`/`Revoked` are the documented terminal dial
/// contract. Declared per kind on the reconciler registration channel
/// (see [`core_task_policies`]); the manager derives the schedule from
/// the admission-resolved record, never from the tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryClass {
  /// Join/connect dials: convergence and transport transients retry.
  Network,
  /// Caller-registered custom kinds: a returned `Err` never re-arms the
  /// schedule (the reconciler's explicit `Retry` decision is the only
  /// re-arm path — see the manager's `EffectOutcome::Retry`), so the
  /// class itself treats every error as terminal.
  Extension,
  /// Everything else: one attempt, no retry.
  Once,
}

impl RetryClass {
  /// Whether a returned error of this kind may re-arm the schedule
  /// under this class.
  pub(crate) const fn retryable(self, kind: ErrorKind) -> bool {
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
      RetryClass::Extension | RetryClass::Once => false,
    }
  }
}

/// The coalescing rule a kind's registration declares: whether one
/// subject's in-flight task admits later same-intent submissions, and
/// which payload shape carries that subject. Declared per kind on the
/// reconciler registration channel (see [`core_task_policies`]); the
/// manager derives the admission shape check and the coalescing key
/// from the resolved record, never from the tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Coalescing {
  /// The kind never coalesces: every admission is a fresh task.
  None,
  /// Coalesces on the dialed peer; the payload is the whole dial intent
  /// (the manager's `TaskPayload::PeerDial`), so a coalesced submission
  /// may only join a dial to the same endpoint.
  PeerDial,
  /// Coalesces on the acted-on peer (the manager's
  /// `TaskPayload::Peer`).
  Peer,
  /// Coalesces on the revoke subject; the pinned expected key rides the
  /// payload (the manager's `TaskPayload::Revoke`) and is part of the
  /// compared intent.
  RevokeKey,
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
  /// such workflow deadlocks on itself). Same-class recursive waiting
  /// is refused, not merely discouraged: a submission made from inside
  /// an effect of the same class is a typed admission refusal (the
  /// nested-submit refusal), because awaiting a task of one's own
  /// bounded channel can self-deadlock on that budget.
  Extension,
}

/// The execution policy a task kind's registration declares: the slot
/// class its effect draws from, whether the shutdown drain awaits it to
/// terminality, the retry classification its schedule rides, and the
/// coalescing rule its admission applies. The policy rides the
/// reconciler registration (the core verbs declare theirs through the
/// same channel in
/// [`ExtensionRegistry::register_default`](crate::ExtensionRegistry::register_default),
/// see [`core_task_policies`]); it is never derived from the tag being
/// a core verb. Every per-kind behavior the manager dispatches on —
/// slot routing, the shutdown drain, the retry schedule, and the
/// coalescing shape/key — reads this one admission-resolved record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskReconcilePolicy {
  /// The execution-slot channel the kind's effect draws from (see
  /// [`SlotClass`]). The core budgets live in
  /// [`NodeConfig::with_task_reconcile_slots`](crate::NodeConfig::with_task_reconcile_slots);
  /// the extension channel's budget lives in
  /// [`NodeConfig::with_task_reconcile_extension_slots`](crate::NodeConfig::with_task_reconcile_extension_slots).
  pub(crate) slot_class: SlotClass,
  /// Whether the kind's effect is awaited to its terminal phase during
  /// node shutdown instead of being cancelled on the manager's cancel
  /// watch: the journaled/store-atomic kinds whose outcome must settle
  /// before teardown completes. Every other kind's effect may exit
  /// mid-flight, leaving the task non-terminal for the process.
  pub(crate) drains_on_shutdown: bool,
  /// The retry classification the kind's bounded schedule rides (see
  /// [`RetryClass`]).
  pub(crate) retry_class: RetryClass,
  /// The coalescing rule the kind's admission applies (see
  /// [`Coalescing`]).
  pub(crate) coalescing: Coalescing,
}

impl TaskReconcilePolicy {
  /// The extension policy every caller-registered kind declares: its
  /// own slot channel, cancelled on shutdown, with the reconciler-owned
  /// retry semantics and no coalescing.
  pub(crate) const EXTENSION: Self = Self {
    slot_class: SlotClass::Extension,
    drains_on_shutdown: false,
    retry_class: RetryClass::Extension,
    coalescing: Coalescing::None,
  };
}

/// Every core verb's declared execution policy: the single source of
/// the core kinds' slot class and shutdown drain, installed onto the
/// reconciler registration channel by `register_default`. A caller
/// kind never appears here — its registration declares
/// [`TaskReconcilePolicy::EXTENSION`].
pub(crate) fn core_task_policies() -> impl Iterator<Item = (TaskKind, TaskReconcilePolicy)> {
  CORE_TASK_KINDS
    .iter()
    .copied()
    .map(|core| (core.tag(), core.policy()))
}

/// The task phase machine. `Succeeded` and `Failed` are terminal; no
/// transition ever leaves a terminal state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
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

/// One task's typed failure surface: the effect's terminal error as
/// the stable kind plus its full-detail context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskError {
  kind: ErrorKind,
  context: Cow<'static, str>,
}

impl TaskError {
  /// Projects one error onto the terminal-failure surface: the stable
  /// kind plus its full-detail context. Also the constructor for the
  /// explicit [`ReconcileDecision::Failed`] decision.
  pub fn from_error(error: Error) -> Self {
    let (kind, context) = error.into_parts();
    Self { kind, context }
  }

  /// The stable, secret-safe error category.
  pub const fn kind(&self) -> ErrorKind {
    self.kind
  }

  /// The error context: the same dynamic surface the crate's [`Error`]
  /// carries. It may name the offending value — the crate reports full
  /// detail, and redaction is an upper layer's policy (cryptographic
  /// secret hygiene is a separate, untouched rule).
  pub fn as_str(&self) -> &str {
    &self.context
  }

  pub(crate) fn into_error(self) -> Error {
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

/// One task's terminal success payload: the opaque payload bytes, stored
/// on the task so late `wait()` callers can read the outcome after the
/// fact from the bounded terminal history.
///
/// A core verb's payload is its result in the crate's canonical CBOR
/// encoding; a caller-defined kind's payload is exactly the bytes its
/// reconciler returned. The typed form of a core result is recovered
/// through [`Task::wait`], which decodes the payload under the kind the
/// handle was admitted for; the repeatedly readable view exposes the
/// bytes. The credential kinds' payload carries the
/// [`CredentialIssued`] observation only — the secret is collected once
/// through the typed handle (see [`CredentialIssued`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskOutput {
  bytes: Arc<[u8]>,
}

impl TaskOutput {
  /// The opaque payload bytes.
  pub fn bytes(&self) -> &[u8] {
    &self.bytes
  }

  pub(crate) fn new(bytes: Arc<[u8]>) -> Self {
    Self { bytes }
  }
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
  pub fn error(&self) -> Option<TaskError> {
    self.error.clone()
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

  pub(crate) fn status(&self) -> TaskStatus {
    TaskStatus::new(self.phase, self.attempts, self.error.clone())
  }
}

/// One task-table entry: the kind, the admission-resolved execution
/// policy, the per-task status watch, and the terminal payloads.
/// `secret` holds an issued credential exactly until the first typed
/// `wait()` collects it; eviction and shutdown drop the entry, and the
/// secret's own zeroizing drop does the rest.
pub(crate) struct TaskEntry {
  pub(crate) kind: TaskKind,
  pub(crate) policy: TaskReconcilePolicy,
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
    self
      .entries
      .lock()
      .map_err(|_| Error::poisoned("task table"))
  }

  /// Inserts one admitted task's `Pending` entry, carrying the
  /// execution policy admission resolved from the kind's registration
  /// (the single resolution point: every later consumer — the slot
  /// channel, the shutdown drain, the wait arbitration — reads the
  /// entry, never the registry). `false` when the id already exists (an
  /// admission invariant violation, never a caller path).
  pub(crate) fn insert_pending(
    &self, id: &TaskId, kind: TaskKind, policy: TaskReconcilePolicy, created: SystemTime,
  ) -> bool {
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
        policy,
        status,
        output: None,
        secret: None,
      },
    );
    true
  }

  /// Whether the id's effect is awaited to its terminal phase by the
  /// shutdown drain, read off the admission-resolved registration
  /// policy. `None` for an unknown or evicted id.
  pub(crate) fn drains_on_shutdown(&self, id: &TaskId) -> Option<bool> {
    self
      .lock()
      .ok()
      .and_then(|entries| entries.get(id).map(|entry| entry.policy.drains_on_shutdown))
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
  pub(crate) fn page_views(
    &self, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<crate::view::TaskPage> {
    let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
    // Collect the (id bytes, view) pairs under the lock, then page them
    // through the shared in-memory keyset loop; the guard drops before
    // the page is assembled.
    let entries = self
      .lock()?
      .iter()
      .map(|(id, entry)| {
        (
          id.as_str().as_bytes().to_vec(),
          crate::view::TaskView::from_record(
            id.clone(),
            entry.kind.clone(),
            &entry.status.borrow(),
            entry.output.clone(),
          ),
        )
      })
      .collect::<Vec<_>>();
    crate::paging::finish_page(
      crate::paging::page_keys(entries, cursor, limit),
      crate::view::TaskPage::new,
    )
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
          entry.policy.slot_class == class && !entry.status.borrow().phase.is_terminal()
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
  /// shutdown drain does not await — read off the admission-resolved
  /// registration policy). A kind the drain awaits to
  /// terminality (the journaled leave and frozen-journal resolution)
  /// still resolves with its real outcome: the manager publishes it
  /// before the drain completes.
  pub(crate) async fn await_terminal(&self, id: &TaskId) -> Result<TaskStatusRecord> {
    // The drain decision first: an unknown id falls through to the
    // watch lookup's typed not-found below.
    let drains = self.table.drains_on_shutdown(id);
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
        changed = stop.changed() => changed.is_err() || !drains.unwrap_or(false),
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
/// [`TaskOutput`] payload to the verb's historical return type, once per
/// verb output, and only this crate can implement it.
mod private {
  pub(crate) trait Sealed {}
}

pub(crate) trait TaskResult: private::Sealed + Sized + Send + 'static {
  /// Builds the verb's success value from the stored output, decoded
  /// under the kind the handle was admitted for (a kind outside that
  /// verb's set is the typed internal mismatch). The `secret` slot is
  /// the consumed-once credential payload: the first collector receives
  /// `Some`, every later caller `None` (a typed invalid-input error for
  /// the credential kinds, ignored by the rest).
  fn from_output(
    kind: &TaskKind, output: TaskOutput, secret: Option<IssuedMergeCredential>,
  ) -> Result<Self>;
}

/// The mismatch error for every wrong-kind mapping: the handle's type
/// and the task's kind drifted, which only a crate bug can cause.
const OUTPUT_MISMATCH: &str = "task output";

/// One impl row per verb return type: the kinds whose payload the type
/// decodes (matched against the handle's admitted kind) plus the payload
/// decoder. The unit result and the credential kinds' consumed-once
/// secret slot have their own impls below.
macro_rules! task_result {
  ($($ty:ty => [$($kind:ident)|+] via $decode:path),+ $(,)?) => { $(
    impl TaskResult for $ty {
      fn from_output(
        kind: &TaskKind, output: TaskOutput, _secret: Option<IssuedMergeCredential>,
      ) -> Result<Self> {
        match CoreTaskKind::from_tag(kind) {
          $(Some(CoreTaskKind::$kind) => $decode(output.bytes()),)+
          _ => Err(Error::internal(OUTPUT_MISMATCH)),
        }
      }
    }
    impl private::Sealed for $ty {}
  )+ };
}

task_result!(
  MergeView => [Join] via output::decode_join,
  LeaveOutcome => [Leave] via output::decode_leave,
  NodeId => [Connect] via output::decode_connect,
  RevokeOutcome => [Revoke] via output::decode_revoke,
  i64 => [IssueCleanupCheckpoint] via output::decode_checkpoint,
  ListenerView => [Listen] via output::decode_listen,
  ResourceMutationView => [PutResource | DeleteResource] via output::decode_resource_mutation,
  MemberView => [PatchNodeMetadata] via output::decode_member,
  RecoveryView => [StartRecovery] via output::decode_recovery,
  ReceiptRetentionReport => [ApplyReceiptRetention] via output::decode_receipt_retention,
);

impl TaskResult for () {
  fn from_output(
    kind: &TaskKind, output: TaskOutput, _secret: Option<IssuedMergeCredential>,
  ) -> Result<Self> {
    match CoreTaskKind::from_tag(kind) {
      Some(
        CoreTaskKind::Disconnect
        | CoreTaskKind::PurgeRevocation
        | CoreTaskKind::Cleanup
        | CoreTaskKind::ResolveFrozenJournal
        | CoreTaskKind::StopListener
        | CoreTaskKind::SyncRound,
      ) => output::decode_unit(output.bytes()),
      // A caller-defined kind's payload is the reconciler's own bytes:
      // the crate decodes nothing out of it.
      None => Ok(()),
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl TaskResult for IssuedMergeCredential {
  fn from_output(
    kind: &TaskKind, output: TaskOutput, secret: Option<IssuedMergeCredential>,
  ) -> Result<Self> {
    match CoreTaskKind::from_tag(kind) {
      Some(CoreTaskKind::IssueCredential | CoreTaskKind::RotateCredential) => {
        // The payload is the non-secret expiry observation; decoding it
        // pins that the stored bytes are the shape this kind owns.
        output::decode_credential(output.bytes())?;
        secret.ok_or_else(|| Error::invalid_input("task output already collected"))
      }
      _ => Err(Error::internal(OUTPUT_MISMATCH)),
    }
  }
}

impl private::Sealed for () {}
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
  /// without a runtime round trip.
  ///
  /// `None` means the id left the live table and the bounded terminal
  /// history: the task was evicted long after it terminalized, so the
  /// runtime no longer observes it. An evicted task has no status at all —
  /// it is never reported as a fresh `Pending` admission — and the typed
  /// surfaces ([`crate::Tasks::get`], [`crate::Tasks::wait`]) report the
  /// same absence as `None` and a typed not-found error.
  pub fn status(&self) -> Option<TaskStatus> {
    self
      .observer
      .table
      .status(&self.id)
      .map(|(_, status)| status)
  }

  /// Resolves when the task reaches a terminal phase: `Ok(T)` on
  /// `Succeeded`, the typed effect error on `Failed`, and
  /// [`ErrorKind::ShuttingDown`] if the node stops before the effect
  /// settles. A kind the shutdown drain awaits to terminality (the
  /// journaled leave and frozen-journal resolution) still resolves with
  /// its real outcome: the manager publishes it before the drain
  /// completes.
  pub async fn wait(self) -> Result<T> {
    let record = self.observer.await_terminal(&self.id).await?;
    resolve_terminal::<T>(record, &self.id, &self.kind, &self.observer.table)
  }
}

/// Maps one terminal status record to its result: the success path
/// takes (consumes) the secret slot and maps the stored output through
/// [`TaskResult`] under the handle's expected kind; the failure path
/// rebuilds the typed error.
fn resolve_terminal<T: TaskResult>(
  record: TaskStatusRecord, id: &TaskId, kind: &TaskKind, table: &TaskTable,
) -> Result<T> {
  match record.phase {
    TaskPhase::Succeeded => {
      let collected = table.update(id, |entry| (entry.output.clone(), entry.secret.take()));
      match collected {
        // A `Succeeded` entry always carries its output; the missing
        // shapes are internal invariant violations, never caller data.
        // The payload decodes under the kind this handle was admitted
        // for: a drift between the two decodes as the typed internal
        // mismatch, never caller data.
        Ok(Some((Some(output), secret))) => T::from_output(kind, output, secret),
        Ok(Some((None, _))) => Err(Error::internal(OUTPUT_MISMATCH)),
        Ok(None) => Err(Error::not_found("task")),
        Err(error) => Err(error),
      }
    }
    TaskPhase::Failed => Err(
      record
        .error
        .map_or_else(|| Error::internal("task failure"), TaskError::into_error),
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
/// caller's admission path, before any IO; they must not block, because
/// a slow or waiting hook stalls the caller's `put().await`. `observed`
/// runs on the node's bounded observation lanes after this node's own
/// commit lands, off the write task's execution slot.
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
  /// the put or delete. Cluster visibility is observable through
  /// [`crate::ResourceChanged`], which reports both local commits and
  /// the peer-converged records the reconcile plane applies; its
  /// [`origin`](crate::ResourceChanged::origin) distinguishes the two
  /// and its [`removal`](crate::ResourceChanged::removal) says whether
  /// the winner is a removal. The observation runs on the node's
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
/// reconcile half of a caller-registered [`TaskKind`] tag. Registered
/// through
/// [`ExtensionRegistry::register_task_reconciler`](crate::ExtensionRegistry::register_task_reconciler)
/// under a caller-owned tag and dispatched by the `tasks().submit`
/// admission.
///
/// A reconciler runs on the extension slot channel: it may freely await
/// core verbs (the local and network classes) through its handle, but
/// never another extension-kind task — the extension channel's bounded
/// budget is not reentrant, and same-class recursive waiting can
/// self-deadlock. The refusal is enforced, not documented: a submission
/// made from inside an effect of the same slot class fails admission
/// with a typed conflict error instead of deadlocking (see `SlotClass`).
///
/// One reconciler registration record: the reconciler itself (the core
/// verbs declare policy-only records — their effects are the runtime's
/// own closures, never registered reconcilers) plus the execution
/// policy the registration declares.
pub(crate) struct TaskReconcilerRegistration {
  pub(crate) reconciler: Option<Arc<dyn TaskReconciler>>,
  pub(crate) policy: TaskReconcilePolicy,
}

pub trait TaskReconciler: std::fmt::Debug + Send + Sync + 'static {
  /// Produces the effect for one attempt. `Ok(Succeeded)` completes the
  /// task with an empty output payload, `Ok(SucceededWithOutput)`
  /// completes it with the caller's opaque bytes, `Ok(Retry)` re-arms
  /// the bounded retry schedule without progress, and `Ok(Failed)` or
  /// `Err` terminalizes the task as failed with that error — the crate
  /// never re-runs a failed attempt on its own; retrying a failed
  /// effect is the caller's logic to re-submit.
  fn reconcile<'a>(&'a self, ctx: ReconcileContext) -> BoxFuture<'a, Result<ReconcileDecision>>;
}

/// What one reconcile attempt decided.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReconcileDecision {
  /// The effect completed: the task terminalizes `Succeeded` with an
  /// empty output payload.
  Succeeded,
  /// The effect completed with the caller's opaque output payload: the
  /// bytes become the task's [`TaskOutput`] payload verbatim, observable
  /// through [`TaskView::output`](crate::TaskView::output).
  SucceededWithOutput(Vec<u8>),
  /// The effect made no progress: re-arm the bounded retry schedule.
  /// The only decision that retries an attempt — an error or a `Failed`
  /// decision terminalizes the task.
  Retry,
  /// The effect decided to fail: the task terminalizes `Failed` with
  /// the carried error, exactly like a returned `Err`, but as an
  /// explicit terminal decision rather than an exceptional one.
  Failed(TaskError),
}

/// The owned context of one reconcile attempt.
///
/// The handle is the ordinary public node surface — reads, watches,
/// `send`, `open_stream`: a custom kind is a caller workflow over the
/// crate's public contract, never privileged core access (no store, no
/// sessions, no supervisor internals).
#[derive(Clone)]
pub struct ReconcileContext {
  handle: crate::NodeHandle,
  spec: CustomTaskSpec,
  attempt: u32,
  last_error: Option<TaskError>,
}

impl ReconcileContext {
  /// The ordinary public node surface this attempt reconciles through.
  pub const fn handle(&self) -> &crate::NodeHandle {
    &self.handle
  }

  /// The caller's submission this attempt belongs to.
  pub const fn spec(&self) -> &CustomTaskSpec {
    &self.spec
  }

  /// The 1-based reconcile attempt number of this context.
  pub const fn attempt(&self) -> u32 {
    self.attempt
  }

  /// The typed error of the previous attempt, once one failed.
  pub fn last_error(&self) -> Option<TaskError> {
    self.last_error.clone()
  }

  pub(crate) const fn new(
    handle: crate::NodeHandle, spec: CustomTaskSpec, attempt: u32, last_error: Option<TaskError>,
  ) -> Self {
    Self {
      handle,
      spec,
      attempt,
      last_error,
    }
  }
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

  use super::{
    CORE_TASK_KINDS, Coalescing, CoreTaskKind, ObservationLanes, ResourceHook, RetryClass,
    SlotClass, TASK_OBSERVATION_INBOX, TaskKind, TaskReconcilePolicy, TaskTable,
    core_task_policies, lane_of, notify_resource_observers,
  };
  use crate::{ErrorKind, NodeId, Result, TaskId};

  /// The core kind set is one table: every constant parses to itself
  /// (the const constructor computes the same offsets the parser does),
  /// maps back onto its `CoreTaskKind`, and its declared policy — the
  /// one `core_task_policies` installs onto the registration channel —
  /// agrees with the verb's class and drain.
  #[test]
  fn every_core_kind_constant_parses_maps_and_declares_its_policy() {
    let declared: Vec<(TaskKind, TaskReconcilePolicy)> = core_task_policies().collect();
    assert_eq!(declared.len(), CORE_TASK_KINDS.len());
    for core in CORE_TASK_KINDS {
      let tag = core.tag();
      assert_eq!(
        TaskKind::parse(tag.as_str()).expect("parse"),
        tag,
        "the fixed tag text drifted from the parser's canonical form"
      );
      assert_eq!(CoreTaskKind::from_tag(&tag), Some(core));
      let (_, policy) = declared
        .iter()
        .find(|(kind, _)| kind == &tag)
        .expect("every core verb declares a policy");
      assert_eq!(
        policy.slot_class,
        match core {
          CoreTaskKind::Join | CoreTaskKind::Connect => SlotClass::Network,
          _ => SlotClass::Local,
        }
      );
      assert_eq!(
        policy.drains_on_shutdown,
        matches!(
          core,
          CoreTaskKind::Leave | CoreTaskKind::ResolveFrozenJournal
        )
      );
      assert_eq!(
        policy.retry_class,
        match core {
          CoreTaskKind::Join | CoreTaskKind::Connect => RetryClass::Network,
          _ => RetryClass::Once,
        }
      );
      assert_eq!(
        policy.coalescing,
        match core {
          CoreTaskKind::Connect => Coalescing::PeerDial,
          CoreTaskKind::Disconnect | CoreTaskKind::PurgeRevocation | CoreTaskKind::Cleanup =>
            Coalescing::Peer,
          CoreTaskKind::Revoke => Coalescing::RevokeKey,
          _ => Coalescing::None,
        }
      );
    }
  }

  /// A caller-defined kind is just a tag outside the core set: it never
  /// collides with a core verb, and the extension policy its registration
  /// declares is not derived from any core table entry.
  #[test]
  fn a_caller_tag_takes_the_extension_policy() {
    let caller = TaskKind::parse("example.com/tasks/v1/probe").expect("tag");
    assert_eq!(CoreTaskKind::from_tag(&caller), None);
    assert!(!core_task_policies().any(|(kind, _)| kind == caller));
    assert!(CORE_TASK_KINDS.iter().all(|core| core.tag() != caller));
  }

  struct Harness {
    table: TaskTable,
    next: u64,
  }

  impl Harness {
    fn new() -> Self {
      Self {
        table: TaskTable::new(),
        next: 1,
      }
    }

    fn admit(&mut self, kind: TaskKind) -> TaskId {
      let id = TaskId::compose(0, self.next).expect("composition");
      self.next += 1;
      assert!(self.table.insert_pending(
        &id,
        kind,
        super::TaskReconcilePolicy::EXTENSION,
        SystemTime::UNIX_EPOCH
      ));
      id
    }
  }

  fn node(suffix: char) -> NodeId {
    let text = format!("node-00000000000000000000{suffix}");
    NodeId::parse(&text).expect("node id")
  }

  /// The observation-lane regression at the facility level: a wedged
  /// observation parks its lane's runner, the lane's inbox bounds how much
  /// further work may queue behind it, the next observation is dropped with the
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

  /// The resource-observer half: awaiting
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

  /// A table whose lock was poisoned reports the typed internal error
  /// instead of posing as an empty page: the read never invents "no
  /// tasks" out of a broken table.
  #[test]
  fn page_views_reports_a_poisoned_table_instead_of_an_empty_page() {
    let mut harness = Harness::new();
    harness.admit(TaskKind::SYNC_ROUND);
    let poisoner = harness.table.clone();
    // Panicking while holding the guard poisons the shared table.
    let _ = std::thread::spawn(move || {
      let _guard = poisoner.lock().expect("task table guard");
      panic!("poison the task table");
    })
    .join();

    let error = harness.table.page_views(None, 8).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "task table");
  }
}
