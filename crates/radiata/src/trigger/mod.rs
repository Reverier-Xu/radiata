//! Trigger declarations as durable node-local rows: the declarative
//! surface behind time and event triggers.
//!
//! A trigger row is a node policy, not cluster state: it lives in the
//! dedicated node-local trigger family (the reconcile plane owns no lane
//! for its namespace, so the rows are never carried between nodes) and
//! survives restarts. One row carries its source — a `sched` schedule
//! expression for a time trigger or a [`SubscriptionPredicate`] for an
//! event trigger — and its target: the qualified tag of a registered
//! caller-owned task reconciler. The row is spec-only: the trigger
//! *policy* (overlap = skip, missed tick = skip, never replay) is the
//! `sched` engine's declared behavior, not per-row state.
//!
//! The rows are the durable declarations; the `sched` task table is the
//! runtime state, rebuilt from the rows on every incarnation. A time
//! trigger's next window is computed from the current clock, so a node
//! that was down across a window does not replay it — the same
//! stale-tick policy the `sched` engine applies to a late dispatch. The
//! evaluation pass keeps the table in step with the rows (registration,
//! replacement, removal) and refreshes the event-trigger cache. Event
//! triggers are evaluated push-driven against the live change stream,
//! reusing the W2-2 emit-side predicate evaluation (one matching path).
//!
//! Schedules name their frame explicitly (`Z`, a fixed offset, or an
//! IANA zone): the core refuses a device-local pattern at registration,
//! fail-closed, so fire times never depend on the host's timezone.

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
};

use minicbor::{Decode, Encode};
use sched::{Schedule, TaskId, Timestamp};
use tokio::sync::{Notify, mpsc};

use crate::{
  Error, ProviderErrorContext, ProviderErrorKind, Result, StoreKey, StoreNamespace, StoreOperation,
  StoreValue, SubscriptionPredicate,
  api::Entropy,
  extension_registry::ExtensionRegistry,
  protocol::{CborLimits, QualifiedTag, decode_canonical_strict, encode_canonical},
  storage::MetadataStore,
};

/// The node-local trigger family: only this node writes it through the
/// core-verb entry, and the reconcile plane owns no lane for its
/// namespace, so trigger declarations never replicate.
pub(crate) const TRIGGER_NAMESPACE: &str = "radiata.woooo.tech/metadata/v1/trigger";

/// The canonical body of one trigger row.
pub(crate) const TRIGGER_SCHEMA: &str = "radiata.woooo.tech/schemas/v1/trigger";
/// Version 2 dropped the time-trigger watermark: the `sched` task table
/// is the runtime state now, and the row is declaration-only. A version
/// 1 row fails the schema check and is skipped with a warn (fail-closed).
const TRIGGER_RECORD_VERSION: u16 = 2;
/// One row is a handful of short strings; the bound matches the other
/// flat record families.
const TRIGGER_LIMITS: CborLimits = CborLimits::new(4, 64, 8 * 1024);

/// The bounded trigger-row population one evaluation pass considers: a
/// node whose trigger table grew past this cap evaluates the first cap
/// rows in canonical key order every pass (the bound degrades
/// bounded, never unbounded).
pub(crate) const TRIGGER_ROW_CAP: usize = 256;

/// The depth of the fire queue between the evaluation pass (and the
/// event path) and the dispatch engine: a full queue drops the fire
/// with a warn — the overlap policy is skip, never queue.
pub(crate) const TRIGGER_FIRE_QUEUE: usize = 64;

/// The bound on a trigger's caller-chosen name: a non-empty bounded
/// UTF-8 store key, no grammar beyond the store key's own byte rules.
const TRIGGER_NAME_MAX_BYTES: usize = 128;

/// What fires a trigger: a `sched` schedule expression against the wall
/// clock, or a subscription predicate against the live change stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TriggerSource {
  /// A `sched` schedule expression in its declared frame (`Z`, a fixed
  /// offset, or an IANA zone; the device-local frame is refused at
  /// registration).
  Time { pattern: String },
  /// A subscription predicate over resource changes.
  Event { predicate: SubscriptionPredicate },
}

/// One trigger fire enqueued for dispatch: the trigger that fired, the
/// source kind that fired it, and the target task kind to admit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TriggerFire {
  pub(crate) trigger: String,
  pub(crate) source: crate::TriggerSourceKind,
  pub(crate) target: QualifiedTag,
}

/// One cached event trigger: the predicate plus the target kind, kept in
/// the engine's in-memory view so the live change stream evaluates
/// without a store scan per event. Refreshed by every evaluation pass.
#[derive(Clone, Debug)]
pub(crate) struct EventTrigger {
  pub(crate) predicate: SubscriptionPredicate,
  pub(crate) target: QualifiedTag,
}

/// The trigger engine's shared state: the event-trigger cache the
/// evaluation pass refreshes, the bounded fire queue the dispatch
/// engine drains, and the `sched` task table that drives time triggers.
/// All three halves are available wherever the operation planes are;
/// the default state has a closed fire queue (no engine — enqueued
/// fires drop with a warn) and an empty scheduler.
#[derive(Clone)]
pub(crate) struct TriggerState {
  event_rows: Arc<Mutex<BTreeMap<String, EventTrigger>>>,
  fires: Arc<mpsc::Sender<TriggerFire>>,
  scheduler: Arc<Mutex<TriggerScheduler>>,
  wake: Arc<Notify>,
}

/// The `sched` task table plus the declaration each task was registered
/// from: the evaluation pass replaces a task when its declaration
/// changes, and the dispatch engine drives the table's next-fire
/// computation.
#[derive(Default)]
struct TriggerScheduler {
  trigger: sched::Trigger,
  registered: BTreeMap<String, RegisteredTime>,
}

/// One registered time-trigger task: the `sched` handle plus the
/// declaration signature the registration was built from.
struct RegisteredTime {
  task: TaskId,
  pattern: String,
  target: QualifiedTag,
}

impl Default for TriggerState {
  fn default() -> Self {
    // The default fire queue is closed: with no dispatch engine, every
    // enqueue fails and the caller's drop path (warn) is the behavior.
    let (fires, _receiver) = mpsc::channel(TRIGGER_FIRE_QUEUE);
    Self {
      event_rows: Arc::new(Mutex::new(BTreeMap::new())),
      fires: Arc::new(fires),
      scheduler: Arc::new(Mutex::new(TriggerScheduler::default())),
      wake: Arc::new(Notify::new()),
    }
  }
}

impl TriggerState {
  /// Builds the live state: `fires` is the queue half the dispatch
  /// engine owns the receiving end of.
  pub(crate) fn new(fires: mpsc::Sender<TriggerFire>) -> Self {
    Self {
      event_rows: Arc::new(Mutex::new(BTreeMap::new())),
      fires: Arc::new(fires),
      scheduler: Arc::new(Mutex::new(TriggerScheduler::default())),
      wake: Arc::new(Notify::new()),
    }
  }

  /// Replaces the event-trigger cache with one decoded per pass.
  fn replace_event_rows(&self, rows: BTreeMap<String, EventTrigger>) {
    if let Ok(mut guard) = self.event_rows.lock() {
      *guard = rows;
    }
  }

  /// A snapshot of the cached event triggers: the live change stream
  /// evaluates against this view, never against the store per event.
  pub(crate) fn event_rows(&self) -> BTreeMap<String, EventTrigger> {
    self
      .event_rows
      .lock()
      .map(|guard| guard.clone())
      .unwrap_or_default()
  }

  /// Enqueues one fire for dispatch. `false` when the queue is full or
  /// the engine is gone: a time trigger's tick is dropped (the `sched`
  /// table has already advanced — missed ticks are never replayed) and
  /// an event fire follows the transient stream's own contract.
  pub(crate) fn try_enqueue_fire(&self, fire: TriggerFire) -> bool {
    self.fires.try_send(fire).is_ok()
  }

  /// The soonest pending time-trigger instant, if any. Computes each
  /// registered task's next occurrence lazily; the returned instant may
  /// already be in the past when the dispatch engine is late.
  pub(crate) fn next_fire(&self, now: Timestamp) -> Option<Timestamp> {
    self.with_scheduler(|scheduler| scheduler.trigger.next(now))
  }

  /// Fires the `sched` tick scheduled for `scheduled_at` and returns the
  /// pending runs. Only the tick the engine waited for may fire; a stale
  /// tick is skipped, never replayed.
  pub(crate) fn fire_due(
    &self, scheduled_at: Timestamp, started_at: Timestamp,
  ) -> Vec<sched::TaskRun> {
    self.with_scheduler(|scheduler| scheduler.trigger.fire_due(scheduled_at, started_at))
  }

  /// Resolves when the declaration set changed: the evaluation pass
  /// notifies after every sync so the dispatch engine recomputes its
  /// next instant instead of sleeping on a stale table.
  pub(crate) async fn changed(&self) {
    self.wake.notified().await;
  }

  /// Runs one closure over the scheduler table, recovering a poisoned
  /// lock: a panicking callback must not wedge the trigger engine.
  fn with_scheduler<R>(&self, f: impl FnOnce(&mut TriggerScheduler) -> R) -> R {
    let mut scheduler = match self.scheduler.lock() {
      Ok(guard) => guard,
      Err(poisoned) => {
        tracing::warn!("the trigger scheduler lock was poisoned; recovering");
        poisoned.into_inner()
      }
    };
    f(&mut scheduler)
  }
}

/// One stored trigger row: the caller-chosen name (the store key), the
/// source, and the target task kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TriggerRow {
  name: String,
  source: TriggerSource,
  target: QualifiedTag,
}

/// The canonical wire body of one trigger row.
#[derive(Encode, Decode)]
#[cbor(array)]
struct TriggerWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  name: String,
  /// 0 = time, 1 = event; anything else fails the decode.
  #[n(3)]
  source_kind: u8,
  /// Time source: the pattern text. Event source: empty.
  #[n(4)]
  pattern: String,
  /// Event source: the canonical resource domains. Time source: empty.
  #[n(5)]
  domains: Vec<String>,
  /// Event source: the canonical selector text, empty when absent. Time
  /// source: empty.
  #[n(6)]
  selector: String,
  #[n(7)]
  target: String,
}

impl TriggerRow {
  /// Builds one row, validating the name and the source shape.
  pub(crate) fn new(name: String, source: TriggerSource, target: QualifiedTag) -> Result<Self> {
    Self::validate_name(&name)?;
    Ok(Self {
      name,
      source,
      target,
    })
  }

  /// Validates one trigger name: non-empty, bounded UTF-8.
  fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > TRIGGER_NAME_MAX_BYTES {
      return Err(Error::invalid_input("trigger name"));
    }
    Ok(())
  }

  pub(crate) fn name(&self) -> &str {
    &self.name
  }

  pub(crate) const fn source(&self) -> &TriggerSource {
    &self.source
  }

  pub(crate) const fn target(&self) -> &QualifiedTag {
    &self.target
  }

  /// The row's stored bytes: the canonical record body.
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    let (source_kind, pattern, domains, selector) = match &self.source {
      TriggerSource::Time { pattern } => (0_u8, pattern.clone(), Vec::new(), String::new()),
      TriggerSource::Event { predicate } => (
        1_u8,
        String::new(),
        predicate.domains().map(str::to_owned).collect(),
        predicate
          .label_selector()
          .map(|selector| selector.as_str().to_owned())
          .unwrap_or_default(),
      ),
    };
    encode_canonical(
      &TriggerWire {
        schema: TRIGGER_SCHEMA.to_owned(),
        record_version: TRIGGER_RECORD_VERSION,
        name: self.name.clone(),
        source_kind,
        pattern,
        domains,
        selector,
        target: self.target.as_str().to_owned(),
      },
      TRIGGER_LIMITS,
    )
  }

  /// Decodes one row from its canonical body.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: TriggerWire =
      decode_canonical_strict(bytes, TRIGGER_LIMITS, "trigger record canonical")?;
    if wire.schema != TRIGGER_SCHEMA || wire.record_version != TRIGGER_RECORD_VERSION {
      return Err(Error::invalid_input("trigger record schema"));
    }
    Self::validate_name(&wire.name)?;
    let source = match wire.source_kind {
      0 => {
        if !wire.domains.is_empty() || !wire.selector.is_empty() {
          return Err(Error::invalid_input("trigger record source"));
        }
        TriggerSource::Time {
          pattern: wire.pattern,
        }
      }
      1 => {
        if !wire.pattern.is_empty() {
          return Err(Error::invalid_input("trigger record source"));
        }
        let mut predicate = SubscriptionPredicate::new();
        for domain in &wire.domains {
          predicate = predicate.domain(domain)?;
        }
        if !wire.selector.is_empty() {
          predicate = predicate.selector(&wire.selector)?;
        }
        TriggerSource::Event { predicate }
      }
      _ => return Err(Error::invalid_input("trigger record source")),
    };
    Ok(Self {
      name: wire.name,
      source,
      target: QualifiedTag::parse(&wire.target)?,
    })
  }
}

/// The trigger family's provider namespace.
pub(crate) fn namespace() -> Result<StoreNamespace> {
  crate::storage::families::namespace(TRIGGER_NAMESPACE)
}

/// The store key of one trigger row: the name's UTF-8 bytes.
fn trigger_key(name: &str) -> StoreKey {
  StoreKey::new(Arc::from(name.as_bytes().to_vec()))
}

/// Validates the trigger target the store layer cannot see: a
/// registered caller-owned task reconciler (the same rule the public
/// `tasks().submit` admission enforces — the builtin domain is
/// reserved).
pub(crate) fn validate_trigger_target(
  extensions: &ExtensionRegistry, target: &QualifiedTag,
) -> Result<()> {
  if target.domain() == crate::protocol::tag::BUILTIN_DOMAIN
    || extensions.task_reconciler(target).is_none()
  {
    return Err(Error::unsupported(format!("trigger target {target}")));
  }
  Ok(())
}

/// Builds one time-trigger row: the schedule must parse and bind in a
/// declared frame (the core resolves no device-local timezone — the
/// pattern's frame must name its zone, so fire times never depend on
/// the host's timezone). The row is declaration-only: the runtime's
/// next window is computed from the clock when the `sched` table
/// registers it.
pub(crate) fn prepare_time_trigger(
  name: &str, pattern: &str, target: QualifiedTag,
) -> Result<TriggerRow> {
  validate_time_pattern(pattern)?;
  TriggerRow::new(
    name.to_owned(),
    TriggerSource::Time {
      pattern: pattern.to_owned(),
    },
    target,
  )
}

/// Builds one event-trigger row: the predicate is already typed value
/// state.
pub(crate) fn prepare_event_trigger(
  name: &str, predicate: SubscriptionPredicate, target: QualifiedTag,
) -> Result<TriggerRow> {
  TriggerRow::new(name.to_owned(), TriggerSource::Event { predicate }, target)
}

/// Parses and binds one time-trigger schedule. The expression is
/// forwarded to `sched` as written: `Z`, a fixed offset, an IANA zone,
/// and the device-local frame all bind through the library's timezone
/// resolution. The bind also proves an IANA name exists; the first
/// lookup may read the timezone database, so callers on an async
/// runtime run this through the blocking pool.
fn validate_time_pattern(pattern: &str) -> Result<()> {
  let schedule = Schedule::parse(pattern).map_err(|_| Error::invalid_input("trigger pattern"))?;
  schedule
    .bind()
    .map(|_| ())
    .map_err(|_| Error::invalid_input("trigger pattern frame"))
}

/// The host wall clock as a `sched` instant. The crate's [`crate::time`]
/// seam is the only clock authority; the conversion's failure is
/// unreachable for a host reading and falls back to the epoch rather
/// than panicking.
pub(crate) fn timestamp_now() -> Timestamp {
  Timestamp::from_millisecond(crate::time::now_millis()).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// The wall-clock wait until `at`: zero when the instant is already due
/// (the caller's `fire_due` skips a stale tick instead of replaying it).
pub(crate) fn wait_until(now: Timestamp, at: Timestamp) -> std::time::Duration {
  let nanos = at.as_nanosecond().saturating_sub(now.as_nanosecond());
  if nanos <= 0 {
    std::time::Duration::ZERO
  } else {
    std::time::Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
  }
}

/// The bounded re-drive budget for a registration or removal whose
/// conditional commit lost an optimistic-concurrency race: each retry
/// re-reads the current row and re-derives the operation against it, so
/// a bounded burst of racing writers still converges; past the budget
/// the caller's error surfaces typed (the crate's conflict convention —
/// a lost race is a definitive did-not-land, never a silent success).
const ROW_COMMIT_ATTEMPTS: usize = 4;

/// Persists one trigger declaration through the core-verb entry: the
/// registration write behind `register-trigger`.
///
/// Semantics: re-registering an existing name REPLACES its declaration
/// (a documented overwrite — callers never need `remove` to change a
/// declaration). The row is declaration-only; the runtime `sched` table
/// is rebuilt from it, so a replacement takes effect at the next
/// evaluation pass with no watermark to carry across declarations.
///
/// The write is an idempotent conditional put (identical bytes are a
/// no-op) under the store's writer permit, and the commit verdict is
/// fail-closed like every core writer (see
/// `crate::provider::commit_verdict`): a lost optimistic-concurrency
/// race is re-driven against a fresh snapshot within
/// [`ROW_COMMIT_ATTEMPTS`] and otherwise surfaces as the typed conflict
/// — the caller's `wait()` never resolves success for a put that did
/// not land.
pub(crate) async fn put_trigger_row_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, row: &TriggerRow,
) -> Result<()> {
  let namespace = namespace()?;
  let key = trigger_key(row.name());
  let _permit = store.write_permit().await;
  for _ in 0..ROW_COMMIT_ATTEMPTS {
    let snapshot = store.snapshot().await?;
    let stored = snapshot.get(&namespace, &key).await?;
    // A stored row that already equals the caller's declaration is the
    // idempotent no-op. A corrupt stored row is hygiene, not a
    // declaration: the registration overwrites it outright (the repair
    // path).
    if let Some(existing) = stored.as_ref() {
      match TriggerRow::decode(existing.as_bytes()) {
        Ok(decoded) if decoded == *row => return Ok(()),
        Ok(_) => {}
        Err(_) => tracing::warn!(trigger = row.name(), "replacing an undecodable trigger row"),
      }
    }
    let value = StoreValue::new(Arc::from(row.encode()?));
    let expected =
      crate::provider::snapshot_expectation(snapshot.as_ref(), &namespace, &key).await?;
    let revision = snapshot.revision().clone();
    drop(snapshot);
    let transaction = store.prepare_core_verb_transaction(
      crate::TransactionId::generate(entropy)?,
      revision,
      vec![StoreOperation::Put {
        namespace: namespace.clone(),
        key: key.clone(),
        expected,
        value,
      }],
    )?;
    // The commit's outcome is deliberately not signaled to the
    // anti-entropy plane: the trigger family is node-local and no lane
    // owns its namespace, so there is nothing to rescan. The verdict
    // itself is fail-closed: a lost race re-drives against the fresh
    // snapshot (the loop's next round), past the budget it errors.
    match store.commit(transaction).await? {
      crate::CommitOutcome::Committed(_) => return Ok(()),
      crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => continue,
      crate::CommitOutcome::Unknown { .. } => {
        return Err(Error::provider(
          ProviderErrorKind::CommitUnknown,
          ProviderErrorContext::StorageCommit,
        ));
      }
    }
  }
  Err(Error::conflict("trigger registration race"))
}

/// Removes one trigger declaration by name. Idempotent: an absent name
/// succeeds, and a delete whose conditional commit loses a race to a
/// concurrent removal succeeds too (the name is absent afterwards,
/// which is the contract). A name that keeps being re-registered under
/// the removal re-drives within [`ROW_COMMIT_ATTEMPTS`] and then fails
/// typed — the caller learns a live declaration still carries the name
/// instead of a silent false success.
pub(crate) async fn remove_trigger_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, name: &str,
) -> Result<()> {
  TriggerRow::validate_name(name)?;
  let namespace = namespace()?;
  let key = trigger_key(name);
  let _permit = store.write_permit().await;
  for _ in 0..ROW_COMMIT_ATTEMPTS {
    let snapshot = store.snapshot().await?;
    let Some(existing) = snapshot.get(&namespace, &key).await? else {
      return Ok(());
    };
    let revision = snapshot.revision().clone();
    drop(snapshot);
    let transaction = store.prepare_core_verb_transaction(
      crate::TransactionId::generate(entropy)?,
      revision,
      vec![StoreOperation::Delete {
        namespace: namespace.clone(),
        key: key.clone(),
        expected: existing.digest().clone(),
      }],
    )?;
    match store.commit(transaction).await? {
      crate::CommitOutcome::Committed(_) => return Ok(()),
      crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => continue,
      crate::CommitOutcome::Unknown { .. } => {
        return Err(Error::provider(
          ProviderErrorKind::CommitUnknown,
          ProviderErrorContext::StorageCommit,
        ));
      }
    }
  }
  // Past the re-drive budget: the name's presence decides the verdict —
  // absent means a racing removal won (the contract holds), present
  // means a racing registration keeps replacing it.
  let snapshot = store.snapshot().await?;
  if snapshot.get(&namespace, &key).await?.is_none() {
    return Ok(());
  }
  Err(Error::conflict("trigger removal race"))
}

/// Lists the stored trigger rows in canonical key order, bounded by
/// [`TRIGGER_ROW_CAP`]. A corrupt row is skipped with a warn
/// (bounded-degrading: the declaration is unreadable, so it cannot be
/// evaluated) — never a failed pass.
pub(crate) async fn list_trigger_rows_ctx(store: &MetadataStore) -> Result<Vec<TriggerRow>> {
  let namespace = namespace()?;
  let snapshot = store.snapshot().await?;
  let mut scan = snapshot.scan(&namespace, &[]).await?;
  let mut rows = Vec::new();
  while let Some(entry) = scan.next().await? {
    if rows.len() >= TRIGGER_ROW_CAP {
      break;
    }
    match TriggerRow::decode(entry.value().as_bytes()) {
      Ok(row) => rows.push(row),
      Err(error) => {
        tracing::warn!(kind = ?error.kind(), "trigger row skipped: undecodable declaration");
      }
    }
  }
  Ok(rows)
}

/// One evaluation pass over the durable trigger rows: refreshes the
/// engine's event-trigger cache and synchronizes the `sched` task table
/// with the stored time-trigger declarations. The rows are the durable
/// declarations; the table is the runtime state, rebuilt from them on
/// every incarnation, so a removed row leaves the table and a
/// re-declared row replaces its task. A row's next window is computed
/// from the current clock when the table registers it: a window missed
/// while the node was down is not replayed (the `sched` stale-tick
/// policy).
pub(crate) async fn evaluate_pass(store: &MetadataStore, state: &TriggerState) -> Result<()> {
  let rows = list_trigger_rows_ctx(store).await?;
  let mut event_rows = BTreeMap::new();
  let mut time_rows = Vec::new();
  for row in rows {
    match row.source() {
      TriggerSource::Event { predicate } => {
        event_rows.insert(
          row.name().to_owned(),
          EventTrigger {
            predicate: predicate.clone(),
            target: row.target().clone(),
          },
        );
      }
      TriggerSource::Time { .. } => time_rows.push(row),
    }
  }
  state.replace_event_rows(event_rows);
  state.sync_time_rows(time_rows).await;
  Ok(())
}

impl TriggerState {
  /// Synchronizes the `sched` task table with the stored time-trigger
  /// declarations. The change plan is computed under a short table lock,
  /// the potentially blocking schedule validation runs on the blocking
  /// pool, and the table mutations land under a second short lock.
  async fn sync_time_rows(&self, rows: Vec<TriggerRow>) {
    // The plan: which registered names left, and which rows are new or
    // changed. Unchanged rows keep their task (and its pending window).
    let (stale, changed) = {
      let scheduler = match self.scheduler.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
          tracing::warn!("the trigger scheduler lock was poisoned; recovering");
          poisoned.into_inner()
        }
      };
      let names: std::collections::BTreeSet<String> =
        rows.iter().map(|row| row.name().to_owned()).collect();
      let stale: Vec<String> = scheduler
        .registered
        .keys()
        .filter(|name| !names.contains(*name))
        .cloned()
        .collect();
      let changed: Vec<TriggerRow> = rows
        .into_iter()
        .filter(|row| {
          let TriggerSource::Time { pattern } = row.source() else {
            return false;
          };
          !scheduler
            .registered
            .get(row.name())
            .is_some_and(|entry| entry.pattern == *pattern && entry.target == *row.target())
        })
        .collect();
      (stale, changed)
    };
    // Validate the changed schedules off the async worker: the first
    // IANA lookup may read the timezone database.
    let (valid, invalid) = if changed.is_empty() {
      (Vec::new(), Vec::new())
    } else {
      match tokio::task::spawn_blocking(move || {
        let mut valid = Vec::new();
        let mut invalid = Vec::new();
        for row in changed {
          let TriggerSource::Time { pattern } = row.source() else {
            continue;
          };
          match validate_time_pattern(pattern) {
            Ok(()) => valid.push(row),
            Err(error) => {
              tracing::warn!(
                trigger = row.name(),
                kind = ?error.kind(),
                "trigger row skipped: unparsable schedule"
              );
              invalid.push(row.name().to_owned());
            }
          }
        }
        (valid, invalid)
      })
      .await
      {
        Ok(plan) => plan,
        Err(error) => {
          tracing::warn!(%error, "the trigger schedule validation task failed");
          return;
        }
      }
    };
    // Apply under the table lock: deregister the departed and invalid
    // rows, then replace the changed ones. `register` binds the schedule
    // again; the validation above warmed the timezone database cache, so
    // the bind is a cache hit.
    {
      let mut scheduler = match self.scheduler.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
          tracing::warn!("the trigger scheduler lock was poisoned; recovering");
          poisoned.into_inner()
        }
      };
      for name in stale.into_iter().chain(invalid) {
        if let Some(entry) = scheduler.registered.remove(&name) {
          scheduler.trigger.deregister(entry.task);
        }
      }
      for row in valid {
        let TriggerSource::Time { pattern } = row.source() else {
          continue;
        };
        if let Some(entry) = scheduler.registered.remove(row.name()) {
          scheduler.trigger.deregister(entry.task);
        }
        let state = self.clone();
        let name = row.name().to_owned();
        let target = row.target().clone();
        let callback = move |_scheduled_at: Timestamp| {
          if !state.try_enqueue_fire(TriggerFire {
            trigger: name.clone(),
            source: crate::TriggerSourceKind::Time,
            target: target.clone(),
          }) {
            tracing::warn!(
              trigger = %name,
              "trigger fire dropped: the dispatch queue is full"
            );
          }
          async {}
        };
        match scheduler
          .trigger
          .register_at(timestamp_now(), pattern, callback)
        {
          Ok(task) => {
            scheduler.registered.insert(
              row.name().to_owned(),
              RegisteredTime {
                task,
                pattern: pattern.clone(),
                target: row.target().clone(),
              },
            );
          }
          Err(error) => {
            tracing::warn!(
              trigger = row.name(),
              %error,
              "trigger registration failed"
            );
          }
        }
      }
    }
    // The table may have gained or lost a task: wake the dispatch engine
    // so it recomputes its next instant instead of sleeping on a stale
    // one.
    self.wake.notify_one();
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use super::*;
  use crate::{
    extension_registry::ExtensionRegistry, identity::testing::SequenceEntropy,
    storage::contract::ReferenceFactory,
  };

  /// The every-second UTC test pattern: every wall-clock second matches.
  const EVERY_TEST_SECOND: &str = "{*}-{*}-{*}T{*}:{*}:{*}Z";

  fn entropy() -> SequenceEntropy {
    SequenceEntropy::default()
  }

  fn registry() -> ExtensionRegistry {
    let mut extensions = ExtensionRegistry::new();
    extensions.register_default().expect("default pass");
    extensions
  }

  /// Registers one trigger row over the store directly (the test-level
  /// composition of the production path's prepare + validate + persist).
  async fn register_time_trigger_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, extensions: &ExtensionRegistry, name: &str,
    pattern: &str, target: QualifiedTag,
  ) -> Result<()> {
    validate_trigger_target(extensions, &target)?;
    let row = prepare_time_trigger(name, pattern, target)?;
    put_trigger_row_ctx(store, entropy, &row).await
  }

  async fn register_event_trigger_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, extensions: &ExtensionRegistry, name: &str,
    predicate: SubscriptionPredicate, target: QualifiedTag,
  ) -> Result<()> {
    validate_trigger_target(extensions, &target)?;
    let row = prepare_event_trigger(name, predicate, target)?;
    put_trigger_row_ctx(store, entropy, &row).await
  }

  fn target() -> QualifiedTag {
    QualifiedTag::parse("example.com/tasks/v1/probe").expect("tag")
  }

  /// A no-op reconciler registered under the tests' target kind, so the
  /// registration validation's reconciler lookup passes.
  #[derive(Debug)]
  struct ProbeReconciler;

  impl crate::TaskReconciler for ProbeReconciler {
    fn reconcile<'a>(
      &'a self, _ctx: crate::ReconcileContext,
    ) -> crate::BoxFuture<'a, crate::Result<crate::ReconcileDecision>> {
      Box::pin(async { Ok(crate::ReconcileDecision::Succeeded) })
    }
  }

  fn registered_target(extensions: &mut ExtensionRegistry) -> QualifiedTag {
    extensions
      .register_task_reconciler(target(), Arc::new(ProbeReconciler))
      .expect("register reconciler");
    target()
  }

  async fn store() -> MetadataStore {
    let factory = ReferenceFactory::new(crate::storage::contract::required_capabilities());
    MetadataStore::open(
      &(Arc::new(factory) as Arc<dyn crate::provider::StorageFactory>),
      Duration::from_secs(30),
    )
    .await
    .expect("store")
  }

  /// The node-local pin: no reconcile lane owns the trigger namespace,
  /// so no lane can ever carry a trigger row between nodes, and the
  /// store's write seam refuses external writers for the core-verb-gated
  /// family — the rows exist only on the node that declared them.
  #[test]
  fn trigger_rows_are_node_local() {
    for lane in crate::reconcile::wire::LaneId::all() {
      assert!(
        !lane.namespaces().contains(&TRIGGER_NAMESPACE),
        "lane {lane:?} must not own the trigger namespace"
      );
    }
    let namespace = namespace().expect("namespace");
    assert!(
      !crate::storage::families::external_write_admitted(&namespace).expect("admission"),
      "only the core-verb entry may write trigger rows"
    );
  }

  /// A trigger row round-trips its canonical body exactly, for both
  /// source kinds, and the event predicate survives the row codec
  /// byte-identically (the domains and the selector re-parse to the same
  /// canonical value state).
  #[test]
  fn trigger_rows_round_trip_both_sources() {
    let time = TriggerRow::new(
      "nightly".to_owned(),
      TriggerSource::Time {
        pattern: "{*}-{*}-{*}T00:00:00Z".to_owned(),
      },
      target(),
    )
    .expect("row");
    assert_eq!(
      TriggerRow::decode(&time.encode().expect("encode")).expect("decode"),
      time
    );

    let predicate = SubscriptionPredicate::new()
      .domain("example.org")
      .expect("domain")
      .selector("example.org/labels/owner=team-a")
      .expect("selector");
    let event = TriggerRow::new(
      "on-change".to_owned(),
      TriggerSource::Event { predicate },
      target(),
    )
    .expect("row");
    let decoded = TriggerRow::decode(&event.encode().expect("encode")).expect("decode");
    assert_eq!(decoded, event);
    let TriggerSource::Event {
      predicate: decoded_predicate,
    } = decoded.source()
    else {
      panic!("event source expected");
    };
    assert_eq!(
      decoded_predicate.domains().collect::<Vec<_>>(),
      vec!["example.org"]
    );
    assert_eq!(
      decoded_predicate
        .label_selector()
        .expect("selector")
        .as_str(),
      "example.org/labels/owner=team-a"
    );
  }

  /// Malformed rows fail closed: an empty or oversized name is refused
  /// before a row can be built.
  #[test]
  fn malformed_trigger_rows_fail_closed() {
    assert!(
      TriggerRow::new(
        String::new(),
        TriggerSource::Time {
          pattern: String::new()
        },
        target(),
      )
      .is_err()
    );
    assert!(
      TriggerRow::new(
        "x".repeat(TRIGGER_NAME_MAX_BYTES + 1),
        TriggerSource::Time {
          pattern: String::new()
        },
        target(),
      )
      .is_err()
    );
  }

  /// Registration validates the whole declaration: an unparsable
  /// pattern and an unregistered or builtin target fail typed, and
  /// nothing is persisted.
  #[tokio::test]
  async fn registration_validates_source_and_target() {
    let store = store().await;
    let entropy = entropy();
    let mut extensions = registry();
    let registered = registered_target(&mut extensions);

    for pattern in ["not-a-pattern"] {
      assert!(
        register_time_trigger_ctx(&store, &entropy, &extensions, "bad", pattern, target())
          .await
          .is_err(),
        "pattern {pattern:?} must be refused"
      );
    }
    // A builtin-domain target is refused even when a reconciler exists
    // under it, and an unregistered caller tag is refused.
    assert!(
      register_time_trigger_ctx(
        &store,
        &entropy,
        &extensions,
        "bad",
        "{*}-{*}-{*}T00:00:00Z",
        QualifiedTag::parse("radiata.woooo.tech/tasks/join").expect("tag")
      )
      .await
      .is_err()
    );
    assert!(
      register_time_trigger_ctx(
        &store,
        &entropy,
        &extensions,
        "bad",
        "{*}-{*}-{*}T00:00:00Z",
        QualifiedTag::parse("example.com/tasks/v1/missing").expect("tag")
      )
      .await
      .is_err()
    );
    assert!(
      list_trigger_rows_ctx(&store)
        .await
        .expect("rows")
        .is_empty()
    );

    // A valid registration with a registered target succeeds.
    register_time_trigger_ctx(
      &store,
      &entropy,
      &extensions,
      "good",
      "{*}-{*}-{*}T00:00:00Z",
      registered,
    )
    .await
    .expect("register");
    assert_eq!(list_trigger_rows_ctx(&store).await.expect("rows").len(), 1);
  }

  /// Every frame is forwarded to `sched`: `Z`, a fixed offset, an IANA
  /// zone, and the device-local default all bind.
  #[test]
  fn every_schedule_frame_binds() {
    for pattern in [
      "{*}-{*}-{*}T00:00:00Z",
      "{*}-{*}-{*}T00:00:00+08:00",
      "{*}-{*}-{*}T00:00:00[Asia/Shanghai]",
      "{*}-{*}-{*}T00:00:00",
    ] {
      prepare_time_trigger("framed", pattern, target())
        .unwrap_or_else(|error| panic!("pattern {pattern:?} must bind: {error}"));
    }
  }

  /// A registered time trigger persists durably, the rows list in key
  /// order, re-registration replaces the declaration outright, and
  /// removal is idempotent by name.
  #[tokio::test]
  async fn trigger_rows_persist_list_and_remove() {
    let store = store().await;
    let entropy = entropy();
    let mut extensions = registry();
    let registered = registered_target(&mut extensions);

    register_time_trigger_ctx(
      &store,
      &entropy,
      &extensions,
      "alpha",
      "{*}-{*}-{*}T00:00:00Z",
      registered.clone(),
    )
    .await
    .expect("register");
    let first = list_trigger_rows_ctx(&store).await.expect("rows");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].name(), "alpha");

    // Re-registering replaces the declaration (a documented overwrite):
    // the new pattern takes over and there is no watermark to carry.
    register_time_trigger_ctx(
      &store,
      &entropy,
      &extensions,
      "alpha",
      EVERY_TEST_SECOND,
      registered,
    )
    .await
    .expect("re-register");
    let rows = list_trigger_rows_ctx(&store).await.expect("rows");
    assert_eq!(rows.len(), 1);
    let TriggerSource::Time { pattern } = rows[0].source() else {
      panic!("the replacement's declaration must take over");
    };
    assert_eq!(pattern, EVERY_TEST_SECOND, "the declaration is replaced");

    // Removal is by name and idempotent: both removals succeed.
    remove_trigger_ctx(&store, &entropy, "alpha")
      .await
      .expect("remove");
    remove_trigger_ctx(&store, &entropy, "alpha")
      .await
      .expect("remove again");
    assert!(
      list_trigger_rows_ctx(&store)
        .await
        .expect("rows")
        .is_empty()
    );
  }

  /// The evaluation pass rebuilds the `sched` table from the durable
  /// rows: a registered time trigger has a pending window, firing it
  /// enqueues the declared fire, and removing the row leaves the table
  /// empty.
  #[tokio::test]
  async fn the_sched_table_follows_the_rows() {
    let store = store().await;
    let entropy = entropy();
    let mut extensions = registry();
    let registered = registered_target(&mut extensions);

    register_time_trigger_ctx(
      &store,
      &entropy,
      &extensions,
      "every-second",
      EVERY_TEST_SECOND,
      registered,
    )
    .await
    .expect("register");
    let (fires, mut rx) = mpsc::channel(TRIGGER_FIRE_QUEUE);
    let state = TriggerState::new(fires);
    evaluate_pass(&store, &state).await.expect("pass");

    let now = timestamp_now();
    let next = state.next_fire(now).expect("a pending window");
    // The dispatch round starts at the window it waited for (the engine
    // captures the dispatch start after sleeping); the callback enqueues
    // synchronously and returns an empty future.
    drop(state.fire_due(next, next));
    let fire = rx.try_recv().expect("the fire is enqueued");
    assert_eq!(fire.trigger, "every-second");
    assert_eq!(fire.source, crate::TriggerSourceKind::Time);
    assert_eq!(fire.target, target());

    remove_trigger_ctx(&store, &entropy, "every-second")
      .await
      .expect("remove");
    evaluate_pass(&store, &state).await.expect("pass");
    assert!(
      state.next_fire(timestamp_now()).is_none(),
      "the removed declaration leaves the sched table"
    );
  }

  /// The event-trigger cache refresh: the pass loads every event row
  /// into the engine's view, and the evaluation pass after a removal
  /// drops it from the cache.
  #[tokio::test]
  async fn the_event_cache_follows_the_rows() {
    let store = store().await;
    let entropy = entropy();
    let mut extensions = registry();
    let registered = registered_target(&mut extensions);

    register_event_trigger_ctx(
      &store,
      &entropy,
      &extensions,
      "on-change",
      SubscriptionPredicate::new()
        .domain("example.org")
        .expect("domain"),
      registered,
    )
    .await
    .expect("register");
    let (fires, _rx) = mpsc::channel(TRIGGER_FIRE_QUEUE);
    let state = TriggerState::new(fires);
    evaluate_pass(&store, &state).await.expect("pass");
    assert_eq!(state.event_rows().len(), 1);

    remove_trigger_ctx(&store, &entropy, "on-change")
      .await
      .expect("remove");
    evaluate_pass(&store, &state).await.expect("pass");
    assert!(state.event_rows().is_empty());
  }
}
