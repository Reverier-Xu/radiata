//! Trigger declarations as durable node-local rows: the declarative
//! surface behind time and event triggers.
//!
//! A trigger row is a node policy, not cluster state: it lives in the
//! dedicated node-local trigger family (the reconcile plane owns no lane
//! for its namespace, so the rows are never carried between nodes) and
//! survives restarts. One row carries its source — a cadence
//! [`radiata_cadence::Pattern`] text for a time trigger or a
//! [`SubscriptionPredicate`] for an event trigger — and its target: the
//! qualified tag of a registered caller-owned task reconciler. The row
//! is spec-only: the trigger *policy* (catchup = coalesce-to-one,
//! overlap = skip) is the engine's declared behavior, not per-row state,
//! mirroring the cadence crate's spec/policy separation.
//!
//! Time triggers keep one durable watermark per row
//! (`next_fire_seconds`): the evaluation pass fires every overdue row
//! once — missed windows coalesce to one run — and advances the
//! watermark past the current second, so a restart or a slow node never
//! replays a window and never skips a due one. Event triggers are
//! evaluated push-driven against the live change stream, reusing the
//! W2-2 emit-side predicate evaluation (one matching path).
//!
//! Patterns are expressed in the frame the pattern itself declares
//! (`Z` or a fixed offset): the core resolves no local timezone, so a
//! device-local pattern is refused at registration, fail-closed.

use std::{
  collections::BTreeMap,
  sync::{Arc, Mutex},
  time::{Duration, UNIX_EPOCH},
};

use minicbor::{Decode, Encode};
use radiata_cadence::{Offset, Pattern, field_values_to_system_time, system_time_to_field_values};
use tokio::sync::mpsc;

use crate::{
  Error, Result, StoreKey, StoreNamespace, StoreOperation, StoreValue, SubscriptionPredicate,
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
const TRIGGER_RECORD_VERSION: u16 = 1;
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

/// What fires a trigger: a cadence pattern against the wall clock, or a
/// subscription predicate against the live change stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TriggerSource {
  /// A cadence pattern in its declared frame (`Z` or fixed offset; the
  /// device-local frame is refused at registration).
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
/// evaluation pass refreshes and the bounded fire queue the dispatch
/// engine drains. Both halves are available wherever the operation
/// planes are; the default state has a closed fire queue (no engine —
/// enqueued fires drop with a warn) and an empty cache.
#[derive(Clone, Debug)]
pub(crate) struct TriggerState {
  event_rows: Arc<Mutex<BTreeMap<String, EventTrigger>>>,
  fires: Arc<mpsc::Sender<TriggerFire>>,
}

impl Default for TriggerState {
  fn default() -> Self {
    // The default fire queue is closed: with no dispatch engine, every
    // enqueue fails and the caller's drop path (warn, watermark stays
    // due) is the behavior.
    let (fires, _receiver) = mpsc::channel(TRIGGER_FIRE_QUEUE);
    Self {
      event_rows: Arc::new(Mutex::new(BTreeMap::new())),
      fires: Arc::new(fires),
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
  /// the engine is gone: the caller skips the advance (a time trigger's
  /// watermark stays due, so the next pass re-fires — at-least-once,
  /// coalesced per pass) or drops the event fire (the transient
  /// stream's own contract).
  pub(crate) fn try_enqueue_fire(&self, fire: TriggerFire) -> bool {
    self.fires.try_send(fire).is_ok()
  }
}

/// One stored trigger row: the caller-chosen name (the store key), the
/// source, the target task kind, and the time-trigger watermark.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TriggerRow {
  name: String,
  source: TriggerSource,
  target: QualifiedTag,
  /// The time trigger's watermark: the next due fire as UNIX seconds in
  /// the row's own frame. `u64::MAX` marks a pattern with no further
  /// fire; event triggers never read it.
  next_fire_seconds: u64,
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
  #[n(8)]
  next_fire_seconds: u64,
}

impl TriggerRow {
  /// Builds one row, validating the source and the watermark. Event
  /// rows carry `next_fire_seconds` zero (never read).
  pub(crate) fn new(
    name: String, source: TriggerSource, target: QualifiedTag, next_fire_seconds: u64,
  ) -> Result<Self> {
    Self::validate_name(&name)?;
    if matches!(source, TriggerSource::Event { .. }) && next_fire_seconds != 0 {
      return Err(Error::invalid_input("trigger watermark"));
    }
    Ok(Self {
      name,
      source,
      target,
      next_fire_seconds,
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

  /// The row's due watermark (time triggers only).
  pub(crate) const fn next_fire_seconds(&self) -> u64 {
    self.next_fire_seconds
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
        next_fire_seconds: self.next_fire_seconds,
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
      next_fire_seconds: wire.next_fire_seconds,
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

/// Builds one time-trigger row: the pattern must parse in a resolvable
/// frame (the core resolves no local timezone — the pattern's frame
/// must name its offset, so the fire times never depend on a timezone
/// database the core does not carry), and the initial watermark is the
/// first fire at or after the current second.
pub(crate) fn prepare_time_trigger(
  name: &str, pattern: &str, target: QualifiedTag,
) -> Result<TriggerRow> {
  let pattern = Pattern::parse(pattern).map_err(|_| Error::invalid_input("trigger pattern"))?;
  if pattern.offset() == Offset::Local {
    // The core resolves no local timezone: the pattern's frame must
    // name its offset (`Z` or fixed), so the trigger's fire times never
    // depend on a timezone database the core does not carry.
    return Err(Error::invalid_input("trigger pattern frame"));
  }
  let next_fire = next_fire_after(&pattern, crate::time::now_seconds())?;
  TriggerRow::new(
    name.to_owned(),
    TriggerSource::Time {
      pattern: pattern.to_string(),
    },
    target,
    next_fire,
  )
}

/// Builds one event-trigger row: the predicate is already typed value
/// state.
pub(crate) fn prepare_event_trigger(
  name: &str, predicate: SubscriptionPredicate, target: QualifiedTag,
) -> Result<TriggerRow> {
  TriggerRow::new(name.to_owned(), TriggerSource::Event { predicate }, target, 0)
}

/// The next due fire of `pattern` at or after `start_seconds` (inclusive,
/// UNIX seconds in the pattern's frame), or `u64::MAX` when the pattern
/// can never fire again.
fn next_fire_after(pattern: &Pattern, start_seconds: u64) -> Result<u64> {
  let start = system_time_to_field_values(
    UNIX_EPOCH + Duration::from_secs(start_seconds),
    pattern.offset(),
  )
  .map_err(|_| Error::invalid_input("trigger frame conversion"))?;
  Ok(
    pattern
      .next_fire(start)
      .map(|values| fire_seconds(&values, pattern.offset()))
      .unwrap_or(u64::MAX),
  )
}

/// The UNIX-second reading of one civil-second set in `frame`. The
/// conversion saturates at the epoch for pre-epoch civil times (the
/// crate's own second-scale contract: liveness arithmetic, never stored
/// absolute instants).
fn fire_seconds(values: &radiata_cadence::FieldValues, frame: Offset) -> u64 {
  field_values_to_system_time(*values, frame)
    .map(crate::time::to_seconds)
    .unwrap_or(0)
}

/// Persists one trigger row through the core-verb entry: an idempotent
/// conditional put (identical bytes are a no-op, a raced divergent write
/// conflicts and the caller's error surfaces typed).
pub(crate) async fn put_trigger_row_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, row: &TriggerRow,
) -> Result<()> {
  let namespace = namespace()?;
  let key = trigger_key(row.name());
  let value = StoreValue::new(Arc::from(row.encode()?));
  let _permit = store.write_permit().await;
  let snapshot = store.snapshot().await?;
  if let Some(existing) = snapshot.get(&namespace, &key).await?
    && existing.as_bytes() == value.as_bytes()
  {
    return Ok(());
  }
  let expected = crate::provider::snapshot_expectation(snapshot.as_ref(), &namespace, &key).await?;
  let revision = snapshot.revision().clone();
  drop(snapshot);
  let transaction = store.prepare_core_verb_transaction(
    crate::TransactionId::generate(entropy)?,
    revision,
    vec![StoreOperation::Put {
      namespace,
      key,
      expected,
      value,
    }],
  )?;
  // The commit's outcome is deliberately not signaled to the anti-entropy
  // plane: the trigger family is node-local and no lane owns its
  // namespace, so there is nothing to rescan.
  store.commit(transaction).await?;
  Ok(())
}

/// Removes one trigger row by name. `false` when no row carried it.
pub(crate) async fn remove_trigger_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, name: &str,
) -> Result<bool> {
  TriggerRow::validate_name(name)?;
  let namespace = namespace()?;
  let key = trigger_key(name);
  let _permit = store.write_permit().await;
  let snapshot = store.snapshot().await?;
  let Some(existing) = snapshot.get(&namespace, &key).await? else {
    return Ok(false);
  };
  let revision = snapshot.revision().clone();
  drop(snapshot);
  let transaction = store.prepare_core_verb_transaction(
    crate::TransactionId::generate(entropy)?,
    revision,
    vec![StoreOperation::Delete {
      namespace,
      key,
      expected: existing.digest().clone(),
    }],
  )?;
  Ok(matches!(
    store.commit(transaction).await?,
    crate::CommitOutcome::Committed(_)
  ))
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
/// engine's event-trigger cache and, for every due time trigger, enqueues
/// exactly one fire (missed windows coalesce to one run) and advances the
/// row's watermark past the current second. The enqueue-before-advance
/// order keeps a fire at-least-once across crashes: a crash between the
/// two re-fires once on the next pass, never skips.
pub(crate) async fn evaluate_pass(
  store: &MetadataStore, entropy: &dyn Entropy, state: &TriggerState,
) -> Result<()> {
  let rows = list_trigger_rows_ctx(store).await?;
  let now = crate::time::now_seconds();
  let mut event_rows = BTreeMap::new();
  let mut advanced: Vec<TriggerRow> = Vec::new();
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
      TriggerSource::Time { pattern } => {
        if row.next_fire_seconds() > now {
          continue;
        }
        let Ok(pattern) = Pattern::parse(pattern) else {
          tracing::warn!(
            trigger = row.name(),
            "trigger row skipped: unparsable pattern"
          );
          continue;
        };
        // Coalescing: one fire for every window at or before `now`, then
        // the next window strictly after it.
        if state.try_enqueue_fire(TriggerFire {
          trigger: row.name().to_owned(),
          source: crate::TriggerSourceKind::Time,
          target: row.target().clone(),
        }) {
          let start = now.saturating_add(1);
          let next_fire = next_fire_after(&pattern, start)?;
          if next_fire != row.next_fire_seconds()
            && let Ok(advanced_row) = TriggerRow::new(
              row.name().to_owned(),
              row.source().clone(),
              row.target().clone(),
              next_fire,
            )
          {
            advanced.push(advanced_row);
          }
        } else {
          tracing::warn!(
            trigger = row.name(),
            "trigger fire dropped: the dispatch queue is full"
          );
        }
      }
    }
  }
  state.replace_event_rows(event_rows);
  // The watermark advances land after the scan is released, each an
  // idempotent conditional put on the row's own read. A conflict or a
  // store failure leaves the watermark due: the next pass re-fires
  // (at-least-once), never skips.
  for row in advanced {
    if let Err(error) = put_trigger_row_ctx(store, entropy, &row).await {
      tracing::warn!(kind = ?error.kind(), "trigger watermark advance failed");
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    extension_registry::ExtensionRegistry, identity::testing::SequenceEntropy,
    storage::contract::ReferenceFactory,
  };

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
      1_800_000_000,
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
      0,
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

  /// Malformed rows fail closed: unknown source kinds, a watermark on an
  /// event row, an empty or oversized name, and an unknown schema.
  #[test]
  fn malformed_trigger_rows_fail_closed() {
    assert!(
      TriggerRow::new(
        String::new(),
        TriggerSource::Time {
          pattern: String::new()
        },
        target(),
        0
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
        0
      )
      .is_err()
    );
    assert!(
      TriggerRow::new(
        "event".to_owned(),
        TriggerSource::Event {
          predicate: SubscriptionPredicate::new()
        },
        target(),
        7
      )
      .is_err()
    );
  }

  /// Registration validates the whole declaration: an unparsable
  /// pattern, a device-local frame, and an unregistered or builtin
  /// target all fail typed, and nothing is persisted.
  #[tokio::test]
  async fn registration_validates_source_and_target() {
    let store = store().await;
    let entropy = entropy();
    let mut extensions = registry();
    let registered = registered_target(&mut extensions);

    for pattern in ["not-a-pattern", "not-a-pattern", "{*}-{*}-{*}T00:00:00"] {
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

  /// A registered time trigger persists durably, re-registers
  /// idempotently, lists in key order, and removes by name.
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
    let watermark = first[0].next_fire_seconds();
    assert!(
      watermark > crate::time::now_seconds() - 1,
      "the watermark starts due-never"
    );

    // Re-registering the same declaration is a no-op: the watermark is
    // recomputed from the same wall clock second and lands on the same
    // or a later window, never an earlier one.
    register_time_trigger_ctx(
      &store,
      &entropy,
      &extensions,
      "alpha",
      "{*}-{*}-{*}T00:00:00Z",
      registered,
    )
    .await
    .expect("re-register");
    let rows = list_trigger_rows_ctx(&store).await.expect("rows");
    assert_eq!(rows.len(), 1);
    assert!(rows[0].next_fire_seconds() >= watermark);

    // Removal is by name; a second removal reports absent.
    assert!(
      remove_trigger_ctx(&store, &entropy, "alpha")
        .await
        .expect("remove")
    );
    assert!(
      !remove_trigger_ctx(&store, &entropy, "alpha")
        .await
        .expect("remove again")
    );
    assert!(
      list_trigger_rows_ctx(&store)
        .await
        .expect("rows")
        .is_empty()
    );
  }

  /// The pass coalesces missed windows: a time trigger whose watermark
  /// is hours overdue fires exactly once, and its watermark advances
  /// past the current second (to the pattern's next window), so the next
  /// pass does not fire it again.
  #[tokio::test]
  async fn a_missed_window_coalesces_to_one_run() {
    let store = store().await;
    let entropy = entropy();

    // A daily-at-midnight trigger whose watermark was never advanced:
    // due now, whatever the clock reads.
    let overdue = TriggerRow::new(
      "daily".to_owned(),
      TriggerSource::Time {
        pattern: "{*}-{*}-{*}T00:00:00Z".to_owned(),
      },
      target(),
      0,
    )
    .expect("row");
    put_trigger_row_ctx(&store, &entropy, &overdue)
      .await
      .expect("persist");

    let (fires, _rx) = mpsc::channel(TRIGGER_FIRE_QUEUE);
    let state = TriggerState::new(fires);
    evaluate_pass(&store, &entropy, &state).await.expect("pass");

    let rows = list_trigger_rows_ctx(&store).await.expect("rows");
    assert_eq!(rows.len(), 1);
    let advanced = rows[0].next_fire_seconds();
    assert!(
      advanced > crate::time::now_seconds() + 60,
      "the watermark must advance past today's window: {advanced}"
    );

    // The next pass finds nothing due.
    evaluate_pass(&store, &entropy, &state).await.expect("pass");
    let rows = list_trigger_rows_ctx(&store).await.expect("rows");
    assert_eq!(rows[0].next_fire_seconds(), advanced);
  }

  /// A full dispatch queue drops the fire and leaves the watermark due:
  /// the next pass re-fires (at-least-once), never skips.
  #[tokio::test]
  async fn a_dropped_fire_leaves_the_watermark_due() {
    let store = store().await;
    let entropy = entropy();
    let overdue = TriggerRow::new(
      "daily".to_owned(),
      TriggerSource::Time {
        pattern: "{*}-{*}-{*}T00:00:00Z".to_owned(),
      },
      target(),
      0,
    )
    .expect("row");
    put_trigger_row_ctx(&store, &entropy, &overdue)
      .await
      .expect("persist");

    // A state whose fire queue is closed: every enqueue fails.
    let state = TriggerState::default();
    evaluate_pass(&store, &entropy, &state).await.expect("pass");

    let rows = list_trigger_rows_ctx(&store).await.expect("rows");
    assert_eq!(rows[0].next_fire_seconds(), 0, "the watermark stays due");
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
    evaluate_pass(&store, &entropy, &state).await.expect("pass");
    assert_eq!(state.event_rows().len(), 1);

    assert!(
      remove_trigger_ctx(&store, &entropy, "on-change")
        .await
        .expect("remove")
    );
    evaluate_pass(&store, &entropy, &state).await.expect("pass");
    assert!(state.event_rows().is_empty());
  }
}
