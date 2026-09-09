//! Durable route-trace metadata.
//!
//! The trace store persists a bounded record: identity
//! ([`crate::TraceId`] plus both authenticated endpoints), the selected
//! destination, the attempt count, stream progress, and the terminal
//! state — never payload bytes. Records ride the conditional
//! transaction machinery, so every write reconciles by canonical
//! `TransactionId` and digest, and every stored byte is inspectable.
//!
//! Retention policy (caller-selected through `TraceMetadataLimits`):
//!
//! - active (non-terminal) records are never removed by retention;
//! - terminal records expire at their host-wall-clock deadline;
//! - the terminal population never exceeds the caller-selected cap: the oldest
//!   expired records leave first, then the oldest terminals;
//! - a process restart terminates previously active records explicitly
//!   (`Failed(StreamInterrupted)`); no reopen path continues a body.
//!
//! Record accessors are unit-verified in this module's tests; some stay
//! intentionally dead in non-test builds, where only tests consume them.
#![cfg_attr(not(test), allow(dead_code))]

use std::time::{Duration, SystemTime};

use minicbor::{Decode, Encode};

use crate::{
  Error, ErrorKind, NodeId, ProviderErrorContext, ProviderErrorKind, Result, TraceId,
  api::Entropy,
  protocol::decode_canonical_strict,
  storage::{MetadataStore, receipt::WallClock},
};

/// The durable schema and namespace of one route-trace record.
pub(crate) const TRACE_SCHEMA: &str = "radiata.woooo.tech/schemas/route-trace-v1";
pub(crate) use crate::storage::families::TRACE_NAMESPACE;

/// Maximum operations per retention transaction batch, bounding one
/// sweep's work per commit.
const MAX_BATCH_OPERATIONS: usize = 64;

/// The sentinel failure code for non-failed phases (never a valid kind).
const NO_FAILURE: u8 = 0;

/// One observed trace phase. Terminal phases are `Delivered` and `Failed`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TracePhase {
  Routing,
  Streaming,
  Delivered,
  Failed(ErrorKind),
}

impl TracePhase {
  const ROUTING: u8 = 0;
  const STREAMING: u8 = 1;
  const DELIVERED: u8 = 2;
  const FAILED: u8 = 3;

  fn code(&self) -> u8 {
    match self {
      Self::Routing => Self::ROUTING,
      Self::Streaming => Self::STREAMING,
      Self::Delivered => Self::DELIVERED,
      Self::Failed(_) => Self::FAILED,
    }
  }

  fn from_code(code: u8, failure: Option<u8>) -> Result<Self> {
    match (code, failure) {
      (Self::ROUTING, None) => Ok(Self::Routing),
      (Self::STREAMING, None) => Ok(Self::Streaming),
      (Self::DELIVERED, None) => Ok(Self::Delivered),
      (Self::FAILED, Some(failure)) if failure != NO_FAILURE => {
        Ok(Self::Failed(kind_from_code(failure)?))
      }
      _ => Err(Error::invalid_input("route trace phase")),
    }
  }

  fn is_terminal(&self) -> bool {
    matches!(self, Self::Delivered | Self::Failed(_))
  }
}

/// The closed wire-code mapping for [`ErrorKind`] failures. Codes are
/// internal to this record schema; unknown codes fail closed.
const fn kind_code(kind: ErrorKind) -> Option<u8> {
  let code = match kind {
    ErrorKind::InvalidInput => 1,
    ErrorKind::Conflict => 2,
    ErrorKind::NotFound => 3,
    ErrorKind::NotReady => 4,
    ErrorKind::NotTrusted => 5,
    ErrorKind::Revoked => 6,
    ErrorKind::Unsupported => 7,
    ErrorKind::UnsupportedSchema => 8,
    ErrorKind::UnsupportedCapability => 9,
    ErrorKind::AuthenticationFailed => 10,
    ErrorKind::RouteUnavailable => 11,
    ErrorKind::StreamInterrupted => 12,
    ErrorKind::Overloaded => 13,
    ErrorKind::ResourceExhausted => 14,
    ErrorKind::StorageLocked => 15,
    ErrorKind::StorageCorrupt => 16,
    ErrorKind::PermissionDenied => 17,
    ErrorKind::Io => 18,
    ErrorKind::CommitUnknown => 19,
    ErrorKind::Cancelled => 20,
    ErrorKind::ShuttingDown => 21,
    ErrorKind::Internal => 22,
  };
  Some(code)
}

/// The inverse of [`kind_code`]: a stored failure byte outside the known
/// set is schema corruption and fails closed instead of masquerading as
/// `Internal`.
const fn kind_from_code(code: u8) -> Result<ErrorKind> {
  let kind = match code {
    1 => ErrorKind::InvalidInput,
    2 => ErrorKind::Conflict,
    3 => ErrorKind::NotFound,
    4 => ErrorKind::NotReady,
    5 => ErrorKind::NotTrusted,
    6 => ErrorKind::Revoked,
    7 => ErrorKind::Unsupported,
    8 => ErrorKind::UnsupportedSchema,
    9 => ErrorKind::UnsupportedCapability,
    10 => ErrorKind::AuthenticationFailed,
    11 => ErrorKind::RouteUnavailable,
    12 => ErrorKind::StreamInterrupted,
    13 => ErrorKind::Overloaded,
    14 => ErrorKind::ResourceExhausted,
    15 => ErrorKind::StorageLocked,
    16 => ErrorKind::StorageCorrupt,
    17 => ErrorKind::PermissionDenied,
    18 => ErrorKind::Io,
    19 => ErrorKind::CommitUnknown,
    20 => ErrorKind::Cancelled,
    21 => ErrorKind::ShuttingDown,
    22 => ErrorKind::Internal,
    _ => return Err(Error::invalid_input("route trace failure code")),
  };
  Ok(kind)
}

/// One durable route-trace record: bounded metadata only, never payload
/// bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TraceRecord {
  trace_id: TraceId,
  source: NodeId,
  /// The selected destination: exact target or load-balancer pick.
  destination: NodeId,
  attempts: u32,
  phase: TracePhase,
  updated_at: SystemTime,
}

impl TraceRecord {
  /// Opens the record for a newly routed attempt toward `destination`.
  pub(crate) fn new(
    trace_id: TraceId, source: NodeId, destination: NodeId, updated_at: SystemTime,
  ) -> Self {
    Self {
      trace_id,
      source,
      destination,
      attempts: 1,
      phase: TracePhase::Routing,
      updated_at,
    }
  }

  pub(crate) fn failed(mut self, kind: ErrorKind) -> Self {
    self.phase = TracePhase::Failed(kind);
    self
  }

  pub(crate) fn trace_id(&self) -> &TraceId {
    &self.trace_id
  }

  pub(crate) fn source(&self) -> &NodeId {
    &self.source
  }

  pub(crate) fn destination(&self) -> &NodeId {
    &self.destination
  }

  pub(crate) fn phase(&self) -> &TracePhase {
    &self.phase
  }

  /// Applies one route transition beyond the initial routing record.
  pub(crate) fn with_transition(mut self, transition: TraceTransition, at: SystemTime) -> Self {
    self.updated_at = at;
    self.phase = match transition {
      TraceTransition::Streaming => TracePhase::Streaming,
      TraceTransition::Delivered => TracePhase::Delivered,
      TraceTransition::Failed(kind) => TracePhase::Failed(kind),
    };
    self
  }

  /// Canonical wire encoding of the trace record; the compatibility
  /// suite's golden-vector reader shares this exact encoder.
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical_record(self)
  }
}

/// One persisted route transition beyond the initial routing record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceTransition {
  Streaming,
  Delivered,
  Failed(ErrorKind),
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct TraceWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  trace_id: String,
  #[n(3)]
  source: String,
  #[n(4)]
  destination: String,
  #[n(5)]
  attempts: u32,
  #[n(6)]
  phase: u8,
  #[n(7)]
  failure: Option<u8>,
  #[n(8)]
  updated_at_millis: u64,
}

fn encode_canonical_record(record: &TraceRecord) -> Result<Vec<u8>> {
  let (phase_code, failure) = match &record.phase {
    TracePhase::Failed(kind) => (
      TracePhase::FAILED,
      kind_code(*kind).ok_or_else(|| Error::invalid_input("route trace failure"))?,
    ),
    phase => (phase.code(), NO_FAILURE),
  };
  crate::protocol::encode_canonical(
    &TraceWire {
      schema: TRACE_SCHEMA.to_owned(),
      record_version: 1,
      trace_id: record.trace_id.to_string(),
      source: record.source.to_string(),
      destination: record.destination.to_string(),
      attempts: record.attempts,
      phase: phase_code,
      failure: if failure == NO_FAILURE {
        None
      } else {
        Some(failure)
      },
      updated_at_millis: crate::time::to_millis(record.updated_at),
    },
    crate::protocol::CONTROL_CBOR_LIMITS,
  )
}

/// The single canonical trace-record decoder: canonical encoding, schema,
/// version, and field validation fail closed.
pub(crate) fn decode_trace_record(bytes: &[u8]) -> Result<TraceRecord> {
  let wire: TraceWire = decode_canonical_strict(
    bytes,
    crate::protocol::CONTROL_CBOR_LIMITS,
    "route trace canonical",
  )?;
  if wire.schema != TRACE_SCHEMA || wire.record_version != 1 {
    return Err(Error::invalid_input("route trace schema"));
  }
  Ok(TraceRecord {
    trace_id: wire.trace_id.parse()?,
    source: wire.source.parse()?,
    destination: wire.destination.parse()?,
    attempts: wire.attempts,
    phase: TracePhase::from_code(wire.phase, wire.failure)?,
    updated_at: crate::time::from_millis(wire.updated_at_millis),
  })
}

fn namespace() -> Result<crate::StoreNamespace> {
  crate::storage::families::namespace(TRACE_NAMESPACE)
}

fn key(trace_id: &TraceId) -> crate::StoreKey {
  crate::StoreKey::new(std::sync::Arc::from(trace_id.as_str().as_bytes().to_vec()))
}

/// Persists one route-trace record through one conditional transaction.
/// The write reconciles by canonical `TransactionId` and digest; a lost
/// compare-and-swap surfaces as a typed conflict instead of a silent
/// overwrite.
pub(crate) async fn put_trace(
  store: &MetadataStore, entropy: &dyn Entropy, clock: &dyn WallClock, mut record: TraceRecord,
) -> Result<()> {
  record.updated_at = clock.now();
  let encoded = record.encode()?;
  let space = namespace()?;
  let key = key(&record.trace_id);
  let snapshot = store.snapshot().await?;
  let expected = crate::provider::snapshot_expectation(snapshot.as_ref(), &space, &key).await?;
  let transaction = store.prepare_transaction(
    crate::TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![crate::StoreOperation::Put {
      namespace: space,
      key,
      expected,
      value: crate::StoreValue::new(std::sync::Arc::from(encoded)),
    }],
  )?;
  match store.commit(transaction).await? {
    crate::CommitOutcome::Committed(_) => Ok(()),
    crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => {
      Err(Error::conflict("route trace"))
    }
    crate::CommitOutcome::Unknown { .. } => Err(Error::provider(
      ProviderErrorKind::CommitUnknown,
      ProviderErrorContext::StorageReconcile,
    )),
  }
}

/// Terminates every non-terminal record left by a previous incarnation:
/// a restart ends each in-flight route explicitly with
/// `StreamInterrupted`, and no reopen path continues a body. Returns how
/// many records were terminated.
pub(crate) async fn terminate_stale(
  store: &MetadataStore, entropy: &dyn Entropy, clock: &dyn WallClock,
) -> Result<usize> {
  let _permit = store.write_permit().await;
  let space = namespace()?;
  let snapshot = store.snapshot().await?;
  let mut scan = snapshot.scan(&space, &[]).await?;
  let mut stale: Vec<(crate::StoreKey, crate::Digest, TraceRecord)> = Vec::new();
  while let Some(entry) = scan.next().await? {
    let Ok(record) = decode_trace_record(entry.value().as_bytes()) else {
      continue;
    };
    if record.phase.is_terminal() {
      continue;
    }
    stale.push((
      crate::StoreKey::new(std::sync::Arc::from(entry.key().as_bytes().to_vec())),
      entry.value().digest().clone(),
      record,
    ));
  }
  drop(scan);
  let mut operations = Vec::with_capacity(stale.len());
  let now = clock.now();
  for (key, digest, mut record) in stale {
    record.updated_at = now;
    let value = record.failed(ErrorKind::StreamInterrupted).encode()?;
    operations.push(crate::StoreOperation::Put {
      namespace: space.clone(),
      key,
      expected: crate::StoreExpectation::Exact(digest),
      value: crate::StoreValue::new(std::sync::Arc::from(value)),
    });
  }
  apply_batched(store, entropy, operations).await
}

/// Applies one retention pass over the trace namespace: terminal records
/// past their host-wall-clock deadline are removed first, then the oldest
/// terminals down to the caller-selected cap. Active records are never
/// removed. Returns how many records were removed.
pub(crate) async fn sweep(
  store: &MetadataStore, entropy: &dyn Entropy, clock: &dyn WallClock, terminal_cap: usize,
  retention: Duration,
) -> Result<usize> {
  let _permit = store.write_permit().await;
  let space = namespace()?;
  let now = clock.now();
  let snapshot = store.snapshot().await?;
  let mut scan = snapshot.scan(&space, &[]).await?;
  let mut expired: Vec<(crate::StoreKey, crate::Digest, SystemTime)> = Vec::new();
  let mut fresh_terminals: Vec<(crate::StoreKey, crate::Digest, SystemTime)> = Vec::new();
  while let Some(entry) = scan.next().await? {
    let Ok(record) = decode_trace_record(entry.value().as_bytes()) else {
      continue;
    };
    if !record.phase.is_terminal() {
      // Active streams never enter the removal sets at all.
      continue;
    }
    let item = (
      crate::StoreKey::new(std::sync::Arc::from(entry.key().as_bytes().to_vec())),
      entry.value().digest().clone(),
      record.updated_at,
    );
    if now
      .duration_since(record.updated_at)
      .is_ok_and(|age| age >= retention)
    {
      expired.push(item);
    } else {
      fresh_terminals.push(item);
    }
  }
  drop(scan);
  // Enforce the terminal cap oldest-first across fresh terminals after the
  // expired ones leave.
  let overflow = (expired.len() + fresh_terminals.len()).saturating_sub(terminal_cap);
  let mut removals: Vec<(crate::StoreKey, crate::Digest)> = expired
    .into_iter()
    .map(|(key, digest, _)| (key, digest))
    .collect();
  if overflow > 0 {
    fresh_terminals.sort_by_key(|(_, _, updated_at)| *updated_at);
    removals.extend(
      fresh_terminals
        .into_iter()
        .take(overflow)
        .map(|(key, digest, _)| (key, digest)),
    );
  }
  let total = removals.len();
  let operations = removals
    .into_iter()
    .map(|(key, digest)| crate::StoreOperation::Delete {
      namespace: space.clone(),
      key,
      expected: digest,
    })
    .collect();
  apply_batched(store, entropy, operations).await?;
  Ok(total)
}

/// Applies up to [`MAX_BATCH_OPERATIONS`] conditional operations per
/// transaction until the batch is exhausted.
async fn apply_batched(
  store: &MetadataStore, entropy: &dyn Entropy, operations: Vec<crate::StoreOperation>,
) -> Result<usize> {
  let mut applied = 0_usize;
  for batch in operations.chunks(MAX_BATCH_OPERATIONS) {
    applied += commit_batch(store, entropy, batch.to_vec()).await?;
  }
  Ok(applied)
}

async fn commit_batch(
  store: &MetadataStore, entropy: &dyn Entropy, operations: Vec<crate::StoreOperation>,
) -> Result<usize> {
  let count = operations.len();
  let snapshot = store.snapshot().await?;
  let transaction = store.prepare_transaction(
    crate::TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    operations,
  )?;
  match store.commit(transaction).await? {
    crate::CommitOutcome::Committed(_) | crate::CommitOutcome::Aborted => Ok(count),
    crate::CommitOutcome::Conflict => Ok(0),
    crate::CommitOutcome::Unknown { .. } => Err(Error::provider(
      ProviderErrorKind::CommitUnknown,
      ProviderErrorContext::StorageReconcile,
    )),
  }
}

#[cfg(test)]
mod tests {
  use std::{
    sync::{
      Arc,
      atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
  };

  use super::{
    MAX_QUEUED_TRACE_PERSISTENCE, TRACE_NAMESPACE, TracePhase, TraceRecord, TraceSink,
    decode_trace_record, put_trace, sweep, terminate_stale,
  };
  use crate::{
    ErrorKind, NodeId, TraceId,
    api::SystemEntropy,
    identity::{
      lifecycle,
      testing::{ScriptedKeys, SequenceEntropy},
    },
    provider::StorageFactory,
    storage::{MetadataStore, contract::helpers::ManualClock, receipt::WallClock},
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn trace(seed: u32) -> TraceId {
    TraceId::parse(&format!("trace_{seed:021}")).unwrap()
  }

  async fn open_store() -> (Arc<dyn StorageFactory>, MetadataStore, Arc<ManualClock>) {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    let clock = Arc::new(ManualClock::new(
      std::time::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    (factory, store, clock)
  }

  async fn all_records(store: &MetadataStore) -> Vec<TraceRecord> {
    let space = crate::StoreNamespace::new(crate::QualifiedTag::parse(TRACE_NAMESPACE).unwrap());
    let snapshot = store.snapshot().await.unwrap();
    let mut scan = snapshot.scan(&space, &[]).await.unwrap();
    let mut records = Vec::new();
    while let Some(entry) = scan.next().await.unwrap() {
      records.push(decode_trace_record(entry.value().as_bytes()).unwrap());
    }
    records
  }

  // ---- Trace metadata without body bytes ----

  /// Every `ErrorKind` survives the closed failure-code mapping, and an
  /// unknown stored byte fails closed instead of decoding as a valid kind.
  #[test]
  fn failure_codes_round_trip_and_reject_unknown() {
    let kinds = [
      ErrorKind::InvalidInput,
      ErrorKind::Conflict,
      ErrorKind::NotFound,
      ErrorKind::NotReady,
      ErrorKind::NotTrusted,
      ErrorKind::Revoked,
      ErrorKind::Unsupported,
      ErrorKind::UnsupportedSchema,
      ErrorKind::UnsupportedCapability,
      ErrorKind::AuthenticationFailed,
      ErrorKind::RouteUnavailable,
      ErrorKind::StreamInterrupted,
      ErrorKind::Overloaded,
      ErrorKind::ResourceExhausted,
      ErrorKind::StorageLocked,
      ErrorKind::StorageCorrupt,
      ErrorKind::PermissionDenied,
      ErrorKind::Io,
      ErrorKind::CommitUnknown,
      ErrorKind::Cancelled,
      ErrorKind::ShuttingDown,
      ErrorKind::Internal,
    ];
    for kind in kinds {
      let code = super::kind_code(kind).unwrap();
      assert_eq!(super::kind_from_code(code).unwrap(), kind);
    }
    for code in [0_u8, 23, u8::MAX] {
      assert!(super::kind_from_code(code).is_err());
    }
  }

  /// The record binds identity, selected destination, attempt count,
  /// progress, and terminal state — and byte-for-byte inspection of the
  /// whole namespace proves no payload bytes enter any record.
  #[tokio::test]
  async fn records_bind_route_metadata_and_never_body_bytes() {
    let (_factory, store, clock) = open_store().await;
    let body_marker: std::sync::Arc<[u8]> = std::sync::Arc::from(&b"SECRET-PAYLOAD-BYTES"[..]);

    let routing = TraceRecord::new(trace(1), node(1), node(2), clock.now());
    put_trace(&store, &SystemEntropy, clock.as_ref(), routing)
      .await
      .unwrap();
    put_trace(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      TraceRecord::new(trace(1), node(1), node(2), clock.now())
        .with_transition(super::TraceTransition::Streaming, clock.now()),
    )
    .await
    .unwrap();
    put_trace(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      TraceRecord::new(trace(1), node(1), node(2), clock.now())
        .with_transition(super::TraceTransition::Delivered, clock.now()),
    )
    .await
    .unwrap();

    // Byte-for-byte inspection: exactly one upserted record, fully
    // decodable, and no stored byte sequence contains the body marker.
    let records = all_records(&store).await;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.trace_id(), &trace(1));
    assert_eq!(record.source(), &node(1));
    assert_eq!(record.destination(), &node(2));
    assert_eq!(record.phase(), &TracePhase::Delivered);

    let space = crate::StoreNamespace::new(crate::QualifiedTag::parse(TRACE_NAMESPACE).unwrap());
    let snapshot = store.snapshot().await.unwrap();
    let mut scan = snapshot.scan(&space, &[]).await.unwrap();
    while let Some(entry) = scan.next().await.unwrap() {
      let bytes = entry.value().as_bytes();
      assert!(
        !bytes
          .windows(body_marker.len())
          .any(|window| window == &body_marker[..])
      );
      // Every stored value is a canonical trace record, not a body.
      assert!(decode_trace_record(bytes).is_ok());
    }
  }

  // ---- Atomic reconcile by TransactionId and digest ----

  /// A lost compare-and-swap surfaces as a typed conflict instead of a
  /// silent overwrite, and re-writing the identical record is idempotent.
  #[tokio::test]
  async fn conflicting_writes_reconcile_atomically() {
    let (_factory, store, clock) = open_store().await;
    let record = TraceRecord::new(trace(2), node(1), node(3), clock.now());
    put_trace(&store, &SystemEntropy, clock.as_ref(), record.clone())
      .await
      .unwrap();

    // A stale-expectation write (prepared against an absent key) must
    // conflict deterministically rather than clobber the record.
    let space = crate::StoreNamespace::new(crate::QualifiedTag::parse(TRACE_NAMESPACE).unwrap());
    let encoded = record.encode().unwrap();
    let snapshot = store.snapshot().await.unwrap();
    let transaction = store
      .prepare_transaction(
        crate::TransactionId::generate(&SystemEntropy).unwrap(),
        snapshot.revision().clone(),
        vec![crate::StoreOperation::Put {
          namespace: space.clone(),
          key: crate::StoreKey::new(std::sync::Arc::from(
            record.trace_id().as_str().as_bytes().to_vec(),
          )),
          expected: crate::StoreExpectation::Absent,
          value: crate::StoreValue::new(std::sync::Arc::from(encoded.clone())),
        }],
      )
      .unwrap();
    match store.commit(transaction).await.unwrap() {
      crate::CommitOutcome::Conflict => {}
      other => panic!("expected a typed conflict, got {other:?}"),
    }
    // The authoritative record survived unchanged.
    let records = all_records(&store).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].phase(), &TracePhase::Routing);

    // Re-writing the identical state is idempotent old-or-new.
    put_trace(&store, &SystemEntropy, clock.as_ref(), record)
      .await
      .unwrap();
    assert_eq!(all_records(&store).await.len(), 1);
  }

  // ---- Active streams survive retention; restart terminates ----

  /// Retention never removes active records; a restart terminates them
  /// explicitly with `StreamInterrupted`, and no reopen path continues.
  #[tokio::test]
  async fn retention_preserves_active_and_restart_terminates_stale() {
    let (factory, store, clock) = open_store().await;

    // One active stream, one delivered record already past any retention.
    put_trace(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      TraceRecord::new(trace(3), node(1), node(4), clock.now()),
    )
    .await
    .unwrap();
    clock.set(std::time::UNIX_EPOCH + Duration::from_secs(2_000));
    put_trace(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      TraceRecord::new(trace(4), node(1), node(5), clock.now())
        .with_transition(super::TraceTransition::Delivered, clock.now()),
    )
    .await
    .unwrap();

    // A sweep far before any expiry removes nothing at all.
    let removed = sweep(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      128,
      Duration::from_secs(100),
    )
    .await
    .unwrap();
    assert_eq!(removed, 0);
    assert_eq!(all_records(&store).await.len(), 2);

    // Restart semantics: every non-terminal record terminates explicitly.
    let terminated = terminate_stale(&store, &SystemEntropy, clock.as_ref())
      .await
      .unwrap();
    assert_eq!(terminated, 1);
    let records = all_records(&store).await;
    let stale = records
      .iter()
      .find(|record| record.trace_id() == &trace(3))
      .unwrap();
    assert_eq!(
      stale.phase(),
      &TracePhase::Failed(ErrorKind::StreamInterrupted)
    );

    // Reopening the same store observes the terminated record only; there
    // is nothing to continue. The exclusive lifetime lock requires the
    // previous handle to release first.
    drop(store);
    let reopened_store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    let reopened = all_records(&reopened_store).await;
    assert_eq!(reopened.len(), 2);
    assert!(reopened.iter().all(|record| record.phase().is_terminal()));
  }

  // ---- Caller-selected capacity and wall-clock retention ----

  /// Terminal records expire on host wall time, the terminal population
  /// never exceeds the caller-selected cap, and active records are never
  /// evicted even under capacity pressure.
  #[tokio::test]
  async fn sweep_enforces_retention_and_terminal_cap_without_touching_active() {
    let (_factory, store, clock) = open_store().await;

    // Three terminals written one hundred seconds apart, plus one active.
    for seed in [5_u32, 6, 7] {
      put_trace(
        &store,
        &SystemEntropy,
        clock.as_ref(),
        TraceRecord::new(trace(seed), node(1), node(9), clock.now())
          .with_transition(super::TraceTransition::Delivered, clock.now()),
      )
      .await
      .unwrap();
      clock.set(clock.now() + Duration::from_secs(100));
    }
    put_trace(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      TraceRecord::new(trace(8), node(1), node(9), clock.now()),
    )
    .await
    .unwrap();

    // Cap two with a long retention: the oldest fresh terminal leaves to
    // honor the cap; the active record stays.
    let removed = sweep(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      2,
      Duration::from_secs(10_000),
    )
    .await
    .unwrap();
    assert_eq!(removed, 1);
    let records = all_records(&store).await;
    assert_eq!(records.len(), 3);
    assert!(!records.iter().any(|record| record.trace_id() == &trace(5)));

    // Once wall time passes the retention deadline, the remaining expired
    // terminals leave while the active record still survives.
    clock.set(clock.now() + Duration::from_secs(20_000));
    let removed = sweep(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      2,
      Duration::from_secs(10_000),
    )
    .await
    .unwrap();
    assert_eq!(removed, 2);
    let records = all_records(&store).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].trace_id(), &trace(8));
    assert_eq!(records[0].phase(), &TracePhase::Routing);
  }

  // Retention sweeps re-read the wall clock on every pass, so rollback or
  // freeze delays expiry and a forward jump expires immediately — no
  // monotonic-clock assumption.
  #[tokio::test]
  async fn sweep_rereads_wall_time_across_discontinuities() {
    let (_factory, store, clock) = open_store().await;
    let written_at = UNIX_EPOCH + Duration::from_secs(10_000);
    clock.set(written_at);
    put_trace(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      TraceRecord::new(trace(9), node(1), node(9), clock.now())
        .with_transition(super::TraceTransition::Delivered, clock.now()),
    )
    .await
    .unwrap();

    // Rollback below the write instant: the record's age is not negative;
    // nothing expires and nothing panics.
    clock.set(written_at - Duration::from_secs(5_000));
    let removed = sweep(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      128,
      Duration::from_secs(100),
    )
    .await
    .unwrap();
    assert_eq!(removed, 0);
    assert_eq!(all_records(&store).await.len(), 1);

    // Freeze at the write instant: still inside any positive retention.
    clock.set(written_at);
    let removed = sweep(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      128,
      Duration::from_secs(100),
    )
    .await
    .unwrap();
    assert_eq!(removed, 0);

    // A forward jump past the retention deadline expires the terminal on
    // the very next sweep, without any restart in between.
    clock.set(written_at + Duration::from_secs(101));
    let removed = sweep(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      128,
      Duration::from_secs(100),
    )
    .await
    .unwrap();
    assert_eq!(removed, 1);
    assert!(all_records(&store).await.is_empty());
  }

  // ---- Bounded terminal-record queue: overflow drops and its counter ----

  /// Opens a sink over a real identity context and store, sharing the
  /// live-record counter with the caller.
  async fn open_sink() -> (
    TraceSink,
    Arc<lifecycle::LocalIdentityContext>,
    Arc<AtomicUsize>,
  ) {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = Arc::new(
      lifecycle::open_local_identity(
        &factory,
        &keys.as_provider(),
        entropy.as_ref(),
        Duration::from_secs(10),
      )
      .await
      .unwrap(),
    );
    let live_records = Arc::new(AtomicUsize::new(0));
    let sink = TraceSink::new(
      Arc::clone(&context),
      entropy,
      Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(1_000))),
      Arc::clone(&live_records),
    );
    (sink, context, live_records)
  }

  fn terminal_record(seed: u32, sink: &TraceSink) -> TraceRecord {
    TraceRecord::new(trace(seed), node(1), node(9), sink.clock_now())
      .with_transition(super::TraceTransition::Delivered, sink.clock_now())
  }

  /// The terminal-persistence queue admits at most the bound: overflow
  /// records drop and are counted instead of queueing without limit,
  /// every admitted record still persists, and the drop aggregate reads
  /// back through the observability snapshot's well-known tag.
  #[tokio::test]
  async fn queue_bound_drops_overflow_records_and_counts_them() {
    let (sink, context, live_records) = open_sink().await;

    // Feed past the bound synchronously: on this single-threaded test
    // runtime the spawned persistence tasks cannot run until the test
    // awaits, so exactly the bound admits and every further feed drops.
    const FED: usize = 200;
    for seed in 0..u32::try_from(FED).unwrap() {
      sink.record_terminal(terminal_record(seed, &sink));
    }
    assert_eq!(sink.queued(), MAX_QUEUED_TRACE_PERSISTENCE);
    assert_eq!(sink.dropped(), FED - MAX_QUEUED_TRACE_PERSISTENCE);

    // Every admitted record persists; the drops stay drops. Drain on a
    // wall-clock deadline: persistence tasks contend on the store's
    // single-commit state machine, so spins alone cannot bound the wait.
    let drained_at = std::time::Instant::now() + Duration::from_secs(30);
    while sink.queued() != 0 {
      assert!(
        std::time::Instant::now() < drained_at,
        "the admitted queue never drained"
      );
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sink.queued(), 0);
    let persisted = all_records(context.store()).await.len();
    assert_eq!(persisted, MAX_QUEUED_TRACE_PERSISTENCE);
    assert_eq!(live_records.load(Ordering::Relaxed), persisted);
    // Conservation: dropped plus persisted equals everything fed.
    assert_eq!(sink.dropped(), FED - persisted);

    // The observability snapshot carries the drop counter under its
    // well-known tag.
    let snapshot = crate::ObservabilitySnapshot::new(
      sink.clock_now(),
      0,
      0,
      0,
      0,
      0,
      0,
      persisted,
      sink.dropped(),
      0,
      true,
    )
    .unwrap();
    let dropped_tag =
      crate::QualifiedTag::parse(crate::ObservabilitySnapshot::TRACE_RECORDS_DROPPED).unwrap();
    assert_eq!(
      snapshot.counter(&dropped_tag),
      Some(u64::try_from(sink.dropped()).unwrap())
    );
  }

  /// Under a concurrent terminal-record burst the queue depth stays
  /// within the bound at every observed instant, everything drains, and
  /// the drop aggregate conserves the fed population against the
  /// persisted one.
  #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
  async fn concurrent_terminal_burst_stays_within_the_queue_bound() {
    let (sink, context, live_records) = open_sink().await;

    // Feeder tasks: every fed record either queues (within the bound) or
    // drops; record_terminal never blocks the data-plane caller.
    const FEEDERS: u32 = 3;
    const PER_FEEDER: u32 = 40;
    let mut feeders = tokio::task::JoinSet::new();
    for feeder in 0..FEEDERS {
      let sink = sink.clone();
      feeders.spawn(async move {
        for seed in 0..PER_FEEDER {
          sink.record_terminal(terminal_record(seed + feeder * PER_FEEDER, &sink));
        }
      });
    }

    // A concurrent sampler observes the queue depth live; the bound must
    // hold at every instant it can see.
    let stop = Arc::new(AtomicBool::new(false));
    let sampler_sink = sink.clone();
    let sampler_stop = Arc::clone(&stop);
    let sampler = tokio::spawn(async move {
      let mut deepest = 0_usize;
      let mut samples = 0_u64;
      while !sampler_stop.load(Ordering::Relaxed) {
        deepest = deepest.max(sampler_sink.queued());
        samples += 1;
        tokio::task::yield_now().await;
      }
      (deepest, samples)
    });

    while feeders.join_next().await.is_some() {}
    let drained_at = std::time::Instant::now() + Duration::from_secs(30);
    while sink.queued() != 0 {
      assert!(
        std::time::Instant::now() < drained_at,
        "the admitted queue never drained"
      );
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sink.queued(), 0);
    stop.store(true, Ordering::Relaxed);
    let (deepest, samples) = sampler.await.unwrap();
    assert!(samples > 0, "the sampler never observed the queue");
    assert!(deepest <= MAX_QUEUED_TRACE_PERSISTENCE);

    // Conservation under contention: every fed record is exactly one of
    // dropped or persisted (an admitted write can still lose the store's
    // optimistic-concurrency race, so the persisted side may sit lower).
    let fed = usize::try_from(FEEDERS * PER_FEEDER).unwrap();
    let persisted = live_records.load(Ordering::Relaxed);
    assert!(sink.dropped() + persisted <= fed);
    // Distinct trace ids make the durable population equal the
    // successful-persistence counter.
    assert_eq!(all_records(context.store()).await.len(), persisted);
  }
}

/// The persistence handle shared with the packet pump: clones cheaply and
/// records terminal transitions best-effort — a persistence failure is
/// surfaced as a diagnostic and never corrupts the data plane's explicit
/// semantics. Concurrent persistence tasks are bounded and the admitted
/// queue is bounded too, so a burst of completions cannot spawn unbounded
/// work: once the queue bound is reached, further terminal records are
/// dropped and counted in the observability snapshot instead of queueing
/// without limit. The shared live-record counter lets the retention sweep
/// stay skipped while no durable record exists.
#[derive(Clone)]
pub(crate) struct TraceSink {
  context: std::sync::Arc<crate::identity::lifecycle::LocalIdentityContext>,
  entropy: std::sync::Arc<dyn Entropy>,
  clock: std::sync::Arc<dyn WallClock>,
  /// Bounds concurrently running persistence tasks.
  permits: std::sync::Arc<tokio::sync::Semaphore>,
  /// Admitted-but-unfinished persistence tasks: incremented under the
  /// queue-bound compare-and-swap before each spawn, decremented when the
  /// spawned task finishes. The bound makes the queue depth structural.
  pending: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  /// Terminal records dropped because the queue bound was full; surfaced
  /// through the observability snapshot's drop counter.
  dropped: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  /// Approximate durable record population: incremented per successful
  /// persistence, decremented by the retention sweep's removals. Transition
  /// rewrites may over-approximate; that only costs extra cheap sweeps,
  /// never a missed one.
  live_records: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// The maximum number of concurrent terminal-record persistence tasks.
const MAX_CONCURRENT_TRACE_PERSISTENCE: usize = 16;

/// The maximum number of admitted-but-unfinished terminal-record
/// persistence tasks: at most [`MAX_CONCURRENT_TRACE_PERSISTENCE`] run at
/// once and the rest queue. The durable trace is a best-effort observation
/// surface, so once this bound is reached the next terminal record is
/// dropped and counted rather than queueing without limit.
const MAX_QUEUED_TRACE_PERSISTENCE: usize = 64;

impl TraceSink {
  pub(crate) fn new(
    context: std::sync::Arc<crate::identity::lifecycle::LocalIdentityContext>,
    entropy: std::sync::Arc<dyn Entropy>, clock: std::sync::Arc<dyn WallClock>,
    live_records: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  ) -> Self {
    Self {
      context,
      entropy,
      clock,
      permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
        MAX_CONCURRENT_TRACE_PERSISTENCE,
      )),
      pending: std::sync::Arc::default(),
      dropped: std::sync::Arc::default(),
      live_records,
    }
  }

  /// Admits one terminal-record persistence task when the queue bound has
  /// room, spawning the bounded best-effort write; a full bound drops the
  /// record, counts the drop, and returns immediately. The counter
  /// compare-and-swap keeps the queue depth structurally at or below
  /// [`MAX_QUEUED_TRACE_PERSISTENCE`] under any admission race.
  pub(crate) fn record_terminal(&self, record: TraceRecord) {
    let admitted = self.pending.fetch_update(
      std::sync::atomic::Ordering::Relaxed,
      std::sync::atomic::Ordering::Relaxed,
      |pending| (pending < MAX_QUEUED_TRACE_PERSISTENCE).then_some(pending + 1),
    );
    if admitted.is_err() {
      let dropped = self
        .dropped
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1;
      tracing::debug!(
        dropped,
        "route trace record dropped: persistence queue full"
      );
      return;
    }
    let sink = self.clone();
    tokio::spawn(async move {
      sink.record(record).await;
      sink
        .pending
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    });
  }

  /// The terminal records dropped so far because the persistence queue
  /// was full; the observability snapshot surfaces this aggregate.
  pub(crate) fn dropped(&self) -> usize {
    self.dropped.load(std::sync::atomic::Ordering::Relaxed)
  }

  /// The current admitted-but-unfinished persistence-task population.
  /// Test-only: production reads the drop aggregate, not the queue depth.
  #[cfg(test)]
  pub(crate) fn queued(&self) -> usize {
    self.pending.load(std::sync::atomic::Ordering::Relaxed)
  }

  /// Records one transition; failures are logged, never propagated into
  /// the stream path.
  pub(crate) async fn record(&self, record: TraceRecord) {
    let _permit = self.permits.acquire().await;
    match put_trace(
      self.context.store(),
      self.entropy.as_ref(),
      self.clock.as_ref(),
      record,
    )
    .await
    {
      Ok(()) => {
        self
          .live_records
          .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      }
      Err(error) => {
        tracing::warn!(kind = ?error.kind(), "route trace persistence failed");
      }
    }
  }

  pub(crate) fn clock_now(&self) -> SystemTime {
    self.clock.now()
  }
}
