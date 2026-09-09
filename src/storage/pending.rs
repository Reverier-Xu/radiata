//! Pending-transaction journal for exact recovered opens.
//!
//! A journaled transaction carries one pending record under a singleton key
//! derived from a bounded printable purpose. The record stores the exact
//! target transaction identity, the pre-target base revision, and the planned
//! operation list, excluding the pending-record put and the permanent used-ID
//! marker. Because the record is written atomically with the transaction it
//! describes, a restarted store can reconstruct the exact frozen identity
//! from durable state instead of trusting caller-supplied digests.
//!
//! Discovery scans the pending namespace with the exact purpose key as
//! prefix and fails closed on any ambiguity: extended keys, duplicate
//! entries, malformed values, or purpose mismatches are storage corruption.

use std::{fmt, sync::Arc, time::Duration};

use minicbor::{
  Decode, Decoder, Encode, Encoder,
  decode::{self},
  encode::{self, Write},
};

use super::{
  CommitState, MetadataStore, PendingCommit,
  receipt::{
    HostWallClock, PreparedTransaction, ReceiptIdentity, ReceiptReferenceChange,
    ReceiptReferenceToken, WallClock, build_receipt_change_operations, group_receipt_changes,
    internal_namespace, operation_uses_reserved_namespace, prepare_internal_transaction,
    storage_corrupt,
  },
};
pub(crate) use crate::storage::families::PENDING_NAMESPACE;
use crate::{
  CommitOutcome, CommitReceipt, Digest, Error, QualifiedTag, Result, StoreExpectation, StoreKey,
  StoreNamespace, StoreOperation, StoreRevision, StoreValue, TransactionId,
  error::fixed_bytes,
  protocol::{CborLimits, decode_canonical_strict, encode_canonical},
  provider::{StorageFactory, StoreSnapshot},
};
const PENDING_SCHEMA: &str = "radiata.woooo.tech/schemas/pending-transaction-v1";
const RECORD_VERSION: u64 = 1;
const MAX_PURPOSE_LEN: usize = 128;
const PENDING_LIMITS: CborLimits = CborLimits::new(8, 1_024, 65_536);

#[derive(Encode, Decode)]
#[cbor(array)]
struct PendingTransactionWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  purpose: String,
  #[n(3)]
  transaction_id: String,
  #[n(4)]
  #[cbor(with = "minicbor::bytes")]
  base_revision: Vec<u8>,
  #[n(5)]
  planned_operations: Vec<PlannedOperationWire>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PlannedOperationWire {
  Check {
    namespace: String,
    key: Vec<u8>,
    expectation: ExpectationWire,
  },
  Put {
    namespace: String,
    key: Vec<u8>,
    expectation: ExpectationWire,
    value: Vec<u8>,
  },
  Delete {
    namespace: String,
    key: Vec<u8>,
    expected: Vec<u8>,
  },
  ForgetReceipt {
    transaction: String,
    expected_operation_digest: Vec<u8>,
  },
}

impl<C> Encode<C> for PlannedOperationWire {
  fn encode<W: Write>(
    &self, encoder: &mut Encoder<W>, context: &mut C,
  ) -> std::result::Result<(), encode::Error<W::Error>> {
    match self {
      Self::Check {
        namespace,
        key,
        expectation,
      } => {
        encoder.array(4)?.u64(0)?.str(namespace)?.bytes(key)?;
        expectation.encode(encoder, context)?;
      }
      Self::Put {
        namespace,
        key,
        expectation,
        value,
      } => {
        encoder.array(5)?.u64(1)?.str(namespace)?.bytes(key)?;
        expectation.encode(encoder, context)?;
        encoder.bytes(value)?;
      }
      Self::Delete {
        namespace,
        key,
        expected,
      } => {
        encoder
          .array(4)?
          .u64(2)?
          .str(namespace)?
          .bytes(key)?
          .bytes(expected)?;
      }
      Self::ForgetReceipt {
        transaction,
        expected_operation_digest,
      } => {
        encoder
          .array(3)?
          .u64(3)?
          .str(transaction)?
          .bytes(expected_operation_digest)?;
      }
    }
    Ok(())
  }
}

impl<'bytes, C> Decode<'bytes, C> for PlannedOperationWire {
  fn decode(
    decoder: &mut Decoder<'bytes>, context: &mut C,
  ) -> std::result::Result<Self, decode::Error> {
    let length = decoder
      .array()?
      .ok_or_else(|| decode::Error::message("planned operation length"))?;
    let tag = decoder.u64()?;
    match (tag, length) {
      (0, 4) => Ok(Self::Check {
        namespace: decoder.str()?.to_owned(),
        key: decoder.bytes()?.to_vec(),
        expectation: ExpectationWire::decode(decoder, context)?,
      }),
      (1, 5) => Ok(Self::Put {
        namespace: decoder.str()?.to_owned(),
        key: decoder.bytes()?.to_vec(),
        expectation: ExpectationWire::decode(decoder, context)?,
        value: decoder.bytes()?.to_vec(),
      }),
      (2, 4) => Ok(Self::Delete {
        namespace: decoder.str()?.to_owned(),
        key: decoder.bytes()?.to_vec(),
        expected: decoder.bytes()?.to_vec(),
      }),
      (3, 3) => Ok(Self::ForgetReceipt {
        transaction: decoder.str()?.to_owned(),
        expected_operation_digest: decoder.bytes()?.to_vec(),
      }),
      _ => Err(decode::Error::message("planned operation variant")),
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExpectationWire {
  Absent,
  Exact(Vec<u8>),
}

impl<C> Encode<C> for ExpectationWire {
  fn encode<W: Write>(
    &self, encoder: &mut Encoder<W>, _context: &mut C,
  ) -> std::result::Result<(), encode::Error<W::Error>> {
    match self {
      Self::Absent => {
        encoder.array(1)?.u64(0)?;
      }
      Self::Exact(digest) => {
        encoder.array(2)?.u64(1)?.bytes(digest)?;
      }
    }
    Ok(())
  }
}

impl<'bytes, C> Decode<'bytes, C> for ExpectationWire {
  fn decode(
    decoder: &mut Decoder<'bytes>, _context: &mut C,
  ) -> std::result::Result<Self, decode::Error> {
    let length = decoder
      .array()?
      .ok_or_else(|| decode::Error::message("expectation length"))?;
    let tag = decoder.u64()?;
    match (tag, length) {
      (0, 1) => Ok(Self::Absent),
      (1, 2) => Ok(Self::Exact(decoder.bytes()?.to_vec())),
      _ => Err(decode::Error::message("expectation variant")),
    }
  }
}

impl PlannedOperationWire {
  fn from_operation(operation: &StoreOperation) -> Self {
    match operation {
      StoreOperation::Check {
        namespace,
        key,
        expected,
      } => Self::Check {
        namespace: namespace.as_str().to_owned(),
        key: key.as_bytes().to_vec(),
        expectation: ExpectationWire::from_expectation(expected),
      },
      StoreOperation::Put {
        namespace,
        key,
        expected,
        value,
      } => Self::Put {
        namespace: namespace.as_str().to_owned(),
        key: key.as_bytes().to_vec(),
        expectation: ExpectationWire::from_expectation(expected),
        value: value.as_bytes().to_vec(),
      },
      StoreOperation::Delete {
        namespace,
        key,
        expected,
      } => Self::Delete {
        namespace: namespace.as_str().to_owned(),
        key: key.as_bytes().to_vec(),
        expected: expected.as_bytes().to_vec(),
      },
      StoreOperation::ForgetReceipt {
        transaction,
        expected_operation_digest,
      } => Self::ForgetReceipt {
        transaction: transaction.as_str().to_owned(),
        expected_operation_digest: expected_operation_digest.as_bytes().to_vec(),
      },
    }
  }

  fn into_operation(self) -> Result<StoreOperation> {
    Ok(match self {
      Self::Check {
        namespace,
        key,
        expectation,
      } => StoreOperation::Check {
        namespace: planned_namespace(&namespace)?,
        key: StoreKey::new(Arc::from(key)),
        expected: expectation.into_expectation()?,
      },
      Self::Put {
        namespace,
        key,
        expectation,
        value,
      } => StoreOperation::Put {
        namespace: planned_namespace(&namespace)?,
        key: StoreKey::new(Arc::from(key)),
        expected: expectation.into_expectation()?,
        value: StoreValue::new(Arc::from(value)),
      },
      Self::Delete {
        namespace,
        key,
        expected,
      } => StoreOperation::Delete {
        namespace: planned_namespace(&namespace)?,
        key: StoreKey::new(Arc::from(key)),
        expected: Digest::from_bytes(fixed_bytes(&expected, "planned delete digest")?),
      },
      Self::ForgetReceipt {
        transaction,
        expected_operation_digest,
      } => StoreOperation::ForgetReceipt {
        transaction: TransactionId::parse(&transaction)?,
        expected_operation_digest: Digest::from_bytes(fixed_bytes(
          &expected_operation_digest,
          "planned forget digest",
        )?),
      },
    })
  }
}

impl ExpectationWire {
  fn from_expectation(expectation: &StoreExpectation) -> Self {
    match expectation {
      StoreExpectation::Absent => Self::Absent,
      StoreExpectation::Exact(digest) => Self::Exact(digest.as_bytes().to_vec()),
    }
  }

  fn into_expectation(self) -> Result<StoreExpectation> {
    Ok(match self {
      Self::Absent => StoreExpectation::Absent,
      Self::Exact(digest) => StoreExpectation::Exact(Digest::from_bytes(fixed_bytes(
        &digest,
        "planned expectation digest",
      )?)),
    })
  }
}

/// A decoded pending-transaction journal record.
///
/// The planned operations are the exact caller and receipt-change operations
/// of the target transaction; the pending-record put and the permanent
/// used-ID marker are appended during recovery, never stored.
pub(crate) struct PendingTransactionV1 {
  purpose: String,
  transaction: TransactionId,
  base_revision: StoreRevision,
  planned_operations: Vec<StoreOperation>,
}

impl PendingTransactionV1 {
  pub(super) fn new(
    purpose: &str, transaction: &TransactionId, base_revision: &StoreRevision,
    planned_operations: &[StoreOperation],
  ) -> Result<Self> {
    validate_purpose(purpose)?;
    validate_planned_operations(purpose, planned_operations)?;
    Ok(Self {
      purpose: purpose.to_owned(),
      transaction: transaction.clone(),
      base_revision: base_revision.clone(),
      planned_operations: planned_operations.to_vec(),
    })
  }

  pub(super) fn purpose(&self) -> &str {
    &self.purpose
  }

  pub(super) const fn transaction(&self) -> &TransactionId {
    &self.transaction
  }

  pub(super) const fn base_revision(&self) -> &StoreRevision {
    &self.base_revision
  }

  pub(super) fn planned_operations(&self) -> &[StoreOperation] {
    &self.planned_operations
  }

  /// Canonical wire encoding of the pending-transaction record; shared
  /// by the receipt engine and the compatibility freeze reader.
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &PendingTransactionWire {
        schema: PENDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        purpose: self.purpose.clone(),
        transaction_id: self.transaction.as_str().to_owned(),
        base_revision: self.base_revision.as_bytes().to_vec(),
        planned_operations: self
          .planned_operations
          .iter()
          .map(PlannedOperationWire::from_operation)
          .collect(),
      },
      PENDING_LIMITS,
    )
  }

  /// The canonical pending-transaction decoder; the compatibility
  /// freeze reader consumes the same fail-closed path as the engine.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: PendingTransactionWire =
      decode_canonical_strict(bytes, PENDING_LIMITS, "pending transaction canonical form")?;
    if wire.schema != PENDING_SCHEMA {
      return Err(Error::invalid_input("pending transaction schema"));
    }
    if wire.record_version != RECORD_VERSION {
      return Err(Error::invalid_input("pending transaction version"));
    }
    let transaction = TransactionId::parse(&wire.transaction_id)?;
    let base_revision = StoreRevision::new(Arc::from(wire.base_revision))?;
    let mut planned_operations = Vec::new();
    planned_operations
      .try_reserve_exact(wire.planned_operations.len())
      .map_err(|_| Error::resource_exhausted("pending transaction plan"))?;
    for operation in wire.planned_operations {
      planned_operations.push(operation.into_operation()?);
    }
    Self::new(
      &wire.purpose,
      &transaction,
      &base_revision,
      &planned_operations,
    )
  }

  /// Rebuilds the exact frozen identity of the journaled transaction.
  ///
  /// The reconstruction appends the pending-record put with the stored value
  /// bytes verbatim and then the permanent active used-ID marker, so the
  /// resulting operation digest equals the originally submitted digest.
  pub(super) fn recover_identity(&self, stored_value: &StoreValue) -> Result<ReceiptIdentity> {
    let mut operations = self.planned_operations.clone();
    operations
      .try_reserve_exact(1)
      .map_err(|_| Error::resource_exhausted("pending transaction recovery"))?;
    operations.push(StoreOperation::Put {
      namespace: pending_namespace()?,
      key: pending_key(&self.purpose),
      expected: StoreExpectation::Absent,
      value: stored_value.clone(),
    });
    let prepared = prepare_internal_transaction(
      self.transaction.clone(),
      self.base_revision.clone(),
      operations,
    )
    .map_err(|_| storage_corrupt())?;
    Ok(ReceiptIdentity::from_parts(
      prepared.id().clone(),
      prepared.operation_digest().clone(),
    ))
  }

  #[cfg(test)]
  pub(super) fn encode_for_test(
    purpose: &str, transaction: &TransactionId, base_revision: &StoreRevision,
    planned_operations: &[StoreOperation],
  ) -> Result<Vec<u8>> {
    encode_canonical(
      &PendingTransactionWire {
        schema: PENDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        purpose: purpose.to_owned(),
        transaction_id: transaction.as_str().to_owned(),
        base_revision: base_revision.as_bytes().to_vec(),
        planned_operations: planned_operations
          .iter()
          .map(PlannedOperationWire::from_operation)
          .collect(),
      },
      PENDING_LIMITS,
    )
  }
}

impl fmt::Debug for PendingTransactionV1 {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("PendingTransactionV1")
      .field("purpose", &self.purpose)
      .field("transaction", &self.transaction)
      .field("base_revision", &self.base_revision)
      .field("planned_operations", &self.planned_operations.len())
      .finish_non_exhaustive()
  }
}

/// Outcome of a pending-record cleanup commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupOutcome {
  Applied(CommitReceipt),
  Absent,
  Aborted,
  Conflict,
  Unknown(ReceiptIdentity),
}

impl MetadataStore {
  /// Prepares one journaled transaction from a single snapshot.
  ///
  /// Caller operations and grouped receipt-reference changes form the planned
  /// operation list. The pending record for `purpose` is encoded from those
  /// planned operations and the snapshot base revision, appended exactly once
  /// as a put, and followed by the permanent active used-ID marker. The
  /// pending-record token is injected into the self-reference group so the
  /// target receipt references owner records and its own pending record
  /// atomically.
  pub(crate) async fn prepare_journaled_transaction(
    &self, snapshot: &dyn StoreSnapshot, id: TransactionId, purpose: &str,
    caller_operations: Vec<StoreOperation>, mut changes: Vec<ReceiptReferenceChange>,
  ) -> Result<PreparedTransaction> {
    validate_purpose(purpose)?;
    if caller_operations
      .iter()
      .any(operation_uses_reserved_namespace)
    {
      return Err(Error::invalid_input("metadata storage reserved namespace"));
    }
    let namespace = pending_namespace()?;
    let key = pending_key(purpose);
    if caller_operations
      .iter()
      .any(|operation| operation_targets_pending_record(operation, &namespace, &key))
    {
      return Err(Error::invalid_input("pending transaction record"));
    }
    let token = ReceiptReferenceToken::for_record(&namespace, &key);
    inject_self_token(&mut changes, token)?;

    let internal = internal_namespace()?;
    let groups = group_receipt_changes(&id, changes)?;
    let mut operations = caller_operations;
    for group in &groups {
      let built = build_receipt_change_operations(snapshot, &internal, &id, group).await?;
      operations
        .try_reserve_exact(built.len())
        .map_err(|_| Error::resource_exhausted("metadata storage transaction"))?;
      operations.extend(built);
    }
    let record = PendingTransactionV1::new(purpose, &id, snapshot.revision(), &operations)?;
    let value = StoreValue::new(Arc::from(record.encode()?));
    operations
      .try_reserve_exact(1)
      .map_err(|_| Error::resource_exhausted("metadata storage transaction"))?;
    operations.push(StoreOperation::Put {
      namespace,
      key,
      expected: StoreExpectation::Absent,
      value,
    });
    prepare_internal_transaction(id, snapshot.revision().clone(), operations)
  }

  /// Opens a store classified by the pending journal for `purpose`.
  ///
  /// The open itself walks the production open path, so the schema gate
  /// applies before any journal discovery. Without a pending record the
  /// store starts ready on the old state. With a pending record the store
  /// starts frozen on the exact identity reconstructed from the record,
  /// and reconciliation must prove the journaled transaction committed.
  pub(crate) async fn open_pending_recovered(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, purpose: &str,
  ) -> Result<(Self, Option<ReceiptIdentity>)> {
    Self::open_pending_recovered_with_clock(
      factory,
      receipt_retention,
      purpose,
      Arc::new(HostWallClock),
    )
    .await
  }

  pub(super) async fn open_pending_recovered_with_clock(
    factory: &Arc<dyn StorageFactory>, receipt_retention: Duration, purpose: &str,
    clock: Arc<dyn WallClock>,
  ) -> Result<(Self, Option<ReceiptIdentity>)> {
    validate_purpose(purpose)?;
    // The recovered open walks the production open path: the capability
    // check, the schema gate, and the store construction stay single-
    // sourced in `open_with_state`, so a store whose schema version this
    // build does not know fails closed before any pending record is
    // discovered or replayed.
    let store =
      Self::open_with_state(factory, receipt_retention, clock, CommitState::Ready).await?;
    let discovered = {
      let snapshot = store.snapshot().await?;
      discover_pending(snapshot.as_ref(), purpose).await?
    };
    let Some((stored, record)) = discovered else {
      return Ok((store, None));
    };
    let identity = record.recover_identity(&stored)?;
    *store.lock_state()? = CommitState::Frozen {
      pending: PendingCommit {
        transaction: identity.transaction().clone(),
        digest: identity.operation_digest().clone(),
        journal_proven: true,
      },
      provider_call_active: false,
    };
    Ok((store, Some(identity)))
  }

  /// Recovers a pending journal for `purpose` on an already open store.
  ///
  /// Without a pending record the store stays ready on the old state. With
  /// a pending record the store freezes on the exact identity reconstructed
  /// from the journal and reconciliation must prove the journaled
  /// transaction committed.
  pub(crate) async fn recover_pending(&self, purpose: &str) -> Result<Option<ReceiptIdentity>> {
    validate_purpose(purpose)?;
    let discovered = {
      let snapshot = self.snapshot().await?;
      discover_pending(snapshot.as_ref(), purpose).await?
    };
    let Some((stored, record)) = discovered else {
      return Ok(None);
    };
    let identity = record.recover_identity(&stored)?;
    self.freeze_journaled(&identity)?;
    Ok(Some(identity))
  }

  /// Deletes the pending record for `purpose` and removes only its
  /// receipt-reference token from the target receipt in one transaction.
  ///
  /// Family owner tokens remain referenced. The cleanup transaction itself
  /// is not journaled; a restart after an unknown cleanup outcome is
  /// classified by pending-record presence and may retry the cleanup.
  pub(crate) async fn cleanup_pending(
    &self, purpose: &str, operation_id: TransactionId,
  ) -> Result<PendingCleanupOutcome> {
    validate_purpose(purpose)?;
    let snapshot = self.snapshot().await?;
    let namespace = pending_namespace()?;
    let key = pending_key(purpose);
    let Some((stored, record)) = discover_pending(snapshot.as_ref(), purpose).await? else {
      return Ok(PendingCleanupOutcome::Absent);
    };
    let target = record.recover_identity(&stored)?;
    let token = ReceiptReferenceToken::for_record(&namespace, &key);
    let groups = group_receipt_changes(
      &operation_id,
      vec![ReceiptReferenceChange::Remove {
        target,
        tokens: vec![token],
      }],
    )?;
    let internal = internal_namespace()?;
    let revision = snapshot.revision().clone();
    let mut operations = Vec::new();
    operations
      .try_reserve_exact(1)
      .map_err(|_| Error::resource_exhausted("pending cleanup transaction"))?;
    operations.push(StoreOperation::Delete {
      namespace,
      key,
      expected: stored.digest().clone(),
    });
    for group in &groups {
      let built =
        build_receipt_change_operations(snapshot.as_ref(), &internal, &operation_id, group).await?;
      operations
        .try_reserve_exact(built.len())
        .map_err(|_| Error::resource_exhausted("pending cleanup transaction"))?;
      operations.extend(built);
    }
    drop(snapshot);
    let prepared = prepare_internal_transaction(operation_id, revision, operations)?;
    Ok(match self.commit(prepared).await? {
      CommitOutcome::Committed(receipt) => PendingCleanupOutcome::Applied(receipt),
      CommitOutcome::Aborted => PendingCleanupOutcome::Aborted,
      CommitOutcome::Conflict => PendingCleanupOutcome::Conflict,
      CommitOutcome::Unknown {
        transaction,
        operation_digest,
      } => {
        PendingCleanupOutcome::Unknown(ReceiptIdentity::from_parts(transaction, operation_digest))
      }
    })
  }
}

/// Discovers zero or one pending record for `purpose` from a snapshot.
///
/// Any prefix-extended key, duplicate entry, malformed value, or purpose
/// mismatch fails closed as storage corruption.
pub(crate) async fn discover_pending(
  snapshot: &dyn StoreSnapshot, purpose: &str,
) -> Result<Option<(StoreValue, PendingTransactionV1)>> {
  validate_purpose(purpose)?;
  let namespace = pending_namespace()?;
  let key = pending_key(purpose);
  let mut scan = snapshot.scan(&namespace, key.as_bytes()).await?;
  let mut found = None;
  while let Some(entry) = scan.next().await? {
    if entry.namespace() != &namespace || entry.key().as_bytes() != key.as_bytes() {
      return Err(storage_corrupt());
    }
    if found.is_some() {
      return Err(storage_corrupt());
    }
    let record =
      PendingTransactionV1::decode(entry.value().as_bytes()).map_err(|_| storage_corrupt())?;
    if record.purpose != purpose {
      return Err(storage_corrupt());
    }
    found = Some((entry.value().clone(), record));
  }
  Ok(found)
}

fn inject_self_token(
  changes: &mut Vec<ReceiptReferenceChange>, token: ReceiptReferenceToken,
) -> Result<()> {
  for change in changes.iter_mut() {
    if let ReceiptReferenceChange::AddSelf(tokens) = change {
      tokens
        .try_reserve_exact(1)
        .map_err(|_| Error::resource_exhausted("pending transaction change"))?;
      tokens.push(token);
      return Ok(());
    }
  }
  changes
    .try_reserve_exact(1)
    .map_err(|_| Error::resource_exhausted("pending transaction change"))?;
  changes.push(ReceiptReferenceChange::AddSelf(vec![token]));
  Ok(())
}

fn operation_targets_pending_record(
  operation: &StoreOperation, namespace: &StoreNamespace, key: &StoreKey,
) -> bool {
  match operation {
    StoreOperation::Check {
      namespace: actual_namespace,
      key: actual_key,
      ..
    }
    | StoreOperation::Put {
      namespace: actual_namespace,
      key: actual_key,
      ..
    }
    | StoreOperation::Delete {
      namespace: actual_namespace,
      key: actual_key,
      ..
    } => actual_namespace == namespace && actual_key == key,
    StoreOperation::ForgetReceipt { .. } => false,
  }
}

fn validate_planned_operations(purpose: &str, operations: &[StoreOperation]) -> Result<()> {
  let namespace = pending_namespace()?;
  let key = pending_key(purpose);
  if operations
    .iter()
    .any(|operation| operation_targets_pending_record(operation, &namespace, &key))
  {
    return Err(Error::invalid_input("pending transaction plan"));
  }
  Ok(())
}

fn validate_purpose(purpose: &str) -> Result<()> {
  if purpose.is_empty()
    || purpose.len() > MAX_PURPOSE_LEN
    || !purpose.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
  {
    return Err(Error::invalid_input("pending transaction purpose"));
  }
  Ok(())
}

pub(super) fn pending_namespace() -> Result<StoreNamespace> {
  let tag = QualifiedTag::parse(PENDING_NAMESPACE)?;
  if tag.category() != crate::protocol::tag::CATEGORY_METADATA {
    return Err(Error::invalid_input("pending transaction namespace"));
  }
  Ok(StoreNamespace::new(tag))
}

/// Counts pending journal records for the bounded runtime status view.
/// The journal is bounded by construction (one record per in-flight
/// transaction); the count never exposes record contents.
pub(crate) async fn pending_transaction_count(
  store: &crate::storage::MetadataStore,
) -> Result<usize> {
  let snapshot = store.snapshot().await?;
  let namespace = pending_namespace()?;
  let mut scan = snapshot.scan(&namespace, &[]).await?;
  let mut count = 0_usize;
  while let Some(entry) = scan.next().await? {
    if entry.namespace() != &namespace {
      return Err(storage_corrupt());
    }
    count += 1;
  }
  Ok(count)
}

pub(super) fn pending_key(purpose: &str) -> StoreKey {
  StoreKey::new(Arc::from(purpose.as_bytes()))
}

fn planned_namespace(value: &str) -> Result<StoreNamespace> {
  Ok(StoreNamespace::new(QualifiedTag::parse(value)?))
}

#[cfg(test)]
mod tests {
  use super::*;

  const PURPOSE: &str = "local-identity";
  const TRANSACTION: &str = "txn_0123456789abcdefghijk";
  const FORGOTTEN_TRANSACTION: &str = "txn_111111111111111111111";
  use crate::{
    identity::records::LOCAL_IDENTITY_NAMESPACE as IDENTITY_NAMESPACE,
    storage::families::MERGE_GRANT_NAMESPACE as GRANT_NAMESPACE,
  };

  fn namespace(value: &str) -> StoreNamespace {
    StoreNamespace::new(QualifiedTag::parse(value).unwrap())
  }

  fn transaction() -> TransactionId {
    TransactionId::parse(TRANSACTION).unwrap()
  }

  fn revision() -> StoreRevision {
    StoreRevision::new(Arc::from([1])).unwrap()
  }

  fn planned_operations() -> Vec<StoreOperation> {
    vec![
      StoreOperation::Check {
        namespace: namespace(IDENTITY_NAMESPACE),
        key: StoreKey::new(Arc::from(b"self".as_slice())),
        expected: StoreExpectation::Absent,
      },
      StoreOperation::Put {
        namespace: namespace(IDENTITY_NAMESPACE),
        key: StoreKey::new(Arc::from(b"binding".as_slice())),
        expected: StoreExpectation::Exact(Digest::from_bytes([0x0B; 32])),
        value: StoreValue::new(Arc::from(b"record-bytes".as_slice())),
      },
      StoreOperation::Delete {
        namespace: namespace(GRANT_NAMESPACE),
        key: StoreKey::new(Arc::from(b"old".as_slice())),
        expected: Digest::from_bytes([0x0C; 32]),
      },
      StoreOperation::ForgetReceipt {
        transaction: TransactionId::parse(FORGOTTEN_TRANSACTION).unwrap(),
        expected_operation_digest: Digest::from_bytes([0x0D; 32]),
      },
    ]
  }

  fn record() -> PendingTransactionV1 {
    PendingTransactionV1::new(PURPOSE, &transaction(), &revision(), &planned_operations()).unwrap()
  }

  fn golden(hex: &str) -> Vec<u8> {
    crate::hex::decode(hex, "golden").unwrap()
  }

  use crate::hex::encode as hex;

  const PENDING_RECORD_GOLDEN: &str = "867831726164696174612e776f6f6f6f2e746563682f736368656d61732f70656e64696e672d7472616e73616374696f6e2d7631016e6c6f63616c2d6964656e74697479781974786e5f303132333435363738396162636465666768696a6b4101848400782d726164696174612e776f6f6f6f2e746563682f6d657461646174612f6c6f63616c2d6964656e746974792d76314473656c6681008501782d726164696174612e776f6f6f6f2e746563682f6d657461646174612f6c6f63616c2d6964656e746974792d76314762696e64696e67820158200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b4c7265636f72642d62797465738402782a726164696174612e776f6f6f6f2e746563682f6d657461646174612f6d657267652d6772616e742d7631436f6c6458200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c8303781974786e5f31313131313131313131313131313131313131313158200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";

  #[test]
  fn identity_records_pending_record_golden_matches_exact_bytes() {
    let encoded = record().encode().unwrap();
    assert_eq!(encoded, golden(PENDING_RECORD_GOLDEN));
    assert_eq!(record().encode().unwrap(), encoded);
  }

  #[test]
  fn identity_records_pending_record_decodes_golden_to_exact_record() {
    let decoded = PendingTransactionV1::decode(&golden(PENDING_RECORD_GOLDEN)).unwrap();
    assert_eq!(decoded.purpose, PURPOSE);
    assert_eq!(decoded.transaction, transaction());
    assert_eq!(decoded.base_revision, revision());
    assert_eq!(decoded.planned_operations, planned_operations());
    assert_eq!(decoded.encode().unwrap(), golden(PENDING_RECORD_GOLDEN));
  }

  fn version_position(bytes: &[u8]) -> usize {
    // [array header][text header 0x78 len][schema bytes][version]
    assert_eq!(bytes[1], 0x78);
    1 + 2 + bytes[2] as usize
  }

  #[test]
  fn identity_records_pending_record_rejects_noncanonical_trailing_and_shape_mutations() {
    let encoded = golden(PENDING_RECORD_GOLDEN);

    let mut trailed = encoded.clone();
    trailed.push(0x00);
    assert!(PendingTransactionV1::decode(&trailed).is_err());

    let mut extra_field = encoded.clone();
    extra_field[0] = 0x87;
    extra_field.push(0x00);
    assert!(PendingTransactionV1::decode(&extra_field).is_err());

    let mut missing_field = encoded.clone();
    missing_field[0] = 0x85;
    assert!(PendingTransactionV1::decode(&missing_field).is_err());

    let mut map_header = encoded.clone();
    map_header[0] = 0xA6;
    assert!(PendingTransactionV1::decode(&map_header).is_err());

    let mut indefinite = encoded.clone();
    indefinite[0] = 0x9F;
    indefinite.push(0xFF);
    assert!(PendingTransactionV1::decode(&indefinite).is_err());

    let version = version_position(&encoded);
    assert_eq!(encoded[version], 0x01);
    let mut widened = encoded[..version].to_vec();
    widened.extend_from_slice(&[0x18, encoded[version]]);
    widened.extend_from_slice(&encoded[version + 1..]);
    assert!(PendingTransactionV1::decode(&widened).is_err());

    let mut wrong_version = encoded.clone();
    wrong_version[version] = 0x02;
    assert!(PendingTransactionV1::decode(&wrong_version).is_err());

    let mut wrong_schema = encoded.clone();
    let needle = b"pending-transaction-v1";
    let start = wrong_schema
      .windows(needle.len())
      .position(|window| window == needle)
      .unwrap();
    wrong_schema[start + needle.len() - 1] = b'0';
    assert!(PendingTransactionV1::decode(&wrong_schema).is_err());
  }

  fn wire_bytes(
    purpose: &str, transaction: &str, base_revision: Vec<u8>,
    planned_operations: Vec<PlannedOperationWire>,
  ) -> Vec<u8> {
    encode_canonical(
      &PendingTransactionWire {
        schema: PENDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        purpose: purpose.to_owned(),
        transaction_id: transaction.to_owned(),
        base_revision,
        planned_operations,
      },
      PENDING_LIMITS,
    )
    .unwrap()
  }

  #[test]
  fn identity_records_pending_record_rejects_malformed_fields() {
    let operations = || {
      planned_operations()
        .iter()
        .map(PlannedOperationWire::from_operation)
        .collect::<Vec<_>>()
    };
    for bytes in [
      wire_bytes("", TRANSACTION, vec![1], operations()),
      wire_bytes("bad\tpurpose", TRANSACTION, vec![1], operations()),
      wire_bytes("bad\u{7f}purpose", TRANSACTION, vec![1], operations()),
      wire_bytes(&"p".repeat(129), TRANSACTION, vec![1], operations()),
      wire_bytes(PURPOSE, "txn_!12345678abcdefghijk", vec![1], operations()),
      wire_bytes(PURPOSE, "txn_short", vec![1], operations()),
      wire_bytes(PURPOSE, TRANSACTION, vec![], operations()),
    ] {
      assert!(
        PendingTransactionV1::decode(&bytes).is_err(),
        "{}",
        hex(&bytes)
      );
    }
    let longest = wire_bytes(&"p".repeat(128), TRANSACTION, vec![1], operations());
    assert!(PendingTransactionV1::decode(&longest).is_ok());
  }

  #[test]
  fn identity_records_pending_record_rejects_planned_operation_mutations() {
    let short_exact = wire_bytes(
      PURPOSE,
      TRANSACTION,
      vec![1],
      vec![PlannedOperationWire::Check {
        namespace: IDENTITY_NAMESPACE.to_owned(),
        key: b"self".to_vec(),
        expectation: ExpectationWire::Exact(vec![0x0B; 31]),
      }],
    );
    assert!(PendingTransactionV1::decode(&short_exact).is_err());

    let long_exact = wire_bytes(
      PURPOSE,
      TRANSACTION,
      vec![1],
      vec![PlannedOperationWire::Check {
        namespace: IDENTITY_NAMESPACE.to_owned(),
        key: b"self".to_vec(),
        expectation: ExpectationWire::Exact(vec![0x0B; 33]),
      }],
    );
    assert!(PendingTransactionV1::decode(&long_exact).is_err());

    let short_delete = wire_bytes(
      PURPOSE,
      TRANSACTION,
      vec![1],
      vec![PlannedOperationWire::Delete {
        namespace: IDENTITY_NAMESPACE.to_owned(),
        key: b"self".to_vec(),
        expected: vec![0x0C; 31],
      }],
    );
    assert!(PendingTransactionV1::decode(&short_delete).is_err());

    let long_forget = wire_bytes(
      PURPOSE,
      TRANSACTION,
      vec![1],
      vec![PlannedOperationWire::ForgetReceipt {
        transaction: FORGOTTEN_TRANSACTION.to_owned(),
        expected_operation_digest: vec![0x0D; 33],
      }],
    );
    assert!(PendingTransactionV1::decode(&long_forget).is_err());

    let malformed_namespace = wire_bytes(
      PURPOSE,
      TRANSACTION,
      vec![1],
      vec![PlannedOperationWire::Delete {
        namespace: "not a qualified tag".to_owned(),
        key: b"self".to_vec(),
        expected: vec![0x0C; 32],
      }],
    );
    assert!(PendingTransactionV1::decode(&malformed_namespace).is_err());

    let malformed_forget_transaction = wire_bytes(
      PURPOSE,
      TRANSACTION,
      vec![1],
      vec![PlannedOperationWire::ForgetReceipt {
        transaction: "txn_short".to_owned(),
        expected_operation_digest: vec![0x0D; 32],
      }],
    );
    assert!(PendingTransactionV1::decode(&malformed_forget_transaction).is_err());

    let unknown_operation = encode_canonical(
      &(
        PENDING_SCHEMA,
        1_u64,
        PURPOSE,
        TRANSACTION,
        minicbor::bytes::ByteVec::from(vec![1_u8]),
        vec![(9_u64,)],
      ),
      PENDING_LIMITS,
    )
    .unwrap();
    assert!(PendingTransactionV1::decode(&unknown_operation).is_err());

    let short_operation = encode_canonical(
      &(
        PENDING_SCHEMA,
        1_u64,
        PURPOSE,
        TRANSACTION,
        minicbor::bytes::ByteVec::from(vec![1_u8]),
        vec![(
          0_u64,
          IDENTITY_NAMESPACE,
          minicbor::bytes::ByteVec::from(b"self".to_vec()),
        )],
      ),
      PENDING_LIMITS,
    )
    .unwrap();
    assert!(PendingTransactionV1::decode(&short_operation).is_err());

    let unknown_expectation = encode_canonical(
      &(
        PENDING_SCHEMA,
        1_u64,
        PURPOSE,
        TRANSACTION,
        minicbor::bytes::ByteVec::from(vec![1_u8]),
        vec![(
          0_u64,
          IDENTITY_NAMESPACE,
          minicbor::bytes::ByteVec::from(b"self".to_vec()),
          (7_u64,),
        )],
      ),
      PENDING_LIMITS,
    )
    .unwrap();
    assert!(PendingTransactionV1::decode(&unknown_expectation).is_err());

    let self_referencing_plan = PendingTransactionV1::encode_for_test(
      PURPOSE,
      &transaction(),
      &revision(),
      &[StoreOperation::Put {
        namespace: pending_namespace().unwrap(),
        key: pending_key(PURPOSE),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from([0xAA])),
      }],
    )
    .unwrap();
    assert!(PendingTransactionV1::decode(&self_referencing_plan).is_err());
    assert!(
      PendingTransactionV1::new(
        PURPOSE,
        &transaction(),
        &revision(),
        &[StoreOperation::Delete {
          namespace: pending_namespace().unwrap(),
          key: pending_key(PURPOSE),
          expected: Digest::from_bytes([0x0E; 32]),
        }],
      )
      .is_err()
    );
  }

  #[test]
  fn identity_records_pending_purpose_is_bounded_printable_ascii() {
    assert!(validate_purpose("").is_err());
    assert!(validate_purpose(&"p".repeat(129)).is_err());
    assert!(validate_purpose("bad\tpurpose").is_err());
    assert!(validate_purpose("bad\u{7f}purpose").is_err());
    assert!(validate_purpose("node identity").is_ok());
    assert!(validate_purpose(&"p".repeat(128)).is_ok());
  }

  #[test]
  fn identity_records_pending_namespace_and_singleton_key_are_exact() {
    let namespace = pending_namespace().unwrap();
    assert_eq!(
      namespace.as_str(),
      "radiata.woooo.tech/metadata/pending-transaction-v1"
    );
    assert_eq!(
      QualifiedTag::parse(namespace.as_str()).unwrap().category(),
      "metadata"
    );
    assert_eq!(pending_key(PURPOSE).as_bytes(), b"local-identity");
    assert_ne!(pending_key(PURPOSE), pending_key("cluster-genesis"));
  }

  #[test]
  fn identity_records_pending_record_debug_is_redacted() {
    let debug = format!("{:?}", record());
    assert!(debug.contains("PendingTransactionV1"));
    assert!(debug.contains(PURPOSE));
    assert!(!debug.contains("record-bytes"));
    assert!(!debug.contains("binding"));
    assert!(!debug.contains(hex(b"record-bytes").as_str()));
    assert!(!debug.contains(hex(&[0x0B; 32]).as_str()));
  }

  #[test]
  fn identity_records_pending_recovery_rebuilds_exact_identity() {
    let record = record();
    let stored = StoreValue::new(Arc::from(record.encode().unwrap()));
    let identity = record.recover_identity(&stored).unwrap();

    let mut operations = planned_operations();
    operations.push(StoreOperation::Put {
      namespace: pending_namespace().unwrap(),
      key: pending_key(PURPOSE),
      expected: StoreExpectation::Absent,
      value: stored,
    });
    let expected = prepare_internal_transaction(transaction(), revision(), operations).unwrap();
    assert_eq!(identity.transaction(), expected.id());
    assert_eq!(identity.operation_digest(), expected.operation_digest());
  }
}
