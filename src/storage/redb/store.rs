//! The redb production storage adapter implementing the backend-neutral
//! storage SPI (T-G08-02).
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

const ENTRIES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-entries-v1");
const DIGESTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-digests-v1");
const RECEIPTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-receipts-v1");
const VALUE_DIGEST_BYTES: usize = 32;
const META_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("relay-meta-v1");
const REVISION_META_KEY: &[u8] = b"revision";
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

#[cfg(test)]
fn crash_hook(point: u8) {
  if CRASH_POINT.load(std::sync::atomic::Ordering::SeqCst) == point {
    std::process::abort();
  }
}

#[cfg(not(test))]
#[inline(always)]
fn crash_hook(_point: u8) {}

/// A factory for redb stores rooted at one database file.
pub(crate) struct RedbStoreFactory {
  path: PathBuf,
}

impl RedbStoreFactory {
  pub(crate) fn new(path: PathBuf) -> Self {
    Self { path }
  }

  fn capabilities() -> StoreCapabilities {
    StoreCapabilities::new(DurabilityLevel::OsCrashDurable)
      .conditional_batch(true)
      .ordered_scan(true)
      .reconciliation(true)
      .exclusive_lifetime_lock(true)
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
      Ok(Box::new(RedbStorage { database }) as Box<dyn Storage>)
    })
  }
}

struct RedbStorage {
  database: Arc<Database>,
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
    Box::pin(async move {
      let transaction = self
        .database
        .begin_read()
        .map_err(|error| map_transaction_error(error, ProviderErrorContext::StorageSnapshot))?;
      let revision = snapshot_revision(&transaction)?;
      Ok(Box::new(RedbSnapshot {
        transaction,
        revision,
      }) as Box<dyn StoreSnapshot>)
    })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    let database = self.database.clone();
    Box::pin(async move {
      tokio::task::spawn_blocking(move || commit_blocking(&database, transaction))
        .await
        .map_err(|_| internal(ProviderErrorContext::StorageCommit))?
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    Box::pin(async move {
      let read = self
        .database
        .begin_read()
        .map_err(|error| map_transaction_error(error, ProviderErrorContext::StorageReconcile))?;
      let receipts = read
        .open_table(RECEIPTS_TABLE)
        .map_err(|error| map_table_error(error, ProviderErrorContext::StorageReconcile))?;
      let receipt = read_receipt(&receipts, transaction)?;
      Ok(match receipt {
        Some(existing) if existing.operation_digest() == digest => {
          ReconcileOutcome::Committed(existing)
        }
        Some(_) => ReconcileOutcome::DigestConflict,
        None => ReconcileOutcome::Aborted,
      })
    })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    // Every commit already fsyncs; there is no deferred durability to flush.
    Box::pin(async { Ok(()) })
  }
}

struct RedbSnapshot {
  transaction: redb::ReadTransaction,
  revision: StoreRevision,
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
        .ok_or_else(|| digest_corrupt(ProviderErrorContext::StorageSnapshot))?;
      let digest_bytes: [u8; VALUE_DIGEST_BYTES] = persisted
        .value()
        .try_into()
        .map_err(|_| digest_corrupt(ProviderErrorContext::StorageSnapshot))?;
      Ok(Some(StoreValue::from_parts(
        Arc::from(guard.value()),
        Digest::from_bytes(digest_bytes),
      )))
    })
  }

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
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
      let bound = composite_prefix(namespace, prefix);
      let range = entries
        .range::<&[u8]>(&*bound..)
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageScan))?;
      let digest_range = digests
        .range::<&[u8]>(&*bound..)
        .map_err(|error| map_storage_error(error, ProviderErrorContext::StorageScan))?;
      Ok(Box::new(RedbScan {
        range,
        digest_range,
        namespace: namespace.clone(),
        prefix: bound,
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
            return Err(digest_corrupt(ProviderErrorContext::StorageScan));
          }
          if !bytes.starts_with(&self.prefix) {
            return Ok(None);
          }
          let user_key = &bytes[self.base_len..];
          let digest_bytes: [u8; VALUE_DIGEST_BYTES] = digest
            .value()
            .try_into()
            .map_err(|_| digest_corrupt(ProviderErrorContext::StorageScan))?;
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
        _ => Err(digest_corrupt(ProviderErrorContext::StorageScan)),
      }
    })
  }
}

fn internal(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::Internal, context)
}

/// A persisted digest sidecar row is missing or malformed: the commit
/// path maintains both sides atomically, so this is storage corruption.
fn digest_corrupt(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::StorageCorrupt, context)
}

fn composite_key(namespace: &StoreNamespace, key: &StoreKey) -> Vec<u8> {
  let mut bytes = Vec::with_capacity(namespace.as_str().len() + 1 + key.as_bytes().len());
  bytes.extend_from_slice(namespace.as_str().as_bytes());
  bytes.push(0);
  bytes.extend_from_slice(key.as_bytes());
  bytes
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
    Some(guard) => decode_revision(guard.value())?,
    None => 0,
  })
}

fn decode_revision(bytes: &[u8]) -> Result<u64> {
  let raw: [u8; 8] = bytes
    .try_into()
    .map_err(|_| Error::invalid_input("redb store revision"))?;
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
        .map_err(|_| corrupt(ProviderErrorContext::StorageReconcile))?;
      let generation = decode_revision(revision_bytes)?;
      Some(CommitReceipt::new(
        transaction.clone(),
        Digest::from_bytes(digest_digest),
        StoreRevision::new(Arc::from(generation.to_be_bytes()))?,
      ))
    }
    None => None,
  })
}

fn corrupt(context: ProviderErrorContext) -> Error {
  Error::provider(ProviderErrorKind::StorageCorrupt, context)
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
    while let Some(Ok((key, value))) = cursor.next() {
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
    if let Some(existing) = read_receipt(&receipts, transaction.id())? {
      return Ok(
        if existing.operation_digest() == transaction.operation_digest() {
          CommitOutcome::Committed(existing)
        } else {
          CommitOutcome::Conflict
        },
      );
    }
    // Development tripwire: the digest is fixed at prepare over private
    // immutable fields (see the json adapter's note).
    debug_assert_eq!(
      transaction.operation_digest(),
      &transaction.computed_operation_digest()
    );
    let generation = current_generation(&meta, ProviderErrorContext::StorageCommit)?;
    if transaction.base_revision().as_bytes() != generation.to_be_bytes() {
      return Ok(CommitOutcome::Conflict);
    }
    for operation in transaction.operations() {
      if !crate::provider::condition_matches(
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
            .ok_or_else(|| digest_corrupt(ProviderErrorContext::StorageCommit))?;
          let bytes: [u8; VALUE_DIGEST_BYTES] = persisted
            .value()
            .try_into()
            .map_err(|_| digest_corrupt(ProviderErrorContext::StorageCommit))?;
          Ok(Some(Digest::from_bytes(bytes)))
        },
        |forgotten: &TransactionId| {
          Ok(read_receipt(&receipts, forgotten)?.map(|receipt| receipt.operation_digest().clone()))
        },
        operation,
      )? {
        return Ok(CommitOutcome::Conflict);
      }
    }
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
  write
    .commit()
    .map_err(|error| map_commit_error(error, ProviderErrorContext::StorageCommit))?;
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
    | redb::TableError::TypeDefinitionChanged { .. } => corrupt(context),
    redb::TableError::Storage(storage) => map_storage_error(storage, context),
    redb::TableError::TableIsMultimap(_)
    | redb::TableError::TableIsNotMultimap(_)
    | redb::TableError::TableExists(_) => Error::provider(ProviderErrorKind::Io, context),
    _ => Error::provider(ProviderErrorKind::Io, context),
  }
}
