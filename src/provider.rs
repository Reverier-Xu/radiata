use std::{fmt, str::FromStr, sync::Arc};

use sha2::{Digest as ShaDigest, Sha256};

use crate::{BoxFuture, Digest, Error, PublicKey, QualifiedTag, Result, Signature, TransactionId};

const KEY_OPERATION_PREFIX: &str = "keyop_";
const STORE_VALUE_DOMAIN: &[u8] = b"radiata/store-value/v1\0";
const STORE_TRANSACTION_DOMAIN: &[u8] = b"radiata/store-transaction/v1\0";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeyCapabilities {
  ed25519: bool,
  reconciliation: bool,
  deletion: bool,
}

impl KeyCapabilities {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn ed25519(mut self, supported: bool) -> Self {
    self.ed25519 = supported;
    self
  }

  pub fn reconciliation(mut self, supported: bool) -> Self {
    self.reconciliation = supported;
    self
  }

  pub fn deletion(mut self, supported: bool) -> Self {
    self.deletion = supported;
    self
  }

  pub fn has_ed25519(&self) -> bool {
    self.ed25519
  }

  pub fn has_reconciliation(&self) -> bool {
    self.reconciliation
  }

  pub fn has_deletion(&self) -> bool {
    self.deletion
  }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyOperationId(String);

impl KeyOperationId {
  pub fn parse(value: &str) -> Result<Self> {
    crate::identity::validate_id(value, KEY_OPERATION_PREFIX, "key operation id")?;
    Ok(Self(value.to_owned()))
  }

  #[allow(dead_code)]
  pub(crate) fn generate(entropy: &dyn crate::api::Entropy) -> Result<Self> {
    let suffix = crate::identity::random_base62_suffix(entropy)?;
    Ok(Self(format!("{KEY_OPERATION_PREFIX}{suffix}")))
  }

  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl FromStr for KeyOperationId {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

impl fmt::Debug for KeyOperationId {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_tuple("KeyOperationId")
      .field(&self.0)
      .finish()
  }
}

impl fmt::Display for KeyOperationId {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.0)
  }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyHandle(Arc<[u8]>);

impl KeyHandle {
  pub fn from_provider_bytes(value: Arc<[u8]>) -> Result<Self> {
    if value.is_empty() {
      return Err(Error::invalid_input("key handle"));
    }
    Ok(Self(value))
  }

  pub fn expose_provider_handle(&self) -> &[u8] {
    &self.0
  }
}

impl fmt::Debug for KeyHandle {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("KeyHandle(..)")
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedKey {
  handle: KeyHandle,
  public_key: PublicKey,
}

impl CreatedKey {
  pub fn new(handle: KeyHandle, public_key: PublicKey) -> Self {
    Self { handle, public_key }
  }

  pub fn handle(&self) -> &KeyHandle {
    &self.handle
  }

  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyCreateState {
  Present(CreatedKey),
  Absent,
  Unknown,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyDeleteState {
  Present,
  Absent,
  Unknown,
}

pub trait KeyProvider: fmt::Debug + Send + Sync + 'static {
  fn capabilities(&self) -> KeyCapabilities;

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>>;

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>>;

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>>;

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>>;

  fn delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>>;

  fn reconcile_delete<'a>(
    &'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DurabilityLevel {
  ProcessCrashAtomic,
  OsCrashDurable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreRequirements {
  required_durability: DurabilityLevel,
  conditional_batch: bool,
  ordered_scan: bool,
  reconciliation: bool,
  exclusive_lifetime_lock: bool,
  transactional_migration: bool,
}

impl StoreRequirements {
  pub(crate) const fn metadata() -> Self {
    Self {
      required_durability: DurabilityLevel::OsCrashDurable,
      conditional_batch: true,
      ordered_scan: true,
      reconciliation: true,
      exclusive_lifetime_lock: true,
      transactional_migration: false,
    }
  }

  pub fn required_durability(&self) -> DurabilityLevel {
    self.required_durability
  }

  pub fn requires_conditional_batch(&self) -> bool {
    self.conditional_batch
  }

  pub fn requires_ordered_scan(&self) -> bool {
    self.ordered_scan
  }

  pub fn requires_reconciliation(&self) -> bool {
    self.reconciliation
  }

  pub fn requires_exclusive_lifetime_lock(&self) -> bool {
    self.exclusive_lifetime_lock
  }

  pub fn requires_transactional_migration(&self) -> bool {
    self.transactional_migration
  }

  #[cfg(test)]
  pub(crate) const fn transactional_migration(mut self, required: bool) -> Self {
    self.transactional_migration = required;
    self
  }

  #[cfg(all(test, not(unix)))]
  pub(crate) const fn with_required_durability(mut self, level: DurabilityLevel) -> Self {
    self.required_durability = level;
    self
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreCapabilities {
  durability: DurabilityLevel,
  conditional_batch: bool,
  ordered_scan: bool,
  reconciliation: bool,
  exclusive_lifetime_lock: bool,
  transactional_migration: bool,
}

impl StoreCapabilities {
  pub fn new(durability: DurabilityLevel) -> Self {
    Self {
      durability,
      conditional_batch: false,
      ordered_scan: false,
      reconciliation: false,
      exclusive_lifetime_lock: false,
      transactional_migration: false,
    }
  }

  pub fn conditional_batch(mut self, supported: bool) -> Self {
    self.conditional_batch = supported;
    self
  }

  pub fn ordered_scan(mut self, supported: bool) -> Self {
    self.ordered_scan = supported;
    self
  }

  pub fn reconciliation(mut self, supported: bool) -> Self {
    self.reconciliation = supported;
    self
  }

  pub fn exclusive_lifetime_lock(mut self, supported: bool) -> Self {
    self.exclusive_lifetime_lock = supported;
    self
  }

  pub fn transactional_migration(mut self, supported: bool) -> Self {
    self.transactional_migration = supported;
    self
  }

  pub fn durability(&self) -> DurabilityLevel {
    self.durability
  }

  pub fn has_conditional_batch(&self) -> bool {
    self.conditional_batch
  }

  pub fn has_ordered_scan(&self) -> bool {
    self.ordered_scan
  }

  pub fn has_reconciliation(&self) -> bool {
    self.reconciliation
  }

  pub fn has_exclusive_lifetime_lock(&self) -> bool {
    self.exclusive_lifetime_lock
  }

  pub fn has_transactional_migration(&self) -> bool {
    self.transactional_migration
  }

  pub(crate) const fn satisfies(&self, requirements: &StoreRequirements) -> bool {
    durability_satisfies(self.durability, requirements.required_durability)
      && (!requirements.conditional_batch || self.conditional_batch)
      && (!requirements.ordered_scan || self.ordered_scan)
      && (!requirements.reconciliation || self.reconciliation)
      && (!requirements.exclusive_lifetime_lock || self.exclusive_lifetime_lock)
      && (!requirements.transactional_migration || self.transactional_migration)
  }
}

const fn durability_satisfies(actual: DurabilityLevel, required: DurabilityLevel) -> bool {
  matches!(
    (actual, required),
    (DurabilityLevel::OsCrashDurable, _)
      | (
        DurabilityLevel::ProcessCrashAtomic,
        DurabilityLevel::ProcessCrashAtomic
      )
  )
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreRevision(Arc<[u8]>);

impl StoreRevision {
  pub fn new(value: Arc<[u8]>) -> Result<Self> {
    if value.is_empty() {
      return Err(Error::invalid_input("store revision"));
    }
    Ok(Self(value))
  }

  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

impl fmt::Debug for StoreRevision {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("StoreRevision")
      .field("bytes", &self.0.len())
      .finish()
  }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreNamespace(QualifiedTag);

impl StoreNamespace {
  /// The namespace is a plain wrapper over an already-validated
  /// [`QualifiedTag`]; construction cannot fail and performs no further
  /// validation.
  pub const fn new(value: QualifiedTag) -> Self {
    Self(value)
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreKey(Arc<[u8]>);

impl StoreKey {
  pub fn new(value: Arc<[u8]>) -> Self {
    Self(value)
  }

  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

impl fmt::Debug for StoreKey {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("StoreKey(..)")
  }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoreValue {
  value: Arc<[u8]>,
  digest: Digest,
}

impl StoreValue {
  pub fn new(value: Arc<[u8]>) -> Self {
    let digest = digest_store_value(&value);
    Self { value, digest }
  }

  /// Reassembles a value from bytes and a digest that a backend persisted
  /// alongside them, so reads do not recompute the digest. The caller
  /// guarantees the pair is consistent; a backend that persists digests
  /// writes both sides in one atomic transaction and fails closed when a
  /// digest row is missing. Without a digest-persisting backend the only
  /// callers live in that backend's feature build, which is intentionally
  /// allowed.
  #[cfg_attr(not(feature = "redb"), allow(dead_code))]
  pub(crate) fn from_parts(value: Arc<[u8]>, digest: Digest) -> Self {
    Self { value, digest }
  }

  pub fn as_bytes(&self) -> &[u8] {
    &self.value
  }

  pub fn digest(&self) -> &Digest {
    &self.digest
  }
}

impl fmt::Debug for StoreValue {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("StoreValue")
      .field("bytes", &self.value.len())
      .field("digest", &self.digest)
      .finish()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreEntry {
  namespace: StoreNamespace,
  key: StoreKey,
  value: StoreValue,
}

impl StoreEntry {
  pub fn new(namespace: StoreNamespace, key: StoreKey, value: StoreValue) -> Self {
    Self {
      namespace,
      key,
      value,
    }
  }

  pub fn namespace(&self) -> &StoreNamespace {
    &self.namespace
  }

  pub fn key(&self) -> &StoreKey {
    &self.key
  }

  pub fn value(&self) -> &StoreValue {
    &self.value
  }
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreExpectation {
  Absent,
  Exact(Digest),
}

/// Builds the per-key expectation for a conditional write from one
/// snapshot view, so the expectation and the CAS revision handed to
/// `prepare_transaction` cannot disagree (single source for the
/// snapshot-view CAS pattern).
pub(crate) async fn snapshot_expectation(
  snapshot: &dyn StoreSnapshot, namespace: &StoreNamespace, key: &StoreKey,
) -> Result<StoreExpectation> {
  Ok(match snapshot.get(namespace, key).await? {
    Some(current) => StoreExpectation::Exact(current.digest().clone()),
    None => StoreExpectation::Absent,
  })
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreOperation {
  Check {
    namespace: StoreNamespace,
    key: StoreKey,
    expected: StoreExpectation,
  },
  Put {
    namespace: StoreNamespace,
    key: StoreKey,
    expected: StoreExpectation,
    value: StoreValue,
  },
  Delete {
    namespace: StoreNamespace,
    key: StoreKey,
    expected: Digest,
  },
  ForgetReceipt {
    transaction: TransactionId,
    expected_operation_digest: Digest,
  },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreTransaction {
  id: TransactionId,
  operation_digest: Digest,
  base_revision: StoreRevision,
  operations: Arc<[StoreOperation]>,
}

impl StoreTransaction {
  pub(crate) fn new(
    id: TransactionId, base_revision: StoreRevision, operations: Vec<StoreOperation>,
  ) -> Result<Self> {
    if operations.is_empty() {
      return Err(Error::invalid_input("storage transaction operations"));
    }
    validate_distinct_operations(&operations)?;

    let operations: Arc<[StoreOperation]> = operations.into();
    let operation_digest = digest_store_operations(&base_revision, &operations);
    Ok(Self {
      id,
      operation_digest,
      base_revision,
      operations,
    })
  }

  pub fn id(&self) -> &TransactionId {
    &self.id
  }

  pub fn operation_digest(&self) -> &Digest {
    &self.operation_digest
  }

  pub fn computed_operation_digest(&self) -> Digest {
    digest_store_operations(&self.base_revision, &self.operations)
  }

  pub fn base_revision(&self) -> &StoreRevision {
    &self.base_revision
  }

  pub fn operations(&self) -> &[StoreOperation] {
    &self.operations
  }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum StoreOperationIdentity<'a> {
  Key(&'a StoreNamespace, &'a StoreKey),
  Receipt(&'a TransactionId),
}

fn validate_distinct_operations(operations: &[StoreOperation]) -> Result<()> {
  let mut identities = Vec::new();
  identities
    .try_reserve_exact(operations.len())
    .map_err(|_| Error::resource_exhausted("storage transaction operations"))?;
  for operation in operations {
    identities.push(match operation {
      StoreOperation::Check { namespace, key, .. }
      | StoreOperation::Put { namespace, key, .. }
      | StoreOperation::Delete { namespace, key, .. } => {
        StoreOperationIdentity::Key(namespace, key)
      }
      StoreOperation::ForgetReceipt { transaction, .. } => {
        StoreOperationIdentity::Receipt(transaction)
      }
    });
  }
  identities.sort_unstable();
  if identities.windows(2).any(|pair| pair[0] == pair[1]) {
    return Err(Error::invalid_input("storage transaction operations"));
  }
  Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
  transaction: TransactionId,
  operation_digest: Digest,
  committed_revision: StoreRevision,
}

impl CommitReceipt {
  pub fn new(
    transaction: TransactionId, operation_digest: Digest, committed_revision: StoreRevision,
  ) -> Self {
    Self {
      transaction,
      operation_digest,
      committed_revision,
    }
  }

  pub fn transaction(&self) -> &TransactionId {
    &self.transaction
  }

  pub fn operation_digest(&self) -> &Digest {
    &self.operation_digest
  }

  pub fn committed_revision(&self) -> &StoreRevision {
    &self.committed_revision
  }
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
  Committed(CommitReceipt),
  Aborted,
  Conflict,
  Unknown {
    transaction: TransactionId,
    operation_digest: Digest,
  },
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
  Committed(CommitReceipt),
  Aborted,
  DigestConflict,
  Unknown,
}

pub trait StoreScan: fmt::Debug + Send {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>>;
}

/// Converts one provider [`StoreScan`] into the standard stream view:
/// consumers compose scans with the ecosystem stream combinators while
/// providers keep implementing the explicit cursor [`StoreScan::next`].
/// Items preserve scan order and the crate's typed error.
pub fn store_scan_stream(
  scan: Box<dyn StoreScan + '_>,
) -> futures_core::stream::BoxStream<'_, Result<StoreEntry>> {
  use futures_util::TryStreamExt;
  Box::pin(
    futures_util::stream::try_unfold(scan, |mut scan| async move {
      scan
        .next()
        .await
        .map(|entry| entry.map(|entry| (entry, scan)))
    })
    .into_stream(),
  )
}

pub trait StoreSnapshot: fmt::Debug + Send + Sync + 'static {
  fn revision(&self) -> &StoreRevision;

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>>;

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>>;

  /// Positioned ordered scan (the seek primitive behind keyset-cursor
  /// paging). The full contract, at the same level as the commit-ordering
  /// contract on [`Storage`]:
  ///
  /// - **Ordering identity.** Entries stream in the exact unsigned-byte key
  ///   order and namespace/prefix filter of [`StoreSnapshot::scan`];
  ///   positioning never reorders or refilters.
  /// - **Strict positioning.** `Some(from)` yields the first key *strictly
  ///   greater than* `from` first — the keyset-cursor semantics, where a
  ///   continuation cursor is the last key already seen and the next page
  ///   resumes after it. Positioning is by key order, so `from` need not exist
  ///   in the store.
  /// - **`None` equivalence.** `None` observes exactly [`StoreSnapshot::scan`].
  /// - **Out of bounds is empty.** A `from` at or past the namespace or prefix
  ///   end is an empty scan, never an error.
  /// - **One revision.** The positioned scan observes the same single snapshot
  ///   revision as `get`/`scan` (the snapshot-immutability contract on
  ///   [`Storage`]).
  ///
  /// The default implementation delegates to [`StoreSnapshot::scan`] and
  /// skips the ordered head at or before `from`, which is correct but
  /// linear in the skip distance; backends with native range starts
  /// override it.
  fn scan_from<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8], from: Option<&'a [u8]>,
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    let Some(from) = from else {
      return self.scan(namespace, prefix);
    };
    let from = from.to_vec();
    Box::pin(async move {
      let inner = self.scan(namespace, prefix).await?;
      Ok(Box::new(SkippingScan { inner, from }) as Box<dyn StoreScan>)
    })
  }
}

/// The default [`StoreSnapshot::scan_from`] path: the backend scan
/// already streams the namespace's prefix range in key order, so the
/// wrapper drops the ordered head at or before `from` and then passes
/// every strictly-greater entry through untouched.
#[derive(Debug)]
struct SkippingScan<'a> {
  inner: Box<dyn StoreScan + 'a>,
  from: Vec<u8>,
}

impl StoreScan for SkippingScan<'_> {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    Box::pin(async move {
      loop {
        match self.inner.next().await? {
          // The scan is ordered, so this drops exactly the cursor head
          // and stops skipping at the first strictly-greater key.
          Some(entry) if entry.key().as_bytes() <= self.from.as_slice() => {}
          other => return Ok(other),
        }
      }
    })
  }
}

pub trait StorageFactory: fmt::Debug + Send + Sync + 'static {
  fn open<'a>(&'a self, requirements: StoreRequirements)
  -> BoxFuture<'a, Result<Box<dyn Storage>>>;
}

/// The durable, conditionally-transactional key-value storage contract.
///
/// One store owns a single key space of ([`StoreNamespace`],
/// [`StoreKey`]) records plus the receipts of the transactions that
/// changed them. Every adapter must provide the same observable
/// behavior at the five contract points:
///
/// - **Commit ordering.** [`Storage::commit`] evaluates one prepared
///   transaction against the committing state in a fixed order, and the first
///   failing check wins without applying anything: the receipt replay first (a
///   transaction id that already carries a receipt returns
///   [`CommitOutcome::Committed`] when the prepared operation digest matches —
///   the idempotent replay — and [`CommitOutcome::Conflict`] otherwise), then
///   the base-revision check ([`CommitOutcome::Conflict`] for a transaction
///   prepared on any revision but the current one), then every operation's
///   conditional expectation including `ForgetReceipt`'s digest expectation
///   ([`CommitOutcome::Conflict`] on the first miss). Only then do the changes
///   apply atomically, the revision advances by exactly one, and the receipt
///   persists under the transaction's own identity, so a retry of the same id
///   and digest replays to the same receipt.
/// - **Unknown outcomes.** An adapter that cannot decide whether a commit
///   applied (a crash or an indeterminate backend answer) must return
///   [`CommitOutcome::Unknown`] carrying the exact transaction identity it was
///   handed — the original id and operation digest, never a guess — and leave
///   classification to [`Storage::reconcile`].
/// - **Snapshot immutability.** [`Storage::snapshot`] observes exactly one
///   revision; later commits never mutate an outstanding snapshot, so a
///   decision made on it stays authoritative until the caller's own commit
///   lands.
/// - **Positioned scans.** [`StoreSnapshot::scan_from`] is the read-side seek
///   primitive: `Some(from)` starts at the first key strictly greater than
///   `from` in the exact [`StoreSnapshot::scan`] order (a keyset continuation
///   cursor is the last key already seen), `None` equals a plain scan, and a
///   `from` past the namespace or prefix end is an empty scan, never an error.
/// - **Reconciliation.** [`Storage::reconcile`] classifies a past transaction
///   exactly three ways: [`ReconcileOutcome::Committed`] when a receipt exists
///   for the id with the exact digest, [`ReconcileOutcome::DigestConflict`]
///   when the id exists with a different digest, and
///   [`ReconcileOutcome::Aborted`] when no receipt exists (the transaction
///   never applied; a fresh prepare may retry it).
pub trait Storage: fmt::Debug + Send + Sync + 'static {
  fn capabilities(&self) -> StoreCapabilities;

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>>;

  /// Atomically applies one prepared conditional transaction in the
  /// contract order documented on [`Storage`]: receipt replay, base
  /// revision, conditional expectations, then the atomic change
  /// application with the single revision bump and receipt persistence.
  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>>;

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>>;

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}

fn digest_store_value(value: &[u8]) -> Digest {
  let mut hasher = Sha256::new();
  hasher.update(STORE_VALUE_DOMAIN);
  update_bytes(&mut hasher, value);
  Digest::from_bytes(hasher.finalize().into())
}

/// Evaluates one conditional operation against closure lookups over the
/// committing state: `entry` resolves one record to its content digest
/// (None when absent) and `receipt` resolves one transaction id to its
/// operation digest. This is the single definition shared by every
/// storage adapter AND the reference provider in the storage contract
/// suite, so a condition bug cannot hide by being copied into both the
/// oracle and the adapter under test. Without a storage-backend feature
/// the only callers live in test builds, which is intentionally allowed.
#[cfg_attr(not(any(feature = "json", feature = "redb")), allow(dead_code))]
pub(crate) fn condition_matches(
  mut entry: impl FnMut(&StoreNamespace, &StoreKey) -> Result<Option<Digest>>,
  mut receipt: impl FnMut(&TransactionId) -> Result<Option<Digest>>, operation: &StoreOperation,
) -> Result<bool> {
  Ok(match operation {
    StoreOperation::Check {
      namespace,
      key,
      expected,
    }
    | StoreOperation::Put {
      namespace,
      key,
      expected,
      ..
    } => expectation_matches(entry(namespace, key)?, expected),
    StoreOperation::Delete {
      namespace,
      key,
      expected,
    } => entry(namespace, key)?.is_some_and(|digest| &digest == expected),
    StoreOperation::ForgetReceipt {
      transaction,
      expected_operation_digest,
    } => receipt(transaction)?.is_some_and(|digest| &digest == expected_operation_digest),
  })
}

fn expectation_matches(digest: Option<Digest>, expected: &StoreExpectation) -> bool {
  match (digest, expected) {
    (None, StoreExpectation::Absent) => true,
    (Some(digest), StoreExpectation::Exact(expected)) => &digest == expected,
    _ => false,
  }
}

fn digest_store_operations(base_revision: &StoreRevision, operations: &[StoreOperation]) -> Digest {
  let mut hasher = Sha256::new();
  hasher.update(STORE_TRANSACTION_DOMAIN);
  update_bytes(&mut hasher, base_revision.as_bytes());
  update_length(&mut hasher, operations.len());
  for operation in operations {
    match operation {
      StoreOperation::Check {
        namespace,
        key,
        expected,
      } => {
        hasher.update([0]);
        update_namespace_and_key(&mut hasher, namespace, key);
        update_expectation(&mut hasher, expected);
      }
      StoreOperation::Put {
        namespace,
        key,
        expected,
        value,
      } => {
        hasher.update([1]);
        update_namespace_and_key(&mut hasher, namespace, key);
        update_expectation(&mut hasher, expected);
        update_bytes(&mut hasher, value.as_bytes());
      }
      StoreOperation::Delete {
        namespace,
        key,
        expected,
      } => {
        hasher.update([2]);
        update_namespace_and_key(&mut hasher, namespace, key);
        hasher.update(expected.as_bytes());
      }
      StoreOperation::ForgetReceipt {
        transaction,
        expected_operation_digest,
      } => {
        hasher.update([3]);
        update_bytes(&mut hasher, transaction.as_str().as_bytes());
        hasher.update(expected_operation_digest.as_bytes());
      }
    }
  }
  Digest::from_bytes(hasher.finalize().into())
}

fn update_namespace_and_key(hasher: &mut Sha256, namespace: &StoreNamespace, key: &StoreKey) {
  update_bytes(hasher, namespace.as_str().as_bytes());
  update_bytes(hasher, key.as_bytes());
}

fn update_expectation(hasher: &mut Sha256, expectation: &StoreExpectation) {
  match expectation {
    StoreExpectation::Absent => hasher.update([0]),
    StoreExpectation::Exact(digest) => {
      hasher.update([1]);
      hasher.update(digest.as_bytes());
    }
  }
}

fn update_bytes(hasher: &mut Sha256, value: &[u8]) {
  update_length(hasher, value.len());
  hasher.update(value);
}

fn update_length(hasher: &mut Sha256, value: usize) {
  hasher.update((value as u128).to_be_bytes());
}

/// The shared intent-purpose bound: nonempty, bounded, printable ASCII
/// purposes live in both the identity intent records and the pending
/// transaction journal, so the grammar and its limit are defined once
/// here and both sides validate through [`validate_purpose`].
pub(crate) const MAX_PURPOSE_LEN: usize = 128;

/// The intent-purpose grammar (single source): nonempty, bounded, and
/// printable ASCII, with the caller's context in the typed error. Both
/// the identity intent records and the storage pending journal validate
/// purposes through this one gate so the two bounds cannot drift.
pub(crate) fn validate_purpose(purpose: &str, context: &'static str) -> Result<()> {
  if purpose.is_empty()
    || purpose.len() > MAX_PURPOSE_LEN
    || !purpose.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
  {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{
    DurabilityLevel, StoreEntry, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
    StoreRequirements, StoreRevision, StoreTransaction, StoreValue,
  };
  use crate::{Digest, QualifiedTag, TransactionId};

  /// The `StoreScan` to `BoxStream` converter preserves
  /// order, items, end-of-scan, and the typed error, matching an explicit
  /// `next()` loop exactly.
  #[tokio::test]
  async fn store_scan_stream_matches_next_loop_parity() {
    use futures_util::StreamExt;

    #[derive(Debug)]
    struct ScriptedScan {
      items: std::vec::IntoIter<crate::Result<Option<StoreEntry>>>,
    }

    impl crate::provider::StoreScan for ScriptedScan {
      fn next<'a>(&'a mut self) -> crate::BoxFuture<'a, crate::Result<Option<StoreEntry>>> {
        Box::pin(async move { self.items.next().unwrap_or(Ok(None)) })
      }
    }

    let namespace =
      StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/metadata/scan-parity").unwrap());
    let entry = |index: u8| {
      StoreEntry::new(
        namespace.clone(),
        StoreKey::new(Arc::from(&[index][..])),
        StoreValue::new(Arc::from(&[index][..])),
      )
    };
    let expected = [entry(1), entry(2), entry(3)];

    let scan = Box::new(ScriptedScan {
      items: vec![
        Ok(Some(expected[0].clone())),
        Ok(Some(expected[1].clone())),
        Ok(Some(expected[2].clone())),
        Ok(None),
      ]
      .into_iter(),
    });
    let collected: Vec<StoreEntry> = super::store_scan_stream(scan)
      .collect::<Vec<crate::Result<StoreEntry>>>()
      .await
      .into_iter()
      .collect::<crate::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(collected, expected);

    // A typed error surfaces as an item in place and ends nothing early.
    let scan = Box::new(ScriptedScan {
      items: vec![
        Ok(Some(entry(9))),
        Err(crate::Error::internal("scan parity")),
      ]
      .into_iter(),
    });
    let mut stream = super::store_scan_stream(scan);
    assert_eq!(stream.next().await.unwrap().unwrap(), entry(9));
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Internal);
  }

  #[test]
  fn core_store_requirements_expose_every_required_capability() {
    let requirements = StoreRequirements {
      required_durability: DurabilityLevel::OsCrashDurable,
      conditional_batch: true,
      ordered_scan: true,
      reconciliation: true,
      exclusive_lifetime_lock: true,
      transactional_migration: true,
    };

    assert_eq!(
      requirements.required_durability(),
      DurabilityLevel::OsCrashDurable,
    );
    assert!(requirements.requires_conditional_batch());
    assert!(requirements.requires_ordered_scan());
    assert!(requirements.requires_reconciliation());
    assert!(requirements.requires_exclusive_lifetime_lock());
    assert!(requirements.requires_transactional_migration());
  }

  #[test]
  fn core_store_transaction_digest_is_canonical_and_redacted() {
    let mut transaction = transaction_fixture(1, b"secret-value");
    let computed = transaction.computed_operation_digest();
    transaction.operation_digest = computed.clone();

    assert_eq!(transaction.id().as_str(), "txn_0123456789abcdefghijk");
    assert_eq!(transaction.operation_digest(), &computed);
    assert_eq!(transaction.computed_operation_digest(), computed);
    assert_eq!(transaction.base_revision().as_bytes(), &[1]);
    assert_eq!(transaction.operations().len(), 1);
    assert_eq!(
      computed.as_bytes(),
      &[
        27, 57, 99, 211, 121, 199, 94, 1, 95, 13, 213, 92, 46, 162, 233, 180, 153, 33, 204, 121,
        57, 33, 236, 231, 201, 243, 143, 107, 110, 194, 112, 52,
      ],
    );

    let same = transaction_fixture(1, b"secret-value").computed_operation_digest();
    let changed_revision = transaction_fixture(2, b"secret-value").computed_operation_digest();
    let changed_value = transaction_fixture(1, b"other-value").computed_operation_digest();
    assert_eq!(computed, same);
    assert_ne!(computed, changed_revision);
    assert_ne!(computed, changed_value);

    let raw_value_digest = StoreValue::new(Arc::from(b"secret-value".as_slice()))
      .digest()
      .clone();
    assert_ne!(computed, raw_value_digest);

    let debug = format!("{transaction:?}");
    assert!(!debug.contains("secret-key"));
    assert!(!debug.contains("secret-value"));
  }

  #[test]
  fn core_store_transaction_rejects_duplicate_identities_across_variants() {
    let namespace =
      StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/metadata/duplicates").unwrap());
    let key = StoreKey::new(Arc::from(b"same-key".as_slice()));
    let revision = StoreRevision::new(Arc::from([1])).unwrap();
    let operations = [
      StoreOperation::Check {
        namespace: namespace.clone(),
        key: key.clone(),
        expected: StoreExpectation::Absent,
      },
      StoreOperation::Put {
        namespace: namespace.clone(),
        key: key.clone(),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(b"value".as_slice())),
      },
      StoreOperation::Delete {
        namespace,
        key,
        expected: Digest::from_bytes([0; 32]),
      },
    ];
    for first in 0..operations.len() {
      for second in first + 1..operations.len() {
        assert!(
          StoreTransaction::new(
            TransactionId::parse(&format!("txn_{first:010}{second:011}")).unwrap(),
            revision.clone(),
            vec![operations[first].clone(), operations[second].clone()],
          )
          .is_err()
        );
      }
    }

    let receipt = TransactionId::parse("txn_111111111111111111111").unwrap();
    assert!(
      StoreTransaction::new(
        TransactionId::parse("txn_222222222222222222222").unwrap(),
        revision,
        vec![
          StoreOperation::ForgetReceipt {
            transaction: receipt.clone(),
            expected_operation_digest: Digest::from_bytes([1; 32]),
          },
          StoreOperation::ForgetReceipt {
            transaction: receipt,
            expected_operation_digest: Digest::from_bytes([2; 32]),
          },
        ],
      )
      .is_err()
    );
  }

  #[test]
  fn core_store_transaction_accepts_large_unique_operation_set() {
    const OPERATION_COUNT: usize = 16_384;
    let namespace =
      StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/metadata/large").unwrap());
    let operations = (0..OPERATION_COUNT)
      .map(|index| StoreOperation::Check {
        namespace: namespace.clone(),
        key: StoreKey::new(Arc::from(index.to_be_bytes())),
        expected: StoreExpectation::Absent,
      })
      .collect();
    let transaction = StoreTransaction::new(
      TransactionId::parse("txn_333333333333333333333").unwrap(),
      StoreRevision::new(Arc::from([1])).unwrap(),
      operations,
    )
    .unwrap();

    assert_eq!(transaction.operations().len(), OPERATION_COUNT);
  }

  fn transaction_fixture(revision: u8, value: &[u8]) -> StoreTransaction {
    let namespace =
      StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/metadata/identity").unwrap());
    let operations = Arc::from([StoreOperation::Put {
      namespace,
      key: StoreKey::new(Arc::from(b"secret-key".as_slice())),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(value)),
    }]);
    StoreTransaction {
      id: TransactionId::parse("txn_0123456789abcdefghijk").unwrap(),
      operation_digest: Digest::from_bytes([0; 32]),
      base_revision: StoreRevision::new(Arc::from([revision])).unwrap(),
      operations,
    }
  }
}
