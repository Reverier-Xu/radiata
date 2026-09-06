//! Shared integration-test providers implementing the public provider SPI.
//!
//! The in-memory storage factory ports the `src/storage/contract.rs`
//! reference semantics (immutable snapshots, ordered streaming scans,
//! conditional all-or-nothing commits, receipt reconciliation, exclusive
//! lifetime locking, and checked revision exhaustion) so integration tests
//! exercise the runtime through the exact provider contract. The scripted
//! key provider derives deterministic ed25519 keys from fixed seeds and
//! records every call for exact-order assertions.
#![allow(dead_code)]

use std::{
  collections::{BTreeMap, HashMap, VecDeque},
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};
use radiata::{
  BoxFuture, CommitOutcome, CommitReceipt, CreatedKey, Digest, DurabilityLevel, Error,
  KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle, KeyOperationId, ProviderErrorContext,
  ProviderErrorKind, PublicKey, QualifiedTag, ReconcileOutcome, Result, Signature,
  StoreCapabilities, StoreEntry, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
  StoreRequirements, StoreRevision, StoreTransaction, StoreValue, TransactionId,
  extension::{Entropy, KeyProvider, Storage, StorageFactory, StoreScan, StoreSnapshot},
};
use tokio::sync::Notify;

pub const LOCAL_IDENTITY_NAMESPACE: &str = "radiata.woooo.tech/metadata/local-identity-v1";
pub const KEY_CREATION_INTENT_NAMESPACE: &str =
  "radiata.woooo.tech/metadata/key-creation-intent-v1";
pub const PENDING_NAMESPACE: &str = "radiata.woooo.tech/metadata/pending-transaction-v1";

/// One merge with bounded retries against one stable credential: the
/// accept loop precomputes its merge hint, so rotating on every retry
/// would invalidate the in-flight accept's hint forever (rotate once,
/// retry with the same secret). Merge-sensitive operations
/// transiently refuse while concurrent metadata commits hold the store.
pub async fn merge_with_retry(
  node: &radiata::NodeHandle, issuer: &radiata::NodeHandle, endpoint: radiata::Endpoint,
) {
  use radiata::{MergeCluster, MergeCredential, RotateMergeCredential};
  let issued = issuer.command(RotateMergeCredential::new()).await.unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  let deadline = std::time::Instant::now() + Duration::from_secs(60);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    let credential = MergeCredential::parse(&secret).unwrap();
    match node
      .command(MergeCluster::new(endpoint.clone(), credential))
      .await
    {
      Ok(_) => return,
      Err(error) => {
        assert!(
          deadline.elapsed() < Duration::from_secs(60),
          "merge never succeeded: {error:?}"
        );
        let backoff = Duration::from_millis(100 * (1_u64 << attempts.min(4)));
        tokio::time::sleep(backoff).await;
      }
    }
  }
}

/// One resource write with bounded retries: a commit racing the
/// anti-entropy driver's writes transiently refuses with NotReady (the
/// single-store in-flight-commit rule). Retries with a bound, matching
/// the merge harness precedent. `write` rebuilds the command for
/// each attempt (commands are single-use values).
pub async fn put_resource_with_retry(
  node: &radiata::NodeHandle, mut write: impl FnMut() -> radiata::PutResource,
) {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    match node.command(write()).await {
      Ok(_) => return,
      Err(error) => {
        assert!(
          deadline.elapsed() < Duration::from_secs(30),
          "put never committed: {error:?}"
        );
        assert_eq!(error.kind(), radiata::ErrorKind::NotReady);
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
    }
  }
}

pub fn required_capabilities() -> StoreCapabilities {
  StoreCapabilities::new(DurabilityLevel::OsCrashDurable)
    .conditional_batch(true)
    .ordered_scan(true)
    .reconciliation(true)
    .exclusive_lifetime_lock(true)
}

pub fn namespace(tag: &str) -> StoreNamespace {
  StoreNamespace::new(QualifiedTag::parse(tag).unwrap())
}

/// An ordered, cross-provider event log for startup-order assertions.
#[derive(Debug, Default)]
pub struct EventLog {
  events: Mutex<Vec<&'static str>>,
}

impl EventLog {
  pub fn push(&self, event: &'static str) {
    self.events.lock().unwrap().push(event);
  }

  pub fn events(&self) -> Vec<&'static str> {
    self.events.lock().unwrap().clone()
  }
}

/// Counts provider drops and notifies waiters.
#[derive(Debug, Default)]
pub struct DropTracker {
  count: AtomicUsize,
  changed: Notify,
}

impl DropTracker {
  pub fn record(&self) {
    self.count.fetch_add(1, Ordering::SeqCst);
    self.changed.notify_waiters();
  }

  pub fn count(&self) -> usize {
    self.count.load(Ordering::SeqCst)
  }

  pub async fn wait_for(&self, expected: usize) {
    loop {
      let changed = self.changed.notified();
      if self.count() >= expected {
        return;
      }
      changed.await;
    }
  }
}

/// Deterministic entropy: every fill yields the next counter in big-endian
/// bytes right-aligned into the output. Sixteen-byte fills stay far below
/// the base62 suffix space, so generated IDs are `...1`, `...2`, and so on.
#[derive(Debug, Default)]
pub struct SequenceEntropy {
  next: Mutex<u128>,
  fills: Mutex<Vec<usize>>,
  events: Option<Arc<EventLog>>,
}

impl SequenceEntropy {
  pub fn with_events(events: Arc<EventLog>) -> Self {
    Self {
      events: Some(events),
      ..Self::default()
    }
  }

  pub fn fills(&self) -> Vec<usize> {
    self.fills.lock().unwrap().clone()
  }
}

impl Entropy for SequenceEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    if let Some(events) = &self.events {
      events.push("entropy");
    }
    let mut next = self.next.lock().unwrap();
    *next = next.checked_add(1).ok_or_else(|| {
      Error::provider(
        ProviderErrorKind::ResourceExhausted,
        ProviderErrorContext::Entropy,
      )
    })?;
    self.fills.lock().unwrap().push(output.len());
    output.fill(0);
    let bytes = next.to_be_bytes();
    let length = output.len();
    let tail = bytes.len().min(length);
    output[length - tail..].copy_from_slice(&bytes[bytes.len() - tail..]);
    Ok(())
  }
}

/// Entropy that succeeds `successes` times and then fails with a typed,
/// redacted provider error.
#[derive(Debug)]
pub struct FailingEntropy {
  successes: Mutex<usize>,
}

impl FailingEntropy {
  pub fn new(successes: usize) -> Self {
    Self {
      successes: Mutex::new(successes),
    }
  }
}

impl Entropy for FailingEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    let mut left = self.successes.lock().unwrap();
    if *left == 0 {
      return Err(Error::provider(
        ProviderErrorKind::Io,
        ProviderErrorContext::Entropy,
      ));
    }
    *left -= 1;
    output.fill(0xA5);
    Ok(())
  }
}

#[derive(Debug)]
pub struct MemoryState {
  generation: u64,
  open: bool,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
  receipts: HashMap<TransactionId, CommitReceipt>,
}

/// A persistent in-memory `StorageFactory` implementing the full public
/// storage SPI with the reference contract semantics.
#[derive(Debug)]
pub struct MemoryStorageFactory {
  capabilities: StoreCapabilities,
  state: Arc<Mutex<MemoryState>>,
  commit_calls: Arc<AtomicUsize>,
  open_calls: Arc<AtomicUsize>,
  open_error: Option<ProviderErrorKind>,
  events: Option<Arc<EventLog>>,
  factory_drops: Option<Arc<DropTracker>>,
  storage_drops: Option<Arc<DropTracker>>,
}

impl MemoryStorageFactory {
  pub fn new(capabilities: StoreCapabilities) -> Self {
    Self {
      capabilities,
      state: Arc::new(Mutex::new(MemoryState {
        generation: 1,
        open: false,
        entries: BTreeMap::new(),
        receipts: HashMap::new(),
      })),
      commit_calls: Arc::new(AtomicUsize::new(0)),
      open_calls: Arc::new(AtomicUsize::new(0)),
      open_error: None,
      events: None,
      factory_drops: None,
      storage_drops: None,
    }
  }

  pub fn with_events(mut self, events: Arc<EventLog>) -> Self {
    self.events = Some(events);
    self
  }

  pub fn with_open_error(mut self, kind: ProviderErrorKind) -> Self {
    self.open_error = Some(kind);
    self
  }

  pub fn with_factory_drops(mut self, drops: Arc<DropTracker>) -> Self {
    self.factory_drops = Some(drops);
    self
  }

  pub fn with_storage_drops(mut self, drops: Arc<DropTracker>) -> Self {
    self.storage_drops = Some(drops);
    self
  }

  pub fn open_calls(&self) -> usize {
    self.open_calls.load(Ordering::SeqCst)
  }

  pub fn commit_calls(&self) -> usize {
    self.commit_calls.load(Ordering::SeqCst)
  }

  pub fn entries(&self) -> BTreeMap<(StoreNamespace, StoreKey), StoreValue> {
    self.state.lock().unwrap().entries.clone()
  }

  pub fn receipt_count(&self) -> usize {
    self.state.lock().unwrap().receipts.len()
  }

  /// Injects a raw entry, bypassing the commit path, to set up corruption
  /// and recovery scenarios.
  pub fn inject_entry(&self, namespace: StoreNamespace, key: StoreKey, bytes: Vec<u8>) {
    self.state.lock().unwrap().entries.insert(
      (namespace, key),
      StoreValue::new(Arc::from(bytes.as_slice())),
    );
  }
}

impl Drop for MemoryStorageFactory {
  fn drop(&mut self) {
    if let Some(drops) = &self.factory_drops {
      drops.record();
    }
  }
}

impl StorageFactory for MemoryStorageFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    self.open_calls.fetch_add(1, Ordering::SeqCst);
    if let Some(events) = &self.events {
      events.push("open");
    }
    let capabilities = self.capabilities;
    let state = Arc::clone(&self.state);
    let commit_calls = Arc::clone(&self.commit_calls);
    let open_error = self.open_error;
    let events = self.events.clone();
    let drops = self.storage_drops.clone();
    Box::pin(async move {
      if let Some(kind) = open_error {
        return Err(Error::provider(kind, ProviderErrorContext::StorageOpen));
      }
      if !capabilities_satisfy(capabilities, &requirements) {
        return Err(Error::provider(
          ProviderErrorKind::UnsupportedCapability,
          ProviderErrorContext::StorageOpen,
        ));
      }
      {
        let mut state = state.lock().unwrap();
        if state.open {
          return Err(Error::provider(
            ProviderErrorKind::StorageLocked,
            ProviderErrorContext::StorageOpen,
          ));
        }
        state.open = true;
      }
      Ok(Box::new(MemoryStorage {
        capabilities,
        state,
        commit_calls,
        events,
        drops,
      }) as Box<dyn Storage>)
    })
  }
}

#[derive(Debug)]
struct MemoryStorage {
  capabilities: StoreCapabilities,
  state: Arc<Mutex<MemoryState>>,
  commit_calls: Arc<AtomicUsize>,
  events: Option<Arc<EventLog>>,
  drops: Option<Arc<DropTracker>>,
}

impl Drop for MemoryStorage {
  fn drop(&mut self) {
    self.state.lock().unwrap().open = false;
    if let Some(drops) = &self.drops {
      drops.record();
    }
  }
}

impl Storage for MemoryStorage {
  fn capabilities(&self) -> StoreCapabilities {
    if let Some(events) = &self.events {
      events.push("capabilities");
    }
    self.capabilities
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    if let Some(events) = &self.events {
      events.push("snapshot");
    }
    let state = self.state.lock().unwrap();
    let snapshot = MemorySnapshot {
      revision: memory_revision(state.generation),
      entries: state.entries.clone(),
      events: self.events.clone(),
    };
    Box::pin(async move { Ok(Box::new(snapshot) as Box<dyn StoreSnapshot>) })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    if let Some(events) = &self.events {
      events.push("commit");
    }
    self.commit_calls.fetch_add(1, Ordering::SeqCst);
    let outcome = memory_commit(&self.state, transaction);
    Box::pin(async move { outcome })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    if let Some(events) = &self.events {
      events.push("reconcile");
    }
    let state = self.state.lock().unwrap();
    let outcome = match state.receipts.get(transaction) {
      Some(receipt) if receipt.operation_digest() == digest => {
        ReconcileOutcome::Committed(receipt.clone())
      }
      Some(_) => ReconcileOutcome::DigestConflict,
      None => ReconcileOutcome::Aborted,
    };
    Box::pin(async move { Ok(outcome) })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    if let Some(events) = &self.events {
      events.push("flush");
    }
    Box::pin(async { Ok(()) })
  }
}

#[derive(Debug)]
struct MemorySnapshot {
  revision: StoreRevision,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
  events: Option<Arc<EventLog>>,
}

impl StoreSnapshot for MemorySnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    if let Some(events) = &self.events {
      events.push("get");
    }
    let value = self.entries.get(&(namespace.clone(), key.clone())).cloned();
    Box::pin(async move { Ok(value) })
  }

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    if let Some(events) = &self.events {
      events.push("scan");
    }
    let scan = MemoryScan {
      entries: self.entries.iter(),
      namespace,
      prefix,
    };
    Box::pin(async move { Ok(Box::new(scan) as Box<dyn StoreScan + 'a>) })
  }
}

#[derive(Debug)]
struct MemoryScan<'a> {
  entries: std::collections::btree_map::Iter<'a, (StoreNamespace, StoreKey), StoreValue>,
  namespace: &'a StoreNamespace,
  prefix: &'a [u8],
}

impl StoreScan for MemoryScan<'_> {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    let next = self.entries.find_map(|((namespace, key), value)| {
      (namespace == self.namespace && key.as_bytes().starts_with(self.prefix))
        .then(|| StoreEntry::new(namespace.clone(), key.clone(), value.clone()))
    });
    Box::pin(async move { Ok(next) })
  }
}

fn capabilities_satisfy(capabilities: StoreCapabilities, requirements: &StoreRequirements) -> bool {
  durability_satisfies(
    capabilities.durability(),
    requirements.required_durability(),
  ) && (!requirements.requires_conditional_batch() || capabilities.has_conditional_batch())
    && (!requirements.requires_ordered_scan() || capabilities.has_ordered_scan())
    && (!requirements.requires_reconciliation() || capabilities.has_reconciliation())
    && (!requirements.requires_exclusive_lifetime_lock()
      || capabilities.has_exclusive_lifetime_lock())
    && (!requirements.requires_transactional_migration()
      || capabilities.has_transactional_migration())
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

fn memory_revision(generation: u64) -> StoreRevision {
  StoreRevision::new(Arc::from(generation.to_be_bytes())).unwrap()
}

fn memory_commit(
  state: &Mutex<MemoryState>, transaction: StoreTransaction,
) -> Result<CommitOutcome> {
  let mut state = state.lock().unwrap();
  if let Some(receipt) = state.receipts.get(transaction.id()) {
    return if receipt.operation_digest() == transaction.operation_digest() {
      Ok(CommitOutcome::Committed(receipt.clone()))
    } else {
      Ok(CommitOutcome::Conflict)
    };
  }
  if transaction.operation_digest() != &transaction.computed_operation_digest() {
    return Ok(CommitOutcome::Conflict);
  }
  if transaction.base_revision() != &memory_revision(state.generation) {
    return Ok(CommitOutcome::Conflict);
  }
  if !transaction
    .operations()
    .iter()
    .all(|operation| condition_matches(&state, operation))
  {
    return Ok(CommitOutcome::Conflict);
  }

  let next_generation = state.generation.checked_add(1).ok_or_else(|| {
    Error::provider(
      ProviderErrorKind::ResourceExhausted,
      ProviderErrorContext::StorageCommit,
    )
  })?;
  let mut entries = state.entries.clone();
  for operation in transaction.operations() {
    match operation {
      StoreOperation::Check { .. } => {}
      StoreOperation::Put {
        namespace,
        key,
        value,
        ..
      } => {
        entries.insert((namespace.clone(), key.clone()), value.clone());
      }
      StoreOperation::Delete { namespace, key, .. } => {
        entries.remove(&(namespace.clone(), key.clone()));
      }
      StoreOperation::ForgetReceipt {
        transaction,
        expected_operation_digest,
      } if state
        .receipts
        .get(transaction)
        .is_some_and(|receipt| receipt.operation_digest() == expected_operation_digest) =>
      {
        state.receipts.remove(transaction);
      }
      _ => {}
    }
  }
  state.generation = next_generation;
  state.entries = entries;
  let receipt = CommitReceipt::new(
    transaction.id().clone(),
    transaction.operation_digest().clone(),
    memory_revision(state.generation),
  );
  state
    .receipts
    .insert(transaction.id().clone(), receipt.clone());
  Ok(CommitOutcome::Committed(receipt))
}

fn condition_matches(state: &MemoryState, operation: &StoreOperation) -> bool {
  match operation {
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
    } => expectation_matches(
      state.entries.get(&(namespace.clone(), key.clone())),
      expected,
    ),
    StoreOperation::Delete {
      namespace,
      key,
      expected,
    } => state
      .entries
      .get(&(namespace.clone(), key.clone()))
      .is_some_and(|value| value.digest() == expected),
    StoreOperation::ForgetReceipt {
      transaction,
      expected_operation_digest,
    } => state
      .receipts
      .get(transaction)
      .is_some_and(|receipt| receipt.operation_digest() == expected_operation_digest),
    _ => false,
  }
}

fn expectation_matches(value: Option<&StoreValue>, expected: &StoreExpectation) -> bool {
  match (value, expected) {
    (None, StoreExpectation::Absent) => true,
    (Some(value), StoreExpectation::Exact(digest)) => value.digest() == digest,
    _ => false,
  }
}

/// Commit-fault injection over the in-memory storage for exact crash
/// recovery scenarios.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitFault {
  Pass,
  Aborted,
  UnknownApplied,
  UnknownNotApplied,
}

#[derive(Debug)]
pub struct FaultingFactory {
  memory: Arc<MemoryStorageFactory>,
  script: Arc<Mutex<VecDeque<CommitFault>>>,
  reconcile_unknowns: Arc<Mutex<usize>>,
}

impl FaultingFactory {
  pub fn new(memory: Arc<MemoryStorageFactory>, script: Vec<CommitFault>) -> Self {
    Self {
      memory,
      script: Arc::new(Mutex::new(script.into())),
      reconcile_unknowns: Arc::new(Mutex::new(0)),
    }
  }

  pub fn add_reconcile_unknowns(&self, count: usize) {
    *self.reconcile_unknowns.lock().unwrap() += count;
  }

  /// Replaces the commit-fault script; the runtime lane uses this to pin
  /// an abort to the merge commit regardless of how many earlier
  /// setup commits (identity, rotation, listen) were consumed.
  pub fn reset_script(&self, script: Vec<CommitFault>) {
    *self.script.lock().unwrap() = script.into();
  }
}

impl StorageFactory for FaultingFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    Box::pin(async move {
      let memory = self.memory.open(requirements).await?;
      Ok(Box::new(FaultingStorage {
        memory,
        script: Arc::clone(&self.script),
        reconcile_unknowns: Arc::clone(&self.reconcile_unknowns),
      }) as Box<dyn Storage>)
    })
  }
}

#[derive(Debug)]
struct FaultingStorage {
  memory: Box<dyn Storage>,
  script: Arc<Mutex<VecDeque<CommitFault>>>,
  reconcile_unknowns: Arc<Mutex<usize>>,
}

impl Storage for FaultingStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.memory.capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    self.memory.snapshot()
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    let fault = self
      .script
      .lock()
      .unwrap()
      .pop_front()
      .unwrap_or(CommitFault::Pass);
    Box::pin(async move {
      let id = transaction.id().clone();
      let digest = transaction.operation_digest().clone();
      match fault {
        CommitFault::Pass => self.memory.commit(transaction).await,
        CommitFault::Aborted => Ok(CommitOutcome::Aborted),
        CommitFault::UnknownNotApplied => Ok(CommitOutcome::Unknown {
          transaction: id,
          operation_digest: digest,
        }),
        CommitFault::UnknownApplied => {
          assert!(matches!(
            self.memory.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
          Ok(CommitOutcome::Unknown {
            transaction: id,
            operation_digest: digest,
          })
        }
      }
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    let unknown = {
      let mut left = self.reconcile_unknowns.lock().unwrap();
      if *left > 0 {
        *left -= 1;
        true
      } else {
        false
      }
    };
    Box::pin(async move {
      if unknown {
        return Ok(ReconcileOutcome::Unknown);
      }
      self.memory.reconcile(transaction, digest).await
    })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    self.memory.flush()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyCall {
  Create(KeyOperationId),
  ReconcileCreate(KeyOperationId),
  PublicKey(Vec<u8>),
  Sign,
  Delete,
  ReconcileDelete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateScript {
  Apply,
  ApplyReportUnknown,
  ReportAbsent,
}

/// Derives the deterministic signing key for a fixed-seed index.
pub fn scripted_signing(index: u64) -> SigningKey {
  let mut seed = [0_u8; 32];
  seed[..8].copy_from_slice(&index.to_be_bytes());
  SigningKey::from_bytes(&seed)
}

/// A deterministic scripted `KeyProvider` with opaque handles, configurable
/// capabilities, and a full call log.
#[derive(Debug)]
pub struct ScriptedKeys {
  capabilities: KeyCapabilities,
  inner: Arc<ScriptedKeyInner>,
}

#[derive(Debug)]
pub struct ScriptedKeyInner {
  records: Mutex<BTreeMap<Vec<u8>, (KeyOperationId, SigningKey)>>,
  operations: Mutex<BTreeMap<KeyOperationId, Vec<u8>>>,
  calls: Mutex<Vec<KeyCall>>,
  create_script: Mutex<VecDeque<CreateScript>>,
  reconcile_unknowns: Mutex<usize>,
  public_key_override: Mutex<Option<PublicKey>>,
  next_handle: AtomicUsize,
  events: Option<Arc<EventLog>>,
  drops: Option<Arc<DropTracker>>,
}

impl ScriptedKeys {
  pub fn new(capabilities: KeyCapabilities) -> Self {
    Self {
      capabilities,
      inner: Arc::new(ScriptedKeyInner {
        records: Mutex::new(BTreeMap::new()),
        operations: Mutex::new(BTreeMap::new()),
        calls: Mutex::new(Vec::new()),
        create_script: Mutex::new(VecDeque::new()),
        reconcile_unknowns: Mutex::new(0),
        public_key_override: Mutex::new(None),
        next_handle: AtomicUsize::new(0),
        events: None,
        drops: None,
      }),
    }
  }

  pub fn full() -> Self {
    Self::full_at(0)
  }

  /// Full capabilities with handle allocation starting at `base`, so two
  /// nodes never derive the same identity key.
  pub fn full_at(base: u64) -> Self {
    let mut keys = Self::new(
      KeyCapabilities::new()
        .ed25519(true)
        .reconciliation(true)
        .deletion(true),
    );
    Arc::get_mut(&mut keys.inner)
      .expect("scripted keys must be uniquely owned")
      .next_handle = AtomicUsize::new(base as usize);
    keys
  }

  pub fn with_events(mut self, events: Arc<EventLog>) -> Self {
    Arc::get_mut(&mut self.inner)
      .expect("scripted keys must be uniquely owned")
      .events = Some(events);
    self
  }

  pub fn with_drops(mut self, drops: Arc<DropTracker>) -> Self {
    Arc::get_mut(&mut self.inner)
      .expect("scripted keys must be uniquely owned")
      .drops = Some(drops);
    self
  }

  pub fn take_calls(&self) -> Vec<KeyCall> {
    std::mem::take(&mut *self.inner.calls.lock().unwrap())
  }

  pub fn push_create_script(&self, script: CreateScript) {
    self.inner.create_script.lock().unwrap().push_back(script);
  }

  pub fn add_reconcile_unknowns(&self, count: usize) {
    *self.inner.reconcile_unknowns.lock().unwrap() += count;
  }

  pub fn override_public_key(&self, public_key: PublicKey) {
    *self.inner.public_key_override.lock().unwrap() = Some(public_key);
  }

  pub fn lookup_operation(&self, operation: &KeyOperationId) -> Option<CreatedKey> {
    self.inner.lookup_operation(operation)
  }
}

impl Drop for ScriptedKeys {
  fn drop(&mut self) {
    if let Some(drops) = &self.inner.drops {
      drops.record();
    }
  }
}

impl ScriptedKeyInner {
  fn push_call(&self, call: KeyCall) {
    self.calls.lock().unwrap().push(call);
  }

  fn push_event(&self, event: &'static str) {
    if let Some(events) = &self.events {
      events.push(event);
    }
  }

  fn apply_create(&self, operation: &KeyOperationId) -> CreatedKey {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation) {
      let records = self.records.lock().unwrap();
      let (_, signing) = records.get(handle).unwrap();
      return CreatedKey::new(
        KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
        PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      );
    }
    let index = self.next_handle.fetch_add(1, Ordering::SeqCst) as u64;
    let signing = scripted_signing(index);
    let handle = format!("scripted-handle-{index}").into_bytes();
    let created = CreatedKey::new(
      KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    );
    operations.insert(operation.clone(), handle.clone());
    self
      .records
      .lock()
      .unwrap()
      .insert(handle, (operation.clone(), signing));
    created
  }

  fn lookup_operation(&self, operation: &KeyOperationId) -> Option<CreatedKey> {
    let handle = self.operations.lock().unwrap().get(operation).cloned()?;
    let records = self.records.lock().unwrap();
    let (_, signing) = records.get(&handle).unwrap();
    Some(CreatedKey::new(
      KeyHandle::from_provider_bytes(Arc::from(handle)).unwrap(),
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    ))
  }
}

impl KeyProvider for ScriptedKeys {
  fn capabilities(&self) -> KeyCapabilities {
    self.inner.push_event("key-capabilities");
    self.capabilities
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.inner.push_event("create");
    self.inner.push_call(KeyCall::Create(operation.clone()));
    let script = self
      .inner
      .create_script
      .lock()
      .unwrap()
      .pop_front()
      .unwrap_or(CreateScript::Apply);
    Box::pin(async move {
      match script {
        CreateScript::Apply => Ok(KeyCreateState::Present(self.inner.apply_create(operation))),
        CreateScript::ApplyReportUnknown => {
          self.inner.apply_create(operation);
          Ok(KeyCreateState::Unknown)
        }
        CreateScript::ReportAbsent => Ok(KeyCreateState::Absent),
      }
    })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    self.inner.push_event("reconcile-create");
    self
      .inner
      .push_call(KeyCall::ReconcileCreate(operation.clone()));
    let unknown = {
      let mut left = self.inner.reconcile_unknowns.lock().unwrap();
      if *left > 0 {
        *left -= 1;
        true
      } else {
        false
      }
    };
    let present = self.inner.lookup_operation(operation);
    Box::pin(async move {
      if unknown {
        return Ok(KeyCreateState::Unknown);
      }
      Ok(match present {
        Some(created) => KeyCreateState::Present(created),
        None => KeyCreateState::Absent,
      })
    })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
    self.inner.push_event("public-key");
    self
      .inner
      .push_call(KeyCall::PublicKey(handle.expose_provider_handle().to_vec()));
    let override_key = self.inner.public_key_override.lock().unwrap().clone();
    let result = match &override_key {
      Some(key) => Ok(key.clone()),
      None => self
        .inner
        .records
        .lock()
        .unwrap()
        .get(handle.expose_provider_handle())
        .map(|(_, signing)| PublicKey::from_bytes(signing.verifying_key().to_bytes()))
        .ok_or_else(|| {
          Error::provider(
            ProviderErrorKind::Internal,
            ProviderErrorContext::KeyPublicKey,
          )
        }),
    };
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    self.inner.push_event("sign");
    self.inner.push_call(KeyCall::Sign);
    let result = self
      .inner
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .map(|(_, signing)| Signature::from_bytes(signing.sign(message).to_bytes()))
      .ok_or_else(|| Error::provider(ProviderErrorKind::Internal, ProviderErrorContext::KeySign));
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.inner.push_event("delete");
    self.inner.push_call(KeyCall::Delete);
    Box::pin(async {
      Err(Error::provider(
        ProviderErrorKind::Internal,
        ProviderErrorContext::KeyDelete,
      ))
    })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.inner.push_event("reconcile-delete");
    self.inner.push_call(KeyCall::ReconcileDelete);
    Box::pin(async {
      Err(Error::provider(
        ProviderErrorKind::Internal,
        ProviderErrorContext::KeyDelete,
      ))
    })
  }
}
