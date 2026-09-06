//! Shared test harness for the identity record state machines.
//!
//! Provides scripted key providers, fault-injecting storage factories over
//! the reference storage contract, deterministic sequence entropy, and
//! reference-state inspection helpers used by the genesis and admission
//! state-machine tests.

use std::{
  collections::{BTreeMap, VecDeque},
  fmt, future,
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use ed25519_dalek::{Signer, SigningKey};

use super::lifecycle::{LocalIdentityContext, open_local_identity};
use crate::{
  BoxFuture, CommitOutcome, CreatedKey, Digest, Error, KeyCapabilities, KeyCreateState,
  KeyDeleteState, KeyHandle, KeyOperationId, NodeId, ProviderErrorContext, ProviderErrorKind,
  PublicKey, QualifiedTag, ReconcileOutcome, Result, Signature, StoreCapabilities, StoreKey,
  StoreNamespace, StoreOperation, StoreRequirements, StoreTransaction, StoreValue, TransactionId,
  api::Entropy,
  provider::{KeyProvider, Storage, StorageFactory},
  storage::contract::{ReferenceFactory, required_capabilities},
};

pub(crate) const RETENTION: Duration = Duration::from_secs(3_600);
pub(crate) use crate::storage::pending::PENDING_NAMESPACE;

/// Deterministic entropy: fills produce base62 suffix values 1, 2, 3, ...;
/// every test uses fewer than ten fills per id, so decimal zero-padding
/// matches base62 encoding.
#[derive(Debug, Default)]
pub(crate) struct SequenceEntropy(Mutex<u128>);

impl SequenceEntropy {
  #[allow(dead_code)]
  pub(crate) fn fills(&self) -> u128 {
    *self.0.lock().unwrap()
  }

  /// Starts the deterministic sequence at `offset` so two test nodes never
  /// derive the same identities.
  pub(crate) fn starting_at(offset: u128) -> Self {
    Self(Mutex::new(offset))
  }
}

impl Entropy for SequenceEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    // Deterministic per-call sequence: each fill draws sequential 16-byte
    // blocks, so 16- and 32-byte requests both remain deterministic.
    let mut offset = 0;
    while offset < output.len() {
      let mut next = self.0.lock().unwrap();
      *next = next
        .checked_add(1)
        .ok_or_else(|| Error::internal("sequence entropy exhausted"))?;
      let block = next.to_be_bytes();
      drop(next);
      let take = (output.len() - offset).min(16);
      output[offset..offset + take].copy_from_slice(&block[..take]);
      offset += take;
    }
    Ok(())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KeyCall {
  Create(KeyOperationId),
  ReconcileCreate(KeyOperationId),
  PublicKey(Vec<u8>),
  Sign(Vec<u8>),
  Delete,
  ReconcileDelete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignScript {
  Apply,
  InvalidBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteScript {
  Apply,
  StillPresent,
  Unknown,
}

/// Scripts the key-creation-intent path: `ApplyReportUnknown` commits the
/// key then reports an unknown outcome so the caller exercises
/// reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateScript {
  Apply,
  ApplyReportUnknown,
}

pub(crate) struct ScriptedKeys {
  capabilities: KeyCapabilities,
  inner: Arc<ScriptedKeyInner>,
}

impl fmt::Debug for ScriptedKeys {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ScriptedKeys")
      .finish_non_exhaustive()
  }
}

#[derive(Debug)]
struct ScriptedKeyInner {
  records: Mutex<BTreeMap<Vec<u8>, SigningKey>>,
  operations: Mutex<BTreeMap<KeyOperationId, Vec<u8>>>,
  calls: Mutex<Vec<KeyCall>>,
  sign_script: Mutex<VecDeque<SignScript>>,
  delete_script: Mutex<VecDeque<DeleteScript>>,
  create_script: Mutex<VecDeque<CreateScript>>,
  reconcile_unknowns: Mutex<usize>,
  public_key_override: Mutex<Option<PublicKey>>,
  next_handle: AtomicUsize,
}

pub(crate) fn scripted_signing(index: u64) -> SigningKey {
  let mut seed = [0_u8; 32];
  seed[..8].copy_from_slice(&index.to_be_bytes());
  SigningKey::from_bytes(&seed)
}

impl ScriptedKeys {
  pub(crate) fn full() -> Arc<Self> {
    Self::full_at(0)
  }

  /// Starts handle allocation at `base` so distinct test nodes never share
  /// a key pair.
  pub(crate) fn full_at(base: u64) -> Arc<Self> {
    Arc::new(Self {
      capabilities: KeyCapabilities::new()
        .ed25519(true)
        .reconciliation(true)
        .deletion(true),
      inner: Arc::new(ScriptedKeyInner {
        records: Mutex::new(BTreeMap::new()),
        operations: Mutex::new(BTreeMap::new()),
        calls: Mutex::new(Vec::new()),
        sign_script: Mutex::new(VecDeque::new()),
        delete_script: Mutex::new(VecDeque::new()),
        create_script: Mutex::new(VecDeque::new()),
        reconcile_unknowns: Mutex::new(0),
        public_key_override: Mutex::new(None),
        next_handle: AtomicUsize::new(base as usize),
      }),
    })
  }

  /// A scripted provider with caller-chosen capabilities, for refusal
  /// tests that must prove no key mutation happens before capability
  /// checks.
  pub(crate) fn with_capabilities(capabilities: KeyCapabilities) -> Self {
    Self {
      capabilities,
      inner: Arc::new(ScriptedKeyInner {
        records: Mutex::new(BTreeMap::new()),
        operations: Mutex::new(BTreeMap::new()),
        calls: Mutex::new(Vec::new()),
        sign_script: Mutex::new(VecDeque::new()),
        delete_script: Mutex::new(VecDeque::new()),
        create_script: Mutex::new(VecDeque::new()),
        reconcile_unknowns: Mutex::new(0),
        public_key_override: Mutex::new(None),
        next_handle: AtomicUsize::new(0),
      }),
    }
  }

  pub(crate) fn as_provider(self: &Arc<Self>) -> Arc<dyn KeyProvider> {
    self.clone()
  }

  #[allow(dead_code)]
  pub(crate) fn take_calls(&self) -> Vec<KeyCall> {
    std::mem::take(&mut *self.inner.calls.lock().unwrap())
  }

  pub(crate) fn all_calls(&self) -> Vec<KeyCall> {
    self.inner.calls.lock().unwrap().clone()
  }

  pub(crate) fn push_sign_script(&self, script: SignScript) {
    self.inner.sign_script.lock().unwrap().push_back(script);
  }

  pub(crate) fn push_delete_script(&self, script: DeleteScript) {
    self.inner.delete_script.lock().unwrap().push_back(script);
  }

  pub(crate) fn push_create_script(&self, script: CreateScript) {
    self.inner.create_script.lock().unwrap().push_back(script);
  }

  /// Sets the key returned by `public_key` regardless of the stored handle,
  /// for public-key mismatch tests.
  pub(crate) fn set_public_key_override(&self, key: PublicKey) {
    *self.inner.public_key_override.lock().unwrap() = Some(key);
  }

  /// Makes the next `count` reconciliation calls report `Unknown`.
  pub(crate) fn set_reconcile_unknowns(&self, count: usize) {
    *self.inner.reconcile_unknowns.lock().unwrap() = count;
  }

  pub(crate) fn create_detached(&self, operation: &KeyOperationId) -> CreatedKey {
    self.inner.apply_create(operation)
  }

  pub(crate) fn has_handle(&self, handle: &KeyHandle) -> bool {
    self
      .inner
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle())
  }

  #[allow(dead_code)]
  pub(crate) fn signing_key(&self, handle: &KeyHandle) -> SigningKey {
    self
      .inner
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .unwrap()
      .clone()
  }

  /// Registers the deterministic handle for one creation index without
  /// consuming the creation counter (crash-matrix parents resolve the
  /// child process's handles this way).
  #[cfg(all(test, unix, any(feature = "json", feature = "redb")))]
  pub(crate) fn register_handle_index(&self, index: u64) {
    let handle = format!("scripted-handle-{index}").into_bytes();
    self
      .inner
      .records
      .lock()
      .unwrap()
      .entry(handle)
      .or_insert_with(|| scripted_signing(index));
  }

  /// Looks up the created key for one operation without recording a
  /// provider call, for assertions on already-created handles.
  pub(crate) fn lookup_operation(&self, operation: &KeyOperationId) -> Option<CreatedKey> {
    self.inner.lookup_operation(operation)
  }
}

impl ScriptedKeyInner {
  fn push_call(&self, call: KeyCall) {
    self.calls.lock().unwrap().push(call);
  }

  fn apply_create(&self, operation: &KeyOperationId) -> CreatedKey {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation) {
      let records = self.records.lock().unwrap();
      let signing = records.get(handle).unwrap();
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
    self.records.lock().unwrap().insert(handle, signing);
    created
  }

  fn lookup_operation(&self, operation: &KeyOperationId) -> Option<CreatedKey> {
    let handle = self.operations.lock().unwrap().get(operation).cloned()?;
    let records = self.records.lock().unwrap();
    let signing = records.get(&handle).unwrap();
    Some(CreatedKey::new(
      KeyHandle::from_provider_bytes(Arc::from(handle)).unwrap(),
      PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    ))
  }
}

impl KeyProvider for ScriptedKeys {
  fn capabilities(&self) -> KeyCapabilities {
    self.capabilities
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
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
      }
    })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
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
        .map(|signing| PublicKey::from_bytes(signing.verifying_key().to_bytes()))
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
    self
      .inner
      .push_call(KeyCall::Sign(handle.expose_provider_handle().to_vec()));
    let script = self
      .inner
      .sign_script
      .lock()
      .unwrap()
      .pop_front()
      .unwrap_or(SignScript::Apply);
    let result = self
      .inner
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .cloned()
      .map(|signing| match script {
        SignScript::Apply => Signature::from_bytes(signing.sign(message).to_bytes()),
        SignScript::InvalidBytes => Signature::from_bytes([0x5A; 64]),
      })
      .ok_or_else(|| Error::provider(ProviderErrorKind::Internal, ProviderErrorContext::KeySign));
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.inner.push_call(KeyCall::Delete);
    let script = self
      .inner
      .delete_script
      .lock()
      .unwrap()
      .pop_front()
      .unwrap_or(DeleteScript::Apply);
    let state = match script {
      DeleteScript::Apply => {
        self
          .inner
          .records
          .lock()
          .unwrap()
          .remove(handle.expose_provider_handle());
        KeyDeleteState::Absent
      }
      DeleteScript::StillPresent => KeyDeleteState::Present,
      DeleteScript::Unknown => KeyDeleteState::Unknown,
    };
    Box::pin(async move { Ok(state) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    self.inner.push_call(KeyCall::ReconcileDelete);
    let state = if self
      .inner
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle())
    {
      KeyDeleteState::Present
    } else {
      KeyDeleteState::Absent
    };
    Box::pin(async move { Ok(state) })
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitFault {
  Pass,
  /// Returns `Aborted` after applying: the caller observes an equivocated
  /// pre-commit rejection while the records actually committed.
  Aborted,
  /// Returns `Conflict` after applying: equivocated pre-commit conflict.
  Conflict,
  /// Returns `Aborted` without touching the provider: a genuine pre-commit
  /// rejection that leaves every record absent.
  PureAborted,
  /// Returns `Conflict` without touching the provider: a genuine
  /// pre-commit conflict that leaves every record absent.
  PureConflict,
  UnknownApplied,
  UnknownNotApplied,
  HangApplied,
}

pub(crate) type CommitHook = Box<dyn FnOnce() + Send>;

/// A fault-injecting storage factory over the reference contract that also
/// records the exact operation list of every commit attempt.
pub(crate) struct FaultingFactory {
  pub(crate) reference: Arc<ReferenceFactory>,
  script: Arc<Mutex<VecDeque<CommitFault>>>,
  reconcile_script: Arc<Mutex<VecDeque<ReconcileOutcome>>>,
  hooks: Arc<Mutex<VecDeque<Option<CommitHook>>>>,
  committed_ops: Arc<Mutex<Vec<Vec<StoreOperation>>>>,
}

impl fmt::Debug for FaultingFactory {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("FaultingFactory")
      .finish_non_exhaustive()
  }
}

impl FaultingFactory {
  pub(crate) fn new(reference: &Arc<ReferenceFactory>, script: Vec<CommitFault>) -> Arc<Self> {
    Arc::new(Self {
      reference: Arc::clone(reference),
      script: Arc::new(Mutex::new(script.into())),
      reconcile_script: Arc::new(Mutex::new(VecDeque::new())),
      hooks: Arc::new(Mutex::new(VecDeque::new())),
      committed_ops: Arc::new(Mutex::new(Vec::new())),
    })
  }

  pub(crate) fn push_reconcile_fault(&self, outcome: ReconcileOutcome) {
    self.reconcile_script.lock().unwrap().push_back(outcome);
  }

  pub(crate) fn as_factory(self: &Arc<Self>) -> Arc<dyn StorageFactory> {
    self.clone()
  }

  pub(crate) fn push_hook(&self, hook: CommitHook) {
    self.hooks.lock().unwrap().push_back(Some(hook));
  }

  pub(crate) fn pad_hooks(&self, count: usize) {
    let mut hooks = self.hooks.lock().unwrap();
    while hooks.len() < count {
      hooks.push_back(None);
    }
  }

  pub(crate) fn committed_ops(&self) -> Vec<Vec<StoreOperation>> {
    self.committed_ops.lock().unwrap().clone()
  }
}

struct FaultingStorage {
  reference: Box<dyn Storage>,
  script: Arc<Mutex<VecDeque<CommitFault>>>,
  reconcile_script: Arc<Mutex<VecDeque<ReconcileOutcome>>>,
  hooks: Arc<Mutex<VecDeque<Option<CommitHook>>>>,
  committed_ops: Arc<Mutex<Vec<Vec<StoreOperation>>>>,
}

impl fmt::Debug for FaultingStorage {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("FaultingStorage")
      .finish_non_exhaustive()
  }
}

impl StorageFactory for FaultingFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    Box::pin(async move {
      let reference = self.reference.open(requirements).await?;
      Ok(Box::new(FaultingStorage {
        reference,
        script: Arc::clone(&self.script),
        reconcile_script: Arc::clone(&self.reconcile_script),
        hooks: Arc::clone(&self.hooks),
        committed_ops: Arc::clone(&self.committed_ops),
      }) as Box<dyn Storage>)
    })
  }
}

impl Storage for FaultingStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.reference.capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn crate::provider::StoreSnapshot>>> {
    self.reference.snapshot()
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    if let Some(hook) = self.hooks.lock().unwrap().pop_front().unwrap_or(None) {
      hook();
    }
    self
      .committed_ops
      .lock()
      .unwrap()
      .push(transaction.operations().to_vec());
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
        CommitFault::Pass => self.reference.commit(transaction).await,
        CommitFault::Aborted => {
          assert!(matches!(
            self.reference.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
          Ok(CommitOutcome::Aborted)
        }
        CommitFault::Conflict => {
          assert!(matches!(
            self.reference.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
          Ok(CommitOutcome::Conflict)
        }
        CommitFault::PureAborted => Ok(CommitOutcome::Aborted),
        CommitFault::PureConflict => Ok(CommitOutcome::Conflict),
        CommitFault::UnknownNotApplied => Ok(CommitOutcome::Unknown {
          transaction: id,
          operation_digest: digest,
        }),
        CommitFault::UnknownApplied => {
          assert!(matches!(
            self.reference.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
          Ok(CommitOutcome::Unknown {
            transaction: id,
            operation_digest: digest,
          })
        }
        CommitFault::HangApplied => {
          assert!(matches!(
            self.reference.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
          future::pending().await
        }
      }
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    let fault = self.reconcile_script.lock().unwrap().pop_front();
    Box::pin(async move {
      if let Some(outcome) = fault {
        return Ok(outcome);
      }
      self.reference.reconcile(transaction, digest).await
    })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    self.reference.flush()
  }
}

pub(crate) fn fresh_reference() -> (Arc<ReferenceFactory>, Arc<dyn StorageFactory>) {
  let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
  let factory: Arc<dyn StorageFactory> = reference.clone();
  (reference, factory)
}

pub(crate) async fn open_context(
  factory: &Arc<dyn StorageFactory>, keys: &Arc<ScriptedKeys>, entropy: &Arc<SequenceEntropy>,
) -> Result<LocalIdentityContext> {
  open_local_identity(factory, &keys.as_provider(), entropy.as_ref(), RETENTION).await
}

pub(crate) fn node(value: u128) -> NodeId {
  NodeId::parse(&format!("node_{value:021}")).unwrap()
}

#[allow(dead_code)]
pub(crate) fn transaction(value: u128) -> TransactionId {
  TransactionId::parse(&format!("txn_{value:021}")).unwrap()
}

pub(crate) fn namespace(tag: &str) -> StoreNamespace {
  StoreNamespace::new(QualifiedTag::parse(tag).unwrap())
}

pub(crate) fn entry(
  reference: &Arc<ReferenceFactory>, namespace: &StoreNamespace, key: &StoreKey,
) -> Option<StoreValue> {
  reference
    .state
    .lock()
    .unwrap()
    .entries
    .get(&(namespace.clone(), key.clone()))
    .cloned()
}

#[allow(dead_code)]
pub(crate) fn inject_entry(
  reference: &Arc<ReferenceFactory>, location: (StoreNamespace, StoreKey), bytes: Vec<u8>,
) {
  reference
    .state
    .lock()
    .unwrap()
    .entries
    .insert(location, StoreValue::new(Arc::from(bytes)));
}

pub(crate) fn remove_entry(
  reference: &Arc<ReferenceFactory>, namespace: &StoreNamespace, key: &StoreKey,
) {
  reference
    .state
    .lock()
    .unwrap()
    .entries
    .remove(&(namespace.clone(), key.clone()));
}

pub(crate) fn pending_keys(reference: &Arc<ReferenceFactory>) -> Vec<Vec<u8>> {
  let namespace = namespace(PENDING_NAMESPACE);
  let mut keys: Vec<Vec<u8>> = reference
    .state
    .lock()
    .unwrap()
    .entries
    .keys()
    .filter(|(entry_namespace, _)| entry_namespace == &namespace)
    .map(|(_, key)| key.as_bytes().to_vec())
    .collect();
  keys.sort();
  keys
}

pub(crate) fn receipt_ids(reference: &Arc<ReferenceFactory>) -> Vec<TransactionId> {
  let mut ids: Vec<TransactionId> = reference
    .state
    .lock()
    .unwrap()
    .receipts
    .keys()
    .cloned()
    .collect();
  ids.sort();
  ids
}

pub(crate) fn commit_calls(reference: &Arc<ReferenceFactory>) -> usize {
  reference.commit_calls.load(Ordering::SeqCst)
}

pub(crate) fn assert_never_deleted(keys: &ScriptedKeys) {
  for call in keys.all_calls() {
    assert!(
      !matches!(call, KeyCall::Delete | KeyCall::ReconcileDelete),
      "unexpected provider call: {call:?}"
    );
  }
}
