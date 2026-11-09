//! The in-memory reference metadata provider: the crate's reference
//! implementation of the [`Storage`](crate::extension::Storage) contract
//! and the contract suite's oracle.
//!
//! Two roles, one implementation. As the memory store (see
//! [`crate::adapters::memory_store`]) it is the demo/reference backend a
//! caller can run without a filesystem: fully durable within the process
//! lifetime, no persistence beyond it. As the storage contract's oracle
//! it deliberately keeps its own derivation of the commit and reconcile
//! verdicts (see the oracle comment below), so the contract suite's
//! cross-checks against the production adapters cannot drift in
//! lockstep with them.

use std::{
  collections::BTreeMap,
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
};

use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, Error, ProviderErrorContext, ProviderErrorKind,
  ReconcileOutcome, Result, StoreCapabilities, StoreEntry, StoreExpectation, StoreKey,
  StoreNamespace, StoreOperation, StoreRequirements, StoreRevision, StoreTransaction, StoreValue,
  TransactionId,
  provider::{Storage, StorageFactory, StoreScan, StoreSnapshot},
};

#[derive(Debug)]
pub(crate) struct ReferenceState {
  pub(crate) generation: u64,
  open: bool,
  pub(crate) entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
  pub(crate) receipts: BTreeMap<TransactionId, CommitReceipt>,
}

#[derive(Debug)]
pub(crate) struct ReferenceFactory {
  capabilities: StoreCapabilities,
  pub(crate) state: Arc<Mutex<ReferenceState>>,
  pub(crate) commit_calls: Arc<AtomicUsize>,
}

impl ReferenceFactory {
  pub(crate) fn new(capabilities: StoreCapabilities) -> Self {
    Self {
      capabilities,
      state: Arc::new(Mutex::new(ReferenceState {
        generation: 1,
        open: false,
        entries: BTreeMap::new(),
        receipts: BTreeMap::new(),
      })),
      commit_calls: Arc::new(AtomicUsize::new(0)),
    }
  }
}

#[derive(Debug)]
struct ReferenceStorage {
  capabilities: StoreCapabilities,
  state: Arc<Mutex<ReferenceState>>,
  commit_calls: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct ReferenceSnapshot {
  revision: StoreRevision,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
}

#[derive(Debug)]
struct ReferenceScan<'a> {
  entries: std::collections::btree_map::Range<'a, (StoreNamespace, StoreKey), StoreValue>,
  namespace: &'a StoreNamespace,
  prefix: &'a [u8],
}

/// The store revision of one commit generation: the monotonically
/// advancing logical clock the reference provider commits against. The
/// bytes are the generation's fixed-width big-endian form, so the
/// revision constructor's grammar always accepts them; a failure there
/// is an implementation fault and surfaces as one.
fn generation_revision(generation: u64) -> Result<StoreRevision> {
  StoreRevision::new(Arc::from(generation.to_be_bytes()))
    .map_err(|_| Error::internal("reference store revision"))
}

/// The shared-state lock mapper: a poisoned reference-state mutex is an
/// implementation fault (the critical sections never panic), surfaced
/// as one instead of panicking.
fn lock_state(state: &Mutex<ReferenceState>) -> Result<std::sync::MutexGuard<'_, ReferenceState>> {
  state
    .lock()
    .map_err(|_| Error::poisoned("reference store state"))
}

impl StorageFactory for ReferenceFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let capabilities = self.capabilities;
    let state = Arc::clone(&self.state);
    let commit_calls = Arc::clone(&self.commit_calls);
    Box::pin(async move {
      if !capabilities.satisfies(&requirements) {
        return Err(Error::provider(
          ProviderErrorKind::UnsupportedCapability,
          ProviderErrorContext::StorageOpen,
        ));
      }
      {
        let mut state = lock_state(&state)?;
        if state.open {
          return Err(Error::provider(
            ProviderErrorKind::StorageLocked,
            ProviderErrorContext::StorageOpen,
          ));
        }
        state.open = true;
      }
      Ok(Box::new(ReferenceStorage {
        capabilities,
        state,
        commit_calls,
      }) as Box<dyn Storage>)
    })
  }
}

impl Drop for ReferenceStorage {
  fn drop(&mut self) {
    // A poisoned mutex cannot be reported from Drop; the open flag only
    // gates a second concurrent open, and a poisoned state already
    // failed every operation that touched it.
    if let Ok(mut state) = self.state.lock() {
      state.open = false;
    }
  }
}

impl Storage for ReferenceStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.capabilities
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    let snapshot = lock_state(&self.state).and_then(|state| {
      Ok(ReferenceSnapshot {
        revision: generation_revision(state.generation)?,
        entries: state.entries.clone(),
      })
    });
    Box::pin(async move { snapshot.map(|snapshot| Box::new(snapshot) as Box<dyn StoreSnapshot>) })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    self.commit_calls.fetch_add(1, Ordering::SeqCst);
    let outcome = reference_commit(&self.state, transaction);
    Box::pin(async move { outcome })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    let outcome = lock_state(&self.state)
      .map(|state| reference_reconcile_verdict(&state.receipts, transaction, digest));
    Box::pin(async move { outcome })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async { Ok(()) })
  }
}

impl StoreSnapshot for ReferenceSnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    let value = self.entries.get(&(namespace.clone(), key.clone())).cloned();
    Box::pin(async move { Ok(value) })
  }

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    self.scan_from(namespace, prefix, None)
  }

  fn scan_from<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8], from: Option<&'a [u8]>,
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    // The map is keyed by (namespace, key) in the exact scan order, so
    // one range lower bound carries both the plain prefix start and the
    // strictly-greater positioned start; `next` filters namespace and
    // prefix, keeping out-of-bounds starts empty.
    let lower = match from {
      None => std::ops::Bound::Included((namespace.clone(), StoreKey::new(Arc::from(prefix)))),
      Some(from) => std::ops::Bound::Excluded((namespace.clone(), StoreKey::new(Arc::from(from)))),
    };
    let scan = ReferenceScan {
      entries: self.entries.range((lower, std::ops::Bound::Unbounded)),
      namespace,
      prefix,
    };
    Box::pin(async move { Ok(Box::new(scan) as Box<dyn StoreScan + 'a>) })
  }
}

impl StoreScan for ReferenceScan<'_> {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    let next = self.entries.find_map(|((namespace, key), value)| {
      (namespace == self.namespace && key.as_bytes().starts_with(self.prefix))
        .then(|| StoreEntry::new(namespace.clone(), key.clone(), value.clone()))
    });
    Box::pin(async move { Ok(next) })
  }
}

// Oracle verdicts, deliberately independent of the production helpers
// `crate::provider::commit_precheck`/`classify_receipt`/`condition_matches`:
// those helpers are the single implementation
// behind the redb/json adapters, so a reference provider that calls them
// inherits every production drift and stops being an oracle — the
// adapter contract lanes would compare the adapters against a copy of
// themselves and a semantic drift would never surface as a divergence.
// Each table below is re-derived from the contract prose documented on
// `crate::provider::Storage` (the "Commit ordering" and
// "Reconciliation" bullets), which is also the sync obligation: when
// that prose changes, re-derive these tables from the documentation,
// never from `provider.rs`, and never collapse them back into calls of
// the shared helpers.

/// Reconcile verdict from the "Reconciliation" bullet of the `Storage`
/// contract: no stored receipt means the transaction never applied; a
/// receipt under the exact digest is the committed one; the same
/// transaction id under any other digest is the digest conflict.
fn reference_reconcile_verdict(
  receipts: &BTreeMap<TransactionId, CommitReceipt>, transaction: &TransactionId, digest: &Digest,
) -> ReconcileOutcome {
  let Some(receipt) = receipts.get(transaction) else {
    return ReconcileOutcome::Aborted;
  };
  if receipt.operation_digest() == digest {
    ReconcileOutcome::Committed(receipt.clone())
  } else {
    ReconcileOutcome::DigestConflict
  }
}

/// Commit verdict from the "Commit ordering" bullet of the `Storage`
/// contract: the receipt replay decides first (the same transaction id
/// and operation digest is the idempotent replay; the same id under
/// another digest is a conflict), then the base revision (anything but
/// the committing revision conflicts), then each operation's conditional
/// expectation in order (the first miss conflicts, nothing applies).
/// `None` hands the transaction to the apply phase. The provider-side
/// digest tripwire is intentionally absent here: it guards a
/// `StoreTransaction` construction invariant, not commit semantics.
fn reference_commit_verdict(
  state: &ReferenceState, transaction: &StoreTransaction,
) -> Result<Option<CommitOutcome>> {
  if let Some(receipt) = state.receipts.get(transaction.id()) {
    return Ok(Some(
      if receipt.operation_digest() == transaction.operation_digest() {
        CommitOutcome::Committed(receipt.clone())
      } else {
        CommitOutcome::Conflict
      },
    ));
  }
  if transaction.base_revision() != &generation_revision(state.generation)? {
    return Ok(Some(CommitOutcome::Conflict));
  }
  for operation in transaction.operations() {
    let expectation_holds = match operation {
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
      } => reference_entry_matches(
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
        .is_some_and(|entry| entry.digest() == expected),
      StoreOperation::ForgetReceipt {
        transaction,
        expected_operation_digest,
      } => state
        .receipts
        .get(transaction)
        .is_some_and(|receipt| receipt.operation_digest() == expected_operation_digest),
    };
    if !expectation_holds {
      return Ok(Some(CommitOutcome::Conflict));
    }
  }
  Ok(None)
}

/// Record expectation from the conditional part of the "Commit
/// ordering" bullet of the `Storage` contract: `Absent` holds only over
/// a missing record and `Exact` only over that exact content digest.
fn reference_entry_matches(entry: Option<&StoreValue>, expected: &StoreExpectation) -> bool {
  match expected {
    StoreExpectation::Absent => entry.is_none(),
    StoreExpectation::Exact(digest) => entry.is_some_and(|value| value.digest() == digest),
  }
}

fn reference_commit(
  state: &Mutex<ReferenceState>, transaction: StoreTransaction,
) -> Result<CommitOutcome> {
  let mut state = lock_state(state)?;
  if let Some(outcome) = reference_commit_verdict(&state, &transaction)? {
    return Ok(outcome);
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
      } => {
        if state
          .receipts
          .get(transaction)
          .is_some_and(|receipt| receipt.operation_digest() == expected_operation_digest)
        {
          state.receipts.remove(transaction);
        }
      }
    }
  }
  state.generation = next_generation;
  state.entries = entries;
  let receipt = CommitReceipt::new(
    transaction.id().clone(),
    transaction.operation_digest().clone(),
    generation_revision(state.generation)?,
  );
  state
    .receipts
    .insert(transaction.id().clone(), receipt.clone());
  Ok(CommitOutcome::Committed(receipt))
}
