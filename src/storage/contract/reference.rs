use std::{
  collections::BTreeMap,
  future,
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
};

use super::helpers::reference_revision;
#[cfg(test)]
use super::runner::{
  storage_contract_conflicts_atomicity_and_idempotence,
  storage_contract_snapshot_lookup_and_ordering,
};
use crate::{
  BoxFuture, CommitOutcome, CommitReceipt, Digest, Error, ProviderErrorContext, ProviderErrorKind,
  ReconcileOutcome, Result, StoreCapabilities, StoreEntry, StoreKey, StoreNamespace,
  StoreOperation, StoreRequirements, StoreRevision, StoreTransaction, StoreValue, TransactionId,
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

#[derive(Clone, Copy, Debug)]
pub(crate) enum UnknownFaultMode {
  Applied,
  NotApplied,
  PendingApplied,
  PendingNotApplied,
}

#[derive(Debug)]
pub(crate) struct UnknownFaultFactory {
  pub(crate) reference: Arc<ReferenceFactory>,
  pub(crate) mode: UnknownFaultMode,
  pub(crate) commit_calls: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct UnknownFaultStorage {
  reference: Box<dyn Storage>,
  mode: UnknownFaultMode,
  commit_calls: Arc<AtomicUsize>,
  pending: Mutex<Option<(TransactionId, Digest)>>,
}

#[derive(Debug)]
struct ReferenceSnapshot {
  revision: StoreRevision,
  entries: BTreeMap<(StoreNamespace, StoreKey), StoreValue>,
}

#[derive(Debug)]
struct ReferenceScan<'a> {
  entries: std::collections::btree_map::Iter<'a, (StoreNamespace, StoreKey), StoreValue>,
  namespace: &'a StoreNamespace,
  prefix: &'a [u8],
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
        let mut state = state.lock().unwrap();
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
    self.state.lock().unwrap().open = false;
  }
}

impl Storage for ReferenceStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.capabilities
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    let state = self.state.lock().unwrap();
    let snapshot = ReferenceSnapshot {
      revision: reference_revision(state.generation),
      entries: state.entries.clone(),
    };
    Box::pin(async move { Ok(Box::new(snapshot) as Box<dyn StoreSnapshot>) })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    self.commit_calls.fetch_add(1, Ordering::SeqCst);
    let outcome = reference_commit(&self.state, transaction);
    Box::pin(async move { outcome })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
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
    Box::pin(async { Ok(()) })
  }
}

impl StorageFactory for UnknownFaultFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let mode = self.mode;
    let commit_calls = Arc::clone(&self.commit_calls);
    Box::pin(async move {
      let reference = self.reference.open(requirements).await?;
      Ok(Box::new(UnknownFaultStorage {
        reference,
        mode,
        commit_calls,
        pending: Mutex::new(None),
      }) as Box<dyn Storage>)
    })
  }
}

impl Storage for UnknownFaultStorage {
  fn capabilities(&self) -> StoreCapabilities {
    self.reference.capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    self.reference.snapshot()
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    self.commit_calls.fetch_add(1, Ordering::SeqCst);
    let identity = (
      transaction.id().clone(),
      transaction.operation_digest().clone(),
    );
    *self.pending.lock().unwrap() = Some(identity.clone());
    Box::pin(async move {
      match self.mode {
        UnknownFaultMode::Applied | UnknownFaultMode::PendingApplied => {
          assert!(matches!(
            self.reference.commit(transaction).await?,
            CommitOutcome::Committed(_)
          ));
        }
        UnknownFaultMode::NotApplied | UnknownFaultMode::PendingNotApplied => {}
      }
      if matches!(
        self.mode,
        UnknownFaultMode::PendingApplied | UnknownFaultMode::PendingNotApplied
      ) {
        return future::pending().await;
      }
      Ok(CommitOutcome::Unknown {
        transaction: identity.0,
        operation_digest: identity.1,
      })
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<ReconcileOutcome>> {
    let pending = self.pending.lock().unwrap().clone();
    Box::pin(async move {
      if pending
        .as_ref()
        .is_some_and(|(pending_transaction, pending_digest)| {
          pending_transaction != transaction || pending_digest != digest
        })
      {
        return Ok(ReconcileOutcome::DigestConflict);
      }
      self.reference.reconcile(transaction, digest).await
    })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    self.reference.flush()
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
    let scan = ReferenceScan {
      entries: self.entries.iter(),
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

fn reference_commit(
  state: &Mutex<ReferenceState>, transaction: StoreTransaction,
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
  if transaction.base_revision() != &reference_revision(state.generation) {
    return Ok(CommitOutcome::Conflict);
  }
  for operation in transaction.operations() {
    if !crate::provider::condition_matches(
      |namespace: &StoreNamespace, key: &StoreKey| {
        Ok(
          state
            .entries
            .get(&(namespace.clone(), key.clone()))
            .map(|value| value.digest().clone()),
        )
      },
      |transaction: &TransactionId| {
        Ok(
          state
            .receipts
            .get(transaction)
            .map(|receipt| receipt.operation_digest().clone()),
        )
      },
      operation,
    )? {
      return Ok(CommitOutcome::Conflict);
    }
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
    reference_revision(state.generation),
  );
  state
    .receipts
    .insert(transaction.id().clone(), receipt.clone());
  Ok(CommitOutcome::Committed(receipt))
}

/// Runs the full storage contract suite against the reference factory
/// (contract-evidence only; the fuzz build consumes the factory itself).
#[cfg(test)]
pub(crate) async fn run_storage_contract<F>(fresh: F)
where
  F: Fn() -> Arc<dyn StorageFactory>, {
  storage_contract_snapshot_lookup_and_ordering(fresh()).await;
  storage_contract_conflicts_atomicity_and_idempotence(fresh()).await;
  super::all_family::storage_contract_all_family_roundtrip(fresh()).await;
  super::all_family::storage_contract_cross_family_atomicity(fresh()).await;
}
