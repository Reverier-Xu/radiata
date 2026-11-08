//! The unknown-outcome fault wrapper over the reference provider: the
//! contract lanes' fault injector for indeterminate commits (the
//! `Unknown` outcome paths). The reference provider itself lives in
//! [`crate::storage::memory`], where it doubles as the public memory
//! store.

use std::{
  future,
  sync::{Arc, Mutex},
};

use crate::{
  BoxFuture, CommitOutcome, Digest, ReconcileOutcome, Result, StoreRequirements, TransactionId,
  provider::{Storage, StorageFactory},
};

pub(crate) use crate::storage::memory::ReferenceFactory;

#[derive(Clone, Copy, Debug)]
pub(crate) enum UnknownFaultMode {
  Applied,
  NotApplied,
  PendingApplied,
  PendingNotApplied,
}

#[derive(Debug)]
pub(crate) struct UnknownFaultFactory {
  pub(crate) reference: Arc<crate::storage::memory::ReferenceFactory>,
  pub(crate) mode: UnknownFaultMode,
  pub(crate) commit_calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Debug)]
struct UnknownFaultStorage {
  reference: Box<dyn Storage>,
  mode: UnknownFaultMode,
  commit_calls: Arc<std::sync::atomic::AtomicUsize>,
  pending: Mutex<Option<(TransactionId, Digest)>>,
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
  fn capabilities(&self) -> crate::StoreCapabilities {
    self.reference.capabilities()
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn crate::provider::StoreSnapshot>>> {
    self.reference.snapshot()
  }

  fn commit<'a>(
    &'a self, transaction: crate::StoreTransaction,
  ) -> BoxFuture<'a, Result<CommitOutcome>> {
    use std::sync::atomic::Ordering;

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

/// Runs the full storage contract suite against the reference factory
/// (contract-evidence only; the fuzz build consumes the factory itself).
/// The public, always-compiled runner lives in
/// [`crate::storage::contract_suite`]; this test-only twin is the same
/// five-suite body over the crate-internal fixtures.
#[cfg(test)]
pub(crate) async fn run_reference_storage_contract<F>(fresh: F)
where
  F: Fn() -> Arc<dyn StorageFactory>,
{
  crate::storage::contract_suite::run_storage_contract(fresh).await;
}
