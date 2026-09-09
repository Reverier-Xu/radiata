//! Conditional local transactions for resource metadata.
//!
//! One named resource is one register: a put or removal conditionally
//! commits exactly one whole signed record under the register key, and the
//! commit installs only when the incoming tuple strictly wins over the
//! stored record. Losing records are accepted and store nothing —
//! acceptance never promises a current or future win. A losing,
//! conflicting, or indeterminate outcome never leaves partial labels or a
//! hidden causal ordering behind: the storage contract's conditional
//! transactions reopen to exactly the old or the new whole record, and
//! concurrent exact-version writes resolve to typed conflicts or one
//! commit.

use std::sync::Arc;

use super::{ResourceName, ResourceRecordV1};
/// The durable namespace holding one register per resource name.
pub(crate) use crate::storage::families::RESOURCE_RECORD_NAMESPACE;
use crate::{
  CommitReceipt, Digest, Error, Result, StoreKey, StoreNamespace, StoreOperation, StoreValue,
  TransactionId, api::Entropy, storage::MetadataStore,
};

pub(crate) fn namespace() -> Result<StoreNamespace> {
  crate::identity::records::metadata_namespace(RESOURCE_RECORD_NAMESPACE)
}

fn record_key(name: &ResourceName) -> StoreKey {
  StoreKey::new(Arc::from(name.as_str().as_bytes().to_vec()))
}

/// The outcome of one conditional resource commit.
#[derive(Debug)]
pub(crate) enum ResourceCommitOutcome {
  /// The record is now the register's stored winner; the receipt proves
  /// the durable commit.
  Installed(#[allow(dead_code)] CommitReceipt),
  /// A greater tuple already occupies the register: the write is accepted
  /// but stores nothing and wins nothing (accepted writes may lose tuple
  /// order; losers stay harmless). The payload names the stored winner;
  /// production callers deliberately ignore it, tests read it.
  Superseded(#[allow(dead_code)] ResourceRecordV1),
  /// The commit ended indeterminate: the caller must reconcile the
  /// pending transaction identity before knowing whether old or new
  /// metadata won. The register reopens to exactly one of them.
  Indeterminate {
    #[allow(dead_code)]
    transaction: TransactionId,
    #[allow(dead_code)]
    operation_digest: Digest,
  },
}

/// Reads the stored winner for one resource name, if any.
pub(crate) async fn read_record_ctx(
  store: &MetadataStore, name: &ResourceName,
) -> Result<Option<ResourceRecordV1>> {
  let namespace = namespace()?;
  let value = store
    .snapshot()
    .await?
    .get(&namespace, &record_key(name))
    .await?;
  let Some(value) = value else {
    return Ok(None);
  };
  Ok(Some(ResourceRecordV1::decode(value.as_bytes())?))
}

/// Conditionally commits one signed resource record: the register accepts
/// the record only when its tuple strictly wins over any stored winner.
/// The whole record is one store value, so no outcome can expose partial
/// labels, and every transaction id is freshly generated so digests are
/// never reused.
pub(crate) async fn commit_record_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &ResourceRecordV1,
) -> Result<ResourceCommitOutcome> {
  let _permit = store.write_permit().await;
  let namespace = namespace()?;
  let key = record_key(record.name());
  // One snapshot view for both the tuple decision and the per-key CAS
  // expectation, so a concurrent writer can only produce a typed conflict,
  // never an unordered overwrite.
  let snapshot = store.snapshot().await?;
  if let Some(existing) = snapshot.get(&namespace, &key).await? {
    let existing = ResourceRecordV1::decode(existing.as_bytes())?;
    if !record.wins_over(&existing) {
      return Ok(ResourceCommitOutcome::Superseded(existing));
    }
  }
  commit_put_ctx(
    store,
    entropy,
    snapshot.as_ref(),
    namespace,
    key,
    record,
    "resource record",
  )
  .await
}

/// The shared conditional-put tail of both register commits: one
/// snapshot-exact CAS, one typed outcome mapping. The caller's
/// snapshot view stays the single authority for both the per-key
/// expectation and the CAS revision.
async fn commit_put_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, snapshot: &dyn crate::provider::StoreSnapshot,
  namespace: StoreNamespace, key: StoreKey, record: &ResourceRecordV1, conflict: &'static str,
) -> Result<ResourceCommitOutcome> {
  let expected = crate::provider::snapshot_expectation(snapshot, &namespace, &key).await?;
  let transaction = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![StoreOperation::Put {
      namespace,
      key,
      expected,
      value: StoreValue::new(Arc::from(record.encode()?)),
    }],
  )?;
  match store.commit(transaction).await? {
    crate::CommitOutcome::Committed(receipt) => Ok(ResourceCommitOutcome::Installed(receipt)),
    // A raced writer moved the register between snapshot and commit: the
    // exact-version expectation fails closed with a typed conflict.
    crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => {
      Err(Error::conflict(conflict))
    }
    crate::CommitOutcome::Unknown {
      transaction,
      operation_digest,
    } => Ok(ResourceCommitOutcome::Indeterminate {
      transaction,
      operation_digest,
    }),
  }
}

/// Conditionally commits one signed removal record under an exact-version
/// precondition: the stored winner must still be
/// exactly `expected`, and the removal must strictly win the tuple, so a
/// raced or stale removal can never overwrite a newer record or pose as a
/// newer wall-clock winner. The commit is one conditional transaction, so
/// every fault boundary reopens to exactly the old or the new record
/// without touching unrelated metadata.
pub(crate) async fn commit_removal_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &ResourceRecordV1,
  expected: &ResourceRecordV1,
) -> Result<ResourceCommitOutcome> {
  let _permit = store.write_permit().await;
  debug_assert!(record.removed(), "removal commits carry removal records");
  let namespace = namespace()?;
  let key = record_key(record.name());
  let snapshot = store.snapshot().await?;
  let Some(existing) = snapshot.get(&namespace, &key).await? else {
    return Err(Error::not_found("resource record"));
  };
  let existing = ResourceRecordV1::decode(existing.as_bytes())?;
  // The exact observed version must still occupy the register.
  if &existing != expected {
    return Ok(ResourceCommitOutcome::Superseded(existing));
  }
  // A removal that cannot win the tuple is never committed: the caller
  // sees a typed conflict instead of a fabricated wall-clock winner.
  if !record.wins_over(&existing) {
    return Err(Error::conflict("resource removal tuple"));
  }
  commit_put_ctx(
    store,
    entropy,
    snapshot.as_ref(),
    namespace,
    key,
    record,
    "resource removal",
  )
  .await
}

#[cfg(test)]
mod tests {
  use std::{sync::Arc, time::Duration};

  use ed25519_dalek::SigningKey;

  use super::{
    ResourceCommitOutcome, ResourceName, ResourceRecordV1, commit_record_ctx, read_record_ctx,
  };
  use crate::{
    LabelKey, LabelSet, LabelValue, NodeId, api::SystemEntropy, provider::StorageFactory,
    storage::MetadataStore,
  };

  const SEED: [u8; 32] = [21; 32];

  fn name() -> ResourceName {
    ResourceName::parse("radiata.woooo.tech/resources/store-demo").unwrap()
  }

  fn labels() -> LabelSet {
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/tier").unwrap(),
        LabelValue::parse("gold").unwrap(),
      )
      .unwrap()
  }

  #[allow(clippy::too_many_arguments)]
  fn variant(
    timestamp_millis: u64, removal_rank: u64, removed: bool, uri: &str,
  ) -> ResourceRecordV1 {
    ResourceRecordV1::sign(
      name(),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse(uri).unwrap(),
      labels(),
      timestamp_millis,
      NodeId::parse("node_000000000000000000001").unwrap(),
      removal_rank,
      removed,
      &SigningKey::from_bytes(&SEED),
    )
    .unwrap()
  }

  fn put(timestamp_millis: u64, uri: &str) -> ResourceRecordV1 {
    variant(timestamp_millis, 0, false, uri)
  }

  fn removal(timestamp_millis: u64) -> ResourceRecordV1 {
    variant(timestamp_millis, 1, true, "file:///removed")
  }

  async fn open_store() -> (Arc<dyn StorageFactory>, MetadataStore) {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    (factory, store)
  }

  /// A local put conditionally commits one whole signed record; a fresh
  /// handle reopens exactly that metadata with every label intact.
  #[tokio::test]
  async fn local_put_installs_whole_and_reopens_intact() {
    let (_factory, store) = open_store().await;
    assert!(read_record_ctx(&store, &name()).await.unwrap().is_none());

    let record = put(1_000, "file:///a");
    match commit_record_ctx(&store, &SystemEntropy, &record)
      .await
      .unwrap()
    {
      ResourceCommitOutcome::Installed(_) => {}
      other => panic!("first install must commit, got {other:?}"),
    }

    drop(store);
    let reopened = MetadataStore::open(&_factory, Duration::from_secs(10))
      .await
      .unwrap();
    let stored = read_record_ctx(&reopened, &name()).await.unwrap().unwrap();
    assert_eq!(&stored, &record);
    assert_eq!(stored.labels().entries().count(), 1);
    assert!(!stored.removed());
  }

  /// A losing write is accepted but stores nothing and wins nothing —
  /// the stored winner is untouched and the loser never becomes visible
  /// through any read path.
  #[tokio::test]
  async fn losing_writes_are_accepted_and_stay_harmless() {
    let (_factory, store) = open_store().await;
    let winner = put(2_000, "file:///winner");
    assert!(matches!(
      commit_record_ctx(&store, &SystemEntropy, &winner)
        .await
        .unwrap(),
      ResourceCommitOutcome::Installed(_)
    ));

    // An older-stamped remote write loses by tuple order (clock rollback:
    // later local work can lose).
    let loser = put(1_000, "file:///loser");
    match commit_record_ctx(&store, &SystemEntropy, &loser)
      .await
      .unwrap()
    {
      ResourceCommitOutcome::Superseded(existing) => {
        assert_eq!(existing.digest(), winner.digest());
      }
      other => panic!("losing write must supersede, got {other:?}"),
    }
    // Equal-tuple losers are idempotent-adjacent: same writer, rank, and
    // digest replays stay harmless too.
    match commit_record_ctx(&store, &SystemEntropy, &winner)
      .await
      .unwrap()
    {
      ResourceCommitOutcome::Superseded(_) => {}
      other => panic!("byte-identical replay must not reinstall, got {other:?}"),
    }
    let stored = read_record_ctx(&store, &name()).await.unwrap().unwrap();
    assert_eq!(stored.digest(), winner.digest());
  }

  /// A removal is just a signed record: a greater-tuple removal replaces a
  /// live record, and an even-greater live put replaces the removal — the
  /// register has no hidden causal or tombstone permanence at this layer
  /// (removal evidence retention lives in the retention module).
  #[tokio::test]
  async fn removals_and_puts_converge_by_tuple_order_alone() {
    let (_factory, store) = open_store().await;
    commit_record_ctx(&store, &SystemEntropy, &put(1_000, "file:///live"))
      .await
      .unwrap();
    let remove = removal(2_000);
    assert!(matches!(
      commit_record_ctx(&store, &SystemEntropy, &remove)
        .await
        .unwrap(),
      ResourceCommitOutcome::Installed(_)
    ));
    assert!(
      read_record_ctx(&store, &name())
        .await
        .unwrap()
        .unwrap()
        .removed()
    );

    let revive = put(3_000, "file:///revived");
    assert!(matches!(
      commit_record_ctx(&store, &SystemEntropy, &revive)
        .await
        .unwrap(),
      ResourceCommitOutcome::Installed(_)
    ));
    let stored = read_record_ctx(&store, &name()).await.unwrap().unwrap();
    assert!(!stored.removed());
    assert_eq!(stored.resource_uri(), revive.resource_uri());
  }

  /// Two exact-version writes prepared from one snapshot can produce only
  /// typed conflicts or one commit — never partial labels or hidden
  /// ordering.
  #[tokio::test]
  async fn raced_exact_version_writes_fail_with_typed_conflicts() {
    let (_factory, store) = open_store().await;
    let namespace = crate::StoreNamespace::new(
      crate::QualifiedTag::parse(super::RESOURCE_RECORD_NAMESPACE).unwrap(),
    );
    let key = crate::StoreKey::new(Arc::from(name().as_str().as_bytes().to_vec()));

    let snapshot = store.snapshot().await.unwrap();
    let revision = snapshot.revision().clone();
    let first = put(1_000, "file:///first");
    let second = put(1_000, "file:///second");
    let tx_first = store
      .prepare_transaction(
        crate::TransactionId::generate(&SystemEntropy).unwrap(),
        revision.clone(),
        vec![crate::StoreOperation::Put {
          namespace: namespace.clone(),
          key: key.clone(),
          expected: crate::StoreExpectation::Absent,
          value: crate::StoreValue::new(Arc::from(first.encode().unwrap())),
        }],
      )
      .unwrap();
    let tx_second = store
      .prepare_transaction(
        crate::TransactionId::generate(&SystemEntropy).unwrap(),
        revision,
        vec![crate::StoreOperation::Put {
          namespace,
          key,
          expected: crate::StoreExpectation::Absent,
          value: crate::StoreValue::new(Arc::from(second.encode().unwrap())),
        }],
      )
      .unwrap();

    assert!(matches!(
      store.commit(tx_first).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));
    // The loser of the race fails closed on its stale exact-version
    // expectation with a typed conflict; the register holds exactly one
    // whole winner.
    assert!(matches!(
      store.commit(tx_second).await.unwrap(),
      crate::CommitOutcome::Conflict
    ));
    let stored = read_record_ctx(&store, &name()).await.unwrap().unwrap();
    assert!(stored.digest() == first.digest() || stored.digest() == second.digest());
  }

  /// Both real backends preserve the exact logical tuple version of a
  /// stored record across a reopen — JSON and redb return the identical
  /// signed record, never a normalized or truncated form.
  #[cfg(any(all(feature = "json", unix), feature = "redb"))]
  async fn backend_preserves_the_exact_logical_version(factory: Arc<dyn StorageFactory>) {
    let record = put(7_000, "file:///versioned");
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    match commit_record_ctx(&store, &SystemEntropy, &record)
      .await
      .unwrap()
    {
      ResourceCommitOutcome::Installed(_) => {}
      _ => panic!("a fresh register must install the record"),
    }
    let stored = read_record_ctx(&store, &name()).await.unwrap().unwrap();
    assert_eq!(stored, record);
    drop(store);

    // Reopen: the exact logical version survives restart byte-for-byte.
    let reopened = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    let restored = read_record_ctx(&reopened, &name()).await.unwrap().unwrap();
    assert_eq!(restored, record);
    let version = crate::ResourceVersion::from_record(&restored);
    assert_eq!(version.timestamp(), crate::time::from_millis(7_000));
    assert!(!version.is_removal());
    assert_eq!(version.digest(), record.digest());
  }

  // Windows JSON cannot satisfy the metadata open requirements (no durable
  // directory barrier); the JSON arm is therefore unix-only.
  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn json_backend_preserves_the_exact_logical_version() {
    let directory = tempfile::tempdir().unwrap();
    let factory: Arc<dyn StorageFactory> = Arc::new(crate::storage::json::JsonStoreFactory::new(
      directory.path().to_path_buf(),
    ));
    backend_preserves_the_exact_logical_version(factory).await;
  }

  #[cfg(feature = "redb")]
  #[tokio::test]
  async fn redb_backend_preserves_the_exact_logical_version() {
    let directory = tempfile::tempdir().unwrap();
    let factory: Arc<dyn StorageFactory> = Arc::new(crate::storage::redb::RedbStoreFactory::new(
      directory.path().join("store.redb"),
    ));
    backend_preserves_the_exact_logical_version(factory).await;
  }
}
