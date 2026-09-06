#![cfg(all(test, unix, feature = "json", feature = "redb"))]
//! Mixed-backend metadata E2E (T-G08-05, E2E-07).
//!
//! One metadata side runs on the JSON adapter and the other on the redb
//! adapter. The lanes prove that the same ordinary sync pages converge the
//! two backends to byte-identical logical metadata views across every
//! family, that repeated graceful restarts preserve those views exactly,
//! and that a killed restart during a cross-family seed reopens to the
//! complete old or new state atomically on each backend.

use std::sync::Arc;

use tempfile::TempDir;

use crate::{
  LabelKey, LabelSet, LabelValue, NodeId,
  api::SystemEntropy,
  membership::{NodeDescriptorV1, page as member_page, store as descriptor_store},
  provider::StorageFactory,
  resource::{ResourceName, ResourceRecordV1, page as resource_page, store as resource_store},
  storage::{MetadataStore, families::metadata_families},
};

const RECEIPT_RETENTION: std::time::Duration = std::time::Duration::from_secs(10);

fn json_factory(directory: &std::path::Path) -> Arc<dyn StorageFactory> {
  Arc::new(crate::storage::json::JsonStoreFactory::new(
    directory.to_path_buf(),
  ))
}

#[cfg(feature = "redb")]
fn redb_factory(path: &std::path::Path) -> Arc<dyn StorageFactory> {
  Arc::new(crate::storage::redb::RedbStoreFactory::new(
    path.to_path_buf(),
  ))
}

async fn open_metadata(factory: &Arc<dyn StorageFactory>) -> MetadataStore {
  MetadataStore::open(factory, RECEIPT_RETENTION)
    .await
    .unwrap()
}

/// The logical families: every domain except the storage-internal receipt
/// bookkeeping, whose entries carry per-store transaction identifiers.
fn logical_families() -> Vec<crate::storage::families::MetadataFamily> {
  metadata_families()
    .into_iter()
    .filter(|family| family.domain() != crate::storage::families::MetadataDomain::Receipt)
    .collect()
}

fn writer(seed: u8) -> NodeId {
  NodeId::parse(&format!("node_{seed:021}")).unwrap()
}

fn descriptor(node: &NodeId, revision: u64, seed: [u8; 32]) -> NodeDescriptorV1 {
  let key = crate::PublicKey::from_bytes(
    ed25519_dalek::SigningKey::from_bytes(&seed)
      .verifying_key()
      .to_bytes(),
  );
  NodeDescriptorV1::new(
    node.clone(),
    key,
    vec![crate::Endpoint::parse("wss://127.0.0.1:64000").unwrap()],
    revision,
    false,
    1,
  )
}

fn resource_record(
  seed_index: u8, writer: &NodeId, uri: &str, timestamp_millis: u64, seed: [u8; 32],
) -> ResourceRecordV1 {
  ResourceRecordV1::sign(
    ResourceName::parse(&format!("radiata.woooo.tech/resources/mixed-{seed_index}")).unwrap(),
    LabelValue::parse("document").unwrap(),
    crate::ResourceUri::parse(uri).unwrap(),
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/lane").unwrap(),
        LabelValue::parse("mixed").unwrap(),
      )
      .unwrap(),
    timestamp_millis,
    writer.clone(),
    0,
    false,
    &ed25519_dalek::SigningKey::from_bytes(&seed),
  )
  .unwrap()
}

/// Seeds one record into every caller-writable metadata family through
/// one cross-family transaction. Excluded: the reserved receipt-internal
/// bookkeeping namespace, the pending-transaction journal written by the
/// commit machinery itself, and the two record namespaces whose pages
/// decode real record encodings (they are exercised by the real records
/// and the convergence lanes instead).
fn seedable_family_tags() -> Vec<&'static str> {
  metadata_families()
    .iter()
    .map(crate::storage::families::MetadataFamily::namespace_tag)
    .filter(|tag| *tag != crate::storage::families::INTERNAL_NAMESPACE)
    .filter(|tag| *tag != crate::storage::families::PENDING_NAMESPACE)
    .filter(|tag| *tag != crate::storage::families::RESOURCE_RECORD_NAMESPACE)
    .filter(|tag| *tag != crate::storage::families::NODE_DESCRIPTOR_NAMESPACE)
    .collect()
}

fn seedable_families() -> Vec<crate::storage::families::MetadataFamily> {
  metadata_families()
    .into_iter()
    .filter(|family| seedable_family_tags().contains(&family.namespace_tag()))
    .collect()
}

async fn seed_local_families(store: &MetadataStore, marker: &[u8]) {
  let snapshot = store.snapshot().await.unwrap();
  let operations: Vec<crate::StoreOperation> = seedable_families()
    .into_iter()
    .map(|family| crate::StoreOperation::Put {
      namespace: family.namespace().unwrap(),
      key: crate::StoreKey::new(Arc::from(b"mixed".as_slice())),
      expected: crate::StoreExpectation::Absent,
      value: crate::StoreValue::new(Arc::from(marker)),
    })
    .collect();
  let prepared = store
    .prepare_transaction(
      crate::storage::test_util::transaction_id(877),
      snapshot.revision().clone(),
      operations,
    )
    .unwrap();
  match store.commit(prepared).await.unwrap() {
    crate::CommitOutcome::Committed(_) => {}
    outcome => panic!("cross-family seed must commit, got {outcome:?}"),
  }
}

/// The logical metadata view: every family scanned in order, reduced to
/// (namespace, key, value) triples.
async fn logical_view(store: &MetadataStore) -> Vec<(String, Vec<u8>, Vec<u8>)> {
  logical_view_over(store, &metadata_families()).await
}

/// The view over an explicit family set. Internal storage families carry
/// backend-neutral content only when the transaction sequences are
/// identical, so cross-backend comparisons use the logical families.
async fn logical_view_over(
  store: &MetadataStore, families: &[crate::storage::families::MetadataFamily],
) -> Vec<(String, Vec<u8>, Vec<u8>)> {
  let snapshot = store.snapshot().await.unwrap();
  let mut view = Vec::new();
  for family in families {
    let namespace = family.namespace().unwrap();
    let mut scan = snapshot.scan(&namespace, &[]).await.unwrap();
    while let Some(entry) = scan.next().await.unwrap() {
      view.push((
        namespace.as_str().to_owned(),
        entry.key().as_bytes().to_vec(),
        entry.value().as_bytes().to_vec(),
      ));
    }
  }
  view.sort();
  view
}

async fn put_descriptor(store: &MetadataStore, descriptor: &NodeDescriptorV1) {
  descriptor_store::store_descriptor_ctx(store, &SystemEntropy, descriptor)
    .await
    .unwrap();
}

async fn put_resource(store: &MetadataStore, record: &ResourceRecordV1) {
  match resource_store::commit_record_ctx(store, &SystemEntropy, record)
    .await
    .unwrap()
  {
    resource_store::ResourceCommitOutcome::Installed(_) => {}
    other => panic!("seed resource must install, got {other:?}"),
  }
}

/// One full bidirectional convergence pass over the ordinary sync pages.
async fn converge(sides: [&MetadataStore; 2]) {
  loop {
    let mut applied = 0;
    for index in 0..2 {
      let emitter = sides[index];
      let receiver = sides[1 - index];
      let mut cursor: Option<Vec<u8>> = None;
      loop {
        let page = resource_page::sync::emit_page_ctx(
          emitter,
          cursor.as_deref(),
          resource_page::DEFAULT_RESOURCE_PAGE_LIMIT,
        )
        .await
        .unwrap();
        let done = page.cursor().is_none();
        cursor = page.cursor().map(|value| value.to_vec());
        applied += resource_page::sync::apply_page_ctx(receiver, &SystemEntropy, &page)
          .await
          .unwrap();
        if done {
          break;
        }
      }
      let mut cursor: Option<Vec<u8>> = None;
      loop {
        let page = member_page::sync::emit_page_ctx(emitter, cursor.as_deref(), 16)
          .await
          .unwrap();
        let done = page.cursor().is_none();
        cursor = page.cursor().map(|value| value.to_vec());
        applied += member_page::sync::apply_page_ctx(receiver, &SystemEntropy, &page)
          .await
          .unwrap()
          .len();
        if done {
          break;
        }
      }
    }
    if applied == 0 {
      break;
    }
  }
}

#[cfg(all(feature = "json", feature = "redb"))]
mod cross_backend {
  use super::*;

  /// E2E-07 / SC-G08-P0-13: a JSON side and a redb side converge through
  /// the ordinary sync pages to byte-identical logical metadata views.
  #[tokio::test]
  async fn mixed_storage_backends_converge_to_byte_identical_views() {
    let json_dir = TempDir::new().unwrap();
    let redb_dir = TempDir::new().unwrap();
    let json = json_factory(json_dir.path());
    let redb = redb_factory(&redb_dir.path().join("store.redb"));
    let side_a = open_metadata(&json).await;
    let side_b = open_metadata(&redb).await;

    // Identical local-family markers on both sides, then overlapping
    // membership and resources that only the sync pages can heal.
    seed_local_families(&side_a, b"shared-marker").await;
    seed_local_families(&side_b, b"shared-marker").await;
    let node = writer(1);
    let seed = [7_u8; 32];
    put_descriptor(&side_a, &descriptor(&node, 1, seed)).await;
    put_descriptor(&side_b, &descriptor(&writer(2), 1, [9_u8; 32])).await;
    put_resource(
      &side_a,
      &resource_record(1, &writer(1), "u://a1", 2_000, seed),
    )
    .await;
    put_resource(
      &side_b,
      &resource_record(2, &writer(2), "u://b1", 3_000, [9_u8; 32]),
    )
    .await;

    converge([&side_a, &side_b]).await;

    let view_a = logical_view_over(&side_a, &logical_families()).await;
    let view_b = logical_view_over(&side_b, &logical_families()).await;
    assert_eq!(view_a, view_b, "backends must converge byte-identically");
    assert!(
      view_a
        .iter()
        .any(|(namespace, ..)| namespace.contains("node-descriptor"))
    );
    assert!(
      view_a
        .iter()
        .any(|(namespace, ..)| namespace.contains("resource-record"))
    );
  }

  /// SC-G08-P0-14: repeated graceful restarts preserve the converged
  /// logical view exactly on both backends.
  #[tokio::test]
  async fn mixed_storage_graceful_restarts_preserve_identical_views() {
    let json_dir = TempDir::new().unwrap();
    let redb_dir = TempDir::new().unwrap();
    let json_path = json_dir.path().to_path_buf();
    let redb_path = redb_dir.path().join("store.redb");
    let side_a = open_metadata(&json_factory(&json_path)).await;
    let side_b = open_metadata(&redb_factory(&redb_path)).await;
    seed_local_families(&side_a, b"restart-marker").await;
    seed_local_families(&side_b, b"restart-marker").await;
    converge([&side_a, &side_b]).await;
    let converged = logical_view_over(&side_a, &logical_families()).await;
    assert_eq!(
      converged,
      logical_view_over(&side_b, &logical_families()).await
    );
    drop(side_a);
    drop(side_b);

    for _ in 0..3 {
      let side_a = open_metadata(&json_factory(&json_path)).await;
      let side_b = open_metadata(&redb_factory(&redb_path)).await;
      assert_eq!(
        logical_view_over(&side_a, &logical_families()).await,
        converged
      );
      assert_eq!(
        logical_view_over(&side_b, &logical_families()).await,
        converged
      );
      drop(side_a);
      drop(side_b);
    }
  }
}

/// The complete old-or-new assertion for one killed restart: the reopened
/// full view is either exactly empty (the transaction never committed) or
/// exactly the view of an identical uninterrupted run (the transaction
/// committed), never anything in between.
fn assert_view_old_or_new(
  view: &[(String, Vec<u8>, Vec<u8>)], old_view: &[(String, Vec<u8>, Vec<u8>)],
  new_view: &[(String, Vec<u8>, Vec<u8>)], old: bool, point: u8,
) {
  if old {
    assert_eq!(view, old_view, "point {point} must reopen to the old state");
  } else {
    assert_eq!(
      view, new_view,
      "point {point} must reopen to the complete new state"
    );
  }
}

mod killed_restart_json {
  use super::*;

  const CRASH_DIR_ENV: &str = "RADIATA_MIXED_JSON_CRASH_DIR";
  const CRASH_POINT_ENV: &str = "RADIATA_MIXED_JSON_CRASH_POINT";
  const FIRST_COMMITTED_POINT: u8 = 8;
  const LAST_POINT: u8 = 13;

  #[ignore = "mixed-storage crash-matrix child process entry point"]
  #[tokio::test]
  async fn mixed_storage_json_crash_child_entry() {
    let directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
    let point: u8 = std::env::var(CRASH_POINT_ENV)
      .expect("crash point")
      .parse()
      .expect("numeric crash point");
    crate::storage::json::select_crash_point(point);
    let factory = json_factory(directory.as_ref());
    let store = open_metadata(&factory).await;
    seed_local_families(&store, b"killed-marker").await;
  }

  #[tokio::test]
  async fn mixed_storage_json_killed_restart_reopens_old_or_new_atomically() {
    let empty_dir = TempDir::new().unwrap();
    let json_empty = json_factory(empty_dir.path());
    let old_view = logical_view(&open_metadata(&json_empty).await).await;
    let committed_dir = TempDir::new().unwrap();
    let json_committed = json_factory(committed_dir.path());
    let committed = open_metadata(&json_committed).await;
    seed_local_families(&committed, b"killed-marker").await;
    let new_view = logical_view(&committed).await;
    drop(committed);

    for point in 1..=LAST_POINT {
      let dir = TempDir::new().unwrap();
      crate::storage::test_util::run_crash_child(
        "storage::mixed_e2e::killed_restart_json::mixed_storage_json_crash_child_entry",
        CRASH_DIR_ENV,
        CRASH_POINT_ENV,
        dir.path(),
        point,
        "mixed json",
        &[],
      );
      let store = open_metadata(&json_factory(dir.path())).await;
      let view = logical_view(&store).await;
      assert_view_old_or_new(
        &view,
        &old_view,
        &new_view,
        point < FIRST_COMMITTED_POINT,
        point,
      );
    }
  }
}

#[cfg(feature = "redb")]
mod killed_restart_redb {
  use super::*;

  const CRASH_DIR_ENV: &str = "RADIATA_MIXED_REDB_CRASH_DIR";
  const CRASH_POINT_ENV: &str = "RADIATA_MIXED_REDB_CRASH_POINT";
  const FIRST_COMMITTED_POINT: u8 = 6;
  const LAST_POINT: u8 = 6;

  #[ignore = "mixed-storage crash-matrix child process entry point"]
  #[test]
  fn mixed_storage_redb_crash_child_entry() {
    let directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
    let point: u8 = std::env::var(CRASH_POINT_ENV)
      .expect("crash point")
      .parse()
      .expect("numeric crash point");
    crate::storage::redb::select_crash_point(point);
    let factory = redb_factory(directory.as_ref());
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    runtime.block_on(async move {
      let store = open_metadata(&factory).await;
      seed_local_families(&store, b"killed-marker").await;
    });
  }

  #[tokio::test]
  async fn mixed_storage_redb_killed_restart_reopens_old_or_new_atomically() {
    let empty_dir = TempDir::new().unwrap();
    let redb_empty = redb_factory(&empty_dir.path().join("a.redb"));
    let old_view = logical_view(&open_metadata(&redb_empty).await).await;
    let committed_dir = TempDir::new().unwrap();
    let redb_committed = redb_factory(&committed_dir.path().join("b.redb"));
    let committed = open_metadata(&redb_committed).await;
    seed_local_families(&committed, b"killed-marker").await;
    let new_view = logical_view(&committed).await;
    drop(committed);

    for point in 1..=LAST_POINT {
      let dir = TempDir::new().unwrap();
      let path = dir.path().join("store.redb");
      crate::storage::test_util::run_crash_child(
        "storage::mixed_e2e::killed_restart_redb::mixed_storage_redb_crash_child_entry",
        CRASH_DIR_ENV,
        CRASH_POINT_ENV,
        &path,
        point,
        "mixed redb",
        &[],
      );
      let store = open_metadata(&redb_factory(&path)).await;
      let view = logical_view(&store).await;
      assert_view_old_or_new(
        &view,
        &old_view,
        &new_view,
        point < FIRST_COMMITTED_POINT,
        point,
      );
    }
  }
}
