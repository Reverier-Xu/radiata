//! Shared test helpers for the JSON adapter test lanes.

use std::{
  fs,
  path::{Path, PathBuf},
  sync::Arc,
};

use tempfile::TempDir;

use super::JsonStoreFactory;
#[cfg(unix)]
use super::document::GenerationDocument;
#[cfg(unix)]
use crate::{CommitOutcome, CommitReceipt, StoreRequirements, provider::Storage};
use crate::{
  StoreExpectation, StoreOperation, StoreRevision, StoreTransaction, provider::StorageFactory,
};

pub(crate) fn tempdir() -> TempDir {
  tempfile::tempdir().unwrap()
}

pub(crate) fn factory(dir: &TempDir) -> Arc<dyn StorageFactory> {
  Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()))
}

#[cfg(unix)]
pub(crate) fn limited_factory(
  dir: &TempDir, generations: u64, bytes: u64,
) -> Arc<dyn StorageFactory> {
  Arc::new(JsonStoreFactory::with_limits(
    dir.path().to_path_buf(),
    generations,
    bytes,
  ))
}

pub(crate) use super::super::test_util::{key, namespace, transaction_id, value};

pub(crate) fn put_transaction(
  index: u64, base: StoreRevision, entries: &[(&str, &[u8])],
) -> StoreTransaction {
  let namespace = namespace("one");
  let operations = entries
    .iter()
    .map(|(suffix, value_bytes)| StoreOperation::Put {
      namespace: namespace.clone(),
      key: key(format!("key-{suffix}").as_bytes()),
      expected: StoreExpectation::Absent,
      value: value(value_bytes),
    })
    .collect();
  StoreTransaction::new(transaction_id(index), base, operations).unwrap()
}

#[cfg(unix)]
pub(crate) async fn committed(
  storage: &dyn Storage, transaction: StoreTransaction,
) -> CommitReceipt {
  match storage.commit(transaction).await.unwrap() {
    CommitOutcome::Committed(receipt) => receipt,
    other => panic!("expected committed, got {other:?}"),
  }
}

#[cfg(unix)]
pub(crate) async fn open(factory: &Arc<dyn StorageFactory>) -> Box<dyn Storage> {
  factory.open(StoreRequirements::metadata()).await.unwrap()
}

#[cfg(unix)]
pub(crate) async fn head_revision(storage: &dyn Storage) -> StoreRevision {
  storage.snapshot().await.unwrap().revision().clone()
}

pub(crate) fn generation_files(dir: &Path) -> Vec<PathBuf> {
  let mut files: Vec<PathBuf> = fs::read_dir(dir)
    .unwrap()
    .filter_map(|entry| {
      let path = entry.unwrap().path();
      let name = path.file_name()?.to_str()?.to_owned();
      (name.starts_with("gen-") && name.ends_with(".json")).then_some(path)
    })
    .collect();
  files.sort();
  files
}

#[cfg(unix)]
pub(crate) fn read_generation(dir: &Path, index: usize) -> (Vec<u8>, GenerationDocument) {
  let files = generation_files(dir);
  let bytes = fs::read(&files[index]).unwrap();
  let document = GenerationDocument::parse(&bytes).unwrap();
  (bytes, document)
}

pub(crate) fn temp_files(dir: &Path) -> Vec<PathBuf> {
  fs::read_dir(dir)
    .unwrap()
    .filter_map(|entry| {
      let path = entry.unwrap().path();
      let name = path.file_name()?.to_str()?.to_owned();
      name.starts_with("tmp-").then_some(path)
    })
    .collect()
}
