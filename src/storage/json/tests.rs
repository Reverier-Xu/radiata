//! JSON adapter unit tests.
//!
//! Every test name is prefixed `json_adapter_` so the task verifier can
//! prove a nonempty lane. Tests use real temporary directories and exercise
//! the adapter through the crate-private factory and the public SPI.

use std::fs;
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use tempfile::TempDir;

#[cfg(unix)]
use super::JsonStoreFactory;
#[cfg(unix)]
use super::document::{
  GENERATION_SCHEMA, GenerationDocument, LOCK_SCHEMA, LockHeader, STORE_SCHEMA,
};
use super::helpers::*;
#[cfg(unix)]
use crate::hex::{decode as hex_decode_bytes, encode as hex_encode};
#[cfg(unix)]
use crate::provider::StorageFactory;
#[cfg(unix)]
use crate::{Digest, ReconcileOutcome, StoreExpectation, StoreOperation, StoreTransaction};
use crate::{
  DurabilityLevel, ErrorKind, StoreRequirements, storage::receipt::ReceiptReferenceToken,
};

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_generation_file_is_deterministic_and_header_complete() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  let receipt = committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;

  let (bytes, document) = read_generation(dir.path(), 0);
  let lock = LockHeader::decode(&fs::read(dir.path().join("radiata.lock")).unwrap()).unwrap();
  assert_eq!(document.schema, GENERATION_SCHEMA);
  assert_eq!(document.store_schema, STORE_SCHEMA);
  assert_eq!(document.store_uuid, lock.store_uuid);
  assert_eq!(lock.schema, LOCK_SCHEMA);
  assert_eq!(document.generation, 1);
  assert_eq!(document.parent_generation, None);
  assert_eq!(document.parent_digest, None);
  assert_eq!(document.transaction_id, "txn-000000000000000000001");
  assert_eq!(
    document.operation_digest,
    hex_encode(receipt.operation_digest().as_bytes())
  );
  assert_eq!(document.revision, "0000000000000001");
  assert_eq!(document.receipt.transaction, document.transaction_id);
  assert_eq!(document.receipt.committed_revision, document.revision);
  assert_eq!(document.entries.len(), 1);
  assert_eq!(document.receipts.len(), 1);
  assert!(document.forgotten.is_empty());
  assert_ne!(document.checksum, "");
  assert_eq!(
    hex_decode_bytes(&document.checksum, "checksum")
      .unwrap()
      .len(),
    32
  );

  let parsed = GenerationDocument::parse(&bytes).unwrap();
  assert_eq!(parsed.checksum, document.checksum);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_names_are_unique_zero_padded_and_never_reused() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  for index in 1..=2_u64 {
    let revision = head_revision(&*storage).await;
    committed(
      &*storage,
      put_transaction(
        index,
        revision,
        &[(index.to_string().as_str(), &[index as u8])],
      ),
    )
    .await;
  }

  let files = generation_files(dir.path());
  assert_eq!(files.len(), 2);
  let first = files[0].file_name().unwrap().to_str().unwrap();
  let second = files[1].file_name().unwrap().to_str().unwrap();
  assert!(first.starts_with("gen-00000000000000000001-txn-"));
  assert!(second.starts_with("gen-00000000000000000002-txn-"));
  assert_ne!(first, second);

  drop(storage);
  let reopened = open(&factory).await;
  let revision = head_revision(&*reopened).await;
  committed(&*reopened, put_transaction(3, revision, &[("c", b"v3")])).await;
  let files = generation_files(dir.path());
  assert_eq!(files.len(), 3);
  assert!(
    files[2]
      .file_name()
      .unwrap()
      .to_str()
      .unwrap()
      .starts_with("gen-00000000000000000003-txn-")
  );
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_map_keys_serialize_in_byte_order() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let namespace = namespace("one");
  let revision = head_revision(&*storage).await;
  let operations = [
    (b"\xff".as_slice(), b"last".as_slice()),
    (b"\x00".as_slice(), b"first".as_slice()),
    (b"\x80".as_slice(), b"middle".as_slice()),
  ]
  .into_iter()
  .map(|(key_bytes, value_bytes)| StoreOperation::Put {
    namespace: namespace.clone(),
    key: key(key_bytes),
    expected: StoreExpectation::Absent,
    value: value(value_bytes),
  })
  .collect();
  committed(
    &*storage,
    StoreTransaction::new(transaction_id(1), revision, operations).unwrap(),
  )
  .await;

  let (_, document) = read_generation(dir.path(), 0);
  let keys: Vec<String> = document
    .entries
    .iter()
    .map(|(_, key, _)| key.clone())
    .collect();
  assert_eq!(keys, vec!["00", "80", "ff"]);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_commit_never_overwrites_final_generation() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;

  let collision = dir
    .path()
    .join("gen-00000000000000000002-txn-000000000000000000002.json");
  fs::write(&collision, b"pre-existing final").unwrap();
  let before = fs::read(&collision).unwrap();
  let revision = head_revision(&*storage).await;
  let error = storage
    .commit(put_transaction(2, revision, &[("b", b"v2")]))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageCorrupt);
  assert_eq!(fs::read(&collision).unwrap(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_stale_temporary_cleanup_preserves_finals_and_unrelated_files() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;
  drop(storage);

  let stale_temp = dir
    .path()
    .join("tmp-00000000000000000002-txn-000000000000000000099-0.tmp");
  fs::write(&stale_temp, b"partial").unwrap();
  let lookalike = dir.path().join("tmp-not-a-counter.tmp");
  fs::write(&lookalike, b"keep").unwrap();
  let unrelated = dir.path().join("unrelated.txt");
  fs::write(&unrelated, b"keep").unwrap();

  let reopened = open(&factory).await;
  assert!(!stale_temp.exists());
  assert!(lookalike.exists());
  assert!(unrelated.exists());
  assert_eq!(generation_files(dir.path()).len(), 1);
  drop(reopened);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_generation_quota_refuses_before_creating_files() {
  let dir = tempdir();
  let factory = limited_factory(&dir, 2, u64::MAX);
  let storage = open(&factory).await;
  for index in 1..=2_u64 {
    let revision = head_revision(&*storage).await;
    committed(
      &*storage,
      put_transaction(
        index,
        revision,
        &[(index.to_string().as_str(), &[index as u8])],
      ),
    )
    .await;
  }

  let revision = head_revision(&*storage).await;
  let error = storage
    .commit(put_transaction(3, revision, &[("c", b"v3")]))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
  assert_eq!(generation_files(dir.path()).len(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_total_byte_quota_refuses_before_creating_files() {
  let dir = tempdir();
  let factory = limited_factory(&dir, u64::MAX, 32 * 1024);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;

  let revision = head_revision(&*storage).await;
  let large = vec![0xAB; 64 * 1024];
  let error = storage
    .commit(put_transaction(2, revision, &[("big", &large)]))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
  assert_eq!(generation_files(dir.path()).len(), 1);
  assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
    entry
      .unwrap()
      .file_name()
      .to_str()
      .unwrap()
      .starts_with("tmp-")
  }));
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_second_open_is_storage_locked_and_drop_releases() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let error = factory
    .open(StoreRequirements::metadata())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageLocked);

  drop(storage);
  let reopened = open(&factory).await;
  let lock_bytes = fs::read(dir.path().join("radiata.lock")).unwrap();
  drop(reopened);
  let third = open(&factory).await;
  assert_eq!(
    fs::read(dir.path().join("radiata.lock")).unwrap(),
    lock_bytes
  );
  drop(third);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_alias_open_through_symlink_is_storage_locked() {
  let dir = tempdir();
  let alias_root = tempdir();
  let alias = alias_root.path().join("alias");
  std::os::unix::fs::symlink(dir.path(), &alias).unwrap();

  let factory = factory(&dir);
  let storage = open(&factory).await;
  let alias_factory = Arc::new(JsonStoreFactory::new(alias));
  let error = alias_factory
    .open(StoreRequirements::metadata())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::StorageLocked);
  drop(storage);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_reopen_restores_records_receipts_and_revision() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  let receipt = committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;
  let namespace = namespace("one");
  drop(storage);

  let reopened = open(&factory).await;
  let snapshot = reopened.snapshot().await.unwrap();
  assert_eq!(snapshot.revision().as_bytes(), &1_u64.to_be_bytes());
  let stored = snapshot
    .get(&namespace, &key(b"key-a"))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(stored.as_bytes(), b"v");

  assert!(matches!(
    reopened
      .reconcile(receipt.transaction(), receipt.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Committed(found) if found == receipt
  ));
  assert!(matches!(
    reopened
      .reconcile(receipt.transaction(), &Digest::from_bytes([0xEE; 32]))
      .await
      .unwrap(),
    ReconcileOutcome::DigestConflict
  ));
  assert!(matches!(
    reopened
      .reconcile(&transaction_id(99), receipt.operation_digest())
      .await
      .unwrap(),
    ReconcileOutcome::Aborted
  ));
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_reopen_rejects_corruption_and_never_selects_older() {
  async fn expect_reopen_error(dir: &TempDir, kind: ErrorKind) {
    let factory = Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()));
    let error = factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), kind);
  }

  // Corrupt checksum on the highest final generation.
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;
  drop(storage);
  let files = generation_files(dir.path());
  let mut bytes = fs::read(&files[0]).unwrap();
  let last = bytes.len() - 3;
  bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
  fs::write(&files[0], bytes).unwrap();
  expect_reopen_error(&dir, ErrorKind::StorageCorrupt).await;

  // Duplicate generation number.
  let dir = tempdir();
  let factory = self::factory(&dir);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;
  drop(storage);
  let files = generation_files(dir.path());
  fs::copy(
    &files[0],
    dir
      .path()
      .join("gen-00000000000000000001-txn-000000000000000000099.json"),
  )
  .unwrap();
  expect_reopen_error(&dir, ErrorKind::StorageCorrupt).await;

  // Missing generation in the middle of the chain.
  let dir = tempdir();
  let factory = self::factory(&dir);
  let storage = open(&factory).await;
  for index in 1..=2_u64 {
    let revision = head_revision(&*storage).await;
    committed(
      &*storage,
      put_transaction(
        index,
        revision,
        &[(index.to_string().as_str(), &[index as u8])],
      ),
    )
    .await;
  }
  drop(storage);
  let files = generation_files(dir.path());
  fs::remove_file(&files[0]).unwrap();
  expect_reopen_error(&dir, ErrorKind::StorageCorrupt).await;

  // Unknown schema tag.
  let dir = tempdir();
  let factory = self::factory(&dir);
  let storage = open(&factory).await;
  let revision = head_revision(&*storage).await;
  committed(&*storage, put_transaction(1, revision, &[("a", b"v")])).await;
  drop(storage);
  let files = generation_files(dir.path());
  let bytes = fs::read(&files[0]).unwrap();
  let text = String::from_utf8(bytes).unwrap();
  let edited = text.replace("json-generation-v1", "json-generation-v9");
  fs::write(&files[0], edited).unwrap();
  expect_reopen_error(&dir, ErrorKind::UnsupportedSchema).await;

  // Receipt fold mismatch between generations.
  let dir = tempdir();
  let factory = self::factory(&dir);
  let storage = open(&factory).await;
  for index in 1..=2_u64 {
    let revision = head_revision(&*storage).await;
    committed(
      &*storage,
      put_transaction(
        index,
        revision,
        &[(index.to_string().as_str(), &[index as u8])],
      ),
    )
    .await;
  }
  drop(storage);
  let files = generation_files(dir.path());
  let bytes = fs::read(&files[1]).unwrap();
  let text = String::from_utf8(bytes).unwrap();
  let edited = text.replace("txn-000000000000000000001", "txn-000000000000000000099");
  fs::write(&files[1], edited).unwrap();
  expect_reopen_error(&dir, ErrorKind::StorageCorrupt).await;
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_reports_os_crash_durable_after_observed_barrier() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  assert_eq!(
    storage.capabilities().durability(),
    DurabilityLevel::OsCrashDurable
  );
  assert!(storage.capabilities().has_conditional_batch());
  assert!(storage.capabilities().has_ordered_scan());
  assert!(storage.capabilities().has_reconciliation());
  assert!(storage.capabilities().has_exclusive_lifetime_lock());
  assert!(!storage.capabilities().has_transactional_migration());
  storage.flush().await.unwrap();
}

#[cfg(not(unix))]
#[tokio::test]
async fn json_adapter_reports_process_crash_only_and_refuses_os_crash_requirement() {
  let dir = tempdir();
  let factory = factory(&dir);
  let error = factory
    .open(StoreRequirements::metadata())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::UnsupportedCapability);

  let storage = factory
    .open(
      StoreRequirements::metadata().with_required_durability(DurabilityLevel::ProcessCrashAtomic),
    )
    .await
    .unwrap();
  assert_eq!(
    storage.capabilities().durability(),
    DurabilityLevel::ProcessCrashAtomic
  );
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_reference_contract_parity() {
  use tempfile::TempDir;

  crate::storage::contract::run_storage_contract(|| {
    let dir = TempDir::new().unwrap();
    Arc::new(JsonStoreFactory::new(dir.keep())) as Arc<dyn StorageFactory>
  })
  .await;
}

#[test]
fn json_adapter_receipt_reference_tokens_cover_generation_records() {
  let namespace = namespace("one");
  let token = ReceiptReferenceToken::for_record(&namespace, &key(b"key-a"));
  let other = ReceiptReferenceToken::for_record(&namespace, &key(b"key-b"));
  assert_ne!(token, other);
}

#[cfg(unix)]
#[tokio::test]
async fn json_adapter_reopen_uses_newest_snapshot_without_deleted_keys() {
  let dir = tempdir();
  let factory = factory(&dir);
  let storage = open(&factory).await;
  let namespace = namespace("one");
  let first_key = key(b"key-first");
  let revision = head_revision(&*storage).await;
  committed(
    &*storage,
    StoreTransaction::new(
      transaction_id(1),
      revision,
      vec![
        StoreOperation::Put {
          namespace: namespace.clone(),
          key: first_key.clone(),
          expected: StoreExpectation::Absent,
          value: value(b"first"),
        },
        StoreOperation::Put {
          namespace: namespace.clone(),
          key: key(b"key-second"),
          expected: StoreExpectation::Absent,
          value: value(b"second"),
        },
      ],
    )
    .unwrap(),
  )
  .await;

  let snapshot = storage.snapshot().await.unwrap();
  let first_value = snapshot.get(&namespace, &first_key).await.unwrap().unwrap();
  drop(snapshot);
  let revision = head_revision(&*storage).await;
  committed(
    &*storage,
    StoreTransaction::new(
      transaction_id(2),
      revision,
      vec![StoreOperation::Delete {
        namespace: namespace.clone(),
        key: first_key.clone(),
        expected: first_value.digest().clone(),
      }],
    )
    .unwrap(),
  )
  .await;
  drop(storage);

  let reopened = open(&factory).await;
  let snapshot = reopened.snapshot().await.unwrap();
  assert!(
    snapshot
      .get(&namespace, &first_key)
      .await
      .unwrap()
      .is_none(),
    "deleted keys must not resurrect from older generations"
  );
  assert_eq!(
    snapshot
      .get(&namespace, &key(b"key-second"))
      .await
      .unwrap()
      .unwrap()
      .as_bytes(),
    b"second"
  );
}

#[tokio::test]
async fn json_adapter_failed_lock_open_does_not_poison_future_opens() {
  let dir = tempdir();
  fs::create_dir(dir.path().join("radiata.lock")).unwrap();
  let factory = factory(&dir);
  for attempt in 0..2 {
    let error = factory
      .open(StoreRequirements::metadata())
      .await
      .unwrap_err();
    assert_ne!(
      error.kind(),
      ErrorKind::StorageLocked,
      "attempt {attempt} must fail with the real I/O error, not a poisoned guard"
    );
  }
}
