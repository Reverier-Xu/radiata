//! The metadata schema gate.
//!
//! Opening a store reads and decodes the store's schema record and
//! fails closed on a version this build does not know
//! ([`ensure_open_schema`]). An absent schema record is the implicit
//! baseline and stays absent, so opening a store writes nothing. When
//! the first metadata format change arrives, this module grows the
//! explicit upgrade path it needs — one registry entry plus one
//! conditional transaction — not a new engine.

use std::sync::Arc;

use crate::{
  Error, Result, StoreKey, StoreNamespace, StoreValue, provider::Storage,
  storage::families::SCHEMA_NAMESPACE,
};

pub(crate) const BASE_RECORD_KIND: u8 = 1;

pub(crate) fn schema_key() -> StoreKey {
  StoreKey::new(Arc::from(b"store".as_slice()))
}

pub(crate) fn schema_namespace() -> Result<StoreNamespace> {
  super::families::namespace(SCHEMA_NAMESPACE)
}

/// Encodes one canonical schema record: kind byte, tag length, tag text.
/// Test-only today: production writes no schema record, so only test
/// fixtures and the fail-closed assertions construct one.
#[cfg(test)]
pub(crate) fn encode_schema_record(kind: u8, tag: &str) -> StoreValue {
  let mut bytes = Vec::with_capacity(2 + tag.len());
  bytes.push(kind);
  bytes.push(tag.len() as u8);
  bytes.extend_from_slice(tag.as_bytes());
  StoreValue::new(Arc::from(bytes))
}

/// The canonical schema-record decoder; the open gate consumes the same
/// fail-closed path as every reader. Only the baseline record kind is
/// known: any other kind, a trailing byte, or a malformed frame fails
/// closed.
pub(crate) fn decode_schema_record(value: &StoreValue) -> Result<String> {
  let bytes = value.as_bytes();
  let (kind, rest) = bytes.split_first().ok_or_else(corrupt)?;
  let (tag_len, rest) = rest.split_first().ok_or_else(corrupt)?;
  if *kind != BASE_RECORD_KIND || rest.len() < *tag_len as usize {
    return Err(corrupt());
  }
  let (tag_bytes, tail) = rest.split_at(*tag_len as usize);
  if !tail.is_empty() {
    return Err(corrupt());
  }
  std::str::from_utf8(tag_bytes)
    .map(str::to_owned)
    .map_err(|_| corrupt())
}

fn corrupt() -> Error {
  Error::unsupported_schema("metadata schema record")
}

/// The production metadata schema version: the record format every store
/// carries. A store whose schema record names any other version fails
/// closed on open.
pub(crate) const METADATA_SCHEMA_V1: &str = "radiata.woooo.tech/schemas/v1/metadata";

/// The open-time schema gate: accept a store at the current version —
/// including the implicit baseline of an absent record — and fail closed
/// on a version this build does not know, without mutating anything.
pub(crate) async fn ensure_open_schema(storage: &dyn Storage) -> Result<()> {
  let snapshot = storage.snapshot().await?;
  let existing = snapshot
    .get(&schema_namespace()?, &schema_key())
    .await?
    .map(|value| decode_schema_record(&value))
    .transpose()?;
  drop(snapshot);
  match existing {
    // No record: the implicit baseline is current.
    None => Ok(()),
    Some(tag) if tag == METADATA_SCHEMA_V1 => Ok(()),
    Some(_) => Err(Error::unsupported_schema("metadata schema version")),
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  #[cfg(any(all(feature = "json", unix), feature = "redb"))]
  use crate::{
    StoreExpectation, StoreOperation, StoreTransaction, provider::StorageFactory,
    storage::test_util as util,
  };

  #[cfg(all(feature = "json", unix))]
  fn json_factory() -> (Option<tempfile::TempDir>, Arc<dyn StorageFactory>) {
    let dir = tempfile::tempdir().unwrap();
    (
      None,
      Arc::new(crate::storage::json::JsonStoreFactory::new(dir.keep())),
    )
  }

  #[cfg(feature = "redb")]
  fn redb_factory() -> (Option<tempfile::TempDir>, Arc<dyn StorageFactory>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    (
      Some(dir),
      Arc::new(crate::storage::redb::RedbStoreFactory::new(path)),
    )
  }

  /// One compiled storage backend under test. The backend dimension is
  /// this table alone, so a new backend is one row here rather than a new
  /// copy of every gate test; the label names the backend in every
  /// assertion message and the factory opens a fresh store for it.
  #[cfg(any(all(feature = "json", unix), feature = "redb"))]
  struct BackendCase {
    label: &'static str,
    factory: fn() -> (Option<tempfile::TempDir>, Arc<dyn StorageFactory>),
  }

  #[cfg(any(all(feature = "json", unix), feature = "redb"))]
  const BACKEND_CASES: &[BackendCase] = &[
    #[cfg(all(feature = "json", unix))]
    BackendCase {
      label: "json",
      factory: json_factory,
    },
    #[cfg(feature = "redb")]
    BackendCase {
      label: "redb",
      factory: redb_factory,
    },
  ];

  #[cfg(all(feature = "json", unix))]
  async fn read_schema(storage: &dyn Storage) -> Option<String> {
    let snapshot = storage.snapshot().await.unwrap();
    let namespace = schema_namespace().unwrap();
    let stored = snapshot.get(&namespace, &schema_key()).await.unwrap();
    stored.map(|value| decode_schema_record(&value).unwrap())
  }

  /// The open-time gate: a fresh store opens without any schema write
  /// (the absent record is the implicit baseline) and a reopen is
  /// equally quiet.
  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn metadata_open_gate_accepts_fresh_and_reopened_stores_without_writes() {
    let (_dir, factory) = json_factory();
    crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(30))
      .await
      .unwrap();
    // The first open released the store lock; the gate wrote nothing.
    let raw = factory
      .open(crate::StoreRequirements::metadata())
      .await
      .unwrap();
    ensure_open_schema(raw.as_ref()).await.unwrap();
    assert_eq!(read_schema(raw.as_ref()).await, None);
    drop(raw);
    crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(30))
      .await
      .unwrap();
  }

  /// A store whose schema record names a version this build does not
  /// know fails closed on open without mutating anything.
  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn metadata_open_rejects_a_schema_version_outside_the_chain() {
    use crate::StoreOperation;
    let (_dir, factory) = json_factory();
    // Commit a foreign schema record through the raw storage before the
    // metadata store ever opens.
    let raw = factory
      .open(crate::StoreRequirements::metadata())
      .await
      .unwrap();
    let snapshot = raw.snapshot().await.unwrap();
    let foreign = encode_schema_record(
      BASE_RECORD_KIND,
      "radiata.woooo.tech/schemas/v9/metadata-foreign",
    );
    let transaction = StoreTransaction::new(
      util::transaction_id(910),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: schema_namespace().unwrap(),
        key: schema_key(),
        expected: crate::StoreExpectation::Absent,
        value: foreign,
      }],
    )
    .unwrap();
    assert!(matches!(
      raw.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));
    drop(raw);
    let error = crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(30))
      .await
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::UnsupportedSchema);
  }

  /// The pending recovery path opens through the same gate: a store whose
  /// schema record names a version this build does not know fails closed
  /// there too, before any pending record is discovered.
  #[cfg(any(all(feature = "json", unix), feature = "redb"))]
  async fn pending_recovery_rejects_a_schema_version_outside_the_chain(case: &BackendCase) {
    let backend = case.label;
    let (_dir, factory) = (case.factory)();
    // Commit a foreign schema record through the raw storage before the
    // metadata store ever opens.
    let raw = factory
      .open(crate::StoreRequirements::metadata())
      .await
      .unwrap();
    let snapshot = raw.snapshot().await.unwrap();
    let foreign = encode_schema_record(
      BASE_RECORD_KIND,
      "radiata.woooo.tech/schemas/v9/metadata-foreign",
    );
    let transaction = StoreTransaction::new(
      util::transaction_id(911),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: schema_namespace().unwrap(),
        key: schema_key(),
        expected: StoreExpectation::Absent,
        value: foreign,
      }],
    )
    .unwrap();
    assert!(
      matches!(
        raw.commit(transaction).await.unwrap(),
        crate::CommitOutcome::Committed(_)
      ),
      "{backend}: the foreign schema record must commit"
    );
    drop(raw);
    let error = crate::storage::MetadataStore::open_pending_recovered(
      &factory,
      std::time::Duration::from_secs(30),
      "local-identity",
    )
    .await
    .unwrap_err();
    assert_eq!(
      error.kind(),
      crate::ErrorKind::UnsupportedSchema,
      "{backend}: pending recovery must reject a schema version outside the chain"
    );
  }

  #[cfg(any(all(feature = "json", unix), feature = "redb"))]
  #[tokio::test]
  async fn pending_recovery_rejects_a_schema_version_outside_the_chain_per_backend() {
    for case in BACKEND_CASES {
      pending_recovery_rejects_a_schema_version_outside_the_chain(case).await;
    }
  }

  /// The schema-record decoder fails closed on unknown kinds, trailing
  /// bytes, truncated tags, and non-UTF-8 tag text.
  #[test]
  fn schema_record_decode_fails_closed_on_malformed_frames() {
    let tag = METADATA_SCHEMA_V1;
    assert_eq!(
      decode_schema_record(&encode_schema_record(BASE_RECORD_KIND, tag)).unwrap(),
      tag
    );
    // Unknown record kinds are refused.
    for kind in [0x00_u8, 0x02, 0x03] {
      assert!(decode_schema_record(&encode_schema_record(kind, tag)).is_err());
    }
    // Truncated and trailing-byte frames are refused.
    let full = encode_schema_record(BASE_RECORD_KIND, tag)
      .as_bytes()
      .to_vec();
    for len in [0_usize, 1, 2, full.len() - 1] {
      let truncated = StoreValue::new(Arc::from(full[..len].to_vec().into_boxed_slice()));
      assert!(decode_schema_record(&truncated).is_err(), "len {len}");
    }
    let mut trailed = full.clone();
    trailed.push(0x00);
    assert!(decode_schema_record(&StoreValue::new(Arc::from(trailed.into_boxed_slice()))).is_err());
    // Non-UTF-8 tag text is refused.
    let mut binary = full;
    let tag_start = 2;
    binary[tag_start] = 0xFF;
    assert!(decode_schema_record(&StoreValue::new(Arc::from(binary.into_boxed_slice()))).is_err());
  }
}
