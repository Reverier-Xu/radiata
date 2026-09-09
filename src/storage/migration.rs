//! Transactional metadata schema migrations.
//!
//! A store carries one schema metadata family record naming its current
//! logical schema version. [`MigrationRegistry`] owns an explicit, immutable
//! chain of migration edges from the base version to the current one;
//! construction rejects duplicate edges, cycles, ambiguous paths, unknown
//! endpoints, missing decoders, implicit ordering, and downgrade paths
//! before any metadata transaction opens.
//!
//! Every edge is applied as exactly one conditional transaction that
//! transforms the records and rewrites the schema record together, so an
//! interrupted migration reopens at the complete old or new schema. The
//! deterministic per-edge transaction identifier makes a replay an
//! idempotent no-op only for the exact migration tag and implementation
//! digest, and readers whose registry does not contain the store's version
//! fail closed without mutating anything.

use std::sync::Arc;

use sha2::{Digest as ShaDigest, Sha256};

use crate::{
  BoxFuture, CommitOutcome, Digest, Error, Result, StoreExpectation, StoreKey, StoreNamespace,
  StoreOperation, StoreTransaction, StoreValue, TransactionId,
  identity::id::encode_base62_suffix,
  provider::{Storage, StoreSnapshot},
  storage::families::SCHEMA_NAMESPACE,
};

pub(crate) const BASE_RECORD_KIND: u8 = 1;
const EDGE_RECORD_KIND: u8 = 2;

pub(crate) fn schema_key() -> StoreKey {
  StoreKey::new(Arc::from(b"store".as_slice()))
}

pub(crate) fn schema_namespace() -> Result<StoreNamespace> {
  Ok(StoreNamespace::new(crate::QualifiedTag::parse(
    SCHEMA_NAMESPACE,
  )?))
}

/// Encodes one canonical migration schema-record variant; the migration
/// engine and the compatibility freeze reader share this encoder.
pub(crate) fn encode_schema_record(kind: u8, tag: &str, digest: Option<&Digest>) -> StoreValue {
  let mut bytes = Vec::with_capacity(2 + tag.len() + 32);
  bytes.push(kind);
  bytes.push(tag.len() as u8);
  bytes.extend_from_slice(tag.as_bytes());
  if let Some(digest) = digest {
    bytes.extend_from_slice(digest.as_bytes());
  }
  StoreValue::new(Arc::from(bytes))
}

/// The canonical migration schema-record decoder; the compatibility
/// freeze reader consumes the same fail-closed path as the engine.
pub(crate) fn decode_schema_record(value: &StoreValue) -> Result<(u8, String, Option<Digest>)> {
  let bytes = value.as_bytes();
  let (kind, rest) = bytes.split_first().ok_or_else(corrupt)?;
  let (tag_len, rest) = rest.split_first().ok_or_else(corrupt)?;
  if rest.len() < *tag_len as usize {
    return Err(corrupt());
  }
  let (tag_bytes, tail) = rest.split_at(*tag_len as usize);
  let tag = std::str::from_utf8(tag_bytes).map_err(|_| corrupt())?;
  match *kind {
    BASE_RECORD_KIND => {
      if !tail.is_empty() {
        return Err(corrupt());
      }
      Ok((BASE_RECORD_KIND, tag.to_owned(), None))
    }
    EDGE_RECORD_KIND => {
      let digest_bytes: [u8; 32] = tail.try_into().map_err(|_| corrupt())?;
      Ok((
        EDGE_RECORD_KIND,
        tag.to_owned(),
        Some(Digest::from_bytes(digest_bytes)),
      ))
    }
    _ => Err(corrupt()),
  }
}

fn corrupt() -> Error {
  Error::unsupported_schema("metadata schema record")
}

/// The production metadata schema baseline: the record format every
/// store carries before any migration edge exists. Stores created before
/// versioning stamp this baseline on their first versioned open.
pub(crate) const METADATA_SCHEMA_V1: &str = "radiata.woooo.tech/schemas/metadata-v1";

/// The production migration chain. Every metadata format change lands
/// here as one explicit edge, so an opened store always ends at the
/// chain target before any consumer reads or recovers it. The chain is
/// a compile-time constant, so the validation error is unreachable.
pub(crate) fn production_registry() -> Result<MigrationRegistry> {
  MigrationRegistry::new(METADATA_SCHEMA_V1, Vec::new())
}

/// The open-time schema gate: fail closed on a store whose schema
/// version this build does not know, and upgrade — stamping and walking
/// the explicit edge chain — only when the chain actually has edges to
/// apply. While the production chain is the unedgeed baseline, an absent
/// record is the baseline by definition, so opening a store writes
/// nothing; a format change turns the same gate into the upgrade path.
pub(crate) async fn ensure_open_schema(storage: &dyn Storage) -> Result<()> {
  let registry = production_registry()?;
  let snapshot = storage.snapshot().await?;
  let existing = snapshot
    .get(&schema_namespace()?, &schema_key())
    .await?
    .map(|value| decode_schema_record(&value))
    .transpose()?;
  drop(snapshot);
  match existing {
    // No record and nothing to migrate: the implicit baseline is current.
    None if registry.target() == registry.base => Ok(()),
    // A fresh store in a chain with edges, or a store behind the target:
    // stamp and walk the explicit chain inside one conditional
    // transaction per edge.
    record => {
      if let Some((kind, tag, digest)) = record {
        let known = tag == registry.base || registry.edges.iter().any(|edge| edge.to == tag);
        if !known {
          return Err(Error::unsupported_schema("metadata schema version"));
        }
        if tag == registry.target() {
          // Replay idempotence of the applied edge stays verified by
          // ensure_schema; being at the target needs no writes.
          return Ok(());
        }
        let _ = (kind, digest);
      }
      registry.ensure_schema(storage).await.map(|_| ())
    }
  }
}

/// The transform plan of one migration edge.
///
/// The transform reads the complete old-schema state from one immutable
/// snapshot and plans the record operations that turn it into the new
/// schema. The runner runs the plan against the current revision inside one
/// conditional transaction, so a concurrent writer makes the edge fail
/// closed instead of mixing schemas.
pub(crate) type MigrationTransform =
  for<'a> fn(&'a dyn StoreSnapshot) -> BoxFuture<'a, Result<Vec<StoreOperation>>>;

/// One explicit, immutable schema migration edge.
#[derive(Clone, Debug)]
pub(crate) struct MigrationEdge {
  from: &'static str,
  to: &'static str,
  tag: &'static str,
  digest: Digest,
  transform: Option<MigrationTransform>,
}

impl MigrationEdge {
  pub(crate) fn new(
    from: &'static str, to: &'static str, tag: &'static str, digest: Digest,
    transform: Option<MigrationTransform>,
  ) -> Self {
    Self {
      from,
      to,
      tag,
      digest,
      transform,
    }
  }
}

/// The validated, immutable chain of migration edges.
#[derive(Clone, Debug)]
pub(crate) struct MigrationRegistry {
  base: &'static str,
  edges: Vec<MigrationEdge>,
}

impl MigrationRegistry {
  /// Validates and freezes the edge chain.
  pub(crate) fn new(base: &'static str, edges: Vec<MigrationEdge>) -> Result<Self> {
    let mut seen_versions = vec![base];
    let mut seen_tags: Vec<&'static str> = Vec::new();
    let mut previous: Option<&MigrationEdge> = None;
    for edge in &edges {
      // Missing decoder: an edge without a transform can never be applied.
      if edge.transform.is_none() {
        return Err(Error::invalid_input("migration edge without decoder"));
      }
      // Downgrade and cycle paths: a target must always be a brand-new
      // version, never the base or any version seen earlier in the chain.
      if edge.from == edge.to || seen_versions.contains(&edge.to) {
        return Err(Error::invalid_input("migration edge downgrade or cycle"));
      }
      // Ambiguous paths and implicit ordering: exactly one edge may leave
      // each version, so the successor of a version is never chosen
      // implicitly, and every endpoint must be an explicit chain member.
      if previous.is_none() && edge.from != base {
        return Err(Error::invalid_input("migration edge unknown endpoint"));
      }
      if previous.is_some_and(|previous| previous.to != edge.from) {
        return Err(Error::invalid_input("migration edge ambiguous path"));
      }
      if seen_tags.contains(&edge.tag) {
        return Err(Error::invalid_input("migration edge duplicate tag"));
      }
      seen_versions.push(edge.to);
      seen_tags.push(edge.tag);
      previous = Some(edge);
    }
    Ok(Self { base, edges })
  }

  /// The target version this registry migrates a store to.
  pub(crate) fn target(&self) -> &'static str {
    self.edges.last().map_or(self.base, |edge| edge.to)
  }

  /// The deterministic transaction identifier of one edge: derived from
  /// the exact migration tag and implementation digest, so a replay of the
  /// same edge hits the idempotent receipt path while any other
  /// transaction cannot collide with it.
  pub(super) fn edge_transaction_id(edge: &MigrationEdge) -> Result<TransactionId> {
    TransactionId::parse(&format!(
      "txn_{}",
      encode_base62_suffix(migration_transaction_value(&[
        edge.tag.as_bytes(),
        edge.digest.as_bytes()
      ])?)?
    ))
  }

  async fn schema_record_operation(
    snapshot: &dyn StoreSnapshot, kind: u8, tag: &str, digest: Option<&Digest>,
  ) -> Result<StoreOperation> {
    let current = snapshot.get(&schema_namespace()?, &schema_key()).await?;
    Ok(StoreOperation::Put {
      namespace: schema_namespace()?,
      key: schema_key(),
      expected: current.map_or(StoreExpectation::Absent, |value| {
        StoreExpectation::Exact(value.digest().clone())
      }),
      value: encode_schema_record(kind, tag, digest),
    })
  }

  async fn stamp_base(&self, storage: &dyn Storage) -> Result<()> {
    let snapshot = storage.snapshot().await?;
    let operation =
      Self::schema_record_operation(&*snapshot, BASE_RECORD_KIND, self.base, None).await?;
    let value = migration_transaction_value(&[self.base.as_bytes()])?;
    let transaction = StoreTransaction::new(
      TransactionId::parse(&format!("txn_{}", encode_base62_suffix(value)?))?,
      snapshot.revision().clone(),
      vec![operation],
    )?;
    match storage.commit(transaction).await? {
      CommitOutcome::Committed(_) | CommitOutcome::Aborted => Ok(()),
      _ => Err(Error::conflict("metadata schema stamping")),
    }
  }

  /// Migrates the store to this registry's target version.
  ///
  /// A fresh store (no schema record) is stamped with the base version.
  /// A store whose version or implementation digest is unknown to this
  /// registry fails closed without mutation. Re-running a registry over an
  /// already-migrated store is an idempotent no-op.
  pub(crate) async fn ensure_schema(&self, storage: &dyn Storage) -> Result<SchemaOutcome> {
    let snapshot = storage.snapshot().await?;
    let existing = snapshot
      .get(&schema_namespace()?, &schema_key())
      .await?
      .map(|value| decode_schema_record(&value))
      .transpose()?;
    drop(snapshot);

    let mut start_index = 0_usize;
    if let Some((kind, tag, digest)) = existing {
      // Locate the store's version on this registry's chain. Unknown
      // versions fail closed without mutation (older or foreign reader).
      if tag == self.base {
        start_index = 0;
      } else if let Some(position) = self.edges.iter().position(|edge| edge.to == tag) {
        start_index = position + 1;
        // Replay idempotence: an already-applied edge must carry the exact
        // implementation digest, otherwise the stored schema was produced
        // by a different implementation and the reader fails closed.
        let applied = &self.edges[position];
        if kind != EDGE_RECORD_KIND || digest.as_ref() != Some(&applied.digest) {
          return Err(Error::unsupported_schema("metadata schema digest"));
        }
      } else {
        return Err(Error::unsupported_schema("metadata schema version"));
      }
    } else {
      self.stamp_base(storage).await?;
    }

    let mut migrated_edges = 0_u32;
    for edge in &self.edges[start_index..] {
      let transaction_id = Self::edge_transaction_id(edge)?;
      let snapshot = storage.snapshot().await?;
      let transform = edge.transform.ok_or_else(corrupt)?;
      let mut operations = transform(&*snapshot).await?;
      operations.push(
        Self::schema_record_operation(&*snapshot, EDGE_RECORD_KIND, edge.to, Some(&edge.digest))
          .await?,
      );
      let transaction =
        StoreTransaction::new(transaction_id, snapshot.revision().clone(), operations)?;
      match storage.commit(transaction).await? {
        CommitOutcome::Committed(_) | CommitOutcome::Aborted => migrated_edges += 1,
        CommitOutcome::Unknown { .. } => {
          return Err(Error::provider(
            crate::ProviderErrorKind::CommitUnknown,
            crate::ProviderErrorContext::StorageCommit,
          ));
        }
        CommitOutcome::Conflict => return Err(Error::conflict("metadata schema migration")),
      }
    }
    if migrated_edges == 0 {
      Ok(SchemaOutcome::Current)
    } else {
      Ok(SchemaOutcome::Migrated {
        edges: migrated_edges,
      })
    }
  }
}

/// The outcome of one [`MigrationRegistry::ensure_schema`] pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchemaOutcome {
  /// The store already carried the target schema.
  Current,
  /// The store was migrated across the given number of edges.
  Migrated { edges: u32 },
}

/// The domain-separation string anchoring every migration transaction id
/// derivation. It must stay byte-identical forever: transaction ids are
/// deterministic across releases and re-derivation is what makes replay
/// idempotent.
const MIGRATION_TRANSACTION_DOMAIN: &[u8] = b"radiata.woooo.tech/migration-transaction-v1";

/// The domain-separation string for the migration implementation digest.
/// Must stay byte-identical forever (it anchors edge identity).
const MIGRATION_IMPLEMENTATION_DOMAIN: &[u8] = b"radiata.woooo.tech/migration-implementation-v1";

/// Derives the domain-separated implementation digest of one migration
/// tag. Production edge registration and the compatibility freeze
/// reader share this single derivation.
pub(crate) fn implementation_digest(tag: &str) -> Digest {
  let mut hasher = Sha256::new();
  hasher.update(MIGRATION_IMPLEMENTATION_DOMAIN);
  hasher.update(tag.as_bytes());
  Digest::from_bytes(hasher.finalize().into())
}

/// Derives a deterministic migration transaction-id value: the
/// domain-separated SHA-256 over the ordered parts, truncated to the
/// first 16 bytes and read big-endian. The base stamp passes its schema
/// id bytes; every edge passes its tag and implementation digest, so all
/// sites share one derivation and cannot drift.
fn migration_transaction_value(parts: &[&[u8]]) -> Result<u128> {
  let mut hasher = Sha256::new();
  hasher.update(MIGRATION_TRANSACTION_DOMAIN);
  for part in parts {
    hasher.update(part);
  }
  let hashed = hasher.finalize();
  let bytes: [u8; 16] = hashed[..16]
    .try_into()
    .map_err(|_| Error::internal("migration transaction value"))?;
  Ok(u128::from_be_bytes(bytes))
}

// The declared metadata schema chain frozen for the `0.1.0` wire/metadata
// compatibility contract: the base version, the intermediate
// version, the current target, and each declared edge tag. These
// literals are frozen; every migration fixture and the compatibility
// manifest must agree with them byte-for-byte.
pub(crate) const BASE_VERSION: &str = "radiata.woooo.tech/schemas/metadata-test-v1";
pub(crate) const V2: &str = "radiata.woooo.tech/schemas/metadata-test-v2";
pub(crate) const V3: &str = "radiata.woooo.tech/schemas/metadata-test-v3";
pub(crate) const EDGE_ONE_TAG: &str = "radiata.woooo.tech/schemas/migration-edge-one-v1";
pub(crate) const EDGE_TWO_TAG: &str = "radiata.woooo.tech/schemas/migration-edge-two-v1";

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::*;
  use crate::{
    StoreRequirements, StoreRevision, provider::StorageFactory, storage::test_util as util,
  };

  /// The edge fixtures migrate records into this namespace; single-sourced
  /// because the digest-reconstruction tests must agree with the edge
  /// transforms on the exact namespace text.
  pub(super) const MODERN_NAMESPACE: &str = "radiata.woooo.tech/migration/modern-v1";

  pub(super) fn fixture_digest(tag: &str) -> Digest {
    super::implementation_digest(tag)
  }

  /// Edge one: renames every record from the legacy namespace into the
  /// modern namespace with a versioned value prefix.
  pub(super) fn plan_edge_one(
    snapshot: &dyn StoreSnapshot,
  ) -> BoxFuture<'_, Result<Vec<StoreOperation>>> {
    Box::pin(async move {
      let legacy = util::namespace("migration-legacy");
      let modern = StoreNamespace::new(crate::QualifiedTag::parse(MODERN_NAMESPACE).unwrap());
      let mut operations = Vec::new();
      let mut scan = snapshot.scan(&legacy, &[]).await?;
      while let Some(entry) = scan.next().await? {
        let mut value = b"v2:".to_vec();
        value.extend_from_slice(entry.value().as_bytes());
        operations.push(StoreOperation::Put {
          namespace: modern.clone(),
          key: entry.key().clone(),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(value.into_boxed_slice())),
        });
        operations.push(StoreOperation::Delete {
          namespace: legacy.clone(),
          key: entry.key().clone(),
          expected: entry.value().digest().clone(),
        });
      }
      drop(scan);
      Ok(operations)
    })
  }

  /// Edge two: stamps every modern record with a terminal marker value.
  pub(super) fn plan_edge_two(
    snapshot: &dyn StoreSnapshot,
  ) -> BoxFuture<'_, Result<Vec<StoreOperation>>> {
    Box::pin(async move {
      let modern = StoreNamespace::new(crate::QualifiedTag::parse(MODERN_NAMESPACE).unwrap());
      let mut operations = Vec::new();
      let mut scan = snapshot.scan(&modern, &[]).await?;
      while let Some(entry) = scan.next().await? {
        let mut value = entry.value().as_bytes().to_vec();
        value.extend_from_slice(b":final");
        operations.push(StoreOperation::Put {
          namespace: modern.clone(),
          key: entry.key().clone(),
          expected: StoreExpectation::Exact(entry.value().digest().clone()),
          value: StoreValue::new(Arc::from(value.into_boxed_slice())),
        });
      }
      drop(scan);
      Ok(operations)
    })
  }

  fn edge_one() -> MigrationEdge {
    MigrationEdge::new(
      BASE_VERSION,
      V2,
      EDGE_ONE_TAG,
      fixture_digest(EDGE_ONE_TAG),
      Some(plan_edge_one),
    )
  }

  fn edge_two() -> MigrationEdge {
    MigrationEdge::new(
      V2,
      V3,
      EDGE_TWO_TAG,
      fixture_digest(EDGE_TWO_TAG),
      Some(plan_edge_two),
    )
  }

  async fn seed_legacy(storage: &dyn Storage) -> StoreRevision {
    let snapshot = storage.snapshot().await.unwrap();
    let legacy = util::namespace("migration-legacy");
    let transaction = StoreTransaction::new(
      util::transaction_id(900),
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: legacy,
        key: util::key(b"record"),
        expected: StoreExpectation::Absent,
        value: util::value(b"payload"),
      }],
    )
    .unwrap();
    match storage.commit(transaction).await.unwrap() {
      crate::CommitOutcome::Committed(receipt) => receipt.committed_revision().clone(),
      outcome => panic!("unexpected outcome: {outcome:?}"),
    }
  }

  async fn read_schema(storage: &dyn Storage) -> Option<String> {
    let snapshot = storage.snapshot().await.unwrap();
    let namespace = schema_namespace().unwrap();
    let stored = snapshot.get(&namespace, &schema_key()).await.unwrap();
    stored.map(|value| decode_schema_record(&value).unwrap().1)
  }

  pub(super) fn registry_one_edge() -> MigrationRegistry {
    MigrationRegistry::new(BASE_VERSION, vec![edge_one()]).unwrap()
  }

  fn registry_two_edges() -> MigrationRegistry {
    MigrationRegistry::new(BASE_VERSION, vec![edge_one(), edge_two()]).unwrap()
  }

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

  /// The open-time gate: while the production chain has no edges, a
  /// fresh store opens without any schema write (the absent record is
  /// the implicit baseline) and a reopen is equally quiet.
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

  /// A store whose schema record names a version outside the production
  /// chain fails closed on open without mutating anything.
  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn metadata_open_rejects_a_schema_version_outside_the_chain() {
    use crate::{StoreOperation, storage::families};
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
      "radiata.woooo.tech/schemas/metadata-foreign-v9",
      None,
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
    let _ = families::INTERNAL_NAMESPACE;
  }

  /// The pending recovery path opens through the same gate: a store whose
  /// schema record names a version outside the production chain fails
  /// closed there too, before any pending record is discovered.
  async fn pending_recovery_rejects_a_schema_version_outside_the_chain(
    factory: Arc<dyn StorageFactory>,
  ) {
    // Commit a foreign schema record through the raw storage before the
    // metadata store ever opens.
    let raw = factory
      .open(crate::StoreRequirements::metadata())
      .await
      .unwrap();
    let snapshot = raw.snapshot().await.unwrap();
    let foreign = encode_schema_record(
      BASE_RECORD_KIND,
      "radiata.woooo.tech/schemas/metadata-foreign-v9",
      None,
    );
    let transaction = StoreTransaction::new(
      util::transaction_id(911),
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
    let error = crate::storage::MetadataStore::open_pending_recovered(
      &factory,
      std::time::Duration::from_secs(30),
      "local-identity",
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::UnsupportedSchema);
  }

  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn pending_recovery_rejects_a_schema_version_outside_the_chain_json() {
    let (_dir, factory) = json_factory();
    pending_recovery_rejects_a_schema_version_outside_the_chain(factory).await;
  }

  #[cfg(feature = "redb")]
  #[tokio::test]
  async fn pending_recovery_rejects_a_schema_version_outside_the_chain_redb() {
    let (_dir, factory) = redb_factory();
    pending_recovery_rejects_a_schema_version_outside_the_chain(factory).await;
  }

  #[tokio::test]
  async fn migration_registry_rejects_invalid_edge_graphs() {
    let missing_decoder = MigrationEdge::new(
      BASE_VERSION,
      V2,
      EDGE_ONE_TAG,
      fixture_digest(EDGE_ONE_TAG),
      None,
    );
    let error = MigrationRegistry::new(BASE_VERSION, vec![missing_decoder]).unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);

    // Duplicate edge: identical endpoints and tags cannot repeat.
    let duplicate = MigrationRegistry::new(BASE_VERSION, vec![edge_one(), edge_one()]);
    assert_eq!(
      duplicate.unwrap_err().kind(),
      crate::ErrorKind::InvalidInput
    );

    // Ambiguous path and implicit ordering: two edges leave the base.
    let fork = MigrationEdge::new(
      BASE_VERSION,
      V3,
      EDGE_TWO_TAG,
      fixture_digest(EDGE_TWO_TAG),
      Some(plan_edge_two),
    );
    assert_eq!(
      MigrationRegistry::new(BASE_VERSION, vec![edge_one(), fork])
        .unwrap_err()
        .kind(),
      crate::ErrorKind::InvalidInput
    );

    // Cycle: the last edge returns to the base version.
    let cycle = MigrationEdge::new(
      V2,
      BASE_VERSION,
      EDGE_TWO_TAG,
      fixture_digest(EDGE_TWO_TAG),
      Some(plan_edge_two),
    );
    assert_eq!(
      MigrationRegistry::new(BASE_VERSION, vec![edge_one(), cycle])
        .unwrap_err()
        .kind(),
      crate::ErrorKind::InvalidInput
    );

    // Downgrade: an edge that rewinds to an earlier version is rejected
    // before any transaction opens.
    let downgrade = MigrationEdge::new(
      V3,
      V2,
      EDGE_TWO_TAG,
      fixture_digest(EDGE_TWO_TAG),
      Some(plan_edge_two),
    );
    assert_eq!(
      MigrationRegistry::new(BASE_VERSION, vec![edge_one(), edge_two(), downgrade])
        .unwrap_err()
        .kind(),
      crate::ErrorKind::InvalidInput
    );

    // Unknown endpoints: the chain must start at the declared base.
    let unattached = MigrationRegistry::new(V2, vec![edge_one()]);
    assert_eq!(
      unattached.unwrap_err().kind(),
      crate::ErrorKind::InvalidInput
    );
    let disconnected = MigrationRegistry::new(BASE_VERSION, vec![edge_two()]);
    assert_eq!(
      disconnected.unwrap_err().kind(),
      crate::ErrorKind::InvalidInput
    );

    // A valid chain is accepted and targets its last edge.
    assert_eq!(registry_two_edges().target(), V3);
    assert_eq!(registry_one_edge().target(), V2);
  }

  async fn edges_apply_atomically_and_replay_idempotently(factory: Arc<dyn StorageFactory>) {
    let storage: Arc<dyn Storage> =
      Arc::from(factory.open(StoreRequirements::metadata()).await.unwrap());
    seed_legacy(&*storage).await;

    let registry = registry_two_edges();
    let outcome = registry.ensure_schema(&*storage).await.unwrap();
    assert_eq!(outcome, SchemaOutcome::Migrated { edges: 2 });
    assert_eq!(read_schema(&*storage).await.as_deref(), Some(V3));

    // The legacy record moved through both edges completely; no mixed
    // state exists.
    let snapshot = storage.snapshot().await.unwrap();
    let legacy = util::namespace("migration-legacy");
    let modern = StoreNamespace::new(crate::QualifiedTag::parse(MODERN_NAMESPACE).unwrap());
    assert!(
      snapshot
        .get(&legacy, &util::key(b"record"))
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
      snapshot
        .get(&modern, &util::key(b"record"))
        .await
        .unwrap()
        .unwrap()
        .as_bytes(),
      b"v2:payload:final"
    );
    drop(snapshot);

    // Replay of the exact registry is an idempotent no-op.
    let revision_before = storage.snapshot().await.unwrap().revision().clone();
    assert_eq!(
      registry.ensure_schema(&*storage).await.unwrap(),
      SchemaOutcome::Current
    );
    assert_eq!(
      storage.snapshot().await.unwrap().revision(),
      &revision_before
    );
  }

  async fn older_reader_and_digest_mismatch_fail_closed(factory: Arc<dyn StorageFactory>) {
    let storage: Arc<dyn Storage> =
      Arc::from(factory.open(StoreRequirements::metadata()).await.unwrap());
    seed_legacy(&*storage).await;
    registry_two_edges().ensure_schema(&*storage).await.unwrap();
    let revision_before = storage.snapshot().await.unwrap().revision().clone();

    // Older reader: a registry whose chain ends at v2 does not know the
    // store's v3 schema and must refuse without mutating anything.
    let older = registry_one_edge();
    let error = older.ensure_schema(&*storage).await.unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::UnsupportedSchema);
    assert_eq!(
      storage.snapshot().await.unwrap().revision(),
      &revision_before
    );

    // Implementation digest mismatch: same tags, different transform
    // digest must fail closed.
    let forged = MigrationEdge::new(
      BASE_VERSION,
      V2,
      EDGE_ONE_TAG,
      fixture_digest("forged-edge-one"),
      Some(plan_edge_one),
    );
    let forged_registry = MigrationRegistry::new(BASE_VERSION, vec![forged]).unwrap();
    let error = forged_registry.ensure_schema(&*storage).await.unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::UnsupportedSchema);
    assert_eq!(
      storage.snapshot().await.unwrap().revision(),
      &revision_before
    );
  }

  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn migration_edges_apply_atomically_and_replay_idempotently_json() {
    let (_dir, factory) = json_factory();
    edges_apply_atomically_and_replay_idempotently(factory).await;
  }

  #[cfg(feature = "redb")]
  #[tokio::test]
  async fn migration_edges_apply_atomically_and_replay_idempotently_redb() {
    let (_dir, factory) = redb_factory();
    edges_apply_atomically_and_replay_idempotently(factory).await;
  }

  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn migration_older_reader_and_digest_mismatch_fail_closed_json() {
    let (_dir, factory) = json_factory();
    older_reader_and_digest_mismatch_fail_closed(factory).await;
  }

  #[cfg(feature = "redb")]
  #[tokio::test]
  async fn migration_older_reader_and_digest_mismatch_fail_closed_redb() {
    let (_dir, factory) = redb_factory();
    older_reader_and_digest_mismatch_fail_closed(factory).await;
  }
}

#[cfg(any(all(test, feature = "json", unix), all(test, feature = "redb")))]
mod crash_tests {
  use std::sync::Arc;

  use super::{
    tests::{MODERN_NAMESPACE, fixture_digest, plan_edge_one, registry_one_edge},
    *,
  };
  use crate::{
    CommitOutcome, StoreRequirements, StoreRevision, provider::StorageFactory,
    storage::test_util as util,
  };

  #[cfg(all(feature = "json", unix))]
  const JSON_CRASH_DIR_ENV: &str = "RADIATA_JSON_MIGRATION_CRASH_DIR";
  #[cfg(all(feature = "json", unix))]
  const JSON_CRASH_POINT_ENV: &str = "RADIATA_JSON_MIGRATION_CRASH_POINT";
  #[cfg(all(feature = "json", unix))]
  const JSON_FIRST_COMMITTED_POINT: u8 = 8;
  #[cfg(all(feature = "json", unix))]
  const JSON_LAST_POINT: u8 = 13;

  #[cfg(feature = "redb")]
  const REDB_CRASH_DIR_ENV: &str = "RADIATA_REDB_MIGRATION_CRASH_DIR";
  #[cfg(feature = "redb")]
  const REDB_CRASH_POINT_ENV: &str = "RADIATA_REDB_MIGRATION_CRASH_POINT";
  #[cfg(feature = "redb")]
  const REDB_FIRST_COMMITTED_POINT: u8 = 6;
  #[cfg(feature = "redb")]
  const REDB_LAST_POINT: u8 = 6;

  async fn seed_base_and_legacy(storage: &dyn Storage) {
    let snapshot = storage.snapshot().await.unwrap();
    let legacy = util::namespace("migration-legacy");
    let seed = StoreTransaction::new(
      util::transaction_id(901),
      snapshot.revision().clone(),
      vec![
        StoreOperation::Put {
          namespace: legacy,
          key: util::key(b"record"),
          expected: crate::StoreExpectation::Absent,
          value: util::value(b"payload"),
        },
        StoreOperation::Put {
          namespace: schema_namespace().unwrap(),
          key: schema_key(),
          expected: crate::StoreExpectation::Absent,
          value: encode_schema_record(BASE_RECORD_KIND, BASE_VERSION, None),
        },
      ],
    )
    .unwrap();
    match storage.commit(seed).await.unwrap() {
      CommitOutcome::Committed(_) => {}
      outcome => panic!("unexpected outcome: {outcome:?}"),
    }
  }

  #[cfg(all(feature = "json", unix))]
  async fn child_body(directory: std::ffi::OsString, point: u8) {
    let factory: Arc<dyn StorageFactory> = Arc::new(crate::storage::json::JsonStoreFactory::new(
      directory.into(),
    ));
    let storage: Arc<dyn Storage> =
      Arc::from(factory.open(StoreRequirements::metadata()).await.unwrap());
    seed_base_and_legacy(&*storage).await;
    crate::storage::json::select_crash_point(point);
    registry_one_edge().ensure_schema(&*storage).await.unwrap();
  }

  #[cfg(all(feature = "json", unix))]
  #[ignore = "migration crash-matrix child process entry point"]
  #[tokio::test]
  async fn migration_json_crash_child_entry() {
    let directory = std::env::var_os(JSON_CRASH_DIR_ENV).expect("crash directory");
    let point: u8 = std::env::var(JSON_CRASH_POINT_ENV)
      .expect("crash point")
      .parse()
      .expect("numeric crash point");
    child_body(directory, point).await;
  }

  #[cfg(all(feature = "json", unix))]
  #[tokio::test]
  async fn migration_json_edge_interrupted_reopens_old_or_new() {
    for point in 1..=JSON_LAST_POINT {
      let dir = tempfile::tempdir().unwrap();
      run_json_child(&dir, point);
      let factory: Arc<dyn StorageFactory> = Arc::new(crate::storage::json::JsonStoreFactory::new(
        dir.path().to_path_buf(),
      ));
      let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
      assert_migration_old_or_new(&*storage, point < JSON_FIRST_COMMITTED_POINT, point).await;
    }
  }

  #[cfg(all(feature = "json", unix))]
  fn run_json_child(dir: &tempfile::TempDir, point: u8) {
    crate::storage::test_util::run_crash_child(
      "storage::migration::crash_tests::migration_json_crash_child_entry",
      JSON_CRASH_DIR_ENV,
      JSON_CRASH_POINT_ENV,
      dir.path(),
      point,
      "json migration",
      &[],
    );
  }

  #[cfg(feature = "redb")]
  fn child_body_redb(directory: std::ffi::OsString, point: u8) {
    let factory: Arc<dyn StorageFactory> = Arc::new(crate::storage::redb::RedbStoreFactory::new(
      directory.into(),
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    runtime.block_on(async move {
      let storage: Arc<dyn Storage> =
        Arc::from(factory.open(StoreRequirements::metadata()).await.unwrap());
      seed_base_and_legacy(&*storage).await;
      crate::storage::redb::select_crash_point(point);
      registry_one_edge().ensure_schema(&*storage).await.unwrap();
    });
  }

  #[cfg(feature = "redb")]
  #[ignore = "migration crash-matrix child process entry point"]
  #[test]
  fn migration_redb_crash_child_entry() {
    let directory = std::env::var_os(REDB_CRASH_DIR_ENV).expect("crash directory");
    let point: u8 = std::env::var(REDB_CRASH_POINT_ENV)
      .expect("crash point")
      .parse()
      .expect("numeric crash point");
    child_body_redb(directory, point);
  }

  #[cfg(feature = "redb")]
  #[tokio::test]
  async fn migration_redb_edge_interrupted_reopens_old_or_new() {
    for point in 1..=REDB_LAST_POINT {
      let dir = tempfile::tempdir().unwrap();
      let path = dir.path().join("store.redb");
      run_redb_child(&path, point);
      let factory: Arc<dyn StorageFactory> =
        Arc::new(crate::storage::redb::RedbStoreFactory::new(path));
      let storage = factory.open(StoreRequirements::metadata()).await.unwrap();
      assert_migration_old_or_new(&*storage, point < REDB_FIRST_COMMITTED_POINT, point).await;
    }
  }

  #[cfg(feature = "redb")]
  fn run_redb_child(path: &std::path::Path, point: u8) {
    crate::storage::test_util::run_crash_child(
      "storage::migration::crash_tests::migration_redb_crash_child_entry",
      REDB_CRASH_DIR_ENV,
      REDB_CRASH_POINT_ENV,
      path,
      point,
      "redb migration",
      &[],
    );
  }

  /// The operation digest of the deterministic edge transaction, computed
  /// by reconstructing the exact planned operations: the legacy fixture
  /// holds exactly one record at the seeded revision, so the transform
  /// plan, the schema record rewrite, and the base revision are all fixed.
  fn deterministic_edge_operation_digest(edge: &MigrationEdge) -> Digest {
    let modern = StoreNamespace::new(crate::QualifiedTag::parse(MODERN_NAMESPACE).unwrap());
    let base_record = encode_schema_record(BASE_RECORD_KIND, BASE_VERSION, None);
    let operations = vec![
      StoreOperation::Put {
        namespace: modern,
        key: util::key(b"record"),
        expected: crate::StoreExpectation::Absent,
        value: util::value(b"v2:payload"),
      },
      StoreOperation::Delete {
        namespace: util::namespace("migration-legacy"),
        key: util::key(b"record"),
        expected: util::value(b"payload").digest().clone(),
      },
      StoreOperation::Put {
        namespace: schema_namespace().unwrap(),
        key: schema_key(),
        expected: crate::StoreExpectation::Exact(base_record.digest().clone()),
        value: encode_schema_record(EDGE_RECORD_KIND, edge.to, Some(&edge.digest)),
      },
    ];
    let transaction = StoreTransaction::new(
      MigrationRegistry::edge_transaction_id(edge).unwrap(),
      StoreRevision::new(Arc::from(1_u64.to_be_bytes())).unwrap(),
      operations,
    )
    .unwrap();
    transaction.operation_digest().clone()
  }

  async fn assert_migration_old_or_new(storage: &dyn Storage, old: bool, point: u8) {
    let snapshot = storage.snapshot().await.unwrap();
    let legacy = util::namespace("migration-legacy");
    let modern = StoreNamespace::new(crate::QualifiedTag::parse(MODERN_NAMESPACE).unwrap());
    let legacy_value = snapshot.get(&legacy, &util::key(b"record")).await.unwrap();
    let modern_value = snapshot.get(&modern, &util::key(b"record")).await.unwrap();
    let schema = snapshot
      .get(&schema_namespace().unwrap(), &schema_key())
      .await
      .unwrap();
    drop(snapshot);

    if old {
      assert_eq!(
        schema
          .as_ref()
          .map(|value| decode_schema_record(value).unwrap().1),
        Some(BASE_VERSION.to_owned()),
        "point {point} must keep the base schema"
      );
      assert_eq!(
        legacy_value.as_ref().map(|value| value.as_bytes()),
        Some(b"payload".as_slice()),
        "point {point} must keep the legacy record complete"
      );
      assert!(
        modern_value.is_none(),
        "point {point} must not leave migrated records"
      );
    } else {
      assert_eq!(
        schema
          .as_ref()
          .map(|value| decode_schema_record(value).unwrap().1),
        Some(V2.to_owned()),
        "point {point} must expose the complete new schema"
      );
      assert!(
        legacy_value.is_none(),
        "point {point} must not keep the removed legacy record"
      );
      assert_eq!(
        modern_value.as_ref().map(|value| value.as_bytes()),
        Some(b"v2:payload".as_slice()),
        "point {point} must expose the complete migrated record"
      );
    }

    // The deterministic edge transaction identity reconciles exactly: the
    // operation digest is recomputed by replaying the identical plan on a
    // fresh fixture store.
    let edge = MigrationEdge::new(
      BASE_VERSION,
      V2,
      EDGE_ONE_TAG,
      fixture_digest(EDGE_ONE_TAG),
      Some(plan_edge_one),
    );
    let transaction_id = MigrationRegistry::edge_transaction_id(&edge).unwrap();
    let operation_digest = deterministic_edge_operation_digest(&edge);
    let outcome = storage
      .reconcile(&transaction_id, &operation_digest)
      .await
      .unwrap();
    if old {
      assert!(
        matches!(outcome, crate::ReconcileOutcome::Aborted),
        "point {point} must reconcile the unapplied edge as aborted"
      );
    } else {
      assert!(
        matches!(outcome, crate::ReconcileOutcome::Committed(_)),
        "point {point} must reconcile the applied edge receipt, got {outcome:?}"
      );
    }
  }
}
