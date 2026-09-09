//! Convergent permanent revocation.
//!
//! Revocation is a convergent, permanent, issuer-signed removal tombstone
//! over one exact node-to-key binding: any member may expel a compromised
//! binding cluster-wide, the record rides the sync plane, is never covered
//! by checkpoints, and is cleared only by an explicit local
//! `purge_revocation`. Once the revocation is known committed, the node
//! closes the revoked identity's sessions, rejects its new sessions and
//! online operations, refuses a new merge for it, and never adopts a new
//! binding for it from snapshots. Everything the identity signed before
//! the revoke — resources, descriptors, trust history, and bindings
//! already adopted anywhere — stays eligible for ordinary anti-entropy.
//!
//! The permanence asymmetry is deliberate: revocation subjects have live,
//! hostile keys, and bindings resurface by design (sync, stragglers,
//! storage backup restore), so the revocation record must live as long as
//! the binding it constrains.

use std::sync::Arc;

use minicbor::{Decode, Encode};

/// The durable namespace of revocation records.
pub(crate) use crate::storage::families::REVOCATION_NAMESPACE;
use crate::{
  Error, NodeId, PublicKey, Result, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
  StoreValue, TransactionId, api::Entropy, storage::MetadataStore,
};

/// The durable schema of the issuer-signed revocation record.
pub(crate) const REVOCATION_RECORD_SCHEMA: &str = "radiata.woooo.tech/schemas/revocation-record-v1";
/// The signature domain of the issuer-signed revocation record.
pub(crate) const REVOCATION_RECORD_V1_DOMAIN: &[u8] =
  b"radiata.woooo.tech/crypto/revocation-record-v1";

/// Canonical-decoder bounds for the flat revocation record.
const REVOCATION_LIMITS: crate::protocol::CborLimits =
  crate::protocol::CborLimits::new(1, 8, 1_024);

#[derive(Encode, Decode)]
#[cbor(array)]
struct RevocationRecordBodyWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  subject: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
  #[n(4)]
  issuer: String,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct RevocationRecordWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  subject: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
  #[n(4)]
  issuer: String,
  #[n(5)]
  #[cbor(with = "minicbor::bytes")]
  signature: Vec<u8>,
}

/// One issuer-signed convergent revocation tombstone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevocationRecordV1 {
  subject: NodeId,
  subject_key: PublicKey,
  issuer: NodeId,
  signature: crate::Signature,
}

impl RevocationRecordV1 {
  pub(crate) const fn new(
    subject: NodeId, subject_key: PublicKey, issuer: NodeId, signature: crate::Signature,
  ) -> Self {
    Self {
      subject,
      subject_key,
      issuer,
      signature,
    }
  }

  pub(crate) const fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub(crate) const fn subject_key(&self) -> &PublicKey {
    &self.subject_key
  }

  pub(crate) const fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  /// Encodes the canonical body the issuer signs.
  pub(crate) fn encode_signed_body(
    subject: &NodeId, subject_key: &PublicKey, issuer: &NodeId,
  ) -> Result<Vec<u8>> {
    crate::protocol::encode_canonical(
      &RevocationRecordBodyWire {
        schema: REVOCATION_RECORD_SCHEMA.to_owned(),
        record_version: 1,
        subject: subject.as_str().to_owned(),
        subject_key: subject_key.as_bytes().to_vec(),
        issuer: issuer.as_str().to_owned(),
      },
      REVOCATION_LIMITS,
    )
  }

  /// Verifies the issuer signature against `issuer_key` (the issuer's
  /// permanently retained binding).
  pub(crate) fn verify(&self, issuer_key: &PublicKey) -> Result<()> {
    crate::identity::signature::verify_strict(
      REVOCATION_RECORD_V1_DOMAIN,
      &Self::encode_signed_body(&self.subject, &self.subject_key, &self.issuer)?,
      issuer_key,
      &self.signature,
      "revocation record signature",
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    crate::protocol::encode_canonical(
      &RevocationRecordWire {
        schema: REVOCATION_RECORD_SCHEMA.to_owned(),
        record_version: 1,
        subject: self.subject.as_str().to_owned(),
        subject_key: self.subject_key.as_bytes().to_vec(),
        issuer: self.issuer.as_str().to_owned(),
        signature: self.signature.as_bytes().to_vec(),
      },
      REVOCATION_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: RevocationRecordWire = crate::protocol::decode_canonical_strict(
      bytes,
      REVOCATION_LIMITS,
      "revocation record canonical form",
    )
    .map_err(|_| Error::invalid_input("revocation record"))?;
    if wire.schema != REVOCATION_RECORD_SCHEMA || wire.record_version != 1 {
      return Err(Error::invalid_input("revocation record schema"));
    }
    Ok(Self {
      subject: NodeId::parse(&wire.subject)?,
      subject_key: PublicKey::from_bytes(
        <[u8; 32]>::try_from(wire.subject_key.as_slice())
          .map_err(|_| Error::invalid_input("revocation record key"))?,
      ),
      issuer: NodeId::parse(&wire.issuer)?,
      signature: crate::Signature::from_bytes(
        <[u8; 64]>::try_from(wire.signature.as_slice())
          .map_err(|_| Error::invalid_input("revocation record signature"))?,
      ),
    })
  }
}

/// Signs one revocation tombstone for `subject` under the local identity.
/// The subject must hold a locally trusted binding equal to
/// `expected_key`: an unknown subject fails `NotFound` and a different
/// trusted key fails `Conflict`, so a stale or substituted revocation
/// never signs.
pub(crate) async fn sign_revocation_record(
  context: &super::lifecycle::LocalIdentityContext, keys: &Arc<dyn crate::provider::KeyProvider>,
  subject: &NodeId, expected_key: &PublicKey,
) -> Result<RevocationRecordV1> {
  let bindings = crate::identity::trust::store::trusted_bindings(context.store()).await?;
  match bindings.get(subject) {
    Some(bound) if bound == expected_key => {}
    Some(_) => return Err(Error::conflict("revocation key")),
    None => return Err(Error::not_found("revocation subject")),
  }
  let identity = context.identity();
  let signature = crate::identity::records::sign_tombstone(
    context,
    keys,
    REVOCATION_RECORD_V1_DOMAIN,
    "revocation record signature",
    |identity| RevocationRecordV1::encode_signed_body(subject, expected_key, identity.node()),
  )
  .await?;
  Ok(RevocationRecordV1::new(
    subject.clone(),
    expected_key.clone(),
    identity.node().clone(),
    signature,
  ))
}

fn namespace() -> Result<StoreNamespace> {
  crate::identity::records::metadata_namespace(REVOCATION_NAMESPACE)
}

fn revocation_key(subject: &NodeId) -> StoreKey {
  StoreKey::new(Arc::from(subject.as_str().as_bytes().to_vec()))
}

fn decode_value(bytes: &[u8]) -> Result<RevocationRecordV1> {
  RevocationRecordV1::decode(bytes)
}

/// The outcome of one conditional revocation commit.
#[derive(Debug)]
pub(crate) enum RevokeStoreOutcome {
  /// The revocation committed now; the caller closes sessions and emits
  /// the event for this transition. The receipt proves the durable commit.
  Revoked(#[allow(dead_code)] crate::CommitReceipt),
  /// The exact binding was already revoked; the operation is idempotent
  /// and reports no new transition.
  AlreadyRevoked,
}

/// Conditionally revokes one exact subject/key binding with the given
/// issuer-signed tombstone.
///
/// The record's subject key must equal the locally trusted binding: an
/// unknown subject fails `NotFound` and a different trusted key fails
/// `Conflict`, so a stale or substituted revocation never lands. A stored
/// revocation for a different key also fails `Conflict`; the exact same
/// one is idempotent. The commit is one conditional transaction that pins
/// both the revocation key's absence and the trusted binding record's
/// exact digest, so a concurrent binding change between the snapshot and
/// the commit fails closed instead of letting the revoke land against a
/// stale key (the custody-lane precedent in `deletion.rs`).
pub(crate) async fn revoke_binding_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &RevocationRecordV1,
) -> Result<RevokeStoreOutcome> {
  let _permit = store.write_permit().await;
  let (binding_namespace, binding_key) =
    crate::identity::records::identity_binding_key(record.subject())?;
  let namespace = namespace()?;
  let store_key = revocation_key(record.subject());
  let snapshot = store.snapshot().await?;
  let binding_value = snapshot
    .get(&binding_namespace, &binding_key)
    .await?
    .ok_or_else(|| Error::not_found("revocation subject"))?;
  let binding_digest = binding_value.digest().clone();
  let binding = crate::identity::records::IdentityBindingV1::decode(binding_value.as_bytes())
    .map_err(|_| Error::invalid_input("identity binding"))?;
  if binding.public_key() != record.subject_key() {
    return Err(Error::conflict("revocation key"));
  }
  if let Some(existing) = snapshot.get(&namespace, &store_key).await? {
    let existing_record = decode_value(existing.as_bytes())?;
    if existing_record == *record {
      return Ok(RevokeStoreOutcome::AlreadyRevoked);
    }
    return Err(Error::conflict("revocation key"));
  }
  let expected =
    crate::provider::snapshot_expectation(snapshot.as_ref(), &namespace, &store_key).await?;
  let transaction = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![
      // The revoke lands only against the exact trusted binding observed
      // above: a raced binding change conflicts instead of silently
      // missing the live key.
      StoreOperation::Check {
        namespace: binding_namespace,
        key: binding_key,
        expected: StoreExpectation::Exact(binding_digest),
      },
      StoreOperation::Put {
        namespace,
        key: store_key,
        expected,
        value: StoreValue::new(Arc::from(record.encode()?)),
      },
    ],
  )?;
  match store.commit(transaction).await? {
    crate::CommitOutcome::Committed(receipt) => Ok(RevokeStoreOutcome::Revoked(receipt)),
    // A raced exact revocation committed first: idempotent. Any other
    // interleaving fails closed and the caller retries the operation.
    crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => {
      match revoked_key_ctx(store, record.subject()).await? {
        Some(key) if key == *record.subject_key() => Ok(RevokeStoreOutcome::AlreadyRevoked),
        _ => Err(Error::conflict("revocation commit")),
      }
    }
    crate::CommitOutcome::Unknown { .. } => Err(Error::provider(
      crate::ProviderErrorKind::CommitUnknown,
      crate::ProviderErrorContext::StorageCommit,
    )),
  }
}

/// Persists one issuer-signed revocation tombstone received over sync:
/// verified against the retained issuer binding
/// and the subject binding, idempotent for the exact record, and failing
/// closed on any divergence.
pub(crate) async fn persist_revocation_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &RevocationRecordV1,
) -> Result<()> {
  let _permit = store.write_permit().await;
  let bindings = crate::identity::trust::store::trusted_bindings(store).await?;
  let issuer_key = bindings
    .get(record.issuer())
    .cloned()
    .ok_or_else(|| Error::not_trusted("revocation issuer"))?;
  record.verify(&issuer_key)?;
  if let Some(bound) = bindings.get(record.subject())
    && bound != record.subject_key()
  {
    return Err(Error::not_trusted("revocation subject binding"));
  }
  crate::identity::records::persist_terminal_record(
    store,
    entropy,
    namespace()?,
    revocation_key(record.subject()),
    Arc::from(record.encode()?),
    "revocation record",
  )
  .await
}

/// Every known revocation tombstone, bounded by `cap`, for sync
/// forwarding. Permanent records: never pruned by any GC pass.
pub(crate) async fn known_revocation_records_ctx(
  store: &MetadataStore, cap: usize,
) -> Result<Vec<RevocationRecordV1>> {
  crate::identity::records::scan_decoded_records(
    store,
    namespace()?,
    cap,
    crate::identity::records::skip_none,
    RevocationRecordV1::decode,
  )
  .await
}

/// The revoked tombstone of `subject`, when this node holds one for that
/// exact subject key. Snapshot reads only; the result never fabricates a
/// revocation.
pub(crate) async fn revoked_key_ctx(
  store: &MetadataStore, subject: &NodeId,
) -> Result<Option<PublicKey>> {
  let namespace = namespace()?;
  let key = revocation_key(subject);
  let snapshot = store.snapshot().await?;
  let Some(value) = snapshot.get(&namespace, &key).await? else {
    return Ok(None);
  };
  Ok(Some(decode_value(value.as_bytes())?.subject_key().clone()))
}

/// Whether `subject` is locally revoked under exactly `key` (the session
/// and admission enforcement checks).
pub(crate) async fn is_revoked_ctx(
  store: &MetadataStore, subject: &NodeId, key: &PublicKey,
) -> Result<bool> {
  Ok(revoked_key_ctx(store, subject).await?.as_ref() == Some(key))
}

/// Explicitly clears the local revocation record for `subject`:
/// the purge is local-only and idempotent — an absent record is a no-op.
/// It is the operator's deliberate escape from a fat-fingered revoke; a
/// purge is transient by nature (peers still hold the permanent tombstone
/// and sync re-delivers it).
pub(crate) async fn purge_revocation_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, subject: &NodeId,
) -> Result<()> {
  let _permit = store.write_permit().await;
  // Inside the writer exclusion the read, the explicit-clear decision,
  // and the exact-digest delete are one linear section: no retry needed.
  let namespace = namespace()?;
  let store_key = revocation_key(subject);
  let snapshot = store.snapshot().await?;
  let Some(existing) = snapshot.get(&namespace, &store_key).await? else {
    return Ok(());
  };
  let transaction = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![StoreOperation::Delete {
      namespace,
      key: store_key,
      expected: existing.digest().clone(),
    }],
  )?;
  drop(snapshot);
  match store.commit(transaction).await? {
    crate::CommitOutcome::Committed(_) => Ok(()),
    // Defensive: under the exclusion this is unreachable in-process.
    _ => Err(Error::conflict("revocation purge")),
  }
}

#[cfg(test)]
mod tests {
  use std::{sync::Arc, time::Duration};

  use ed25519_dalek::Signer as _;

  use super::{
    REVOCATION_RECORD_V1_DOMAIN, RevocationRecordV1, RevokeStoreOutcome, is_revoked_ctx,
    known_revocation_records_ctx, revoke_binding_ctx, revoked_key_ctx,
  };
  use crate::{
    ErrorKind, NodeId, PublicKey, Signature, StoreExpectation,
    api::SystemEntropy,
    identity::{
      records::{self, IdentityBindingV1},
      signature::signature_message,
    },
    provider::StorageFactory,
    storage::MetadataStore,
  };

  fn subject() -> NodeId {
    NodeId::parse("node_000000000000000000051").unwrap()
  }

  fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes([seed; 32])
  }

  /// The fixed test issuer: a distinct node whose deterministic signing
  /// key produces byte-identical records across crash-matrix runs.
  fn issuer() -> NodeId {
    NodeId::parse("node_000000000000000000091").unwrap()
  }

  fn issuer_signing() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x2A; 32])
  }

  /// Builds the exact issuer-signed tombstone the store-level revoke
  /// commits (the signature is deterministic, so crash-matrix dry runs
  /// and child processes construct byte-identical records).
  fn signed_record(subject: &NodeId, subject_key: &PublicKey) -> RevocationRecordV1 {
    let body = RevocationRecordV1::encode_signed_body(subject, subject_key, &issuer()).unwrap();
    let signature = issuer_signing().sign(&signature_message(REVOCATION_RECORD_V1_DOMAIN, &body));
    RevocationRecordV1::new(
      subject.clone(),
      subject_key.clone(),
      issuer(),
      Signature::from_bytes(signature.to_bytes()),
    )
  }

  async fn open_store() -> MetadataStore {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap()
  }

  /// Seeds the trusted binding the revocation conditions on.
  async fn trust(store: &MetadataStore, node: &NodeId, key: &PublicKey) {
    let (namespace, store_key) = records::identity_binding_key(node).unwrap();
    let snapshot = store.snapshot().await.unwrap();
    let transaction = store
      .prepare_transaction(
        crate::TransactionId::generate(&SystemEntropy).unwrap(),
        snapshot.revision().clone(),
        vec![crate::StoreOperation::Put {
          namespace,
          key: store_key,
          expected: StoreExpectation::Absent,
          value: crate::StoreValue::new(Arc::from(
            IdentityBindingV1::new(node.clone(), key.clone())
              .encode()
              .unwrap(),
          )),
        }],
      )
      .unwrap();
    assert!(matches!(
      store.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));
  }

  /// The exact binding commits once; a repeated revoke is idempotent, an
  /// unknown subject is not found, and a substituted key fails closed.
  #[tokio::test]
  async fn revoke_commits_the_exact_binding_once() {
    let store = open_store().await;
    trust(&store, &subject(), &key(7)).await;

    assert!(matches!(
      revoke_binding_ctx(&store, &SystemEntropy, &signed_record(&subject(), &key(7)))
        .await
        .unwrap(),
      RevokeStoreOutcome::Revoked(_)
    ));
    assert_eq!(
      revoked_key_ctx(&store, &subject()).await.unwrap(),
      Some(key(7))
    );
    assert!(is_revoked_ctx(&store, &subject(), &key(7)).await.unwrap());
    assert!(!is_revoked_ctx(&store, &subject(), &key(8)).await.unwrap());
    // The permanent record set feeds the sync forwarder.
    let known = known_revocation_records_ctx(&store, 64).await.unwrap();
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].subject(), &subject());

    // Idempotent: the same exact revocation reports no new transition.
    assert!(matches!(
      revoke_binding_ctx(&store, &SystemEntropy, &signed_record(&subject(), &key(7)))
        .await
        .unwrap(),
      RevokeStoreOutcome::AlreadyRevoked
    ));
    // A revocation recorded under one key never silently rekeys.
    assert_eq!(
      revoke_binding_ctx(&store, &SystemEntropy, &signed_record(&subject(), &key(8)))
        .await
        .unwrap_err()
        .kind(),
      ErrorKind::Conflict
    );

    // An unknown subject and a substituted trusted key both fail closed.
    let unknown = NodeId::parse("node_000000000000000000052").unwrap();
    assert_eq!(
      revoke_binding_ctx(&store, &SystemEntropy, &signed_record(&unknown, &key(7)))
        .await
        .unwrap_err()
        .kind(),
      ErrorKind::NotFound
    );
    let substituted = NodeId::parse("node_000000000000000000053").unwrap();
    trust(&store, &substituted, &key(9)).await;
    assert_eq!(
      revoke_binding_ctx(
        &store,
        &SystemEntropy,
        &signed_record(&substituted, &key(10))
      )
      .await
      .unwrap_err()
      .kind(),
      ErrorKind::Conflict
    );
    assert!(!is_revoked_ctx(&store, &substituted, &key(9)).await.unwrap());
  }

  /// A stored revocation survives a reopen exactly (old-or-new storage
  /// semantics for the single conditional transaction).
  #[cfg(all(unix, feature = "json"))]
  #[tokio::test]
  async fn revoked_binding_survives_reopen_on_json() {
    let directory = tempfile::tempdir().unwrap();
    let factory: Arc<dyn StorageFactory> = Arc::new(crate::storage::json::JsonStoreFactory::new(
      directory.path().to_path_buf(),
    ));
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    trust(&store, &subject(), &key(7)).await;
    assert!(matches!(
      revoke_binding_ctx(&store, &SystemEntropy, &signed_record(&subject(), &key(7)))
        .await
        .unwrap(),
      RevokeStoreOutcome::Revoked(_)
    ));
    drop(store);

    let reopened = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    assert_eq!(
      revoked_key_ctx(&reopened, &subject()).await.unwrap(),
      Some(key(7))
    );
  }
}

/// Subprocess durability matrix for revocations.
///
/// Mirrors the resource crash lane: the parent seeds the trusted binding,
/// the child revokes it under deterministic entropy while aborting inside
/// the JSON commit path, and the parent proves the store reopens to
/// exactly the old (trusted, not revoked) or the new (trusted and revoked
/// under the exact key) state — never a partial revocation or a damaged
/// binding — and that the child's transaction reconciles consistently.
#[cfg(all(test, unix, any(feature = "json", feature = "redb")))]
mod crash {
  use std::{sync::Arc, time::Duration};

  use tempfile::TempDir;

  use super::{
    REVOCATION_RECORD_V1_DOMAIN, RevocationRecordV1, RevokeStoreOutcome, revoke_binding_ctx,
    revoked_key_ctx,
  };
  use crate::{
    CommitReceipt, NodeId, PublicKey, ReconcileOutcome, Signature, StoreExpectation,
    api::SystemEntropy,
    identity::{
      records::{self, IdentityBindingV1},
      signature::signature_message,
    },
    provider::StorageFactory,
    storage::{MetadataStore, test_util},
    transport::testing::SeedEntropy,
  };

  /// The fixed test issuer: byte-identical records across dry runs and
  /// child processes keep the crash-matrix receipt comparison exact.
  fn issuer() -> NodeId {
    NodeId::parse("node_000000000000000000091").unwrap()
  }

  fn issuer_signing() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x2A; 32])
  }

  fn signed_record(subject: &NodeId, subject_key: &PublicKey) -> RevocationRecordV1 {
    use ed25519_dalek::Signer as _;
    let body = RevocationRecordV1::encode_signed_body(subject, subject_key, &issuer()).unwrap();
    let signature = issuer_signing().sign(&signature_message(REVOCATION_RECORD_V1_DOMAIN, &body));
    RevocationRecordV1::new(
      subject.clone(),
      subject_key.clone(),
      issuer(),
      Signature::from_bytes(signature.to_bytes()),
    )
  }

  const CRASH_DIR_ENV: &str = "RADIATA_REVOKE_CRASH_DIR";
  const CRASH_POINT_ENV: &str = "RADIATA_REVOKE_CRASH_POINT";
  const CRASH_BACKEND_ENV: &str = "RADIATA_REVOKE_CRASH_BACKEND";
  const CHILD_ENTROPY_SEED: u8 = 11;
  #[cfg(feature = "json")]
  const JSON_LAST_POINT: u8 = 13;
  #[cfg(feature = "redb")]
  const REDB_LAST_POINT: u8 = 6;

  /// The crash backends compiled into this test binary, with each commit
  /// path's boundary count.
  // The cfg-gated pushes defeat vec! construction; the allow documents
  // that the list is compile-time constant, not dynamically extended.
  #[allow(clippy::vec_init_then_push)]
  fn backends() -> Vec<(&'static str, u8)> {
    let mut backends = Vec::with_capacity(2);
    #[cfg(feature = "json")]
    backends.push(("json", JSON_LAST_POINT));
    #[cfg(feature = "redb")]
    backends.push(("redb", REDB_LAST_POINT));
    backends
  }

  fn subject() -> NodeId {
    NodeId::parse("node_000000000000000000051").unwrap()
  }

  fn key() -> PublicKey {
    PublicKey::from_bytes([7; 32])
  }

  fn factory(backend: &str, directory: &std::path::Path) -> Arc<dyn StorageFactory> {
    match backend {
      #[cfg(feature = "json")]
      "json" => Arc::new(crate::storage::json::JsonStoreFactory::new(
        directory.to_path_buf(),
      )),
      #[cfg(feature = "redb")]
      "redb" => Arc::new(crate::storage::redb::RedbStoreFactory::new(
        directory.join("store.redb"),
      )),
      #[allow(unreachable_patterns)]
      _ => panic!("backend {backend} not compiled into this test binary"),
    }
  }

  /// Arms the selected backend's compiled-in commit-path hook.
  fn select_point(backend: &str, point: u8) {
    match backend {
      #[cfg(feature = "json")]
      "json" => crate::storage::json::select_crash_point(point),
      #[cfg(feature = "redb")]
      "redb" => crate::storage::redb::select_crash_point(point),
      #[allow(unreachable_patterns)]
      _ => panic!("backend {backend} not compiled into this test binary"),
    }
  }

  async fn open_store(factory: &Arc<dyn StorageFactory>) -> MetadataStore {
    MetadataStore::open(factory, Duration::from_secs(10))
      .await
      .unwrap()
  }

  /// Seeds the trusted binding the child revokes.
  async fn seed(factory: &Arc<dyn StorageFactory>) {
    let store = open_store(factory).await;
    let (namespace, store_key) = records::identity_binding_key(&subject()).unwrap();
    let snapshot = store.snapshot().await.unwrap();
    let transaction = store
      .prepare_transaction(
        crate::TransactionId::generate(&SystemEntropy).unwrap(),
        snapshot.revision().clone(),
        vec![crate::StoreOperation::Put {
          namespace,
          key: store_key,
          expected: StoreExpectation::Absent,
          value: crate::StoreValue::new(Arc::from(
            IdentityBindingV1::new(subject(), key()).encode().unwrap(),
          )),
        }],
      )
      .unwrap();
    assert!(matches!(
      store.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));
  }

  /// Reproduces the child's exact pending-transaction identity from a
  /// crash-free dry run over the same seeded state and entropy.
  async fn child_identity(backend: &str) -> CommitReceipt {
    let dir = TempDir::new().unwrap();
    let factory = factory(backend, dir.path());
    seed(&factory).await;
    let store = open_store(&factory).await;
    match revoke_binding_ctx(
      &store,
      &SeedEntropy(CHILD_ENTROPY_SEED),
      &signed_record(&subject(), &key()),
    )
    .await
    .unwrap()
    {
      RevokeStoreOutcome::Revoked(receipt) => receipt,
      RevokeStoreOutcome::AlreadyRevoked => panic!("dry-run revoke must commit"),
    }
  }

  fn run_child(dir: &TempDir, backend: &str, point: u8) {
    test_util::run_crash_child(
      "identity::revocation::crash::revoke_crash_child_entry",
      CRASH_DIR_ENV,
      CRASH_POINT_ENV,
      dir.path(),
      point,
      "revocation",
      &[(CRASH_BACKEND_ENV, backend.to_owned())],
    );
  }

  #[ignore = "revocation crash-matrix child process entry point"]
  #[tokio::test]
  async fn revoke_crash_child_entry() {
    let directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
    let point: u8 = std::env::var(CRASH_POINT_ENV)
      .expect("crash point")
      .parse()
      .expect("numeric crash point");
    let backend = std::env::var(CRASH_BACKEND_ENV).unwrap_or_else(|_| "json".to_owned());
    select_point(&backend, point);
    let factory = factory(&backend, &std::path::PathBuf::from(directory));
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    match revoke_binding_ctx(
      &store,
      &SeedEntropy(CHILD_ENTROPY_SEED),
      &signed_record(&subject(), &key()),
    )
    .await
    .unwrap()
    {
      RevokeStoreOutcome::Revoked(_) | RevokeStoreOutcome::AlreadyRevoked => {}
    }
  }

  /// Every crash boundary reopens to exactly the old or the new state:
  /// the trusted binding is always intact, and the revocation is either
  /// absent or the exact committed key — never partial or substituted.
  /// The matrix runs against every compiled backend (JSON and redb).
  #[tokio::test]
  async fn revoke_crash_boundaries_recover_exact_old_or_new_state() {
    for (backend, last_point) in backends() {
      let identity = child_identity(backend).await;
      let mut aborted_points = Vec::new();
      let mut committed_points = Vec::new();
      for point in 1..=last_point {
        let dir = TempDir::new().unwrap();
        let factory = factory(backend, dir.path());
        seed(&factory).await;
        run_child(&dir, backend, point);

        let reopened = open_store(&factory).await;
        let observed = revoked_key_ctx(&reopened, &subject()).await.unwrap();
        let observed_old = observed.is_none();
        let observed_new = observed == Some(key());
        assert!(
          observed_old ^ observed_new,
          "{backend}/{point} must reopen to old-or-new, got {observed:?}"
        );
        // The trusted binding is never damaged by the revocation boundary.
        let (namespace, store_key) = records::identity_binding_key(&subject()).unwrap();
        let snapshot = reopened.snapshot().await.unwrap();
        let binding = snapshot
          .get(&namespace, &store_key)
          .await
          .unwrap()
          .expect("the trusted binding survives every crash point");
        let binding = IdentityBindingV1::decode(binding.as_bytes()).unwrap();
        assert_eq!(binding.public_key(), &key());
        drop(snapshot);
        drop(reopened);

        let provider = factory.open(test_util::crash_requirements()).await.unwrap();
        match provider
          .reconcile(identity.transaction(), identity.operation_digest())
          .await
          .unwrap()
        {
          ReconcileOutcome::Aborted => {
            assert!(
              observed_old,
              "{backend}/{point} reconciled aborted but shows the revocation"
            );
            aborted_points.push(point);
          }
          ReconcileOutcome::Committed(_) => {
            assert!(
              observed_new,
              "{backend}/{point} reconciled committed but shows no revocation"
            );
            committed_points.push(point);
          }
          other => panic!("{backend}/{point} must reconcile decisively, got {other:?}"),
        }
      }

      assert_eq!(aborted_points.first().copied(), Some(1));
      assert_eq!(committed_points.last().copied(), Some(last_point));
      if let (Some(last_aborted), Some(first_committed)) =
        (aborted_points.last(), committed_points.first())
      {
        assert!(
          last_aborted < first_committed,
          "crash boundary must be monotonic"
        );
      }
    }
  }
}
