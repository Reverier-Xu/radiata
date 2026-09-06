//! Dead-node cleanup tombstones (T-G11-08, ADR-0009 decision 4).
//!
//! `cleanup_node` issues a convergent, issuer-signed removal tombstone for
//! a node the operator has decommissioned. The record carries the exact
//! subject binding and the issuer's signature; receivers verify it against
//! the permanently retained issuer binding and the subject binding (a
//! divergent subject key is conflicting evidence and fails closed).
//!
//! Cleanup tombstones are terminal: there is no resurrection path, and the
//! user is responsible for never cleaning a node that is merely offline. A
//! mistakenly cleaned node recovers only by rotating its identity and
//! re-merging as a new `NodeId`. Cleaned nodes are excluded from session
//! establishment and recovery dialing; their historical signed records
//! remain valid evidence.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::{
  lifecycle::LocalIdentityContext,
  records::metadata_namespace,
  signature::{signature_message, verify_strict},
};
/// The durable namespace of cleanup tombstone records.
pub(crate) use crate::storage::families::CLEANUP_NAMESPACE;
use crate::{
  Error, NodeId, PublicKey, Result, Signature, StoreExpectation, StoreKey, StoreNamespace,
  StoreOperation, StoreValue, TransactionId, api::Entropy, provider::KeyProvider,
  storage::MetadataStore,
};

/// The durable schema of the issuer-signed cleanup tombstone.
pub(crate) const CLEANUP_RECORD_SCHEMA: &str = "radiata.woooo.tech/schemas/cleanup-record-v1";
/// The signature domain of the issuer-signed cleanup tombstone.
pub(crate) const CLEANUP_RECORD_V1_DOMAIN: &[u8] = b"radiata.woooo.tech/crypto/cleanup-record-v1";

/// Canonical-decoder bounds for the flat cleanup record.
const CLEANUP_LIMITS: crate::protocol::CborLimits = crate::protocol::CborLimits::new(1, 8, 1_024);

#[derive(Encode, Decode)]
#[cbor(array)]
struct CleanupRecordBodyWire {
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
  /// Signed host wall-clock UNIX milliseconds: the removal timestamp the
  /// checkpoint GC compares against its watermark (T-G11-09).
  #[n(5)]
  timestamp_millis: u64,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct CleanupRecordWire {
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
  timestamp_millis: u64,
  #[n(6)]
  #[cbor(with = "minicbor::bytes")]
  signature: Vec<u8>,
}

/// One issuer-signed cleanup tombstone (ADR-0009 decision 4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CleanupRecordV1 {
  subject: NodeId,
  subject_key: PublicKey,
  issuer: NodeId,
  timestamp_millis: u64,
  signature: Signature,
}

impl CleanupRecordV1 {
  pub(crate) const fn new(
    subject: NodeId, subject_key: PublicKey, issuer: NodeId, timestamp_millis: u64,
    signature: Signature,
  ) -> Self {
    Self {
      subject,
      subject_key,
      issuer,
      timestamp_millis,
      signature,
    }
  }

  pub(crate) const fn timestamp_millis(&self) -> u64 {
    self.timestamp_millis
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
    subject: &NodeId, subject_key: &PublicKey, issuer: &NodeId, timestamp_millis: u64,
  ) -> Result<Vec<u8>> {
    encode_wire(&CleanupRecordBodyWire {
      schema: CLEANUP_RECORD_SCHEMA.to_owned(),
      record_version: 1,
      subject: subject.as_str().to_owned(),
      subject_key: subject_key.as_bytes().to_vec(),
      issuer: issuer.as_str().to_owned(),
      timestamp_millis,
    })
  }

  /// Verifies the issuer signature against `issuer_key` (the issuer's
  /// permanently retained binding).
  pub(crate) fn verify(&self, issuer_key: &PublicKey) -> Result<()> {
    verify_strict(
      CLEANUP_RECORD_V1_DOMAIN,
      &Self::encode_signed_body(
        &self.subject,
        &self.subject_key,
        &self.issuer,
        self.timestamp_millis,
      )?,
      issuer_key,
      &self.signature,
      "cleanup record signature",
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_wire(&CleanupRecordWire {
      schema: CLEANUP_RECORD_SCHEMA.to_owned(),
      record_version: 1,
      subject: self.subject.as_str().to_owned(),
      subject_key: self.subject_key.as_bytes().to_vec(),
      issuer: self.issuer.as_str().to_owned(),
      timestamp_millis: self.timestamp_millis,
      signature: ByteVec::from(self.signature.as_bytes().to_vec()).to_vec(),
    })
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: CleanupRecordWire = crate::protocol::decode_canonical_strict(
      bytes,
      CLEANUP_LIMITS,
      "cleanup record canonical form",
    )
    .map_err(|_| Error::invalid_input("cleanup record"))?;
    if wire.schema != CLEANUP_RECORD_SCHEMA || wire.record_version != 1 {
      return Err(Error::invalid_input("cleanup record schema"));
    }
    Ok(Self {
      subject: NodeId::parse(&wire.subject)?,
      subject_key: PublicKey::from_bytes(
        <[u8; 32]>::try_from(wire.subject_key.as_slice())
          .map_err(|_| Error::invalid_input("cleanup record key"))?,
      ),
      issuer: NodeId::parse(&wire.issuer)?,
      timestamp_millis: wire.timestamp_millis,
      signature: Signature::from_bytes(
        <[u8; 64]>::try_from(wire.signature.as_slice())
          .map_err(|_| Error::invalid_input("cleanup record signature"))?,
      ),
    })
  }
}

fn encode_wire<T: Encode<()>>(wire: &T) -> Result<Vec<u8>> {
  crate::protocol::encode_canonical(wire, CLEANUP_LIMITS)
}

fn cleanup_key(subject: &NodeId) -> StoreKey {
  StoreKey::new(Arc::from(subject.as_str().as_bytes().to_vec()))
}

/// Signs one cleanup tombstone for `subject` with the local identity. The
/// subject must have a locally retained binding: the tombstone pins the
/// exact key so a later divergent binding can never validate against it.
pub(crate) async fn sign_cleanup_record(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, subject: &NodeId,
) -> Result<CleanupRecordV1> {
  let bindings = crate::identity::trust::store::trusted_bindings(context.store()).await?;
  let subject_key = bindings
    .get(subject)
    .cloned()
    .ok_or_else(|| Error::not_found("cleanup subject"))?;
  let identity = context.identity();
  let timestamp_millis = crate::time::now_millis();
  let body =
    CleanupRecordV1::encode_signed_body(subject, &subject_key, identity.node(), timestamp_millis)?;
  let signature = keys
    .sign(
      identity.handle(),
      &signature_message(CLEANUP_RECORD_V1_DOMAIN, &body),
    )
    .await?;
  let record = CleanupRecordV1::new(
    subject.clone(),
    subject_key,
    identity.node().clone(),
    timestamp_millis,
    signature,
  );
  record.verify(identity.public_key())?;
  Ok(record)
}

/// Persists one verified cleanup tombstone (idempotent; a re-delivery of
/// the exact record is a no-op, a divergent record for the same subject
/// fails closed without mutation).
pub(crate) async fn persist_cleanup_record_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &CleanupRecordV1,
) -> Result<()> {
  let bindings = crate::identity::trust::store::trusted_bindings(store).await?;
  let issuer_key = bindings
    .get(record.issuer())
    .cloned()
    .ok_or_else(|| Error::not_trusted("cleanup issuer"))?;
  record.verify(&issuer_key)?;
  if let Some(bound) = bindings.get(record.subject())
    && bound != record.subject_key()
  {
    return Err(Error::not_trusted("cleanup subject binding"));
  }
  let namespace = metadata_namespace(CLEANUP_NAMESPACE)?;
  let key = cleanup_key(record.subject());
  let snapshot = store.snapshot().await?;
  if let Some(existing) = snapshot.get(&namespace, &key).await? {
    if existing.as_bytes() == record.encode()?.as_slice() {
      return Ok(());
    }
    return Err(Error::conflict("cleanup record"));
  }
  let transaction = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![StoreOperation::Put {
      namespace: namespace.clone(),
      key,
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(record.encode()?)),
    }],
  )?;
  drop(snapshot);
  let _ = store.commit(transaction).await?;
  Ok(())
}

/// Whether `node` has a cleanup tombstone in the local store.
pub(crate) async fn is_cleaned_ctx(store: &MetadataStore, node: &NodeId) -> Result<bool> {
  let namespace = metadata_namespace(CLEANUP_NAMESPACE)?;
  let snapshot = store.snapshot().await?;
  Ok(
    snapshot
      .get(&namespace, &cleanup_key(node))
      .await?
      .is_some(),
  )
}

/// Every known cleanup tombstone, bounded by `cap`, for sync forwarding.
pub(crate) async fn known_cleanup_records_ctx(
  store: &MetadataStore, cap: usize,
) -> Result<Vec<CleanupRecordV1>> {
  let namespace = metadata_namespace(CLEANUP_NAMESPACE)?;
  let snapshot = store.snapshot().await?;
  let mut scan = snapshot.scan(&namespace, &[]).await?;
  let mut records = Vec::new();
  while let Some(entry) = scan.next().await? {
    let record = CleanupRecordV1::decode(entry.value().as_bytes())
      .map_err(|_| Error::invalid_input("cleanup record decode"))?;
    records.push(record);
    if records.len() >= cap {
      break;
    }
  }
  Ok(records)
}

/// Every cleaned node, for exclusion sweeps.
pub(crate) async fn cleaned_nodes_ctx(
  store: &MetadataStore,
) -> Result<std::collections::BTreeSet<NodeId>> {
  Ok(
    known_cleanup_records_ctx(store, usize::MAX)
      .await?
      .iter()
      .map(|record| record.subject().clone())
      .collect(),
  )
}

/// The durable schema of the cleanup checkpoint (GC epoch) record.
pub(crate) const CHECKPOINT_SCHEMA: &str = "radiata.woooo.tech/schemas/cleanup-checkpoint-v1";

/// The durable namespace of cleanup checkpoint (GC epoch) records.
pub(crate) use crate::storage::families::CHECKPOINT_NAMESPACE;

#[derive(Encode, Decode)]
#[cbor(array)]
struct CheckpointWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  /// The GC epoch watermark: host wall-clock UNIX milliseconds. Removal
  /// tombstones stamped at or before this watermark are collected.
  #[n(2)]
  watermark_millis: u64,
  /// The member that issued the epoch (hygiene provenance only; the
  /// record is unsigned by design — ADR-0009 decision 5: violations
  /// degrade to metadata hygiene issues, never security failures).
  #[n(3)]
  issuer: String,
}

/// One cleanup checkpoint (ADR-0009 decision 5): an unsigned, max-wins
/// record that rides the sync plane and declares one wall-clock watermark.
/// It is hygiene knowledge, not authorization: it never gates live
/// entries, revocation records, or bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CleanupCheckpointV1 {
  watermark_millis: u64,
  issuer: NodeId,
}

impl CleanupCheckpointV1 {
  pub(crate) const fn new(watermark_millis: u64, issuer: NodeId) -> Self {
    Self {
      watermark_millis,
      issuer,
    }
  }

  pub(crate) const fn watermark_millis(&self) -> u64 {
    self.watermark_millis
  }

  pub(crate) const fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_wire(&CheckpointWire {
      schema: CHECKPOINT_SCHEMA.to_owned(),
      record_version: 1,
      watermark_millis: self.watermark_millis,
      issuer: self.issuer.as_str().to_owned(),
    })
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: CheckpointWire = crate::protocol::decode_canonical_strict(
      bytes,
      CLEANUP_LIMITS,
      "cleanup checkpoint canonical form",
    )
    .map_err(|_| Error::invalid_input("cleanup checkpoint"))?;
    if wire.schema != CHECKPOINT_SCHEMA || wire.record_version != 1 {
      return Err(Error::invalid_input("cleanup checkpoint schema"));
    }
    Ok(Self {
      watermark_millis: wire.watermark_millis,
      issuer: NodeId::parse(&wire.issuer)?,
    })
  }
}

fn checkpoint_key() -> StoreKey {
  StoreKey::new(Arc::from(b"checkpoint".to_vec()))
}

fn checkpoint_namespace() -> Result<StoreNamespace> {
  metadata_namespace(CHECKPOINT_NAMESPACE)
}

/// Issues a new cleanup checkpoint at the current wall clock: max-wins,
/// so a stored checkpoint with a higher watermark survives untouched and
/// a lower request is a no-op returning the stored watermark.
pub(crate) async fn issue_checkpoint_ctx(
  context: &LocalIdentityContext, entropy: &dyn Entropy,
) -> Result<u64> {
  let identity = context.identity();
  let requested = crate::time::now_millis();
  let checkpoint = CleanupCheckpointV1::new(requested, identity.node().clone());
  let namespace = checkpoint_namespace()?;
  let key = checkpoint_key();
  let snapshot = context.store().snapshot().await?;
  if let Some(existing) = snapshot.get(&namespace, &key).await? {
    let stored = CleanupCheckpointV1::decode(existing.as_bytes())?;
    if stored.watermark_millis >= requested {
      return Ok(stored.watermark_millis);
    }
  }
  let expected = crate::provider::snapshot_expectation(snapshot.as_ref(), &namespace, &key).await?;
  let transaction = context.store().prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![StoreOperation::Put {
      namespace,
      key,
      expected,
      value: StoreValue::new(Arc::from(checkpoint.encode()?)),
    }],
  )?;
  drop(snapshot);
  match context.store().commit(transaction).await? {
    crate::CommitOutcome::Committed(_) => Ok(requested),
    // A raced higher checkpoint won: report its watermark.
    crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => {
      let snapshot = context.store().snapshot().await?;
      match snapshot
        .get(&checkpoint_namespace()?, &checkpoint_key())
        .await?
      {
        Some(existing) => Ok(CleanupCheckpointV1::decode(existing.as_bytes())?.watermark_millis),
        None => Err(Error::conflict("cleanup checkpoint")),
      }
    }
    crate::CommitOutcome::Unknown { .. } => Err(Error::provider(
      crate::ProviderErrorKind::CommitUnknown,
      crate::ProviderErrorContext::StorageCommit,
    )),
  }
}

/// The latest local checkpoint watermark, if any.
pub(crate) async fn latest_checkpoint_millis_ctx(store: &MetadataStore) -> Result<Option<u64>> {
  let snapshot = store.snapshot().await?;
  let Some(value) = snapshot
    .get(&checkpoint_namespace()?, &checkpoint_key())
    .await?
  else {
    return Ok(None);
  };
  Ok(Some(
    CleanupCheckpointV1::decode(value.as_bytes())?.watermark_millis,
  ))
}

/// Persists one checkpoint received over sync: max-wins by watermark, so
/// stale epochs from stragglers never roll the local watermark back.
pub(crate) async fn persist_checkpoint_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, checkpoint: &CleanupCheckpointV1,
) -> Result<()> {
  let namespace = checkpoint_namespace()?;
  let key = checkpoint_key();
  let snapshot = store.snapshot().await?;
  if let Some(existing) = snapshot.get(&namespace, &key).await? {
    let stored = CleanupCheckpointV1::decode(existing.as_bytes())?;
    if stored.watermark_millis >= checkpoint.watermark_millis {
      return Ok(());
    }
  }
  let expected = crate::provider::snapshot_expectation(snapshot.as_ref(), &namespace, &key).await?;
  let transaction = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![StoreOperation::Put {
      namespace,
      key,
      expected,
      value: StoreValue::new(Arc::from(checkpoint.encode()?)),
    }],
  )?;
  drop(snapshot);
  let _ = store.commit(transaction).await?;
  Ok(())
}

/// The checkpoint GC pass (ADR-0009 decision 5): after sync rounds, delete
/// the collected leave and cleanup tombstones stamped at or before the
/// latest local checkpoint watermark, reusing the conditional exact-digest
/// delete. Bounded per pass; a raced delete conflicts and stays for the
/// next pass. Revocation records are never collected here (permanent),
/// and live entries are never touched (the filter is removal-only).
pub(crate) async fn collect_collected_tombstones_ctx(
  store: &MetadataStore, entropy: &dyn Entropy,
) -> Result<usize> {
  let Some(watermark) = latest_checkpoint_millis_ctx(store).await? else {
    return Ok(0);
  };
  let mut collected = crate::identity::leave::collect_before_ctx(store, entropy, watermark).await?;
  collected += collect_cleanup_before_ctx(store, entropy, watermark).await?;
  Ok(collected)
}

/// The cleanup-side sweep: conditional exact-digest deletes of collected
/// cleanup tombstones, bounded by [`GC_BATCH`].
async fn collect_cleanup_before_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, watermark: u64,
) -> Result<usize> {
  let namespace = metadata_namespace(CLEANUP_NAMESPACE)?;
  let known = known_cleanup_records_ctx(store, GC_BATCH).await?;
  collect_before_in(store, entropy, namespace, watermark, &known).await
}

/// The bounded per-pass GC batch: one sweep deletes at most this many
/// collected tombstones; the next sync round continues.
const GC_BATCH: usize = 64;

/// Conditional exact-digest deletes for the collected records in one
/// namespace. `known` is the already-decoded record list for that
/// namespace (the caller bounds it); each delete pins the stored value's
/// digest, so a raced write conflicts instead of deleting blind.
async fn collect_before_in(
  store: &MetadataStore, entropy: &dyn Entropy, namespace: StoreNamespace, watermark: u64,
  known: &[CleanupRecordV1],
) -> Result<usize> {
  let mut collected = 0_usize;
  for record in known {
    if record.timestamp_millis() > watermark {
      continue;
    }
    let snapshot = store.snapshot().await?;
    let key = cleanup_key(record.subject());
    let Some(existing) = snapshot.get(&namespace, &key).await? else {
      continue;
    };
    let transaction = store.prepare_transaction(
      TransactionId::generate(entropy)?,
      snapshot.revision().clone(),
      vec![StoreOperation::Delete {
        namespace: namespace.clone(),
        key,
        expected: existing.digest().clone(),
      }],
    )?;
    drop(snapshot);
    // A raced write on this tombstone conflicts: it stays for the next
    // pass (hygiene, never security).
    if let crate::CommitOutcome::Committed(_) = store.commit(transaction).await? {
      collected += 1;
    }
  }
  Ok(collected)
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{
    CHECKPOINT_NAMESPACE, CLEANUP_RECORD_V1_DOMAIN, CleanupCheckpointV1, CleanupRecordV1,
    cleaned_nodes_ctx, collect_collected_tombstones_ctx, is_cleaned_ctx, issue_checkpoint_ctx,
    known_cleanup_records_ctx, latest_checkpoint_millis_ctx, metadata_namespace,
    persist_cleanup_record_ctx, sign_cleanup_record,
  };
  use crate::{
    ErrorKind, NodeId, PublicKey, Signature,
    identity::{
      lifecycle::{self, ensure_self_binding},
      signature::signature_message,
      testing::{ScriptedKeys, SequenceEntropy, node, scripted_signing},
      trust::store::adopt_binding_ctx,
    },
    provider::StorageFactory,
    storage::contract::{ReferenceFactory, required_capabilities},
  };

  fn reference_factory() -> Arc<dyn StorageFactory> {
    Arc::new(ReferenceFactory::new(required_capabilities()))
  }

  /// A cleanup tombstone signed by the local identity with an explicit
  /// (test-chosen) removal timestamp: the signature covers the stamp, so
  /// the checkpoint GC can order it against watermarks.
  async fn stamped_tombstone(
    context: &lifecycle::LocalIdentityContext, keys: &Arc<ScriptedKeys>, subject: &NodeId,
    subject_key: &PublicKey, stamp: u64,
  ) -> CleanupRecordV1 {
    let identity = context.identity();
    let body =
      CleanupRecordV1::encode_signed_body(subject, subject_key, identity.node(), stamp).unwrap();
    let signature = keys
      .as_provider()
      .sign(
        identity.handle(),
        &signature_message(CLEANUP_RECORD_V1_DOMAIN, &body),
      )
      .await
      .unwrap();
    CleanupRecordV1::new(
      subject.clone(),
      subject_key.clone(),
      identity.node().clone(),
      stamp,
      signature,
    )
  }

  /// SC-G11-P0-19: the cleanup tombstone signs, round-trips, and verifies;
  /// any body or signature mutation fails verification.
  #[tokio::test]
  async fn cleanup_record_signs_round_trips_and_rejects_mutation() {
    let factory = reference_factory();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = lifecycle::open_local_identity(
      &factory,
      &keys.as_provider(),
      entropy.as_ref(),
      std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();
    ensure_self_binding(&context, entropy.as_ref())
      .await
      .unwrap();
    let subject = node(7_000);
    let subject_key = PublicKey::from_bytes(scripted_signing(7).verifying_key().to_bytes());
    adopt_binding_ctx(context.store(), entropy.as_ref(), &subject, &subject_key)
      .await
      .unwrap();

    let record = sign_cleanup_record(&context, &keys.as_provider(), &subject)
      .await
      .unwrap();
    assert_eq!(record.subject(), &subject);
    assert_eq!(record.issuer(), context.identity().node());
    record.verify(context.identity().public_key()).unwrap();
    let decoded = CleanupRecordV1::decode(&record.encode().unwrap()).unwrap();
    assert_eq!(decoded, record);
    decoded.verify(context.identity().public_key()).unwrap();

    let forged = CleanupRecordV1::new(
      subject.clone(),
      subject_key.clone(),
      record.issuer().clone(),
      record.timestamp_millis(),
      Signature::from_bytes([0x5A; 64]),
    );
    assert!(forged.verify(context.identity().public_key()).is_err());
  }

  /// SC-G11-P0-20: persistence verifies the issuer binding, is idempotent
  /// for the exact record, and fails closed on divergent subject keys and
  /// unknown issuers; the cleaned set is queryable for exclusion.
  #[tokio::test]
  async fn cleanup_record_persists_idempotently_and_marks_cleaned() {
    let factory = reference_factory();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = lifecycle::open_local_identity(
      &factory,
      &keys.as_provider(),
      entropy.as_ref(),
      std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();
    ensure_self_binding(&context, entropy.as_ref())
      .await
      .unwrap();
    let subject = node(7_100);
    let subject_key = PublicKey::from_bytes(scripted_signing(71).verifying_key().to_bytes());
    adopt_binding_ctx(context.store(), entropy.as_ref(), &subject, &subject_key)
      .await
      .unwrap();

    let record = sign_cleanup_record(&context, &keys.as_provider(), &subject)
      .await
      .unwrap();
    assert!(!is_cleaned_ctx(context.store(), &subject).await.unwrap());
    persist_cleanup_record_ctx(context.store(), entropy.as_ref(), &record)
      .await
      .unwrap();
    persist_cleanup_record_ctx(context.store(), entropy.as_ref(), &record)
      .await
      .unwrap();
    assert!(is_cleaned_ctx(context.store(), &subject).await.unwrap());
    assert!(
      cleaned_nodes_ctx(context.store())
        .await
        .unwrap()
        .contains(&subject)
    );
    assert_eq!(
      known_cleanup_records_ctx(context.store(), 64)
        .await
        .unwrap()
        .len(),
      1
    );

    // A divergent record for the same subject fails closed.
    let divergent = CleanupRecordV1::new(
      subject.clone(),
      subject_key.clone(),
      record.issuer().clone(),
      record.timestamp_millis(),
      Signature::from_bytes([0x5A; 64]),
    );
    let error = persist_cleanup_record_ctx(context.store(), entropy.as_ref(), &divergent)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  }

  /// SC-G11-P0-24/25: the GC pass collects only the tombstones at or
  /// before the checkpoint watermark — newer tombstones and revocation
  /// records stay, and the subject's binding stays as the permanent
  /// anchor. The checkpoint is max-wins by watermark.
  #[tokio::test]
  async fn checkpoint_gc_collects_only_up_to_the_watermark() {
    use crate::{
      StoreExpectation, StoreKey, StoreOperation, StoreValue,
      identity::revocation::{RevocationRecordV1, is_revoked_ctx},
    };

    let factory = reference_factory();
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = lifecycle::open_local_identity(
      &factory,
      &keys.as_provider(),
      entropy.as_ref(),
      std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();
    ensure_self_binding(&context, entropy.as_ref())
      .await
      .unwrap();

    // Two cleaned subjects: one stamped before the watermark, one after.
    let stale_subject = node(7_200);
    let stale_key = PublicKey::from_bytes(scripted_signing(72).verifying_key().to_bytes());
    let fresh_subject = node(7_300);
    let fresh_key = PublicKey::from_bytes(scripted_signing(73).verifying_key().to_bytes());
    adopt_binding_ctx(
      context.store(),
      entropy.as_ref(),
      &stale_subject,
      &stale_key,
    )
    .await
    .unwrap();
    adopt_binding_ctx(
      context.store(),
      entropy.as_ref(),
      &fresh_subject,
      &fresh_key,
    )
    .await
    .unwrap();

    // Tombstones signed by the local identity with explicit stamps: the
    // signature covers the timestamp, so each body is signed exactly.
    let stale = stamped_tombstone(&context, &keys, &stale_subject, &stale_key, 1_000).await;
    let fresh = stamped_tombstone(&context, &keys, &fresh_subject, &fresh_key, 9_000).await;
    persist_cleanup_record_ctx(context.store(), entropy.as_ref(), &stale)
      .await
      .unwrap();
    persist_cleanup_record_ctx(context.store(), entropy.as_ref(), &fresh)
      .await
      .unwrap();

    // A revocation record for a third subject: the permanent class is
    // never collected by the checkpoint GC.
    let expelled = node(7_400);
    let expelled_key = PublicKey::from_bytes(scripted_signing(74).verifying_key().to_bytes());
    adopt_binding_ctx(context.store(), entropy.as_ref(), &expelled, &expelled_key)
      .await
      .unwrap();
    let revocation_body =
      RevocationRecordV1::encode_signed_body(&expelled, &expelled_key, context.identity().node())
        .unwrap();
    let revocation_signature = keys
      .as_provider()
      .sign(
        context.identity().handle(),
        &signature_message(
          crate::identity::revocation::REVOCATION_RECORD_V1_DOMAIN,
          &revocation_body,
        ),
      )
      .await
      .unwrap();
    let revocation = RevocationRecordV1::new(
      expelled.clone(),
      expelled_key.clone(),
      context.identity().node().clone(),
      revocation_signature,
    );
    crate::identity::revocation::persist_revocation_ctx(
      context.store(),
      entropy.as_ref(),
      &revocation,
    )
    .await
    .unwrap();

    // The checkpoint (written directly: unsigned hygiene knowledge)
    // declares a watermark between the two tombstone stamps.
    let checkpoint = CleanupCheckpointV1::new(5_000, context.identity().node().clone());
    let snapshot = context.store().snapshot().await.unwrap();
    let transaction = context
      .store()
      .prepare_transaction(
        crate::TransactionId::generate(entropy.as_ref()).unwrap(),
        snapshot.revision().clone(),
        vec![StoreOperation::Put {
          namespace: metadata_namespace(CHECKPOINT_NAMESPACE).unwrap(),
          key: StoreKey::new(Arc::from(b"checkpoint".to_vec())),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(checkpoint.encode().unwrap())),
        }],
      )
      .unwrap();
    assert!(matches!(
      context.store().commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));

    // The sweep collects exactly the stale tombstone; the fresh tombstone,
    // the revocation, and every binding stay.
    let collected = collect_collected_tombstones_ctx(context.store(), entropy.as_ref())
      .await
      .unwrap();
    assert_eq!(collected, 1);
    assert!(
      !is_cleaned_ctx(context.store(), &stale_subject)
        .await
        .unwrap()
    );
    assert!(
      is_cleaned_ctx(context.store(), &fresh_subject)
        .await
        .unwrap()
    );
    assert!(
      is_revoked_ctx(context.store(), &expelled, &expelled_key)
        .await
        .unwrap()
    );

    // Max-wins: issuing again cannot roll the epoch back.
    let watermark = latest_checkpoint_millis_ctx(context.store()).await.unwrap();
    assert_eq!(watermark, Some(5_000));
    let issued = issue_checkpoint_ctx(&context, entropy.as_ref())
      .await
      .unwrap();
    assert!(issued >= 5_000);
  }
}
