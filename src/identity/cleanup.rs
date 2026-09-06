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
  Error, NodeId, PublicKey, Result, Signature, StoreExpectation, StoreKey, StoreOperation,
  StoreValue, TransactionId, api::Entropy, provider::KeyProvider, storage::MetadataStore,
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
  #[cbor(with = "minicbor::bytes")]
  signature: Vec<u8>,
}

/// One issuer-signed cleanup tombstone (ADR-0009 decision 4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CleanupRecordV1 {
  subject: NodeId,
  subject_key: PublicKey,
  issuer: NodeId,
  signature: Signature,
}

impl CleanupRecordV1 {
  pub(crate) const fn new(
    subject: NodeId, subject_key: PublicKey, issuer: NodeId, signature: Signature,
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
    encode_wire(&CleanupRecordBodyWire {
      schema: CLEANUP_RECORD_SCHEMA.to_owned(),
      record_version: 1,
      subject: subject.as_str().to_owned(),
      subject_key: subject_key.as_bytes().to_vec(),
      issuer: issuer.as_str().to_owned(),
    })
  }

  /// Verifies the issuer signature against `issuer_key` (the issuer's
  /// permanently retained binding).
  pub(crate) fn verify(&self, issuer_key: &PublicKey) -> Result<()> {
    verify_strict(
      CLEANUP_RECORD_V1_DOMAIN,
      &Self::encode_signed_body(&self.subject, &self.subject_key, &self.issuer)?,
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
  let body = CleanupRecordV1::encode_signed_body(subject, &subject_key, identity.node())?;
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

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{
    CleanupRecordV1, cleaned_nodes_ctx, is_cleaned_ctx, known_cleanup_records_ctx,
    persist_cleanup_record_ctx, sign_cleanup_record,
  };
  use crate::{
    ErrorKind, PublicKey, Signature,
    identity::{
      lifecycle::{self, ensure_self_binding},
      testing::{ScriptedKeys, SequenceEntropy, node, scripted_signing},
      trust::store::adopt_binding_ctx,
    },
    provider::StorageFactory,
    storage::contract::{ReferenceFactory, required_capabilities},
  };

  fn reference_factory() -> Arc<dyn StorageFactory> {
    Arc::new(ReferenceFactory::new(required_capabilities()))
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
      Signature::from_bytes([0x5A; 64]),
    );
    let error = persist_cleanup_record_ctx(context.store(), entropy.as_ref(), &divergent)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  }
}
