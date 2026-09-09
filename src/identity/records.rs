use std::sync::Arc;

use minicbor::{Decode, Encode};

use super::{
  lifecycle::LocalIdentityContext,
  signature::{MERGE_GRANT_V1_DOMAIN, signature_message, verify_strict},
};
use crate::{
  BoxFuture, Error, KeyHandle, KeyOperationId, NodeId, OperationId, PublicKey, Result, Signature,
  StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreRevision, StoreValue,
  TransactionId,
  api::Entropy,
  error::fixed_bytes,
  protocol::{CborLimits, decode_canonical_strict, encode_canonical},
  provider::KeyProvider,
  storage::{
    MetadataStore,
    receipt::{ReceiptIdentity, ReceiptReferenceToken, recover_self_referenced_transaction},
  },
};

const RECORD_VERSION: u64 = 1;
/// The typed journal purpose of a durable intent or pending transaction.
///
/// Purposes become persistent storage values, so every producer builds them
/// through this single encoding instead of concatenating strings by hand; a
/// typo here is caught once, at the enum definition.
/// The durable purpose text of the fixed variants, single-sourced so
/// producers, wire code, and tests all reference one literal.
pub(crate) const LOCAL_IDENTITY_PURPOSE_TEXT: &str = "local-identity";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalPurpose {
  /// One credential merge attempt, keyed by issuer generation.
  Merge(GenerationId),
  /// One merge adoption attempt, keyed by merge id.
  MergeAdoption(MergeId),
  /// One key deletion intent, keyed by provider handle digest.
  KeyDeletion(KeyHandle),
}

impl JournalPurpose {
  /// The durable purpose text; the hex-suffixed variants share the crate
  /// codec so wire and persisted values cannot drift in formatting.
  pub(crate) fn text(&self) -> String {
    match self {
      Self::Merge(generation) => {
        format!("merge-{}", crate::hex::encode(generation.as_bytes()))
      }
      Self::MergeAdoption(merge) => {
        format!("merge-adoption-{}", crate::hex::encode(merge.as_bytes()))
      }
      Self::KeyDeletion(handle) => {
        format!(
          "key-delete-{}",
          crate::hex::encode(handle.expose_provider_handle())
        )
      }
    }
  }
}

const ED25519_ALGORITHM: &str = "radiata.woooo.tech/crypto/ed25519";
const MAX_PURPOSE_LEN: usize = 128;

/// The intent-purpose grammar (single source): nonempty, bounded, and
/// printable ASCII, with the caller's context in the typed error.
fn validate_purpose(purpose: &str, context: &'static str) -> Result<()> {
  if purpose.is_empty()
    || purpose.len() > MAX_PURPOSE_LEN
    || !purpose.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
  {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

const LOCAL_IDENTITY_SCHEMA: &str = "radiata.woooo.tech/schemas/local-identity-v1";
const KEY_CREATION_INTENT_SCHEMA: &str = "radiata.woooo.tech/schemas/key-creation-intent-v1";
const IDENTITY_BINDING_SCHEMA: &str = "radiata.woooo.tech/schemas/identity-binding-v1";
const CREDENTIAL_USE_SCHEMA: &str = "radiata.woooo.tech/schemas/credential-use-v1";
const MERGE_GRANT_SCHEMA: &str = "radiata.woooo.tech/schemas/merge-grant-v1";
const KEY_DELETION_INTENT_SCHEMA: &str = "radiata.woooo.tech/schemas/key-deletion-intent-v1";
const KEY_DELETED_SCHEMA: &str = "radiata.woooo.tech/schemas/key-deleted-v1";

pub(crate) use crate::storage::families::{
  CREDENTIAL_USE_NAMESPACE, IDENTITY_BINDING_NAMESPACE, KEY_CREATION_INTENT_NAMESPACE,
  KEY_DELETED_NAMESPACE, KEY_DELETION_INTENT_NAMESPACE, LOCAL_IDENTITY_NAMESPACE,
  MERGE_GRANT_NAMESPACE,
};

const SINGLETON_KEY: &[u8] = b"self";
const RECORD_LIMITS: CborLimits = CborLimits::new(1, 16, 1_024);

fn decode_wire<'bytes, T>(bytes: &'bytes [u8]) -> Result<T>
where
  T: Decode<'bytes, ()> + Encode<()>, {
  decode_canonical_strict(bytes, RECORD_LIMITS, "identity record canonical form")
}

fn expect_schema(actual: &str, expected: &str) -> Result<()> {
  if actual != expected {
    return Err(Error::invalid_input("identity record schema"));
  }
  Ok(())
}

fn expect_version(actual: u64) -> Result<()> {
  if actual != RECORD_VERSION {
    return Err(Error::invalid_input("identity record version"));
  }
  Ok(())
}

fn expect_algorithm(actual: &str) -> Result<()> {
  if actual != ED25519_ALGORITHM {
    return Err(Error::invalid_input("identity record algorithm"));
  }
  Ok(())
}

pub(crate) fn metadata_namespace(tag: &str) -> Result<StoreNamespace> {
  crate::storage::families::namespace(tag)
}

fn store_key(bytes: &[u8]) -> StoreKey {
  StoreKey::new(Arc::from(bytes))
}

pub(crate) fn local_identity_key() -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(LOCAL_IDENTITY_NAMESPACE)?,
    store_key(SINGLETON_KEY),
  ))
}

pub(crate) fn key_creation_intent_namespace() -> Result<StoreNamespace> {
  metadata_namespace(KEY_CREATION_INTENT_NAMESPACE)
}

pub(crate) fn identity_binding_namespace() -> Result<StoreNamespace> {
  metadata_namespace(IDENTITY_BINDING_NAMESPACE)
}

pub(crate) fn key_creation_intent_key(
  operation: &KeyOperationId,
) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(KEY_CREATION_INTENT_NAMESPACE)?,
    store_key(operation.as_str().as_bytes()),
  ))
}

pub(crate) fn identity_binding_key(node: &NodeId) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(IDENTITY_BINDING_NAMESPACE)?,
    store_key(node.as_str().as_bytes()),
  ))
}

pub(crate) fn credential_use_key(
  issuer: &NodeId, generation: &GenerationId,
) -> Result<(StoreNamespace, StoreKey)> {
  // No separator: `NodeId` is fixed-width (base62, exactly
  // `NodeId::TEXT_LEN` characters) and `GenerationId` is a fixed 16
  // bytes, so the issuer/generation split is unambiguous by position.
  let mut key = Vec::with_capacity(issuer.as_str().len() + generation.as_bytes().len());
  key.extend_from_slice(issuer.as_str().as_bytes());
  key.extend_from_slice(generation.as_bytes());
  Ok((
    metadata_namespace(CREDENTIAL_USE_NAMESPACE)?,
    store_key(&key),
  ))
}

pub(crate) fn merge_grant_key(admission: &MergeId) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(MERGE_GRANT_NAMESPACE)?,
    store_key(admission.as_bytes()),
  ))
}

#[cfg(test)]
pub(crate) fn key_deletion_intent_namespace() -> Result<StoreNamespace> {
  metadata_namespace(KEY_DELETION_INTENT_NAMESPACE)
}

#[cfg(test)]
pub(crate) fn key_deleted_namespace() -> Result<StoreNamespace> {
  metadata_namespace(KEY_DELETED_NAMESPACE)
}

pub(crate) fn key_deletion_intent_key(handle: &KeyHandle) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(KEY_DELETION_INTENT_NAMESPACE)?,
    store_key(handle.expose_provider_handle()),
  ))
}

pub(crate) fn key_deleted_key(handle: &KeyHandle) -> Result<(StoreNamespace, StoreKey)> {
  Ok((
    metadata_namespace(KEY_DELETED_NAMESPACE)?,
    store_key(handle.expose_provider_handle()),
  ))
}

/// The two keys whose presence marks a key handle as spent: one carries
/// the deletion intent, the other the deletion tombstone.
pub(crate) fn key_handle_guard_keys(handle: &KeyHandle) -> Result<[(StoreNamespace, StoreKey); 2]> {
  Ok([key_deletion_intent_key(handle)?, key_deleted_key(handle)?])
}

/// The handle-freshness snapshot check shared by the leave swap and the
/// identity finalize: a handle carrying a deletion intent or tombstone
/// must never be referenced by a new record again. Pair with
/// [`key_handle_fresh_checks`], the transactional twin covering the
/// window between this snapshot and the commit.
pub(crate) async fn assert_key_handle_fresh(
  snapshot: &dyn crate::provider::StoreSnapshot, handle: &KeyHandle,
) -> Result<()> {
  for (namespace, key) in key_handle_guard_keys(handle)? {
    if snapshot.get(&namespace, &key).await?.is_some() {
      return Err(Error::conflict("key handle reuse"));
    }
  }
  Ok(())
}

/// The transactional twin of [`assert_key_handle_fresh`]: the two Absent
/// checks a journaled commit installs for the handle's guard keys.
pub(crate) fn key_handle_fresh_checks(handle: &KeyHandle) -> Result<[StoreOperation; 2]> {
  let keys = key_handle_guard_keys(handle)?;
  Ok(keys.map(|(namespace, key)| StoreOperation::Check {
    namespace,
    key,
    expected: StoreExpectation::Absent,
  }))
}

/// The shared idempotent install for one terminal tombstone record
/// (`LeaveRecordV1`, `CleanupRecordV1`, `RevocationRecordV1`): a
/// snapshot-identical record is a no-op, any divergence conflicts, and a
/// fresh record installs through one conditional Absent put. The caller
/// holds the store's writer permit and has already verified the record
/// against the retained bindings; `label` names the family in the
/// conflict error.
pub(crate) async fn persist_terminal_record(
  store: &MetadataStore, entropy: &dyn Entropy, namespace: StoreNamespace, key: StoreKey,
  encoded: Arc<[u8]>, label: &'static str,
) -> Result<()> {
  let snapshot = store.snapshot().await?;
  if let Some(existing) = snapshot.get(&namespace, &key).await? {
    if existing.as_bytes() == encoded.as_ref() {
      return Ok(());
    }
    return Err(Error::conflict(label));
  }
  let transaction = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![StoreOperation::Put {
      namespace,
      key,
      expected: StoreExpectation::Absent,
      value: StoreValue::new(encoded),
    }],
  )?;
  drop(snapshot);
  let _ = store.commit(transaction).await?;
  Ok(())
}

/// The scan skip predicate for families whose namespace carries no extra
/// singleton keys.
pub(crate) fn skip_none(_: &StoreKey) -> bool {
  false
}

/// The shared bounded known-records scan for the terminal tombstone
/// families: one ordered namespace scan decoded through `decode`, capped
/// at `cap` records, skipping keys the family excludes (the leave intent
/// singleton shares its family's namespace).
/// The shared bounded known-records scan for the terminal tombstone
/// families: one ordered namespace scan decoded through `decode`, capped
/// at `cap` records, skipping keys `skip` excludes (the leave intent
/// singleton shares its family's namespace). Function pointers keep the
/// returned future's Send proof simple; the decoders are associated
/// functions already returning crate results.
pub(crate) fn scan_decoded_records<'a, T>(
  store: &'a MetadataStore, namespace: StoreNamespace, cap: usize, skip: fn(&StoreKey) -> bool,
  decode: fn(&[u8]) -> Result<T>,
) -> BoxFuture<'a, Result<Vec<T>>>
where
  T: Send + 'a, {
  Box::pin(async move {
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut records = Vec::new();
    while let Some(entry) = scan.next().await? {
      if skip(entry.key()) {
        continue;
      }
      records.push(decode(entry.value().as_bytes())?);
      if records.len() >= cap {
        break;
      }
    }
    Ok(records)
  })
}

/// The shared signed-tombstone driver behind the leave, cleanup, and
/// revocation signers: encodes the canonical body through `body` against
/// the local identity, signs it under `domain`, and fails closed through
/// a strict self-verification under `label` before returning the
/// signature. A driver assembles its record from the verified pair, so
/// a signing or assembly bug can never emit an unverifiable tombstone.
pub(crate) async fn sign_tombstone(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, domain: &'static [u8],
  label: &'static str, body: impl FnOnce(&LocalIdentityV1) -> Result<Vec<u8>>,
) -> Result<Signature> {
  let identity = context.identity();
  let body = body(identity)?;
  let signature = keys
    .sign(identity.handle(), &signature_message(domain, &body))
    .await?;
  verify_strict(domain, &body, identity.public_key(), &signature, label)?;
  Ok(signature)
}

/// Whether one exact key is present in a metadata namespace (snapshot
/// read only).
pub(crate) async fn key_present(
  store: &MetadataStore, namespace: &StoreNamespace, key: &StoreKey,
) -> Result<bool> {
  let snapshot = store.snapshot().await?;
  Ok(snapshot.get(namespace, key).await?.is_some())
}

/// The subjects of decoded tombstone records, collected into the ordered
/// set the exclusion sweeps consume.
pub(crate) fn collect_subjects<T>(
  records: &[T], subject: fn(&T) -> &NodeId,
) -> std::collections::BTreeSet<NodeId> {
  records
    .iter()
    .map(|record| subject(record).clone())
    .collect()
}

/// The bounded per-pass tombstone GC batch shared by the leave and
/// cleanup sweeps: one pass deletes at most this many collected
/// tombstones; the next sync round continues.
pub(crate) const TOMBSTONE_GC_BATCH: usize = 64;

/// The shared checkpoint sweep body: conditional exact-digest deletes of
/// `entries` (record key plus collection timestamp) stamped at or before
/// `watermark`. A raced write on a tombstone conflicts and stays for the
/// next pass (hygiene, never security). Holds the writer permit across
/// the sweep like every identity phase.
pub(crate) async fn collect_tombstones_before(
  store: &MetadataStore, entropy: &dyn Entropy, namespace: StoreNamespace, watermark: u64,
  entries: &[(StoreKey, u64)],
) -> Result<usize> {
  let _permit = store.write_permit().await;
  let mut collected = 0_usize;
  for (key, stamp_millis) in entries {
    let (key, stamp_millis) = (key.clone(), *stamp_millis);
    if stamp_millis > watermark {
      continue;
    }
    let snapshot = store.snapshot().await?;
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
    if let crate::CommitOutcome::Committed(_) = store.commit(transaction).await? {
      collected += 1;
    }
  }
  Ok(collected)
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct GenerationId(OperationId);

impl GenerationId {
  #[cfg(any(test, fuzzing))]
  pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
    OperationId::generate(entropy).map(Self)
  }

  /// Rebuilds a generation from its raw 16 bytes (e.g. the join
  /// credential's reserved generation) without laundering the value
  /// through an unrelated operation id at the call site.
  pub(crate) const fn from_bytes(value: [u8; 16]) -> Self {
    Self(OperationId::from_bytes(value))
  }

  pub(crate) const fn from_operation(operation: OperationId) -> Self {
    Self(operation)
  }

  pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
    self.0.as_bytes()
  }
}

impl std::fmt::Debug for GenerationId {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("GenerationId(..)")
  }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MergeId(OperationId);

impl MergeId {
  pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self> {
    OperationId::generate(entropy).map(Self)
  }

  pub(crate) const fn from_operation(operation: OperationId) -> Self {
    Self(operation)
  }

  pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
    self.0.as_bytes()
  }
}

impl std::fmt::Debug for MergeId {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("MergeId(..)")
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct LocalIdentityWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  node_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  public_key: Vec<u8>,
  #[n(4)]
  algorithm: String,
  #[n(5)]
  key_operation_id: String,
  #[n(6)]
  #[cbor(with = "minicbor::bytes")]
  key_handle: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalIdentityV1 {
  node: NodeId,
  public_key: PublicKey,
  operation: KeyOperationId,
  handle: KeyHandle,
}

impl LocalIdentityV1 {
  pub(crate) const fn new(
    node: NodeId, public_key: PublicKey, operation: KeyOperationId, handle: KeyHandle,
  ) -> Self {
    Self {
      node,
      public_key,
      operation,
      handle,
    }
  }

  pub(crate) fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  /// The operation id of the bootstrap intent that created this record
  /// (test-verified against the admission state machine).
  #[cfg(test)]
  pub(crate) fn operation(&self) -> &KeyOperationId {
    &self.operation
  }

  pub(crate) fn handle(&self) -> &KeyHandle {
    &self.handle
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &LocalIdentityWire {
        schema: LOCAL_IDENTITY_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: self.node.as_str().to_owned(),
        public_key: self.public_key.as_bytes().to_vec(),
        algorithm: ED25519_ALGORITHM.to_owned(),
        key_operation_id: self.operation.as_str().to_owned(),
        key_handle: self.handle.expose_provider_handle().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: LocalIdentityWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, LOCAL_IDENTITY_SCHEMA)?;
    expect_version(wire.record_version)?;
    expect_algorithm(&wire.algorithm)?;
    Ok(Self {
      node: NodeId::parse(&wire.node_id)?,
      public_key: PublicKey::from_bytes(fixed_bytes(&wire.public_key, "identity public key")?),
      operation: KeyOperationId::parse(&wire.key_operation_id)?,
      handle: KeyHandle::from_provider_bytes(Arc::from(wire.key_handle))?,
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct KeyCreationIntentWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  operation: String,
  #[n(3)]
  intended_node: String,
  #[n(4)]
  purpose: String,
  #[n(5)]
  algorithm: String,
  #[n(6)]
  transaction: String,
  #[n(7)]
  #[cbor(with = "minicbor::bytes")]
  base_revision: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyCreationIntentV1 {
  operation: KeyOperationId,
  intended_node: NodeId,
  purpose: String,
  transaction: TransactionId,
  base_revision: StoreRevision,
}

impl KeyCreationIntentV1 {
  pub(crate) fn new(
    operation: KeyOperationId, intended_node: NodeId, purpose: String, transaction: TransactionId,
    base_revision: StoreRevision,
  ) -> Result<Self> {
    validate_purpose(&purpose, "key creation intent purpose")?;
    Ok(Self {
      operation,
      intended_node,
      purpose,
      transaction,
      base_revision,
    })
  }

  pub(crate) fn operation(&self) -> &KeyOperationId {
    &self.operation
  }

  pub(crate) fn intended_node(&self) -> &NodeId {
    &self.intended_node
  }

  pub(crate) fn purpose(&self) -> &str {
    &self.purpose
  }

  pub(crate) const fn transaction(&self) -> &TransactionId {
    &self.transaction
  }

  /// The store revision the intent was prepared against (test-verified;
  /// recovery reads the field directly).
  #[cfg(test)]
  pub(crate) const fn base_revision(&self) -> &StoreRevision {
    &self.base_revision
  }

  /// Reconstructs the exact storage receipt identity committed with this
  /// intent from the stored intent value.
  ///
  /// The original commit paired the intent `Put` with an `AddSelf` receipt
  /// reference carrying the intent record token, so recovery needs only the
  /// stored value and the transaction coordinates recorded in the intent.
  pub(crate) fn recovery_identity(&self, stored_value: &StoreValue) -> Result<ReceiptIdentity> {
    let (namespace, key) = key_creation_intent_key(&self.operation)?;
    let token = ReceiptReferenceToken::for_record(&namespace, &key);
    recover_self_referenced_transaction(
      &self.transaction,
      &self.base_revision,
      vec![StoreOperation::Put {
        namespace,
        key,
        expected: StoreExpectation::Absent,
        value: stored_value.clone(),
      }],
      &[token],
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &KeyCreationIntentWire {
        schema: KEY_CREATION_INTENT_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        operation: self.operation.as_str().to_owned(),
        intended_node: self.intended_node.as_str().to_owned(),
        purpose: self.purpose.clone(),
        algorithm: ED25519_ALGORITHM.to_owned(),
        transaction: self.transaction.as_str().to_owned(),
        base_revision: self.base_revision.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: KeyCreationIntentWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, KEY_CREATION_INTENT_SCHEMA)?;
    expect_version(wire.record_version)?;
    expect_algorithm(&wire.algorithm)?;
    Self::new(
      KeyOperationId::parse(&wire.operation)?,
      NodeId::parse(&wire.intended_node)?,
      wire.purpose,
      TransactionId::parse(&wire.transaction)?,
      StoreRevision::new(Arc::from(wire.base_revision))?,
    )
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct KeyDeletionIntentWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  operation: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  handle: Vec<u8>,
  #[n(4)]
  purpose: String,
  #[n(5)]
  transaction: String,
  #[n(6)]
  #[cbor(with = "minicbor::bytes")]
  base_revision: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct KeyDeletionIntentV1 {
  operation: KeyOperationId,
  handle: KeyHandle,
  purpose: String,
  transaction: TransactionId,
  base_revision: StoreRevision,
}

impl KeyDeletionIntentV1 {
  pub(crate) fn new(
    operation: KeyOperationId, handle: KeyHandle, purpose: String, transaction: TransactionId,
    base_revision: StoreRevision,
  ) -> Result<Self> {
    validate_purpose(&purpose, "key deletion intent purpose")?;
    Ok(Self {
      operation,
      handle,
      purpose,
      transaction,
      base_revision,
    })
  }

  pub(crate) fn operation(&self) -> &KeyOperationId {
    &self.operation
  }

  pub(crate) fn handle(&self) -> &KeyHandle {
    &self.handle
  }

  pub(crate) fn purpose(&self) -> &str {
    &self.purpose
  }

  pub(crate) const fn transaction(&self) -> &TransactionId {
    &self.transaction
  }

  /// Reconstructs the exact storage receipt identity committed with this
  /// intent from the stored intent value, mirroring the creation-intent
  /// recovery path.
  pub(crate) fn recovery_identity(&self, stored_value: &StoreValue) -> Result<ReceiptIdentity> {
    let (namespace, key) = key_deletion_intent_key(&self.handle)?;
    let token = ReceiptReferenceToken::for_record(&namespace, &key);
    recover_self_referenced_transaction(
      &self.transaction,
      &self.base_revision,
      vec![StoreOperation::Put {
        namespace,
        key,
        expected: StoreExpectation::Absent,
        value: stored_value.clone(),
      }],
      &[token],
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &KeyDeletionIntentWire {
        schema: KEY_DELETION_INTENT_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        operation: self.operation.as_str().to_owned(),
        handle: self.handle.expose_provider_handle().to_vec(),
        purpose: self.purpose.clone(),
        transaction: self.transaction.as_str().to_owned(),
        base_revision: self.base_revision.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: KeyDeletionIntentWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, KEY_DELETION_INTENT_SCHEMA)?;
    expect_version(wire.record_version)?;
    Self::new(
      KeyOperationId::parse(&wire.operation)?,
      KeyHandle::from_provider_bytes(Arc::from(wire.handle))?,
      wire.purpose,
      TransactionId::parse(&wire.transaction)?,
      StoreRevision::new(Arc::from(wire.base_revision))?,
    )
  }
}

impl std::fmt::Debug for KeyDeletionIntentV1 {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("KeyDeletionIntentV1")
      .field("operation", &self.operation)
      .field("purpose", &self.purpose)
      .field("transaction", &self.transaction)
      .finish_non_exhaustive()
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct KeyDeletedWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  operation: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  handle: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct KeyDeletedV1 {
  operation: KeyOperationId,
  handle: KeyHandle,
}

impl KeyDeletedV1 {
  pub(crate) const fn new(operation: KeyOperationId, handle: KeyHandle) -> Self {
    Self { operation, handle }
  }

  pub(crate) fn handle(&self) -> &KeyHandle {
    &self.handle
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &KeyDeletedWire {
        schema: KEY_DELETED_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        operation: self.operation.as_str().to_owned(),
        handle: self.handle.expose_provider_handle().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: KeyDeletedWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, KEY_DELETED_SCHEMA)?;
    expect_version(wire.record_version)?;
    Ok(Self {
      operation: KeyOperationId::parse(&wire.operation)?,
      handle: KeyHandle::from_provider_bytes(Arc::from(wire.handle))?,
    })
  }
}

impl std::fmt::Debug for KeyDeletedV1 {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("KeyDeletedV1")
      .field("operation", &self.operation)
      .finish_non_exhaustive()
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct IdentityBindingWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  node_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  public_key: Vec<u8>,
  #[n(4)]
  algorithm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityBindingV1 {
  node: NodeId,
  public_key: PublicKey,
}

impl IdentityBindingV1 {
  pub(crate) const fn new(node: NodeId, public_key: PublicKey) -> Self {
    Self { node, public_key }
  }

  pub(crate) fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &IdentityBindingWire {
        schema: IDENTITY_BINDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: self.node.as_str().to_owned(),
        public_key: self.public_key.as_bytes().to_vec(),
        algorithm: ED25519_ALGORITHM.to_owned(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: IdentityBindingWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, IDENTITY_BINDING_SCHEMA)?;
    expect_version(wire.record_version)?;
    expect_algorithm(&wire.algorithm)?;
    Ok(Self {
      node: NodeId::parse(&wire.node_id)?,
      public_key: PublicKey::from_bytes(fixed_bytes(&wire.public_key, "identity public key")?),
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct CredentialUseWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  issuer_id: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  generation_id: Vec<u8>,
  #[n(4)]
  #[cbor(with = "minicbor::bytes")]
  merge_id: Vec<u8>,
  #[n(5)]
  subject_id: String,
  #[n(6)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialUseV1 {
  issuer: NodeId,
  generation: GenerationId,
  merge: MergeId,
  subject: NodeId,
  subject_key: PublicKey,
}

impl CredentialUseV1 {
  pub(crate) const fn new(
    issuer: NodeId, generation: GenerationId, merge: MergeId, subject: NodeId,
    subject_key: PublicKey,
  ) -> Self {
    Self {
      issuer,
      generation,
      merge,
      subject,
      subject_key,
    }
  }

  pub(crate) fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  pub(crate) fn generation(&self) -> &GenerationId {
    &self.generation
  }

  pub(crate) fn merge(&self) -> &MergeId {
    &self.merge
  }

  pub(crate) fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub(crate) fn subject_key(&self) -> &PublicKey {
    &self.subject_key
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &CredentialUseWire {
        schema: CREDENTIAL_USE_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        issuer_id: self.issuer.as_str().to_owned(),
        generation_id: self.generation.as_bytes().to_vec(),
        merge_id: self.merge.as_bytes().to_vec(),
        subject_id: self.subject.as_str().to_owned(),
        subject_key: self.subject_key.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: CredentialUseWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, CREDENTIAL_USE_SCHEMA)?;
    expect_version(wire.record_version)?;
    Ok(Self {
      issuer: NodeId::parse(&wire.issuer_id)?,
      generation: GenerationId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.generation_id,
        "credential generation id",
      )?)),
      merge: MergeId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.merge_id,
        "merge id",
      )?)),
      subject: NodeId::parse(&wire.subject_id)?,
      subject_key: PublicKey::from_bytes(fixed_bytes(&wire.subject_key, "identity public key")?),
    })
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct MergeGrantBodyWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  #[cbor(with = "minicbor::bytes")]
  merge_id: Vec<u8>,
  #[n(3)]
  subject_id: String,
  #[n(4)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
  #[n(5)]
  issuer_id: String,
  #[n(6)]
  #[cbor(with = "minicbor::bytes")]
  generation_id: Vec<u8>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct MergeGrantWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u64,
  #[n(2)]
  #[cbor(with = "minicbor::bytes")]
  merge_id: Vec<u8>,
  #[n(3)]
  subject_id: String,
  #[n(4)]
  #[cbor(with = "minicbor::bytes")]
  subject_key: Vec<u8>,
  #[n(5)]
  issuer_id: String,
  #[n(6)]
  #[cbor(with = "minicbor::bytes")]
  generation_id: Vec<u8>,
  #[n(7)]
  #[cbor(with = "minicbor::bytes")]
  signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MergeGrantV1 {
  merge: MergeId,
  subject: NodeId,
  subject_key: PublicKey,
  issuer: NodeId,
  generation: GenerationId,
  signature: Signature,
}

impl MergeGrantV1 {
  pub(crate) const fn new(
    merge: MergeId, subject: NodeId, subject_key: PublicKey, issuer: NodeId,
    generation: GenerationId, signature: Signature,
  ) -> Self {
    Self {
      merge,
      subject,
      subject_key,
      issuer,
      generation,
      signature,
    }
  }

  pub(crate) fn merge(&self) -> &MergeId {
    &self.merge
  }

  pub(crate) fn subject(&self) -> &NodeId {
    &self.subject
  }

  pub(crate) fn subject_key(&self) -> &PublicKey {
    &self.subject_key
  }

  pub(crate) fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  pub(crate) fn generation(&self) -> &GenerationId {
    &self.generation
  }

  /// Encodes the canonical body that the issuer signs.
  pub(crate) fn encode_signed_body(
    merge: &MergeId, subject: &NodeId, subject_key: &PublicKey, issuer: &NodeId,
    generation: &GenerationId,
  ) -> Result<Vec<u8>> {
    encode_canonical(
      &MergeGrantBodyWire {
        schema: MERGE_GRANT_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        merge_id: merge.as_bytes().to_vec(),
        subject_id: subject.as_str().to_owned(),
        subject_key: subject_key.as_bytes().to_vec(),
        issuer_id: issuer.as_str().to_owned(),
        generation_id: generation.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn signed_body(&self) -> Result<Vec<u8>> {
    Self::encode_signed_body(
      &self.merge,
      &self.subject,
      &self.subject_key,
      &self.issuer,
      &self.generation,
    )
  }

  pub(crate) fn verify(&self, issuer_key: &PublicKey) -> Result<()> {
    verify_strict(
      MERGE_GRANT_V1_DOMAIN,
      &self.signed_body()?,
      issuer_key,
      &self.signature,
      "merge grant signature",
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &MergeGrantWire {
        schema: MERGE_GRANT_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        merge_id: self.merge.as_bytes().to_vec(),
        subject_id: self.subject.as_str().to_owned(),
        subject_key: self.subject_key.as_bytes().to_vec(),
        issuer_id: self.issuer.as_str().to_owned(),
        generation_id: self.generation.as_bytes().to_vec(),
        signature: self.signature.as_bytes().to_vec(),
      },
      RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: MergeGrantWire = decode_wire(bytes)?;
    expect_schema(&wire.schema, MERGE_GRANT_SCHEMA)?;
    expect_version(wire.record_version)?;
    Ok(Self {
      merge: MergeId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.merge_id,
        "merge id",
      )?)),
      subject: NodeId::parse(&wire.subject_id)?,
      subject_key: PublicKey::from_bytes(fixed_bytes(&wire.subject_key, "identity public key")?),
      issuer: NodeId::parse(&wire.issuer_id)?,
      generation: GenerationId::from_operation(OperationId::from_bytes(fixed_bytes(
        &wire.generation_id,
        "credential generation id",
      )?)),
      signature: Signature::from_bytes(fixed_bytes(&wire.signature, "identity signature")?),
    })
  }
}

#[cfg(test)]
mod tests {
  use std::{collections::VecDeque, sync::Mutex};

  use ed25519_dalek::{Signer, SigningKey};

  use super::*;
  use crate::{ErrorKind, QualifiedTag, TransactionId};

  const SUBJECT_NODE: &str = "node_100000000000000000000";
  const ISSUER_NODE: &str = "node_200000000000000000000";
  const OPERATION: &str = "keyop_500000000000000000000";
  const TRANSACTION: &str = "txn_600000000000000000000";
  const BASE_REVISION: &[u8] = &[0x07];
  const PURPOSE: &str = "node-identity";
  const SIGNING_SEED: [u8; 32] = [0x42; 32];
  const SUBJECT_KEY: [u8; 32] = [0xA1; 32];
  const HANDLE_BYTES: &[u8] = b"opaque-handle-01";
  const GENERATION_BYTES: [u8; 16] = [0xC3; 16];
  const ADMISSION_BYTES: [u8; 16] = [0xD4; 16];

  fn node(value: &str) -> NodeId {
    NodeId::parse(value).unwrap()
  }

  fn operation() -> KeyOperationId {
    KeyOperationId::parse(OPERATION).unwrap()
  }

  fn transaction() -> TransactionId {
    TransactionId::parse(TRANSACTION).unwrap()
  }

  fn base_revision() -> StoreRevision {
    StoreRevision::new(Arc::from(BASE_REVISION)).unwrap()
  }

  fn handle() -> KeyHandle {
    KeyHandle::from_provider_bytes(Arc::from(HANDLE_BYTES)).unwrap()
  }

  fn generation() -> GenerationId {
    GenerationId::from_operation(OperationId::from_bytes(GENERATION_BYTES))
  }

  fn merge() -> MergeId {
    MergeId::from_operation(OperationId::from_bytes(ADMISSION_BYTES))
  }

  fn issuer_signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_SEED)
  }

  fn issuer_key() -> PublicKey {
    PublicKey::from_bytes(issuer_signing_key().verifying_key().to_bytes())
  }

  fn local_identity() -> LocalIdentityV1 {
    LocalIdentityV1::new(
      node(SUBJECT_NODE),
      PublicKey::from_bytes(SUBJECT_KEY),
      operation(),
      handle(),
    )
  }

  fn key_creation_intent() -> KeyCreationIntentV1 {
    KeyCreationIntentV1::new(
      operation(),
      node(SUBJECT_NODE),
      PURPOSE.to_owned(),
      transaction(),
      base_revision(),
    )
    .unwrap()
  }

  fn identity_binding() -> IdentityBindingV1 {
    IdentityBindingV1::new(node(SUBJECT_NODE), PublicKey::from_bytes(SUBJECT_KEY))
  }

  fn credential_use() -> CredentialUseV1 {
    CredentialUseV1::new(
      node(ISSUER_NODE),
      generation(),
      merge(),
      node(SUBJECT_NODE),
      PublicKey::from_bytes(SUBJECT_KEY),
    )
  }

  fn merge_grant() -> MergeGrantV1 {
    let body_bytes = MergeGrantV1::encode_signed_body(
      &merge(),
      &node(SUBJECT_NODE),
      &PublicKey::from_bytes(SUBJECT_KEY),
      &node(ISSUER_NODE),
      &generation(),
    )
    .unwrap();
    let signature = issuer_signing_key().sign(&super::super::signature::signature_message(
      MERGE_GRANT_V1_DOMAIN,
      &body_bytes,
    ));
    MergeGrantV1::new(
      merge(),
      node(SUBJECT_NODE),
      PublicKey::from_bytes(SUBJECT_KEY),
      node(ISSUER_NODE),
      generation(),
      Signature::from_bytes(signature.to_bytes()),
    )
  }

  fn golden(hex: &str) -> Vec<u8> {
    crate::hex::decode(hex, "golden").unwrap()
  }

  const LOCAL_IDENTITY_GOLDEN: &str = "87782c726164696174612e776f6f6f6f2e746563682f736368656d61732f6c6f63616c2d6964656e746974792d763101781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a17821726164696174612e776f6f6f6f2e746563682f63727970746f2f65643235353139781b6b65796f705f353030303030303030303030303030303030303030506f70617175652d68616e646c652d3031";
  const KEY_CREATION_INTENT_GOLDEN: &str = "887831726164696174612e776f6f6f6f2e746563682f736368656d61732f6b65792d6372656174696f6e2d696e74656e742d763101781b6b65796f705f353030303030303030303030303030303030303030781a6e6f64655f3130303030303030303030303030303030303030306d6e6f64652d6964656e746974797821726164696174612e776f6f6f6f2e746563682f63727970746f2f65643235353139781974786e5f3630303030303030303030303030303030303030304107";
  const IDENTITY_BINDING_GOLDEN: &str = "85782e726164696174612e776f6f6f6f2e746563682f736368656d61732f6964656e746974792d62696e64696e672d763101781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a17821726164696174612e776f6f6f6f2e746563682f63727970746f2f65643235353139";
  const CREDENTIAL_USE_GOLDEN: &str = "87782c726164696174612e776f6f6f6f2e746563682f736368656d61732f63726564656e7469616c2d7573652d763101781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c350d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
  const MERGE_GRANT_GOLDEN: &str = "887829726164696174612e776f6f6f6f2e746563682f736368656d61732f6d657267652d6772616e742d76310150d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3584009dc3281151230e95e83bdbf2cd9980b355e5c18acb600c5114fbf51a082961249d4c580f6a99cb16a10277db527b001de91d55c5be064322a31559377959d0d";
  const MERGE_GRANT_BODY_GOLDEN: &str = "877829726164696174612e776f6f6f6f2e746563682f736368656d61732f6d657267652d6772616e742d76310150d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4781a6e6f64655f3130303030303030303030303030303030303030305820a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1781a6e6f64655f32303030303030303030303030303030303030303050c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

  #[test]
  fn identity_records_golden_vectors_match_exact_bytes() {
    assert_eq!(
      local_identity().encode().unwrap(),
      golden(LOCAL_IDENTITY_GOLDEN)
    );
    assert_eq!(
      key_creation_intent().encode().unwrap(),
      golden(KEY_CREATION_INTENT_GOLDEN)
    );
    assert_eq!(
      identity_binding().encode().unwrap(),
      golden(IDENTITY_BINDING_GOLDEN)
    );
    assert_eq!(
      credential_use().encode().unwrap(),
      golden(CREDENTIAL_USE_GOLDEN)
    );
    assert_eq!(merge_grant().encode().unwrap(), golden(MERGE_GRANT_GOLDEN));
    assert_eq!(
      merge_grant().signed_body().unwrap(),
      golden(MERGE_GRANT_BODY_GOLDEN)
    );
  }

  #[test]
  fn identity_records_golden_vectors_decode_to_exact_records() {
    assert_eq!(
      LocalIdentityV1::decode(&golden(LOCAL_IDENTITY_GOLDEN)).unwrap(),
      local_identity()
    );
    assert_eq!(
      KeyCreationIntentV1::decode(&golden(KEY_CREATION_INTENT_GOLDEN)).unwrap(),
      key_creation_intent()
    );
    assert_eq!(
      IdentityBindingV1::decode(&golden(IDENTITY_BINDING_GOLDEN)).unwrap(),
      identity_binding()
    );
    assert_eq!(
      CredentialUseV1::decode(&golden(CREDENTIAL_USE_GOLDEN)).unwrap(),
      credential_use()
    );
    assert_eq!(
      MergeGrantV1::decode(&golden(MERGE_GRANT_GOLDEN)).unwrap(),
      merge_grant()
    );
  }

  #[test]
  fn identity_records_signed_records_verify_against_golden_bytes() {
    MergeGrantV1::decode(&golden(MERGE_GRANT_GOLDEN))
      .unwrap()
      .verify(&issuer_key())
      .unwrap();
  }

  fn wrong_schema(schema: &str) -> String {
    let stem = schema.strip_suffix("v1").unwrap();
    format!("{stem}v0")
  }

  #[test]
  fn identity_records_reject_wrong_schema_tags() {
    let mut identity = local_identity().encode().unwrap();
    replace_text(
      &mut identity,
      LOCAL_IDENTITY_SCHEMA,
      &wrong_schema(LOCAL_IDENTITY_SCHEMA),
    );
    assert!(LocalIdentityV1::decode(&identity).is_err());

    let mut intent = key_creation_intent().encode().unwrap();
    replace_text(
      &mut intent,
      KEY_CREATION_INTENT_SCHEMA,
      &wrong_schema(KEY_CREATION_INTENT_SCHEMA),
    );
    assert!(KeyCreationIntentV1::decode(&intent).is_err());

    let mut binding = identity_binding().encode().unwrap();
    replace_text(
      &mut binding,
      IDENTITY_BINDING_SCHEMA,
      &wrong_schema(IDENTITY_BINDING_SCHEMA),
    );
    assert!(IdentityBindingV1::decode(&binding).is_err());

    let mut credential = credential_use().encode().unwrap();
    replace_text(
      &mut credential,
      CREDENTIAL_USE_SCHEMA,
      &wrong_schema(CREDENTIAL_USE_SCHEMA),
    );
    assert!(CredentialUseV1::decode(&credential).is_err());

    let mut grant = merge_grant().encode().unwrap();
    replace_text(
      &mut grant,
      MERGE_GRANT_SCHEMA,
      &wrong_schema(MERGE_GRANT_SCHEMA),
    );
    assert!(MergeGrantV1::decode(&grant).is_err());
  }

  #[test]
  fn identity_records_reject_wrong_record_version() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      credential_use().encode().unwrap(),
      merge_grant().encode().unwrap(),
    ] {
      let mut mutated = bytes.clone();
      let version = version_position(&bytes);
      mutated[version] = 0x02;
      assert!(decode_any(&mutated));
    }
  }

  fn decode_any(bytes: &[u8]) -> bool {
    LocalIdentityV1::decode(bytes).is_err()
      && KeyCreationIntentV1::decode(bytes).is_err()
      && IdentityBindingV1::decode(bytes).is_err()
      && CredentialUseV1::decode(bytes).is_err()
      && MergeGrantV1::decode(bytes).is_err()
  }

  fn replace_text(bytes: &mut [u8], from: &str, to: &str) {
    assert_eq!(from.len(), to.len());
    let needle = from.as_bytes();
    let start = bytes
      .windows(needle.len())
      .position(|window| window == needle)
      .unwrap();
    bytes[start..start + needle.len()].copy_from_slice(to.as_bytes());
  }

  fn version_position(bytes: &[u8]) -> usize {
    // [array header][text header 0x78 len][schema bytes][version]
    assert_eq!(bytes[1], 0x78);
    1 + 2 + bytes[2] as usize
  }

  #[test]
  fn identity_records_reject_trailing_bytes() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      credential_use().encode().unwrap(),
      merge_grant().encode().unwrap(),
    ] {
      let mut trailed = bytes;
      trailed.push(0x00);
      assert!(decode_any(&trailed));
    }
  }

  #[test]
  fn identity_records_reject_noncanonical_arguments() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      credential_use().encode().unwrap(),
      merge_grant().encode().unwrap(),
    ] {
      let version = version_position(&bytes);
      let mut widened = bytes[..version].to_vec();
      widened.extend_from_slice(&[0x18, bytes[version]]);
      widened.extend_from_slice(&bytes[version + 1..]);
      assert!(decode_any(&widened));
    }
  }

  #[test]
  fn identity_records_reject_wrong_field_counts() {
    for bytes in [
      local_identity().encode().unwrap(),
      key_creation_intent().encode().unwrap(),
      identity_binding().encode().unwrap(),
      credential_use().encode().unwrap(),
      merge_grant().encode().unwrap(),
    ] {
      let mut extra = bytes.clone();
      extra[0] += 1;
      extra.push(0x00);
      assert!(decode_any(&extra));

      let mut missing = bytes;
      missing[0] -= 1;
      missing.pop();
      assert!(decode_any(&missing));
    }
  }

  #[test]
  fn identity_records_reject_field_value_mutations() {
    let malformed_node = {
      let mut bytes = identity_binding().encode().unwrap();
      replace_text(&mut bytes, SUBJECT_NODE, "node_!00000000000000000000");
      bytes
    };
    assert!(IdentityBindingV1::decode(&malformed_node).is_err());

    let short_key = {
      let wire_bytes = identity_binding().encode().unwrap();
      let mut mutated = wire_bytes;
      let key_start = mutated
        .windows(SUBJECT_KEY.len())
        .position(|window| window == SUBJECT_KEY)
        .unwrap();
      mutated[key_start] ^= 0xFF;
      mutated
    };
    let decoded = IdentityBindingV1::decode(&short_key).unwrap();
    assert_ne!(decoded, identity_binding());

    let short_public_key = encode_canonical(
      &IdentityBindingWire {
        schema: IDENTITY_BINDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: SUBJECT_NODE.to_owned(),
        public_key: vec![0xA1; 31],
        algorithm: ED25519_ALGORITHM.to_owned(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(IdentityBindingV1::decode(&short_public_key).is_err());

    let empty_handle = encode_canonical(
      &LocalIdentityWire {
        schema: LOCAL_IDENTITY_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: SUBJECT_NODE.to_owned(),
        public_key: SUBJECT_KEY.to_vec(),
        algorithm: ED25519_ALGORITHM.to_owned(),
        key_operation_id: OPERATION.to_owned(),
        key_handle: Vec::new(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(LocalIdentityV1::decode(&empty_handle).is_err());

    let wrong_algorithm = encode_canonical(
      &IdentityBindingWire {
        schema: IDENTITY_BINDING_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        node_id: SUBJECT_NODE.to_owned(),
        public_key: SUBJECT_KEY.to_vec(),
        algorithm: "radiata.woooo.tech/crypto/ed25519ph".to_owned(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(IdentityBindingV1::decode(&wrong_algorithm).is_err());

    let short_generation = encode_canonical(
      &CredentialUseWire {
        schema: CREDENTIAL_USE_SCHEMA.to_owned(),
        record_version: RECORD_VERSION,
        issuer_id: ISSUER_NODE.to_owned(),
        generation_id: vec![0xC3; 15],
        merge_id: ADMISSION_BYTES.to_vec(),
        subject_id: SUBJECT_NODE.to_owned(),
        subject_key: SUBJECT_KEY.to_vec(),
      },
      RECORD_LIMITS,
    )
    .unwrap();
    assert!(CredentialUseV1::decode(&short_generation).is_err());
  }

  #[test]
  fn identity_records_merge_signature_covers_every_body_field() {
    let grant = merge_grant();
    grant.verify(&issuer_key()).unwrap();

    let signature = grant_signature(&grant);
    let other_merge = MergeId::from_operation(OperationId::from_bytes([0xE5; 16]));
    let other_generation = GenerationId::from_operation(OperationId::from_bytes([0xE5; 16]));
    let other_node = node("node_900000000000000000000");
    let other_key = PublicKey::from_bytes([0xB2; 32]);

    for mutated in [
      MergeGrantV1::new(
        other_merge,
        node(SUBJECT_NODE),
        PublicKey::from_bytes(SUBJECT_KEY),
        node(ISSUER_NODE),
        generation(),
        signature.clone(),
      ),
      MergeGrantV1::new(
        merge(),
        other_node.clone(),
        PublicKey::from_bytes(SUBJECT_KEY),
        node(ISSUER_NODE),
        generation(),
        signature.clone(),
      ),
      MergeGrantV1::new(
        merge(),
        node(SUBJECT_NODE),
        other_key,
        node(ISSUER_NODE),
        generation(),
        signature.clone(),
      ),
      MergeGrantV1::new(
        merge(),
        node(SUBJECT_NODE),
        PublicKey::from_bytes(SUBJECT_KEY),
        other_node,
        generation(),
        signature.clone(),
      ),
      MergeGrantV1::new(
        merge(),
        node(SUBJECT_NODE),
        PublicKey::from_bytes(SUBJECT_KEY),
        node(ISSUER_NODE),
        other_generation,
        signature.clone(),
      ),
    ] {
      let error = mutated.verify(&issuer_key()).unwrap_err();
      assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    }

    let wrong_issuer_key = PublicKey::from_bytes(
      SigningKey::from_bytes(&[0x24; 32])
        .verifying_key()
        .to_bytes(),
    );
    assert_eq!(
      grant.verify(&wrong_issuer_key).unwrap_err().kind(),
      ErrorKind::AuthenticationFailed
    );
  }

  fn grant_signature(grant: &MergeGrantV1) -> Signature {
    grant.signature.clone()
  }

  #[test]
  fn identity_records_debug_redacts_handles_signatures_and_operation_bytes() {
    let identity_debug = format!("{:?}", local_identity());
    assert!(!identity_debug.contains("opaque-handle-01"));
    let handle_hex: String = HANDLE_BYTES
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    assert!(!identity_debug.contains(&handle_hex));

    let grant_debug = format!("{:?}", merge_grant());
    let signature = grant_signature(&merge_grant());
    let signature_hex: String = signature
      .as_bytes()
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    assert!(!grant_debug.contains(&signature_hex));
    assert!(grant_debug.contains("Signature(..)"));

    let use_debug = format!("{:?}", credential_use());
    let generation_hex: String = GENERATION_BYTES
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    let admission_hex: String = ADMISSION_BYTES
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    assert!(!use_debug.contains(&generation_hex));
    assert!(!use_debug.contains(&admission_hex));
    assert!(use_debug.contains("GenerationId(..)"));
    assert!(use_debug.contains("MergeId(..)"));

    let grant_debug = format!("{:?}", merge_grant());
    assert!(!grant_debug.contains(&generation_hex));
    assert!(!grant_debug.contains(&admission_hex));
    assert!(!grant_debug.contains(&signature_hex));

    assert_eq!(format!("{:?}", generation()), "GenerationId(..)");
    assert_eq!(format!("{:?}", merge()), "MergeId(..)");
  }

  #[test]
  fn identity_records_storage_keys_use_metadata_namespaces() {
    let builders: Vec<(StoreNamespace, StoreKey)> = vec![
      local_identity_key().unwrap(),
      key_creation_intent_key(&operation()).unwrap(),
      identity_binding_key(&node(SUBJECT_NODE)).unwrap(),
      credential_use_key(&node(ISSUER_NODE), &generation()).unwrap(),
      merge_grant_key(&merge()).unwrap(),
    ];

    let mut namespaces = Vec::new();
    for (namespace, _) in &builders {
      let parsed = QualifiedTag::parse(namespace.as_str()).unwrap();
      assert_eq!(parsed.category(), "metadata");
      namespaces.push(namespace.as_str().to_owned());
    }
    namespaces.sort();
    namespaces.dedup();
    assert_eq!(namespaces.len(), builders.len());
  }

  #[test]
  fn identity_records_storage_key_bytes_are_exact() {
    let (identity_namespace, identity_key) = local_identity_key().unwrap();
    assert_eq!(
      identity_namespace.as_str(),
      "radiata.woooo.tech/metadata/local-identity-v1"
    );
    assert_eq!(identity_key.as_bytes(), b"self");

    let (intent_namespace, intent_key) = key_creation_intent_key(&operation()).unwrap();
    assert_eq!(
      intent_namespace.as_str(),
      "radiata.woooo.tech/metadata/key-creation-intent-v1"
    );
    assert_eq!(intent_key.as_bytes(), OPERATION.as_bytes());

    let (binding_namespace, binding_key) = identity_binding_key(&node(SUBJECT_NODE)).unwrap();
    assert_eq!(
      binding_namespace.as_str(),
      "radiata.woooo.tech/metadata/identity-binding-v1"
    );
    assert_eq!(binding_key.as_bytes(), SUBJECT_NODE.as_bytes());

    let (use_namespace, use_key) = credential_use_key(&node(ISSUER_NODE), &generation()).unwrap();
    assert_eq!(
      use_namespace.as_str(),
      "radiata.woooo.tech/metadata/credential-use-v1"
    );
    let mut expected_use_key = ISSUER_NODE.as_bytes().to_vec();
    expected_use_key.extend_from_slice(&GENERATION_BYTES);
    assert_eq!(use_key.as_bytes(), expected_use_key.as_slice());

    let (grant_namespace, grant_key) = merge_grant_key(&merge()).unwrap();
    assert_eq!(
      grant_namespace.as_str(),
      "radiata.woooo.tech/metadata/merge-grant-v1"
    );
    assert_eq!(grant_key.as_bytes(), &ADMISSION_BYTES);
  }

  #[test]
  fn identity_records_key_creation_intent_purpose_is_bounded_printable_ascii() {
    let valid = || {
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        transaction(),
        base_revision(),
      )
    };
    assert!(valid().is_ok());
    let with_purpose = |purpose: String| {
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        purpose,
        transaction(),
        base_revision(),
      )
    };
    assert!(with_purpose(String::new()).is_err());
    assert!(with_purpose("x".repeat(129)).is_err());
    assert!(with_purpose("bad\tpurpose".to_owned()).is_err());
    assert!(with_purpose("bad\u{7f}purpose".to_owned()).is_err());
    assert!(with_purpose("node identity".to_owned()).is_ok());

    let long_purpose = with_purpose("p".repeat(128)).unwrap();
    assert_eq!(
      KeyCreationIntentV1::decode(&long_purpose.encode().unwrap()).unwrap(),
      long_purpose
    );
  }

  #[test]
  fn identity_records_key_creation_intent_recovers_exact_storage_identity() {
    use crate::{
      StoreTransaction,
      storage::receipt::{
        ACTIVE_MARKER_VALUE, encode_reference_count, internal_namespace, reference_edge_key,
        reference_head_key, used_id_key,
      },
    };

    let intent = key_creation_intent();
    let stored_value = StoreValue::new(Arc::from(intent.encode().unwrap()));
    let recovered = intent.recovery_identity(&stored_value).unwrap();

    // Directly prepare the paired storage transaction: the caller intent Put,
    // the AddSelf receipt head and edge, and the permanent used-ID marker.
    let (namespace, key) = key_creation_intent_key(intent.operation()).unwrap();
    let token = ReceiptReferenceToken::for_record(&namespace, &key);
    let internal = internal_namespace().unwrap();
    let direct = StoreTransaction::new(
      intent.transaction().clone(),
      intent.base_revision().clone(),
      vec![
        StoreOperation::Put {
          namespace,
          key,
          expected: StoreExpectation::Absent,
          value: stored_value.clone(),
        },
        StoreOperation::Put {
          namespace: internal.clone(),
          key: reference_head_key(intent.transaction()).unwrap(),
          expected: StoreExpectation::Absent,
          value: encode_reference_count(1),
        },
        StoreOperation::Put {
          namespace: internal.clone(),
          key: reference_edge_key(intent.transaction(), &token).unwrap(),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from([])),
        },
        StoreOperation::Put {
          namespace: internal,
          key: used_id_key(intent.transaction()).unwrap(),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(ACTIVE_MARKER_VALUE)),
        },
      ],
    )
    .unwrap();
    assert_eq!(recovered.transaction(), direct.id());
    assert_eq!(recovered.operation_digest(), direct.operation_digest());

    // Mutating any single intent field changes the recovered identity.
    for mutated in [
      KeyCreationIntentV1::new(
        KeyOperationId::parse("keyop_600000000000000000000").unwrap(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        transaction(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(ISSUER_NODE),
        PURPOSE.to_owned(),
        transaction(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        "cluster-identity".to_owned(),
        transaction(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        TransactionId::parse("txn_700000000000000000000").unwrap(),
        base_revision(),
      )
      .unwrap(),
      KeyCreationIntentV1::new(
        operation(),
        node(SUBJECT_NODE),
        PURPOSE.to_owned(),
        transaction(),
        StoreRevision::new(Arc::from([0x08])).unwrap(),
      )
      .unwrap(),
    ] {
      let mutated_value = StoreValue::new(Arc::from(mutated.encode().unwrap()));
      assert_ne!(
        mutated.recovery_identity(&mutated_value).unwrap(),
        recovered
      );
    }

    // Mutating the stored value itself also changes the recovered identity.
    let mut corrupted = intent.encode().unwrap();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    let corrupted = StoreValue::new(Arc::from(corrupted));
    assert_ne!(intent.recovery_identity(&corrupted).unwrap(), recovered);
  }

  #[derive(Debug)]
  struct ScriptedEntropy {
    chunks: Mutex<VecDeque<Vec<u8>>>,
  }

  impl ScriptedEntropy {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
      Self {
        chunks: Mutex::new(chunks.into()),
      }
    }
  }

  impl Entropy for ScriptedEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<()> {
      let chunk = self
        .chunks
        .lock()
        .map_err(|_| Error::internal("scripted entropy lock"))?
        .pop_front()
        .ok_or_else(|| Error::internal("scripted entropy exhausted"))?;
      if chunk.len() != output.len() {
        return Err(Error::internal("scripted entropy length"));
      }
      output.copy_from_slice(&chunk);
      Ok(())
    }
  }

  #[derive(Debug)]
  struct FailingEntropy;

  impl Entropy for FailingEntropy {
    fn fill(&self, _output: &mut [u8]) -> Result<()> {
      Err(Error::internal("injected entropy failure"))
    }
  }

  fn suffix_space() -> u128 {
    let mut space = 1_u128;
    for _ in 0..21 {
      space *= 62;
    }
    space
  }

  fn entropy_word(value: u128) -> Vec<u8> {
    value.to_be_bytes().to_vec()
  }

  #[test]
  fn identity_records_generated_ids_use_canonical_unbiased_suffixes() {
    let zero = ScriptedEntropy::new(vec![entropy_word(0)]);
    let id = NodeId::generate(&zero).unwrap();
    assert_eq!(id.as_str(), "node_000000000000000000000");
    assert_eq!(NodeId::parse(id.as_str()).unwrap(), id);

    let max = ScriptedEntropy::new(vec![entropy_word(suffix_space() - 1)]);
    let id = NodeId::generate(&max).unwrap();
    assert_eq!(id.as_str(), "node_ZZZZZZZZZZZZZZZZZZZZZ");
    assert_eq!(NodeId::parse(id.as_str()).unwrap(), id);

    let one = ScriptedEntropy::new(vec![entropy_word(1)]);
    let id = TransactionId::generate(&one).unwrap();
    assert_eq!(id.as_str(), "txn_000000000000000000001");

    let digit_run = ScriptedEntropy::new(vec![entropy_word(61)]);
    let id = KeyOperationId::generate(&digit_run).unwrap();
    assert_eq!(id.as_str(), "keyop_00000000000000000000Z");
    assert_eq!(KeyOperationId::parse(id.as_str()).unwrap(), id);
  }

  #[test]
  fn identity_records_generator_rejects_out_of_range_candidates() {
    let entropy = ScriptedEntropy::new(vec![entropy_word(suffix_space()), entropy_word(5)]);
    let id = NodeId::generate(&entropy).unwrap();
    assert_eq!(id.as_str(), "node_000000000000000000005");

    let entropy = ScriptedEntropy::new(vec![
      entropy_word(u128::MAX),
      entropy_word(suffix_space()),
      entropy_word(61),
    ]);
    let id = NodeId::generate(&entropy).unwrap();
    assert_eq!(id.as_str(), "node_00000000000000000000Z");
  }

  #[test]
  fn identity_records_entropy_failure_precedes_any_id_output() {
    let error = NodeId::generate(&FailingEntropy).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Internal);
    assert_eq!(error.context(), "injected entropy failure");

    assert!(NodeId::generate(&FailingEntropy).is_err());
    assert!(TransactionId::generate(&FailingEntropy).is_err());
    assert!(KeyOperationId::generate(&FailingEntropy).is_err());
    assert!(OperationId::generate(&FailingEntropy).is_err());
    assert!(GenerationId::generate(&FailingEntropy).is_err());
    assert!(MergeId::generate(&FailingEntropy).is_err());
  }

  #[test]
  fn identity_records_operation_id_generation_is_deterministic_and_redacted() {
    let entropy = ScriptedEntropy::new(vec![GENERATION_BYTES.to_vec()]);
    let operation = OperationId::generate(&entropy).unwrap();
    assert_eq!(operation.as_bytes(), &GENERATION_BYTES);
    assert_eq!(format!("{operation:?}"), "OperationId(..)");

    let entropy = ScriptedEntropy::new(vec![ADMISSION_BYTES.to_vec()]);
    let wrapper = MergeId::generate(&entropy).unwrap();
    assert_eq!(wrapper, merge());
  }
}
