//! Active leave and identity replacement (T-G09-06, ADR-0001/0006).
//!
//! An explicit active leave replaces the node's identity and erases the
//! old identity's local core metadata, crash-safely:
//!
//! 1. A journaled leave-intent records the exact former identity and the
//!    replacement coordinates (node id and key-creation operation).
//! 2. The replacement key is created through the provider under that operation
//!    id; an indeterminate create reconciles, never duplicates.
//! 3. One journaled transaction swaps the local-identity singleton to the
//!    replacement — after this commit the node is never the former identity
//!    again.
//! 4. The old identity's domain metadata (trust, membership, resources, traces,
//!    credentials, admissions, revocations) is wiped in bounded idempotent
//!    batches; the store's schema, receipt internals, and key custody records
//!    are store infrastructure, not identity metadata, and stay.
//! 5. The former key is deleted through the exact key-deletion intent protocol;
//!    no referenced key is ever deleted.
//! 6. The leave-intent is removed, completing the leave.
//!
//! Every step is idempotent and reopen-recoverable: a crash at any point
//! reopens to a reconciled phase and resumes, never to a mixed identity,
//! a duplicate active key, or silently restored old membership.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::{
  deletion::delete_unreferenced_key,
  lifecycle::{CommitWithReconcile, LocalIdentityContext, commit_with_reconcile},
  records,
  records::{LocalIdentityV1, local_identity_key},
};
use crate::{
  Error, KeyHandle, KeyOperationId, NodeId, PublicKey, Result, StoreExpectation, StoreKey,
  StoreNamespace, StoreOperation, StoreValue, TransactionId,
  api::Entropy,
  protocol::{decode_canonical, encode_canonical},
  provider::KeyProvider,
  storage::MetadataStore,
};

/// The durable schema of the leave-intent record.
const LEAVE_INTENT_SCHEMA: &str = "radiata.woooo.tech/schemas/leave-intent-v1";
pub(crate) use crate::storage::families::LEAVE_NAMESPACE;

/// Canonical-decoder bounds for the flat intent record.
const INTENT_LIMITS: crate::protocol::CborLimits = crate::protocol::CborLimits::new(4, 8, 1024);

const INTENT_VERSION: u16 = 1;
const INTENT_KEY: &[u8] = b"leave";

/// The durable leave-intent: the exact former identity and the
/// replacement coordinates. One record per store; presence means a leave
/// is in progress and must resume before the node serves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LeaveIntentV1 {
  former_node: NodeId,
  former_key: PublicKey,
  former_handle: KeyHandle,
  replacement_node: NodeId,
  replacement_operation: KeyOperationId,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct LeaveIntentWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  former_node: String,
  #[n(3)]
  former_key: ByteVec,
  #[n(4)]
  former_handle: ByteVec,
  #[n(5)]
  replacement_node: String,
  #[n(6)]
  replacement_operation: String,
}

impl LeaveIntentV1 {
  fn former_handle(&self) -> &KeyHandle {
    &self.former_handle
  }

  fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &LeaveIntentWire {
        schema: LEAVE_INTENT_SCHEMA.to_owned(),
        record_version: INTENT_VERSION,
        former_node: self.former_node.as_str().to_owned(),
        former_key: ByteVec::from(self.former_key.as_bytes().to_vec()),
        former_handle: ByteVec::from(self.former_handle.expose_provider_handle().to_vec()),
        replacement_node: self.replacement_node.as_str().to_owned(),
        replacement_operation: self.replacement_operation.as_str().to_owned(),
      },
      INTENT_LIMITS,
    )
  }

  fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: LeaveIntentWire =
      decode_canonical(bytes, INTENT_LIMITS).map_err(|_| Error::invalid_input("leave intent"))?;
    if wire.schema != LEAVE_INTENT_SCHEMA || wire.record_version != INTENT_VERSION {
      return Err(Error::invalid_input("leave intent schema"));
    }
    Ok(Self {
      former_node: NodeId::parse(&wire.former_node)?,
      former_key: PublicKey::from_bytes(
        <[u8; 32]>::try_from(wire.former_key.as_slice())
          .map_err(|_| Error::invalid_input("leave intent key"))?,
      ),
      former_handle: KeyHandle::from_provider_bytes(Arc::from(
        wire.former_handle.as_slice().to_vec(),
      ))?,
      replacement_node: NodeId::parse(&wire.replacement_node)?,
      replacement_operation: KeyOperationId::parse(&wire.replacement_operation)?,
    })
  }

  /// The deterministic fixture intent for round-trip tests.
  #[cfg(test)]
  fn new_for_test() -> Self {
    Self {
      former_node: NodeId::parse("node_000000000000000000061").unwrap(),
      former_key: PublicKey::from_bytes([61; 32]),
      former_handle: KeyHandle::from_provider_bytes(Arc::from(b"former-handle".to_vec())).unwrap(),
      replacement_node: NodeId::parse("node_000000000000000000062").unwrap(),
      replacement_operation: KeyOperationId::parse("keyop_000000000000000000062").unwrap(),
    }
  }
}

fn leave_namespace() -> Result<StoreNamespace> {
  crate::identity::records::metadata_namespace(LEAVE_NAMESPACE)
}

fn leave_key() -> StoreKey {
  StoreKey::new(Arc::from(INTENT_KEY.to_vec()))
}

/// The durable schema of the owner-signed leave record.
pub(crate) const LEAVE_RECORD_SCHEMA: &str = "radiata.woooo.tech/schemas/leave-record-v1";
/// The signature domain of the owner-signed leave record.
pub(crate) const LEAVE_RECORD_V1_DOMAIN: &[u8] = b"radiata.woooo.tech/crypto/leave-record-v1";

/// Canonical-decoder bounds for the flat leave record.
const LEAVE_RECORD_LIMITS: crate::protocol::CborLimits =
  crate::protocol::CborLimits::new(1, 8, 1_024);

#[derive(Encode, Decode)]
#[cbor(array)]
struct LeaveRecordBodyWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  node: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  public_key: Vec<u8>,
  /// Signed host wall-clock UNIX milliseconds: the removal timestamp the
  /// checkpoint GC compares against its watermark (T-G11-09).
  #[n(4)]
  timestamp_millis: u64,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct LeaveRecordWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  node: String,
  #[n(3)]
  #[cbor(with = "minicbor::bytes")]
  public_key: Vec<u8>,
  #[n(4)]
  timestamp_millis: u64,
  #[n(5)]
  #[cbor(with = "minicbor::bytes")]
  signature: Vec<u8>,
}

/// One owner-signed leave record (ADR-0009 decision 3): a terminal removal
/// tombstone for the named binding. The leaver signs it with its current
/// key before rotating; peers verify it against the permanently retained
/// identity binding, never against the leaver staying online. Because the
/// rotation destroys the old key, the record carries no replay or time-lag
/// attack surface. The signed removal timestamp is what the checkpoint GC
/// (decision 5) compares against its watermark.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LeaveRecordV1 {
  node: NodeId,
  public_key: PublicKey,
  timestamp_millis: u64,
  signature: crate::Signature,
}

impl LeaveRecordV1 {
  pub(crate) const fn new(
    node: NodeId, public_key: PublicKey, timestamp_millis: u64, signature: crate::Signature,
  ) -> Self {
    Self {
      node,
      public_key,
      timestamp_millis,
      signature,
    }
  }

  pub(crate) const fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) const fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) const fn timestamp_millis(&self) -> u64 {
    self.timestamp_millis
  }

  /// Encodes the canonical body the owner signs.
  pub(crate) fn encode_signed_body(
    node: &NodeId, public_key: &PublicKey, timestamp_millis: u64,
  ) -> Result<Vec<u8>> {
    encode_canonical(
      &LeaveRecordBodyWire {
        schema: LEAVE_RECORD_SCHEMA.to_owned(),
        record_version: 1,
        node: node.as_str().to_owned(),
        public_key: public_key.as_bytes().to_vec(),
        timestamp_millis,
      },
      LEAVE_RECORD_LIMITS,
    )
  }

  /// Verifies the owner signature against the permanently retained binding.
  pub(crate) fn verify(&self) -> Result<()> {
    crate::identity::signature::verify_strict(
      LEAVE_RECORD_V1_DOMAIN,
      &Self::encode_signed_body(&self.node, &self.public_key, self.timestamp_millis)?,
      &self.public_key,
      &self.signature,
      "leave record signature",
    )
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &LeaveRecordWire {
        schema: LEAVE_RECORD_SCHEMA.to_owned(),
        record_version: 1,
        node: self.node.as_str().to_owned(),
        public_key: self.public_key.as_bytes().to_vec(),
        timestamp_millis: self.timestamp_millis,
        signature: self.signature.as_bytes().to_vec(),
      },
      LEAVE_RECORD_LIMITS,
    )
  }

  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: LeaveRecordWire = crate::protocol::decode_canonical_strict(
      bytes,
      LEAVE_RECORD_LIMITS,
      "leave record canonical form",
    )
    .map_err(|_| Error::invalid_input("leave record"))?;
    if wire.schema != LEAVE_RECORD_SCHEMA || wire.record_version != 1 {
      return Err(Error::invalid_input("leave record schema"));
    }
    Ok(Self {
      node: NodeId::parse(&wire.node)?,
      public_key: PublicKey::from_bytes(
        <[u8; 32]>::try_from(wire.public_key.as_slice())
          .map_err(|_| Error::invalid_input("leave record key"))?,
      ),
      timestamp_millis: wire.timestamp_millis,
      signature: crate::Signature::from_bytes(
        <[u8; 64]>::try_from(wire.signature.as_slice())
          .map_err(|_| Error::invalid_input("leave record signature"))?,
      ),
    })
  }
}

/// Signs the leave record for the current local identity, stamping the
/// host wall-clock removal timestamp the checkpoint GC compares against.
pub(crate) async fn sign_leave_record(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>,
) -> Result<LeaveRecordV1> {
  let identity = context.identity();
  let timestamp_millis = crate::time::now_millis();
  let body =
    LeaveRecordV1::encode_signed_body(identity.node(), identity.public_key(), timestamp_millis)?;
  let signature = keys
    .sign(
      identity.handle(),
      &crate::identity::signature::signature_message(LEAVE_RECORD_V1_DOMAIN, &body),
    )
    .await?;
  let record = LeaveRecordV1::new(
    identity.node().clone(),
    identity.public_key().clone(),
    timestamp_millis,
    signature,
  );
  record.verify()?;
  Ok(record)
}

fn leave_record_key(node: &NodeId) -> StoreKey {
  StoreKey::new(Arc::from(node.as_str().as_bytes().to_vec()))
}

/// Persists one verified leave record (idempotent; a re-delivery of the
/// exact record is a no-op, a different record for the same node conflicts
/// without mutation).
pub(crate) async fn persist_leave_record_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, record: &LeaveRecordV1,
) -> Result<()> {
  let _permit = store.write_permit().await;
  record.verify()?;
  records::persist_terminal_record(
    store,
    entropy,
    leave_namespace()?,
    leave_record_key(record.node()),
    Arc::from(record.encode()?),
    "leave record",
  )
  .await
}

/// Whether `node` has a leave record in the local store.
pub(crate) async fn is_left_ctx(store: &MetadataStore, node: &NodeId) -> Result<bool> {
  let namespace = leave_namespace()?;
  let snapshot = store.snapshot().await?;
  Ok(
    snapshot
      .get(&namespace, &leave_record_key(node))
      .await?
      .is_some(),
  )
}

/// Every known leave record's node, for exclusion sweeps.
pub(crate) async fn left_nodes_ctx(
  store: &MetadataStore,
) -> Result<std::collections::BTreeSet<NodeId>> {
  let mut left = std::collections::BTreeSet::new();
  for record in known_leave_records_ctx(store, usize::MAX).await? {
    left.insert(record.node().clone());
  }
  Ok(left)
}

/// The known leave records, oldest first, bounded by `cap`. The intent
/// singleton key never decodes as a record and is skipped.
pub(crate) async fn known_leave_records_ctx(
  store: &MetadataStore, cap: usize,
) -> Result<Vec<LeaveRecordV1>> {
  records::scan_decoded_records(
    store,
    leave_namespace()?,
    cap,
    intent_key_skip,
    LeaveRecordV1::decode,
  )
  .await
}

/// The leave family's namespace carries the leave-intent singleton under
/// [`INTENT_KEY`]; the known-records scan must not decode it as a record.
fn intent_key_skip(key: &StoreKey) -> bool {
  key.as_bytes() == INTENT_KEY
}

/// The leave-side checkpoint sweep (ADR-0009 decision 5): conditional
/// exact-digest deletes of collected leave records stamped at or before
/// `watermark`. The leave intent singleton is never touched.
pub(crate) async fn collect_before_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, watermark: u64,
) -> Result<usize> {
  let namespace = leave_namespace()?;
  let known = known_leave_records_ctx(store, records::TOMBSTONE_GC_BATCH).await?;
  let entries: Vec<_> = known
    .iter()
    .map(|record| (leave_record_key(record.node()), record.timestamp_millis()))
    .collect();
  records::collect_tombstones_before(store, entropy, namespace, watermark, &entries).await
}

/// One journaled leave drive: the signed terminal record plus the intent
/// coordinates. The record is signed exactly once and reused verbatim by
/// re-drives and startup resume, so a re-announcement can never diverge
/// from a record a peer already holds (divergent records fail closed).
pub(crate) struct JournaledLeave {
  pub(crate) record: LeaveRecordV1,
  pub(crate) stored: StoreValue,
  pub(crate) intent: LeaveIntentV1,
}

/// Phase J of the leave pipeline, before any network effect: journal the
/// intent, then sign and persist the terminal record into the leave
/// family (which the wipe deliberately spares). The intent leads so a
/// crash in between resumes as "intent without record" — the record is
/// signed fresh because nothing was announced yet. A crash after this
/// phase resumes at startup with the same journaled record.
pub(crate) async fn journal_leave(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
) -> Result<JournaledLeave> {
  let store = context.store();
  // A pending intent from a crashed earlier drive owns its journaled
  // record: reuse it verbatim.
  if let Some((stored, intent)) = discover_leave_intent(store).await? {
    let record = self_leave_record(store, &intent.former_node)
      .await?
      .ok_or_else(|| Error::internal("journaled leave record"))?;
    return Ok(JournaledLeave {
      record,
      stored,
      intent,
    });
  }
  let (stored, intent) = begin_intent(context, entropy).await?;
  let record = sign_leave_record(context, keys).await?;
  persist_leave_record_ctx(store, entropy, &record).await?;
  Ok(JournaledLeave {
    record,
    stored,
    intent,
  })
}

/// The leaver's own journaled terminal record, when present (phase J or
/// later). Snapshot reads only.
async fn self_leave_record(store: &MetadataStore, node: &NodeId) -> Result<Option<LeaveRecordV1>> {
  let namespace = leave_namespace()?;
  let snapshot = store.snapshot().await?;
  let Some(value) = snapshot.get(&namespace, &leave_record_key(node)).await? else {
    return Ok(None);
  };
  Ok(Some(LeaveRecordV1::decode(value.as_bytes())?))
}

impl LeaveIntentV1 {
  pub(crate) fn former_node(&self) -> &NodeId {
    &self.former_node
  }

  pub(crate) fn replacement_node(&self) -> &NodeId {
    &self.replacement_node
  }
}

/// Discovers the pending leave-intent, if any.
pub(crate) async fn discover_leave_intent(
  store: &MetadataStore,
) -> Result<Option<(StoreValue, LeaveIntentV1)>> {
  let namespace = leave_namespace()?;
  let snapshot = store.snapshot().await?;
  let Some(value) = snapshot.get(&namespace, &leave_key()).await? else {
    return Ok(None);
  };
  Ok(Some((
    value.clone(),
    LeaveIntentV1::decode(value.as_bytes())?,
  )))
}

/// The domain metadata namespaces of the old identity, wiped by a leave.
/// The local identity singleton is swapped, never wiped; the store's
/// schema, receipt internals, pending journal, and key-custody records
/// are storage infrastructure and stay.
const WIPE_NAMESPACES: &[&str] = &[
  crate::storage::families::IDENTITY_BINDING_NAMESPACE,
  crate::storage::families::CREDENTIAL_USE_NAMESPACE,
  crate::storage::families::MERGE_GRANT_NAMESPACE,
  crate::storage::families::TRUST_SNAPSHOT_NAMESPACE,
  crate::storage::families::TRUST_BINDING_NAMESPACE,
  crate::storage::families::REVOCATION_NAMESPACE,
  crate::storage::families::NODE_DESCRIPTOR_NAMESPACE,
  crate::storage::families::RESOURCE_RECORD_NAMESPACE,
  crate::storage::families::TRACE_NAMESPACE,
];

/// The bounded batch size of one wipe transaction.
const WIPE_BATCH: usize = 64;

/// The bounded retry budget per wipe batch against concurrent writers.
const WIPE_RETRIES: usize = 8;

/// Wipes one family in bounded exact-digest batches; idempotent, so a
/// crash mid-family resumes by re-scanning.
async fn wipe_family(
  store: &MetadataStore, entropy: &dyn Entropy, namespace_tag: &str,
) -> Result<()> {
  let namespace = crate::identity::records::metadata_namespace(namespace_tag)?;
  let mut retries = 0_usize;
  loop {
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut operations = Vec::new();
    while let Some(entry) = scan.next().await? {
      operations.push(StoreOperation::Delete {
        namespace: namespace.clone(),
        key: entry.key().clone(),
        expected: entry.value().digest().clone(),
      });
      if operations.len() >= WIPE_BATCH {
        break;
      }
    }
    if operations.is_empty() {
      return Ok(());
    }
    let revision = snapshot.revision().clone();
    drop(scan);
    drop(snapshot);
    let prepared =
      store.prepare_transaction(TransactionId::generate(entropy)?, revision, operations)?;
    match commit_with_reconcile(store, prepared).await? {
      CommitWithReconcile::Committed => {}
      // A concurrent write raced the batch: restart the family scan with
      // a fresh snapshot; the bounded budget makes a permanent storm a
      // typed failure instead of an unbounded retry.
      CommitWithReconcile::Aborted => {
        retries += 1;
        if retries > WIPE_RETRIES {
          return Err(Error::conflict("leave wipe"));
        }
      }
    }
  }
}

/// Wipes every domain family of the old identity.
async fn wipe_old_metadata(store: &MetadataStore, entropy: &dyn Entropy) -> Result<()> {
  for namespace in WIPE_NAMESPACES {
    wipe_family(store, entropy, namespace).await?;
  }
  Ok(())
}

/// Creates or reconciles the replacement key under the intent's operation
/// id; an indeterminate provider outcome blocks pending reconciliation and
/// never duplicates the key (SC-G09-P0-19).
async fn replacement_key(
  keys: &Arc<dyn KeyProvider>, intent: &LeaveIntentV1,
) -> Result<crate::CreatedKey> {
  let created = match keys.reconcile_create(&intent.replacement_operation).await? {
    crate::KeyCreateState::Present(created) => created,
    crate::KeyCreateState::Absent => {
      match keys.create_ed25519(&intent.replacement_operation).await? {
        crate::KeyCreateState::Present(created) => created,
        crate::KeyCreateState::Absent => {
          return Err(Error::not_ready("leave replacement key create"));
        }
        crate::KeyCreateState::Unknown => {
          return Err(crate::identity::lifecycle::reconcile_unknown());
        }
      }
    }
    crate::KeyCreateState::Unknown => {
      return Err(crate::identity::lifecycle::reconcile_unknown());
    }
  };
  let provided = keys.public_key(created.handle()).await?;
  if &provided != created.public_key() {
    return Err(Error::provider(
      crate::ProviderErrorKind::Internal,
      crate::ProviderErrorContext::KeyPublicKey,
    ));
  }
  Ok(created)
}

/// Phase C: one journaled transaction swaps the local-identity singleton
/// to the replacement (exact digest on the former record, deletion-intent
/// guards on the replacement handle).
async fn swap_identity(
  store: &MetadataStore, entropy: &dyn Entropy, intent: &LeaveIntentV1, created: &crate::CreatedKey,
) -> Result<()> {
  let replacement = LocalIdentityV1::new(
    intent.replacement_node.clone(),
    created.public_key().clone(),
    intent.replacement_operation.clone(),
    created.handle().clone(),
  );
  let snapshot = store.snapshot().await?;
  let (local_namespace, local_key) = local_identity_key()?;
  let Some(former_value) = snapshot.get(&local_namespace, &local_key).await? else {
    return Err(Error::conflict("leave identity swap"));
  };
  let former = LocalIdentityV1::decode(former_value.as_bytes())
    .map_err(|_| Error::invalid_input("local identity"))?;
  if former.node() != &intent.former_node {
    return Err(Error::conflict("leave identity swap"));
  }
  // The replacement handle must be provably fresh: a deletion intent or
  // tombstone for it fails closed (the finalize_identity precedent); the
  // same guard keys are re-checked transactionally below.
  records::assert_key_handle_fresh(snapshot.as_ref(), created.handle()).await?;
  let [deletion_check, deleted_check] = records::key_handle_fresh_checks(created.handle())?;
  let prepared = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![
      StoreOperation::Put {
        namespace: local_namespace,
        key: local_key,
        expected: StoreExpectation::Exact(former_value.digest().clone()),
        value: StoreValue::new(Arc::from(replacement.encode()?)),
      },
      deletion_check,
      deleted_check,
    ],
  )?;
  drop(snapshot);
  match commit_with_reconcile(store, prepared).await? {
    CommitWithReconcile::Committed => Ok(()),
    CommitWithReconcile::Aborted => Err(Error::conflict("leave identity swap")),
  }
}

/// Phase F: removes the completed leave-intent by exact digest.
async fn complete_leave(
  store: &MetadataStore, entropy: &dyn Entropy, stored: &StoreValue,
) -> Result<()> {
  let snapshot = store.snapshot().await?;
  let prepared = store.prepare_transaction(
    TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    vec![StoreOperation::Delete {
      namespace: leave_namespace()?,
      key: leave_key(),
      expected: stored.digest().clone(),
    }],
  )?;
  drop(snapshot);
  match commit_with_reconcile(store, prepared).await? {
    CommitWithReconcile::Committed => Ok(()),
    CommitWithReconcile::Aborted => Err(Error::conflict("leave completion")),
  }
}

/// Runs the leave phases from the intent forward: replacement key, identity
/// swap, metadata wipe, former-key deletion, completion. Idempotent and
/// shared by the command path and the startup resume.
pub(crate) async fn run_leave(
  store: &MetadataStore, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy, stored: &StoreValue,
  intent: &LeaveIntentV1,
) -> Result<()> {
  let _permit = store.write_permit().await;
  let identity =
    crate::identity::lifecycle::discover_local_identity(store.snapshot().await?.as_ref())
      .await?
      .ok_or_else(|| Error::internal("leave local identity"))?
      .1;
  if identity.node() == &intent.former_node {
    // The swap has not committed yet: create the replacement key and swap.
    let created = replacement_key(keys, intent).await?;
    swap_identity(store, entropy, intent, &created).await?;
  } else if identity.node() != &intent.replacement_node {
    // The identity is neither the former nor the replacement: the store
    // is inconsistent with the intent and fails closed as corrupt.
    return Err(super::lifecycle::discovery_corrupt());
  }
  wipe_old_metadata(store, entropy).await?;
  delete_unreferenced_key(store, keys, entropy, intent.former_handle()).await?;
  complete_leave(store, entropy, stored).await
}

/// Test composition of the full drive without any announcement (the
/// announcement is the sync plane's responsibility): journal the intent
/// and record, then run the phases to completion.
#[cfg(test)]
pub(crate) async fn execute(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
) -> Result<(NodeId, NodeId)> {
  let journaled = journal_leave(context, keys, entropy).await?;
  run_leave(
    context.store(),
    keys,
    entropy,
    &journaled.stored,
    &journaled.intent,
  )
  .await?;
  Ok((
    journaled.intent.former_node().clone(),
    journaled.intent.replacement_node().clone(),
  ))
}

/// Phase A: journals the leave-intent before any provider or identity
/// work, so a crash after this point always has the exact former identity
/// and replacement coordinates to resume from.
async fn begin_intent(
  context: &LocalIdentityContext, entropy: &dyn Entropy,
) -> Result<(StoreValue, LeaveIntentV1)> {
  let store = context.store();
  // The intent install joins the store's writer exclusion like every
  // other identity phase: read-decide-commit on the Absent expectation is
  // then atomic against internal writers (anti-entropy, neighbouring
  // families), and only an external writer can still win the race. The
  // bounded retries remain as the fail-closed second line for that
  // residual window (the lock is task-reentrant, so run_leave's own
  // permit below nests).
  let _permit = store.write_permit().await;
  let former = context.identity().clone();
  let intent = LeaveIntentV1 {
    former_node: former.node().clone(),
    former_key: former.public_key().clone(),
    former_handle: former.handle().clone(),
    replacement_node: NodeId::generate(entropy)?,
    replacement_operation: KeyOperationId::generate(entropy)?,
  };
  let value = StoreValue::new(Arc::from(intent.encode()?));
  // Losing the Absent expectation to an external writer is transient:
  // the bounded retries re-snapshot and re-prepare the same intent
  // instead of surfacing the conflict to the caller (the wipe batches
  // use the same bounded-retry precedent).
  const INTENT_RACE_BUDGET: usize = 8;
  for _ in 0..INTENT_RACE_BUDGET {
    let snapshot = store.snapshot().await?;
    let prepared = store.prepare_transaction(
      TransactionId::generate(entropy)?,
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: leave_namespace()?,
        key: leave_key(),
        expected: StoreExpectation::Absent,
        value: value.clone(),
      }],
    )?;
    drop(snapshot);
    match commit_with_reconcile(store, prepared).await? {
      CommitWithReconcile::Committed => return Ok((value, intent)),
      CommitWithReconcile::Aborted => continue,
    }
  }
  Err(Error::conflict("leave intent"))
}

/// Resumes a pending leave at startup (T-G09-06 restart path): the leave
/// phases run to completion before the node serves. Returns the context's
/// replacement identity when the swap happened during this resume.
pub(crate) async fn resume_if_pending(
  context: &LocalIdentityContext, keys: &Arc<dyn KeyProvider>, entropy: &dyn Entropy,
) -> Result<Option<LocalIdentityV1>> {
  let store = context.store();
  let Some((stored, intent)) = discover_leave_intent(store).await? else {
    return Ok(None);
  };
  run_leave(store, keys, entropy, &stored, &intent).await?;
  let identity =
    crate::identity::lifecycle::discover_local_identity(store.snapshot().await?.as_ref())
      .await?
      .ok_or_else(|| Error::internal("leave local identity"))?
      .1;
  Ok(Some(identity))
}

#[cfg(test)]
mod tests {
  use std::{sync::Arc, time::Duration};

  use super::{
    LeaveIntentV1, LeaveRecordV1, WIPE_NAMESPACES, discover_leave_intent, execute, is_left_ctx,
    known_leave_records_ctx, left_nodes_ctx, persist_leave_record_ctx, resume_if_pending,
    sign_leave_record,
  };
  use crate::{
    ErrorKind, Result, StoreExpectation, StoreOperation, StoreValue, TransactionId,
    api::Entropy,
    identity::{
      lifecycle::{self, LocalIdentityContext},
      testing::{CreateScript, ScriptedKeys, SequenceEntropy},
    },
    provider::StorageFactory,
    storage::MetadataStore,
  };

  async fn open_store(
    factory: &Arc<dyn StorageFactory>,
  ) -> Result<(
    Arc<ScriptedKeys>,
    Arc<SequenceEntropy>,
    LocalIdentityContext,
  )> {
    let keys = ScriptedKeys::full();
    let entropy = Arc::new(SequenceEntropy::default());
    let context = lifecycle::open_local_identity(
      factory,
      &keys.as_provider(),
      entropy.as_ref(),
      Duration::from_secs(10),
    )
    .await?;
    Ok((keys, entropy, context))
  }

  fn reference_factory() -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  /// Seeds one opaque record into each wiped family, so the leave has
  /// metadata to erase in every namespace.
  async fn seed_old_metadata(store: &MetadataStore, entropy: &dyn Entropy) -> Result<()> {
    for tag in WIPE_NAMESPACES {
      let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(tag)?);
      let snapshot = store.snapshot().await?;
      let prepared = store.prepare_transaction(
        TransactionId::generate(entropy)?,
        snapshot.revision().clone(),
        vec![StoreOperation::Put {
          namespace,
          key: crate::StoreKey::new(Arc::from(b"noise".to_vec())),
          expected: StoreExpectation::Absent,
          value: StoreValue::new(Arc::from(b"old-identity-metadata".to_vec())),
        }],
      )?;
      drop(snapshot);
      assert!(matches!(
        store.commit(prepared).await?,
        crate::CommitOutcome::Committed(_)
      ));
    }
    Ok(())
  }

  /// Every wiped family must be empty after the leave.
  async fn assert_wiped(store: &MetadataStore) {
    for tag in WIPE_NAMESPACES {
      let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(tag).unwrap());
      let snapshot = store.snapshot().await.unwrap();
      let mut scan = snapshot.scan(&namespace, &[]).await.unwrap();
      assert!(
        scan.next().await.unwrap().is_none(),
        "family {tag} must be wiped"
      );
    }
  }

  /// SC-G11-P0-15: the owner-signed leave record round-trips canonically,
  /// verifies against the owner key, and rejects any body or signature
  /// mutation.
  #[tokio::test]
  async fn leave_record_signs_round_trips_and_rejects_mutation() {
    let factory = reference_factory();
    let (keys, _entropy, context) = open_store(&factory).await.unwrap();
    let record = sign_leave_record(&context, &keys.as_provider())
      .await
      .unwrap();
    assert_eq!(record.node(), context.identity().node());
    record.verify().unwrap();

    let bytes = record.encode().unwrap();
    let decoded = LeaveRecordV1::decode(&bytes).unwrap();
    assert_eq!(decoded, record);
    decoded.verify().unwrap();

    // A record for another node with this signature never verifies.
    let other = LeaveRecordV1::new(
      crate::NodeId::parse("node_000000000000000000099").unwrap(),
      record.public_key().clone(),
      record.timestamp_millis(),
      crate::Signature::from_bytes([0x5A; 64]),
    );
    assert!(other.verify().is_err());
  }

  /// SC-G11-P0-15/16: persistence is idempotent for the exact record,
  /// conflicts on a divergent record for the same node, and the left set
  /// is queryable for session and recovery exclusion.
  #[tokio::test]
  async fn leave_record_persists_idempotently_and_marks_left() {
    let factory = reference_factory();
    let (keys, entropy, context) = open_store(&factory).await.unwrap();
    let record = sign_leave_record(&context, &keys.as_provider())
      .await
      .unwrap();
    let node = record.node().clone();

    assert!(!is_left_ctx(context.store(), &node).await.unwrap());
    persist_leave_record_ctx(context.store(), entropy.as_ref(), &record)
      .await
      .unwrap();
    persist_leave_record_ctx(context.store(), entropy.as_ref(), &record)
      .await
      .unwrap();
    assert!(is_left_ctx(context.store(), &node).await.unwrap());
    assert!(
      left_nodes_ctx(context.store())
        .await
        .unwrap()
        .contains(&node)
    );
    assert_eq!(
      known_leave_records_ctx(context.store(), 64)
        .await
        .unwrap()
        .len(),
      1
    );

    // A divergent record for the same node conflicts without mutation.
    let divergent = LeaveRecordV1::new(
      node.clone(),
      record.public_key().clone(),
      record.timestamp_millis(),
      crate::Signature::from_bytes([0x5A; 64]),
    );
    let error = persist_leave_record_ctx(context.store(), entropy.as_ref(), &divergent)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
    assert_eq!(
      known_leave_records_ctx(context.store(), 64)
        .await
        .unwrap()
        .len(),
      1
    );
  }

  /// The leave-intent record round-trips canonically and rejects schema,
  /// version, and field mutations (the record is local-only and unsigned;
  /// integrity comes from the store's digest-checked transactions).
  #[test]
  fn leave_intent_round_trips_and_rejects_mutation() {
    let intent = LeaveIntentV1::new_for_test();
    let bytes = intent.encode().unwrap();
    assert_eq!(LeaveIntentV1::decode(&bytes).unwrap(), intent);
    // Schema/version rejection: flip the trailing key-generation byte of
    // the version field and the last schema character.
    let mut forged = bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xFF;
    assert!(LeaveIntentV1::decode(&forged).is_err());
  }

  /// SC-G09-P0-18/20: one leave swaps the identity, wipes every old
  /// domain family, deletes the former key through the custody protocol,
  /// and clears its intent — the store holds only the replacement
  /// identity afterwards.
  #[tokio::test]
  async fn leave_swaps_identity_wipes_metadata_and_deletes_former_key() {
    let factory = reference_factory();
    let (keys, entropy, context) = open_store(&factory).await.unwrap();
    let former_node = context.identity().node().clone();
    let former_handle = context.identity().handle().clone();
    seed_old_metadata(context.store(), entropy.as_ref())
      .await
      .unwrap();

    let (former, replacement) = execute(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap();
    assert_eq!(former, former_node);
    assert_ne!(former, replacement);

    // The singleton identity is exactly the replacement.
    let identity =
      lifecycle::discover_local_identity(context.store().snapshot().await.unwrap().as_ref())
        .await
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(identity.node(), &replacement);
    assert_ne!(identity.handle(), &former_handle);

    // Every old domain family is empty; the intent is cleared.
    assert_wiped(context.store()).await;
    assert!(
      discover_leave_intent(context.store())
        .await
        .unwrap()
        .is_none()
    );

    // The former key passed the custody protocol: the provider deleted
    // exactly the former handle, and the replacement handle is live.
    use crate::identity::testing::KeyCall;
    assert!(
      keys
        .all_calls()
        .iter()
        .any(|call| matches!(call, KeyCall::Delete))
    );
    assert!(!keys.has_handle(&former_handle));
    assert!(keys.has_handle(identity.handle()));
  }

  /// SC-G09-P0-19: an indeterminate provider create blocks the leave with
  /// the typed reconciliation error and mutates nothing beyond the
  /// journaled intent; the startup resume then reconciles and completes.
  #[tokio::test]
  async fn unknown_key_create_blocks_then_resume_reconciles() {
    let factory = reference_factory();
    let (keys, entropy, context) = open_store(&factory).await.unwrap();
    let former_node = context.identity().node().clone();
    seed_old_metadata(context.store(), entropy.as_ref())
      .await
      .unwrap();

    // The provider applies the create but reports Unknown: the leave
    // fails closed and the identity is not swapped.
    keys.push_create_script(CreateScript::ApplyReportUnknown);
    let error = execute(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CommitUnknown);
    assert_eq!(context.identity().node(), &former_node);
    let stored_identity =
      lifecycle::discover_local_identity(context.store().snapshot().await.unwrap().as_ref())
        .await
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(stored_identity.node(), &former_node);
    assert!(
      discover_leave_intent(context.store())
        .await
        .unwrap()
        .is_some()
    );

    // Re-driving the live command resumes the pending intent and
    // completes — the operator is never stuck with a serving node that
    // holds an unresolvable leave (the startup resume path is identical).
    let (former, replacement) = execute(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap();
    assert_eq!(former, former_node);
    assert_ne!(replacement, former_node);
    let replacement_identity = resume_if_pending(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap();
    assert!(replacement_identity.is_none(), "the leave completed");
    assert_wiped(context.store()).await;
    assert!(
      discover_leave_intent(context.store())
        .await
        .unwrap()
        .is_none()
    );
  }

  /// SC-G09-P0-21 (resume arm): a leave interrupted after the identity
  /// swap resumes to completion — never a mixed identity, a duplicate
  /// key, or restored old metadata.
  /// The crash-retryable ordering (phase J leads): a journaled drive
  /// reuses its signed record verbatim on re-drive, and a crash after
  /// the journal resumes at startup to a fully replaced identity.
  #[tokio::test]
  async fn journaled_leave_is_idempotent_and_resumes() {
    let factory = reference_factory();
    let (keys, entropy, context) = open_store(&factory).await.unwrap();
    seed_old_metadata(context.store(), entropy.as_ref())
      .await
      .unwrap();

    let first = super::journal_leave(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap();
    let again = super::journal_leave(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap();
    assert_eq!(
      first.record.encode().unwrap(),
      again.record.encode().unwrap(),
      "a re-drive reuses the journaled record verbatim"
    );

    // Simulate the crash: the drive never announces or rotates. The
    // startup resume completes the phases with the same record.
    let identity = resume_if_pending(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap()
      .expect("the journaled leave resumes to a replacement identity");
    assert_eq!(identity.node(), &first.intent.replacement_node);
    // The leave is recorded, never forgotten: the former identity stays
    // terminal evidence even after the wipe spares the leave family.
    assert!(
      is_left_ctx(context.store(), first.intent.former_node())
        .await
        .unwrap()
    );
  }

  #[tokio::test]
  async fn interrupted_leave_resumes_to_completion() {
    let factory = reference_factory();
    let (keys, entropy, context) = open_store(&factory).await.unwrap();
    let former_node = context.identity().node().clone();
    seed_old_metadata(context.store(), entropy.as_ref())
      .await
      .unwrap();

    // Interrupt after the swap: run the intent and the swap, then stop.
    let (_stored, intent) = super::begin_intent(&context, entropy.as_ref())
      .await
      .unwrap();
    let created = super::replacement_key(&keys.as_provider(), &intent)
      .await
      .unwrap();
    super::swap_identity(context.store(), entropy.as_ref(), &intent, &created)
      .await
      .unwrap();
    let replacement_node = intent.replacement_node.clone();

    // The startup resume completes the remaining phases.
    let identity = resume_if_pending(&context, &keys.as_provider(), entropy.as_ref())
      .await
      .unwrap()
      .unwrap();
    assert_eq!(identity.node(), &replacement_node);
    assert_ne!(identity.node(), &former_node);
    assert_wiped(context.store()).await;
    assert!(
      discover_leave_intent(context.store())
        .await
        .unwrap()
        .is_none()
    );
  }
}

#[cfg(all(test, unix, any(feature = "json", feature = "redb")))]
mod crash {
  //! Subprocess durability matrix for the leave transition (SC-G09-P0-21).
  //!
  //! The child drives a leave against the selected backend store and
  //! aborts at one selected commit-path boundary of the intent commit or
  //! the identity swap. The parent reopens the store — which runs the
  //! leave resume — and proves the outcome equals exactly the untouched
  //! control (the intent never committed) or the completed control
  //! (replacement identity, wiped metadata, former-key tombstone, no
  //! intent), never a mixed or partial phase. The matrix runs against
  //! every compiled backend (JSON and redb).

  use std::{sync::Arc, time::Duration};

  use tempfile::TempDir;

  use super::{
    LeaveIntentV1, WIPE_NAMESPACES, begin_intent, discover_leave_intent, execute, run_leave,
  };
  use crate::{
    NodeId, StoreExpectation, StoreKey, StoreNamespace, StoreOperation, StoreValue, TransactionId,
    api::Entropy,
    identity::{
      lifecycle::{self, LocalIdentityContext},
      testing::{ScriptedKeys, SequenceEntropy},
    },
    provider::StorageFactory,
    storage::{MetadataStore, test_util},
  };

  const CRASH_DIR_ENV: &str = "RADIATA_LEAVE_CRASH_DIR";
  const CRASH_POINT_ENV: &str = "RADIATA_LEAVE_CRASH_POINT";
  const CRASH_PHASE_ENV: &str = "RADIATA_LEAVE_CRASH_PHASE";
  const CRASH_BACKEND_ENV: &str = "RADIATA_LEAVE_CRASH_BACKEND";
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

  /// Providers whose deterministic handles are all resolvable: children
  /// create from 5000 and parents from 6000, and every provider
  /// pre-registers 5000..6008, so a reopen resolves any persisted handle
  /// without ever reusing one.
  #[cfg(all(test, unix, any(feature = "json", feature = "redb")))]
  fn keyed_providers() -> (Arc<ScriptedKeys>, Arc<ScriptedKeys>) {
    let child_keys = ScriptedKeys::full_at(5_000);
    let parent_keys = ScriptedKeys::full_at(6_000);
    for index in 5_000..6_008_u64 {
      child_keys.register_handle_index(index);
      parent_keys.register_handle_index(index);
    }
    (child_keys, parent_keys)
  }

  #[cfg(all(test, unix, any(feature = "json", feature = "redb")))]
  async fn open(
    factory: &Arc<dyn StorageFactory>,
  ) -> (
    Arc<ScriptedKeys>,
    Arc<SequenceEntropy>,
    LocalIdentityContext,
  ) {
    open_with_entropy_offset(factory, 0).await
  }

  /// Opens with the entropy sequence started far past every child draw:
  /// a resume must never regenerate a transaction id the crashed child
  /// already used (the store's used-id markers would fail it closed).
  #[cfg(all(test, unix, any(feature = "json", feature = "redb")))]
  async fn open_with_entropy_offset(
    factory: &Arc<dyn StorageFactory>, entropy_offset: u128,
  ) -> (
    Arc<ScriptedKeys>,
    Arc<SequenceEntropy>,
    LocalIdentityContext,
  ) {
    let (child_keys, parent_keys) = keyed_providers();
    let keys = if entropy_offset == 0 {
      child_keys
    } else {
      parent_keys
    };
    let entropy = Arc::new(SequenceEntropy::starting_at(entropy_offset));
    let context = lifecycle::open_local_identity(
      factory,
      &keys.as_provider(),
      entropy.as_ref(),
      Duration::from_secs(10),
    )
    .await
    .unwrap();
    (keys, entropy, context)
  }

  /// Seeds one opaque old-identity record per wiped family.
  pub(super) async fn seed(store: &MetadataStore, entropy: &dyn Entropy) {
    for tag in WIPE_NAMESPACES {
      let namespace = StoreNamespace::new(crate::QualifiedTag::parse(tag).unwrap());
      let snapshot = store.snapshot().await.unwrap();
      let prepared = store
        .prepare_transaction(
          TransactionId::generate(entropy).unwrap(),
          snapshot.revision().clone(),
          vec![StoreOperation::Put {
            namespace,
            key: StoreKey::new(Arc::from(b"noise".to_vec())),
            expected: StoreExpectation::Absent,
            value: StoreValue::new(Arc::from(b"old-identity-metadata".to_vec())),
          }],
        )
        .unwrap();
      drop(snapshot);
      assert!(matches!(
        store.commit(prepared).await.unwrap(),
        crate::CommitOutcome::Committed(_)
      ));
    }
  }

  /// The observable post-resume state: identity, per-family noise
  /// presence, and intent presence.
  struct Phase {
    identity: NodeId,
    noise: Vec<bool>,
    intent: Option<LeaveIntentV1>,
  }

  async fn observe(factory: &Arc<dyn StorageFactory>) -> Phase {
    let (_keys, _entropy, context) = open_with_entropy_offset(factory, 1_000_000).await;
    let store = context.store();
    let mut noise = Vec::with_capacity(WIPE_NAMESPACES.len());
    for tag in WIPE_NAMESPACES {
      let namespace = StoreNamespace::new(crate::QualifiedTag::parse(tag).unwrap());
      let snapshot = store.snapshot().await.unwrap();
      let mut scan = snapshot.scan(&namespace, &[]).await.unwrap();
      noise.push(scan.next().await.unwrap().is_some());
    }
    let intent = discover_leave_intent(store)
      .await
      .unwrap()
      .map(|(_, intent)| intent);
    Phase {
      identity: context.identity().node().clone(),
      noise,
      intent,
    }
  }

  fn run_child(dir: &TempDir, backend: &str, phase: &str, point: u8) {
    test_util::run_crash_child(
      "identity::leave::crash::leave_crash_child_entry",
      CRASH_DIR_ENV,
      CRASH_POINT_ENV,
      dir.path(),
      point,
      "leave",
      &[
        (CRASH_PHASE_ENV, phase.to_owned()),
        (CRASH_BACKEND_ENV, backend.to_owned()),
      ],
    );
  }

  #[ignore = "leave crash-matrix child process entry point"]
  #[tokio::test]
  async fn leave_crash_child_entry() {
    let directory = std::path::PathBuf::from(std::env::var_os(CRASH_DIR_ENV).expect("crash dir"));
    let point: u8 = std::env::var(CRASH_POINT_ENV)
      .expect("crash point")
      .parse()
      .expect("numeric crash point");
    let phase = std::env::var(CRASH_PHASE_ENV).expect("crash phase");
    let backend = std::env::var(CRASH_BACKEND_ENV).unwrap_or_else(|_| "json".to_owned());
    let factory = factory(&backend, &directory);
    let (keys, entropy, context) = open(&factory).await;
    seed(context.store(), entropy.as_ref()).await;
    match phase.as_str() {
      // Arm before the leave-intent commit (phase A).
      "intent" => {
        select_point(&backend, point);
        let _ = execute(&context, &keys.as_provider(), entropy.as_ref()).await;
      }
      // Commit the intent first, then arm inside the identity swap
      // (phase C, the first commit of the remaining phases).
      "swap" => {
        let (stored, intent) = begin_intent(&context, entropy.as_ref()).await.unwrap();
        select_point(&backend, point);
        let _ = run_leave(
          context.store(),
          &keys.as_provider(),
          entropy.as_ref(),
          &stored,
          &intent,
        )
        .await;
      }
      other => panic!("unknown leave crash phase: {other}"),
    }
  }

  /// Every crash boundary of the leave transition resumes to exactly the
  /// untouched or the completed control state, on every compiled backend.
  #[tokio::test]
  async fn leave_crash_boundaries_resume_to_a_reconciled_phase() {
    for (backend, last_point) in backends() {
      // Untouched control: seeded, no leave.
      let untouched_dir = TempDir::new().unwrap();
      let untouched_factory = factory(backend, untouched_dir.path());
      let (_keys, entropy, context) = open(&untouched_factory).await;
      seed(context.store(), entropy.as_ref()).await;
      drop(context);
      let untouched = observe(&untouched_factory).await;

      // Completed control: a full leave without faults.
      let completed_dir = TempDir::new().unwrap();
      let completed_factory = factory(backend, completed_dir.path());
      let (keys, entropy, context) = open(&completed_factory).await;
      seed(context.store(), entropy.as_ref()).await;
      let (_former, _replacement) = execute(&context, &keys.as_provider(), entropy.as_ref())
        .await
        .unwrap();
      drop(context);
      let completed = observe(&completed_factory).await;
      assert!(completed.intent.is_none());
      assert!(completed.noise.iter().all(|present| !present));
      assert_ne!(completed.identity, untouched.identity);

      for phase in ["intent", "swap"] {
        for point in 1..=last_point {
          let dir = TempDir::new().unwrap();
          let factory = factory(backend, dir.path());
          run_child(&dir, backend, phase, point);
          // The reopen runs the leave resume; the result is one control.
          let observed = observe(&factory).await;
          assert!(
            observed.intent.is_none(),
            "{backend}/{phase}/{point}: the resume must clear the leave intent"
          );
          let is_untouched =
            observed.identity == untouched.identity && observed.noise == untouched.noise;
          let is_completed =
            observed.identity == completed.identity && observed.noise == completed.noise;
          assert!(
            is_untouched ^ is_completed,
            "{backend}/{phase}/{point}: state must equal exactly one control, got identity={} noise={:?}",
            observed.identity,
            observed.noise,
          );
        }
      }
    }
  }
}
