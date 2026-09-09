//! Owner-marked node descriptors (session-trust boundary).
//!
//! A [`NodeDescriptorV1`] is the node-owned revision record: it carries the
//! owning node's `NodeId` marking, its endpoint candidates, a strictly
//! increasing revision, and the removal flag. Entries are trusted through
//! the authenticated session that delivered them, so they carry
//! no per-entry signatures. Core accepts an update only at a strictly
//! higher revision; stale and repeated revisions cannot replace the
//! current record, and a retained removal marker defeats reordered or
//! replayed older descriptors.

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{Endpoint, LabelSet, NodeId, PublicKey, Result, protocol::encode_canonical};

/// The durable schema, namespace, and key of one node descriptor record.
pub(crate) const NODE_DESCRIPTOR_SCHEMA: &str = "radiata.woooo.tech/schemas/node-descriptor-v1";
pub(crate) use crate::storage::families::NODE_DESCRIPTOR_NAMESPACE;

/// One owner-marked node descriptor.
///
/// The record carries the owning node's capability labels (record
/// version 2); version 1 records without labels remain decodable
/// as the previous fixture shape and always decode to an empty label set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodeDescriptorV1 {
  node: NodeId,
  public_key: PublicKey,
  endpoints: Vec<Endpoint>,
  labels: LabelSet,
  revision: u64,
  removed: bool,
  version: u16,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct DescriptorWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  node: String,
  #[n(3)]
  public_key: ByteVec,
  #[n(4)]
  endpoints: Vec<String>,
  #[n(5)]
  revision: u64,
  #[n(6)]
  removed: bool,
  #[n(7)]
  version: u16,
  /// Canonical capability labels: key/value pairs sorted by key text,
  /// unique keys. Present from record version 2 on; version 1 records
  /// end at `version` and always decode to an empty label set.
  #[n(8)]
  labels: Vec<(String, String)>,
}

impl NodeDescriptorV1 {
  pub(crate) fn new(
    node: NodeId, public_key: PublicKey, endpoints: Vec<Endpoint>, revision: u64, removed: bool,
    version: u16,
  ) -> Self {
    Self {
      node,
      public_key,
      endpoints,
      labels: LabelSet::new(),
      revision,
      removed,
      version,
    }
  }

  /// Replaces this descriptor's capability labels (the owner-only label
  /// mutation path behind `UpdateNodeMetadata`).
  pub(crate) fn with_labels(mut self, labels: LabelSet) -> Self {
    self.labels = labels;
    self
  }

  pub(crate) const fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) const fn revision(&self) -> u64 {
    self.revision
  }

  pub(crate) fn public_key(&self) -> &PublicKey {
    &self.public_key
  }

  pub(crate) fn endpoints(&self) -> &[Endpoint] {
    &self.endpoints
  }

  pub(crate) const fn labels(&self) -> &LabelSet {
    &self.labels
  }

  pub(crate) const fn removed(&self) -> bool {
    self.removed
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(&self.wire(), crate::protocol::CONTROL_CBOR_LIMITS)
  }

  fn wire(&self) -> DescriptorWire {
    DescriptorWire {
      schema: NODE_DESCRIPTOR_SCHEMA.to_owned(),
      // Version 2 records carry capability labels; the decoder still
      // accepts version 1 (the previous fixture shape, no labels).
      record_version: 2,
      node: self.node.as_str().to_owned(),
      public_key: ByteVec::from(self.public_key.as_bytes().to_vec()),
      endpoints: self
        .endpoints
        .iter()
        .map(|endpoint| endpoint.as_str().to_owned())
        .collect(),
      labels: self
        .labels
        .entries()
        .map(|(key, value)| (key.as_str().to_owned(), value.as_str().to_owned()))
        .collect(),
      revision: self.revision,
      removed: self.removed,
      version: self.version,
    }
  }
}

/// The previous-fixture wire shape (record version 1): identical to the
/// current shape minus the capability-label map.
#[derive(Encode, Decode)]
#[cbor(array)]
struct DescriptorWireV1 {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  node: String,
  #[n(3)]
  public_key: ByteVec,
  #[n(4)]
  endpoints: Vec<String>,
  #[n(5)]
  revision: u64,
  #[n(6)]
  removed: bool,
  #[n(7)]
  version: u16,
}

/// The digest of one descriptor's canonical encoding, for public views.
pub(crate) fn node_descriptor_digest(descriptor: &NodeDescriptorV1) -> Result<crate::Digest> {
  Ok(crate::identity::signature::body_digest(
    &descriptor.encode()?,
  ))
}

/// The single descriptor → public member view mapper: annotates the
/// owner-revision descriptor with the session-table connectivity decision.
/// Every public member view (exact lookup, paged population read, and
/// routed candidate reads) flows through here so the view shape cannot
/// drift between them.
/// Applies one owner-only metadata patch to a descriptor and returns the
/// descriptor at the next revision (owner records): endpoint adds
/// must be new, endpoint removals must exist, label set/insert flows
/// through the label namespace rules, and label removals must exist.
/// Single-sourced here — next to the descriptor type it mutates — so any
/// future writer (sync, recovery) merges identically instead of
/// re-implementing the rules in the runtime supervisor.
pub(crate) fn apply_metadata_patch(
  descriptor: &NodeDescriptorV1, patch: crate::NodeMetadataPatch,
) -> Result<NodeDescriptorV1> {
  let parts = patch.into_parts();
  let mut endpoints: Vec<Endpoint> = descriptor.endpoints().to_vec();
  for endpoint in parts.add_endpoints {
    if endpoints.contains(&endpoint) {
      return Err(crate::Error::conflict("node metadata endpoint"));
    }
    endpoints.push(endpoint);
  }
  for endpoint in parts.remove_endpoints {
    let Some(position) = endpoints
      .iter()
      .position(|candidate| *candidate == endpoint)
    else {
      return Err(crate::Error::not_found("node metadata endpoint"));
    };
    endpoints.remove(position);
  }
  let mut labels = descriptor.labels().clone();
  for (key, value) in parts.set_labels {
    // "set" is an upsert: replacing an existing key's value is the
    // ordinary owner-revision edit, not a conflict.
    labels.remove(&key);
    labels = labels.insert(key, value)?;
  }
  for key in parts.remove_labels {
    if !labels.contains_key(&key) {
      return Err(crate::Error::not_found("node metadata label"));
    }
    labels.remove(&key);
  }
  Ok(
    NodeDescriptorV1::new(
      descriptor.node().clone(),
      descriptor.public_key().clone(),
      endpoints,
      descriptor.revision() + 1,
      false,
      1,
    )
    .with_labels(labels),
  )
}

pub(crate) fn member_view(
  descriptor: &NodeDescriptorV1, status: crate::ConnectivityStatus,
) -> Result<crate::MemberView> {
  Ok(crate::MemberView::new(
    descriptor.node().clone(),
    descriptor.public_key().clone(),
    descriptor.revision(),
    node_descriptor_digest(descriptor)?,
    status,
    descriptor.endpoints().to_vec(),
    descriptor.labels().clone(),
  ))
}

/// The bounded descriptor observation store.
pub(crate) mod neighbor;
pub(crate) mod page;
pub(crate) mod recovery;
pub(crate) mod sync;

pub(crate) mod store {
  use std::sync::Arc;

  use super::{NODE_DESCRIPTOR_NAMESPACE, NodeDescriptorV1};
  use crate::{
    Error, NodeId, Result, StoreKey, StoreNamespace, StoreOperation, StoreValue, TransactionId,
    api::Entropy, storage::MetadataStore,
  };

  fn namespace() -> Result<StoreNamespace> {
    crate::storage::families::namespace(NODE_DESCRIPTOR_NAMESPACE)
  }

  fn descriptor_key(node: &NodeId) -> StoreKey {
    StoreKey::new(Arc::from(node.as_str().as_bytes().to_vec()))
  }

  /// Reads the current descriptor for one node, if any, from an
  /// already-acquired snapshot, so callers iterating many members pay one
  /// snapshot acquisition per cycle instead of one per member.
  pub(crate) async fn read_descriptor_snapshot(
    snapshot: &dyn crate::provider::StoreSnapshot, node: &NodeId,
  ) -> Result<Option<NodeDescriptorV1>> {
    let namespace = namespace()?;
    let key = descriptor_key(node);
    let Some(value) = snapshot.get(&namespace, &key).await? else {
      return Ok(None);
    };
    Ok(Some(crate::membership::page::decode_descriptor(
      value.as_bytes(),
    )?))
  }

  /// Reads the current descriptor for one node, if any, over the running
  /// node's metadata store (the runtime path; never re-opens storage).
  pub(crate) async fn read_descriptor_ctx(
    store: &MetadataStore, node: &NodeId,
  ) -> Result<Option<NodeDescriptorV1>> {
    let namespace = namespace()?;
    let key = descriptor_key(node);
    let value = store.snapshot().await?.get(&namespace, &key).await?;
    let Some(value) = value else {
      return Ok(None);
    };
    Ok(Some(crate::membership::page::decode_descriptor(
      value.as_bytes(),
    )?))
  }

  /// Stores one descriptor over the running node's metadata store. A
  /// record is replaced only by a strictly higher revision; the first
  /// record starts at revision 1. Same-revision and stale (lower)
  /// revisions are rejected, while a skipped intermediate revision still
  /// replaces the record so anti-entropy heals a lost delivery instead of
  /// diverging forever — including a first install at a higher revision
  /// for a node whose trusted binding already exists (the member updated
  /// its labels before its first descriptor page ever arrived here);
  /// a removal marker is never replaced by an older live descriptor.
  pub(crate) async fn store_descriptor_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, descriptor: &NodeDescriptorV1,
  ) -> Result<()> {
    let _permit = store.write_permit().await;
    let namespace = namespace()?;
    let key = descriptor_key(descriptor.node());
    let snapshot = store.snapshot().await?;
    let current = snapshot.get(&namespace, &key).await?;
    if let Some(existing) = current {
      let existing = crate::membership::page::decode_descriptor(existing.as_bytes())?;
      if descriptor.revision() <= existing.revision() {
        return Err(Error::conflict("node descriptor revision"));
      }
      // A removal marker is never replaced by a live descriptor of any
      // revision: rejoining requires a newer signed-out-of-band removal
      // reversal, not a replayed old record.
      if existing.removed() && !descriptor.removed() {
        return Err(Error::conflict("node descriptor removal"));
      }
    } else if descriptor.revision() != 1 {
      // A first install at a revision above 1 is only healable when the
      // node is already trusted (its adopted binding exists): the page
      // arrived over an authenticated session from a trusted member, so
      // the skipped revisions are lost deliveries, never fabrications.
      // A node with no binding and no descriptor is unknown here; its
      // first descriptor must be revision 1.
      let (binding_namespace, binding_key) =
        crate::identity::records::identity_binding_key(descriptor.node())?;
      let adopted = snapshot
        .get(&binding_namespace, &binding_key)
        .await?
        .is_some();
      if !adopted {
        return Err(Error::conflict("node descriptor revision"));
      }
    }
    // One snapshot view for both the per-key expectation and the CAS
    // revision, so a concurrent writer cannot make them disagree.
    let expected =
      crate::provider::snapshot_expectation(snapshot.as_ref(), &namespace, &key).await?;
    let transaction = store.prepare_transaction(
      TransactionId::generate(entropy)?,
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace,
        key,
        expected,
        value: StoreValue::new(Arc::from(descriptor.encode()?)),
      }],
    )?;
    // A discarded commit outcome would silently drop the descriptor: a
    // Conflict (the register moved under the CAS) or an Aborted commit
    // (definitively not applied) must surface so the anti-entropy page
    // applies on a later tick instead of vanishing.
    match store.commit(transaction).await? {
      crate::CommitOutcome::Committed(_) => Ok(()),
      crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => {
        Err(Error::conflict("node descriptor revision"))
      }
      crate::CommitOutcome::Unknown { .. } => Err(Error::provider(
        crate::ProviderErrorKind::CommitUnknown,
        crate::ProviderErrorContext::StorageCommit,
      )),
    }
  }

  /// Reads the current descriptor for one node over a standalone factory
  /// handle (unit/offline path; the caller owns the opened store).
  #[cfg(test)]
  pub(crate) async fn read_descriptor(
    factory: &Arc<dyn crate::provider::StorageFactory>, node: &NodeId,
  ) -> Result<Option<NodeDescriptorV1>> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    read_descriptor_ctx(&store, node).await
  }

  /// Stores one descriptor over a standalone factory handle.
  #[cfg(test)]
  pub(crate) async fn store_descriptor(
    factory: &Arc<dyn crate::provider::StorageFactory>, descriptor: &NodeDescriptorV1,
  ) -> Result<()> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    store_descriptor_ctx(&store, &crate::api::SystemEntropy, descriptor).await
  }
}

#[cfg(test)]
mod tests {
  use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
  };

  use super::{NodeDescriptorV1, store};
  use crate::{
    BoxFuture, CommitOutcome, Endpoint, ErrorKind, NodeId, ReconcileOutcome, StoreCapabilities,
    StoreRequirements, StoreTransaction,
    provider::{Storage, StorageFactory, StoreSnapshot},
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn key(value: u8) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value.into());
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  fn endpoint(host: &str) -> Endpoint {
    Endpoint::parse(&format!("wss://{host}:9000")).unwrap()
  }

  fn descriptor(
    revision: u64, owner_index: u8, endpoints: Vec<&str>, removed: bool,
  ) -> NodeDescriptorV1 {
    NodeDescriptorV1::new(
      node(owner_index),
      key(owner_index),
      endpoints.into_iter().map(endpoint).collect(),
      revision,
      removed,
      1,
    )
  }

  fn factory() -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  /// Test-only storage wrapper that aborts the first scripted commit:
  /// the reference factory is otherwise always-committed, so this is the
  /// only way to drive an `Aborted` outcome into the descriptor store.
  #[derive(Debug)]
  struct AbortingOnceFactory {
    reference: Arc<dyn StorageFactory>,
  }

  #[derive(Debug)]
  struct AbortingOnceStorage {
    reference: Box<dyn Storage>,
    pending: Mutex<VecDeque<()>>,
  }

  impl StorageFactory for AbortingOnceFactory {
    fn open<'a>(
      &'a self, requirements: StoreRequirements,
    ) -> BoxFuture<'a, crate::Result<Box<dyn Storage>>> {
      Box::pin(async move {
        let reference = self.reference.open(requirements).await?;
        Ok(Box::new(AbortingOnceStorage {
          reference,
          pending: Mutex::new(VecDeque::from([()])),
        }) as Box<dyn Storage>)
      })
    }
  }

  impl Storage for AbortingOnceStorage {
    fn capabilities(&self) -> StoreCapabilities {
      self.reference.capabilities()
    }

    fn snapshot<'a>(&'a self) -> BoxFuture<'a, crate::Result<Box<dyn StoreSnapshot>>> {
      self.reference.snapshot()
    }

    fn commit<'a>(
      &'a self, transaction: StoreTransaction,
    ) -> BoxFuture<'a, crate::Result<CommitOutcome>> {
      let abort = self.pending.lock().unwrap().pop_front().is_some();
      Box::pin(async move {
        if abort {
          Ok(CommitOutcome::Aborted)
        } else {
          self.reference.commit(transaction).await
        }
      })
    }

    fn reconcile<'a>(
      &'a self, transaction: &'a crate::TransactionId, digest: &'a crate::Digest,
    ) -> BoxFuture<'a, crate::Result<ReconcileOutcome>> {
      self.reference.reconcile(transaction, digest)
    }

    fn flush<'a>(&'a self) -> BoxFuture<'a, crate::Result<()>> {
      self.reference.flush()
    }
  }

  /// Membership entries are keyed under their marked owner and round-trip
  /// their identity marking through the canonical wire.
  #[test]
  fn descriptor_carries_owner_marking() {
    let descriptor = descriptor(1, 1, vec!["one.example"], false);
    let decoded =
      crate::membership::page::decode_descriptor(&descriptor.encode().unwrap()).unwrap();
    assert_eq!(decoded.node(), &node(1));
    assert_eq!(decoded.public_key(), &key(1));
  }

  /// A record is replaced only by a strictly higher revision, and a
  /// skipped intermediate revision still heals the gap.
  #[tokio::test]
  async fn descriptor_store_enforces_monotonic_revisions() {
    let factory = factory();
    store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
      .await
      .unwrap();

    // Same revision rejected.
    assert!(
      store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
        .await
        .is_err()
    );
    // Lower revision rejected (no rollback).
    let stale = descriptor(0, 1, vec!["stale.example"], false);
    assert!(store::store_descriptor(&factory, &stale).await.is_err());

    // A skipped intermediate revision heals the gap instead of diverging:
    // anti-entropy must converge a peer that missed revision 2.
    store::store_descriptor(&factory, &descriptor(3, 1, vec!["three.example"], false))
      .await
      .unwrap();
    let current = store::read_descriptor(&factory, &node(1))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(current.revision(), 3);
    assert_eq!(current.endpoints()[0].host(), "three.example");

    // Rollback to an older revision after the heal is still rejected.
    assert!(
      store::store_descriptor(&factory, &descriptor(2, 1, vec!["two.example"], false))
        .await
        .is_err()
    );
  }

  /// A removal marker defeats replayed older descriptors.
  #[tokio::test]
  async fn descriptor_removal_marker_defeats_replay() {
    let factory = factory();
    store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
      .await
      .unwrap();
    // Removal at the next revision.
    store::store_descriptor(&factory, &descriptor(2, 1, vec![], true))
      .await
      .unwrap();

    // Replaying the older live descriptor (revision 1) is rejected: the
    // current revision is 2 and a removal marker cannot be replaced by a
    // live descriptor.
    assert!(
      store::store_descriptor(&factory, &descriptor(1, 1, vec!["one.example"], false))
        .await
        .is_err()
    );
    // A removal marker replaced only by a valid newer revision.
    assert!(
      store::store_descriptor(&factory, &descriptor(3, 1, vec![], true))
        .await
        .is_ok()
    );
  }

  /// An aborted commit is definitively not applied: the descriptor store
  /// must fail closed instead of reporting success while the write is
  /// silently dropped (the anti-entropy page then applies on a later
  /// tick through the normal error path).
  #[tokio::test]
  async fn descriptor_store_fails_closed_on_aborted_commit() {
    let factory: Arc<dyn StorageFactory> = Arc::new(AbortingOnceFactory {
      reference: factory(),
    });
    let store = crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(10))
      .await
      .unwrap();
    let error = store::store_descriptor_ctx(
      &store,
      &crate::api::SystemEntropy,
      &descriptor(1, 1, vec!["one.example"], false),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Conflict);
    // The aborted write never landed.
    assert!(
      store::read_descriptor_ctx(&store, &node(1))
        .await
        .unwrap()
        .is_none()
    );
  }

  /// Golden compatibility vectors — current fixtures decode to expected
  /// values; unknown versions fail closed.
  #[test]
  fn descriptor_compatibility_vectors() {
    // Round-trip produces the expected canonical values.
    let descriptor = descriptor(7, 3, vec!["alpha.example", "beta.example"], false);
    let decoded =
      crate::membership::page::decode_descriptor(&descriptor.encode().unwrap()).unwrap();
    assert_eq!(decoded, descriptor);
    assert_eq!(decoded.revision(), 7);
    assert_eq!(decoded.node(), &node(3));
    assert_eq!(decoded.endpoints().len(), 2);

    // Unknown version fails closed.
    let mut unknown = descriptor.clone();
    unknown.version = 99;
    let bytes = unknown.encode().unwrap();
    assert!(crate::membership::page::decode_descriptor(&bytes).is_err());
  }
}
