//! Issuer trust snapshots consumed by the membership sync lane: every
//! node is its own snapshot issuer.
//!
//! A [`TrustSnapshotV1`] is one ordered set of `NodeId`-to-`PublicKey`
//! bindings (strictly increasing revision, version, ordered bindings),
//! carried over authenticated sessions and trusted through them;
//! it carries no per-entry signatures. Conflicting evidence fails closed:
//! wrong issuers in a decoded record's own marking, stale revisions, and
//! `NodeId` key substitutions against locally admitted bindings are rejected
//! without selecting a winner.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::lifecycle::LocalIdentityContext;
use crate::{
  NodeId, PublicKey, Result,
  api::Entropy,
  protocol::{decode_canonical, encode_canonical},
  storage::MetadataStore,
};

/// The durable schema and namespace of one trust snapshot record.
pub(crate) const TRUST_SNAPSHOT_SCHEMA: &str = "radiata.woooo.tech/schemas/trust-snapshot-v1";
pub(crate) use crate::storage::families::TRUST_SNAPSHOT_NAMESPACE;

/// One ordered `(node, key)` binding inside a snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustBinding {
  node: NodeId,
  key: PublicKey,
}

impl TrustBinding {
  pub(crate) const fn new(node: NodeId, key: PublicKey) -> Self {
    Self { node, key }
  }

  pub(crate) const fn node(&self) -> &NodeId {
    &self.node
  }

  pub(crate) const fn key(&self) -> &PublicKey {
    &self.key
  }
}

/// One issuer-marked trust snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustSnapshotV1 {
  revision: u64,
  version: u16,
  issuer: NodeId,
  issuer_key: PublicKey,
  bindings: Vec<TrustBinding>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct BindingWire {
  #[n(0)]
  node: String,
  #[n(1)]
  key: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct SnapshotWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  record_version: u16,
  #[n(2)]
  revision: u64,
  #[n(3)]
  version: u16,
  #[n(4)]
  issuer: String,
  #[n(5)]
  issuer_key: ByteVec,
  #[n(6)]
  bindings: Vec<BindingWire>,
}

impl TrustSnapshotV1 {
  pub(crate) fn new(
    revision: u64, version: u16, issuer: NodeId, issuer_key: PublicKey, bindings: Vec<TrustBinding>,
  ) -> Self {
    Self {
      revision,
      version,
      issuer,
      issuer_key,
      bindings,
    }
  }

  pub(crate) const fn revision(&self) -> u64 {
    self.revision
  }

  pub(crate) const fn issuer(&self) -> &NodeId {
    &self.issuer
  }

  pub(crate) const fn issuer_key(&self) -> &PublicKey {
    &self.issuer_key
  }

  pub(crate) fn bindings(&self) -> &[TrustBinding] {
    &self.bindings
  }

  /// Encodes the full wire record (one 64 KiB control-bound record: at
  /// roughly 870 bindings that bound saturates, so larger memberships
  /// heal through the bounded snapshot resend cadence, never paging).
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(&self.wire(), crate::protocol::CONTROL_CBOR_LIMITS)
  }

  fn wire(&self) -> SnapshotWire {
    SnapshotWire {
      schema: TRUST_SNAPSHOT_SCHEMA.to_owned(),
      record_version: 1,
      revision: self.revision,
      version: self.version,
      issuer: self.issuer.as_str().to_owned(),
      issuer_key: ByteVec::from(self.issuer_key.as_bytes().to_vec()),
      bindings: self
        .bindings
        .iter()
        .map(|binding| BindingWire {
          node: binding.node.as_str().to_owned(),
          key: ByteVec::from(binding.key.as_bytes().to_vec()),
        })
        .collect(),
    }
  }

  /// Decodes one snapshot, checking only its own marking and canonical
  /// wire rules. Entries are trusted through the authenticated session
  /// that delivered them; the caller compares the issuer
  /// marking against its local view where that matters.
  pub(crate) fn decode(bytes: &[u8]) -> Result<TrustSnapshotV1> {
    let wire: SnapshotWire = decode_canonical(bytes, crate::protocol::CONTROL_CBOR_LIMITS)
      .map_err(|_| crate::Error::invalid_input("trust snapshot decode"))?;
    if wire.schema != TRUST_SNAPSHOT_SCHEMA || wire.record_version != 1 {
      return Err(crate::Error::invalid_input("trust snapshot schema"));
    }
    // Only version 1 is known; an unknown version fails closed.
    if wire.version != 1 {
      return Err(crate::Error::invalid_input("trust snapshot version"));
    }
    let issuer = NodeId::parse(&wire.issuer)
      .map_err(|_| crate::Error::invalid_input("trust snapshot issuer"))?;
    let issuer_key = PublicKey::from_bytes(
      <[u8; 32]>::try_from(wire.issuer_key.as_ref())
        .map_err(|_| crate::Error::invalid_input("trust snapshot issuer key"))?,
    );
    let mut bindings = Vec::with_capacity(wire.bindings.len());
    for binding in &wire.bindings {
      let node = NodeId::parse(&binding.node)
        .map_err(|_| crate::Error::invalid_input("trust snapshot node"))?;
      let key = PublicKey::from_bytes(
        <[u8; 32]>::try_from(binding.key.as_ref())
          .map_err(|_| crate::Error::invalid_input("trust snapshot key"))?,
      );
      bindings.push(TrustBinding::new(node, key));
    }
    // Ordered deterministically: canonical node text ascending; a
    // non-canonical order is rejected.
    if !bindings.windows(2).all(|pair| pair[0].node < pair[1].node) {
      return Err(crate::Error::invalid_input("trust snapshot ordering"));
    }
    Ok(Self::new(
      wire.revision,
      wire.version,
      issuer,
      issuer_key,
      bindings,
    ))
  }

  /// True when this snapshot is strictly newer than `other` by revision.
  #[cfg(test)]
  pub(crate) fn is_newer_than(&self, other: &TrustSnapshotV1) -> bool {
    self.revision > other.revision
  }

  /// Rejects a `NodeId` key substitution against the known local bindings:
  /// every binding whose node is already known must carry the exact same
  /// key.
  #[cfg(test)]
  pub(crate) fn assert_no_key_substitution(&self, known: &[(NodeId, PublicKey)]) -> Result<()> {
    let known: std::collections::BTreeMap<&NodeId, &PublicKey> =
      known.iter().map(|(node, key)| (node, key)).collect();
    for binding in &self.bindings {
      if let Some(expected) = known.get(&binding.node)
        && *expected != &binding.key
      {
        return Err(crate::Error::not_trusted("trust snapshot key substitution"));
      }
    }
    Ok(())
  }
}

/// The bounded, deterministic page of one trust observation stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustPage {
  bindings: Vec<TrustBinding>,
  next: Option<usize>,
}

impl TrustPage {
  pub(crate) fn new(bindings: Vec<TrustBinding>, next: Option<usize>) -> Self {
    Self { bindings, next }
  }

  pub(crate) fn bindings(&self) -> &[TrustBinding] {
    &self.bindings
  }

  pub(crate) const fn next(&self) -> Option<usize> {
    self.next
  }
}

/// Paged trust observations over one ordered snapshot's bindings.
#[cfg(test)]
pub(crate) fn page_bindings(
  bindings: &[TrustBinding], offset: usize, limit: usize,
) -> Result<TrustPage> {
  let Some(slice) = bindings.get(offset..) else {
    return Err(crate::Error::invalid_input("trust page offset"));
  };
  let page: Vec<TrustBinding> = slice.iter().take(limit).cloned().collect();
  let next = offset
    .checked_add(page.len())
    .filter(|end| *end < bindings.len());
  Ok(TrustPage::new(page, next))
}

/// Accepts one issuer-marked trust snapshot delivered over an
/// authenticated session: the trust adoption policy for the sync lane.
/// The issuer's declared key must match its locally trusted binding
/// when one exists: a substitution is conflicting evidence and fails
/// closed (snapshots are per-issuer, trusted through the
/// authenticated session and the binding set they extend). The verified
/// snapshot persists, then binding adoption runs per record: a transient
/// store contention on one binding must not abort the remaining bindings
/// of the snapshot; the next delivery retries what was skipped
/// (anti-entropy repair).
pub(crate) async fn accept_snapshot(
  store: &MetadataStore, entropy: &dyn Entropy, snapshot: &TrustSnapshotV1,
) -> Result<()> {
  let bindings = store::trusted_bindings(store).await?;
  if let Some(known) = bindings.get(snapshot.issuer())
    && known != snapshot.issuer_key()
  {
    return Err(crate::Error::not_trusted("trust snapshot issuer key"));
  }
  store::persist_snapshot_ctx(store, entropy, snapshot).await?;
  for binding in snapshot.bindings() {
    // Only transient contention (Conflict) or a not-yet-ready store
    // (NotReady) skips one binding: the next snapshot delivery retries it
    // (anti-entropy repair). Everything else — key substitution,
    // revocation, decode failures, provider faults — is conflicting
    // evidence and fails closed, failing the tick so the sync caller
    // surfaces the typed error.
    if let Err(error) =
      store::persist_binding_ctx(store, entropy, binding.node(), binding.key()).await
    {
      if matches!(
        error.kind(),
        crate::ErrorKind::Conflict | crate::ErrorKind::NotReady
      ) {
        tracing::debug!(node = %binding.node(), kind = ?error.kind(), "trust binding persist skipped");
        continue;
      }
      return Err(error);
    }
    if let Err(error) =
      store::adopt_binding_ctx(store, entropy, binding.node(), binding.key()).await
    {
      if matches!(
        error.kind(),
        crate::ErrorKind::Conflict | crate::ErrorKind::NotReady
      ) {
        tracing::debug!(node = %binding.node(), kind = ?error.kind(), "trust binding adoption skipped");
        continue;
      }
      return Err(error);
    }
  }
  Ok(())
}

/// Every node refreshes its own trust snapshot when its binding set
/// changed: enumerate the durable bindings at revision `latest + 1` and
/// persist. Returns the latest snapshot.
pub(crate) async fn refresh_issuer_snapshot(
  context: &Arc<LocalIdentityContext>, entropy: &Arc<dyn Entropy>,
) -> Result<Option<TrustSnapshotV1>> {
  let store = context.store();
  let issuer = context.identity().node().clone();
  // Cheap short-circuit: bindings are append-only between merges, so an
  // unchanged count means an unchanged binding set; the full enumeration
  // runs only when a merge may have added one.
  let latest = store::latest_snapshot_ctx(store, &issuer).await?;
  if let Some(latest) = &latest
    && !store::has_more_than_bindings(store, latest.bindings().len()).await?
  {
    return Ok(Some(latest.clone()));
  }
  let bindings = store::trusted_bindings(store).await?;
  let current: Vec<TrustBinding> = bindings
    .into_iter()
    .map(|(node, key)| TrustBinding::new(node, key))
    .collect();
  let revision = match &latest {
    Some(latest) if latest.bindings() != current.as_slice() => latest.revision().saturating_add(1),
    Some(latest) => return Ok(Some(latest.clone())),
    None => 1,
  };
  let snapshot = TrustSnapshotV1::new(
    revision,
    1,
    issuer,
    context.identity().public_key().clone(),
    current,
  );
  persist_snapshot_with_bindings(store, entropy, &snapshot).await?;
  Ok(Some(snapshot))
}

/// Persists one verified snapshot plus its binding observations, so the
/// issuer's own trust page and every receiver's page expose the exact
/// binding set.
async fn persist_snapshot_with_bindings(
  store: &crate::storage::MetadataStore, entropy: &Arc<dyn Entropy>, snapshot: &TrustSnapshotV1,
) -> Result<()> {
  store::persist_snapshot_ctx(store, entropy.as_ref(), snapshot).await?;
  for binding in snapshot.bindings() {
    store::persist_binding_ctx(store, entropy.as_ref(), binding.node(), binding.key()).await?;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::{TrustBinding, TrustSnapshotV1, page_bindings};
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn key(value: u8) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value.into());
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  fn issuer_pair(value: u8) -> (NodeId, crate::PublicKey) {
    (node(value), key(value))
  }

  fn snapshot(revision: u64, issuer_index: u8, bindings: Vec<(u8, u8)>) -> TrustSnapshotV1 {
    let (issuer, issuer_key) = issuer_pair(issuer_index);
    TrustSnapshotV1::new(
      revision,
      1,
      issuer,
      issuer_key,
      bindings
        .into_iter()
        .map(|(n, k)| TrustBinding::new(node(n), key(k)))
        .collect(),
    )
  }

  /// The snapshot round-trips its marking, revision, and ordered
  /// bindings durably.
  #[test]
  fn trust_snapshot_round_trips() {
    let snapshot = snapshot(7, 1, vec![(2, 2), (3, 3), (4, 4)]);
    let bytes = snapshot.encode().unwrap();
    let decoded = TrustSnapshotV1::decode(&bytes).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.bindings().len(), 3);
    // Ordered by canonical node text.
    assert_eq!(decoded.bindings()[0].node(), &node(2));
    assert_eq!(decoded.issuer(), &node(1));
  }

  /// Conflicting evidence fails closed.
  #[test]
  fn trust_snapshot_rejects_conflicting_evidence() {
    let first = snapshot(7, 1, vec![(2, 2)]);

    // NodeId key substitution fails closed.
    let known = vec![(node(2), key(9))];
    assert!(first.assert_no_key_substitution(&known).is_err());
    let known_ok = vec![(node(2), key(2))];
    assert!(first.assert_no_key_substitution(&known_ok).is_ok());

    // Revision ordering: newer wins, stale conflicts are rejected by the
    // caller comparing revisions.
    let newer = snapshot(8, 1, vec![(2, 2)]);
    assert!(newer.is_newer_than(&first));
    assert!(!first.is_newer_than(&newer));
  }

  /// All trust views return the same pairs; paging is deterministic and
  /// bounded.
  #[test]
  fn trust_bindings_page_deterministically() {
    let snapshot = snapshot(7, 1, vec![(2, 2), (3, 3), (4, 4), (5, 5)]);
    let page = page_bindings(snapshot.bindings(), 0, 2).unwrap();
    assert_eq!(page.bindings().len(), 2);
    assert_eq!(page.next(), Some(2));
    let page = page_bindings(snapshot.bindings(), 2, 2).unwrap();
    assert_eq!(page.bindings().len(), 2);
    assert_eq!(page.next(), None);
    // Views agree on the exact pairs.
    let all = page_bindings(snapshot.bindings(), 0, 8).unwrap();
    assert_eq!(all.bindings(), snapshot.bindings());
  }

  #[test]
  fn trust_snapshot_rejects_noncanonical_ordering() {
    // Bindings must be canonically ordered; a reordered body fails.
    let mut unordered = snapshot(7, 1, vec![(3, 3), (2, 2)]);
    unordered.bindings = vec![
      TrustBinding::new(node(3), key(3)),
      TrustBinding::new(node(2), key(2)),
    ];
    let error = TrustSnapshotV1::decode(&unordered.encode().unwrap());
    assert!(error.is_err());
  }

  // ---- Durable persistence and paged observations ----

  fn factory() -> std::sync::Arc<dyn crate::provider::StorageFactory> {
    std::sync::Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  #[tokio::test]
  async fn accept_snapshot_fails_closed_on_untrusted_binding_evidence() {
    use super::store;
    use crate::ErrorKind;
    let factory = factory();
    let store = crate::storage::MetadataStore::open(&factory, std::time::Duration::from_secs(10))
      .await
      .unwrap();
    // Node 2 is already locally admitted with its own key.
    store::adopt_binding_ctx(&store, &crate::api::SystemEntropy, &node(2), &key(2))
      .await
      .unwrap();
    // A snapshot from an unbound issuer carrying a re-keyed binding for
    // node 2 is forged evidence: acceptance must fail closed with a typed
    // error, not silently skip the conflicting binding.
    let forged = snapshot(1, 1, vec![(2, 9), (3, 3)]);
    let error = super::accept_snapshot(&store, &crate::api::SystemEntropy, &forged)
      .await
      .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotTrusted);
    // The conflicting binding was never adopted.
    assert_eq!(
      store::trusted_bindings(&store).await.unwrap().get(&node(2)),
      Some(&key(2)),
      "node 2 must keep its locally admitted key"
    );
  }

  #[tokio::test]
  async fn trust_snapshot_persists_and_reloads_after_restart() {
    use super::store;
    let snapshot = snapshot(9, 1, vec![(2, 2), (3, 3)]);

    // Persist; each store call opens and drops its own storage handle, so
    // a later open on the same provider is an offline restart.
    let factory = factory();
    store::persist_snapshot(&factory, &snapshot).await.unwrap();
    store::persist_binding(&factory, &node(2), &key(2))
      .await
      .unwrap();
    store::persist_binding(&factory, &node(3), &key(3))
      .await
      .unwrap();

    // After the restart the exact snapshot and paged view agree with the
    // original bindings.
    let loaded = store::latest_snapshot(&factory, &node(1))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(loaded.revision(), 9);
    assert_eq!(loaded.bindings(), snapshot.bindings());

    let page = store::paged_trust(&factory, 0, 1).await.unwrap();
    assert_eq!(page.bindings().len(), 1);
    assert_eq!(page.next(), Some(1));
    let page = store::paged_trust(&factory, 1, 8).await.unwrap();
    assert_eq!(page.bindings().len(), 1);
    assert_eq!(page.next(), None);
  }

  #[tokio::test]
  async fn trust_snapshot_rejects_stale_conflicts_on_reload() {
    use super::store;
    let older = snapshot(4, 1, vec![(2, 2)]);
    let newer = snapshot(5, 1, vec![(2, 2)]);

    let factory = factory();
    store::persist_snapshot(&factory, &newer).await.unwrap();
    store::persist_snapshot(&factory, &older).await.unwrap();

    // The highest revision wins; the stale snapshot cannot overwrite it.
    let loaded = store::latest_snapshot(&factory, &node(1))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(loaded.revision(), 5);
  }
}

/// The trust observation store: persists issuer-signed snapshots and
/// serves bounded paged views over every binding.
pub(crate) mod store {
  use std::{collections::BTreeMap, sync::Arc};

  use super::{
    TRUST_BINDING_NAMESPACE, TRUST_SNAPSHOT_NAMESPACE, TrustBinding, TrustPage, TrustSnapshotV1,
  };
  #[cfg(test)]
  use crate::provider::StorageFactory;
  use crate::{
    NodeId, PublicKey, Result, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
    StoreValue, TransactionId, api::Entropy, storage::MetadataStore,
  };

  /// The zero-padded revision width in snapshot store keys. Single-sourced
  /// so the writer and the parse-back cannot drift: lexicographic key
  /// order must equal revision order, which requires a fixed width.
  const REVISION_KEY_DIGITS: usize = 20;

  fn snapshot_namespace() -> Result<StoreNamespace> {
    Ok(StoreNamespace::new(crate::QualifiedTag::parse(
      TRUST_SNAPSHOT_NAMESPACE,
    )?))
  }

  fn binding_namespace() -> Result<StoreNamespace> {
    Ok(StoreNamespace::new(crate::QualifiedTag::parse(
      TRUST_BINDING_NAMESPACE,
    )?))
  }

  fn snapshot_key(issuer: &NodeId, revision: u64) -> StoreKey {
    let mut bytes = Vec::with_capacity(issuer.as_str().len() + 1 + REVISION_KEY_DIGITS);
    bytes.extend_from_slice(issuer.as_str().as_bytes());
    bytes.push(b'/');
    bytes.extend_from_slice(format!("{revision:0width$}", width = REVISION_KEY_DIGITS).as_bytes());
    StoreKey::new(Arc::from(bytes))
  }

  /// Persists one verified snapshot over the running node's metadata
  /// store (runtime path; never re-opens storage). Re-delivery of the
  /// same revision is a no-op (idempotent).
  pub(crate) async fn persist_snapshot_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, snapshot: &TrustSnapshotV1,
  ) -> Result<()> {
    let _permit = store.write_permit().await;
    let namespace = snapshot_namespace()?;
    let key = snapshot_key(snapshot.issuer(), snapshot.revision());
    let current = store.snapshot().await?;
    if current.get(&namespace, &key).await?.is_some() {
      return Ok(());
    }
    // Superseded revisions of the same issuer are pruned in the same
    // transaction: only the latest grant set is ever read back, so keeping
    // history would grow the scan unboundedly over the cluster lifetime.
    let mut operations = vec![StoreOperation::Put {
      namespace: namespace.clone(),
      key: key.clone(),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(snapshot.encode()?)),
    }];
    let mut scan = current
      .scan(&namespace, snapshot.issuer().as_str().as_bytes())
      .await?;
    while let Some(entry) = scan.next().await? {
      let revision = revision_from_key(entry.key())?;
      if revision < snapshot.revision() {
        operations.push(StoreOperation::Delete {
          namespace: namespace.clone(),
          key: StoreKey::new(Arc::from(entry.key().as_bytes().to_vec())),
          expected: entry.value().digest().clone(),
        });
      }
    }
    let transaction = store.prepare_transaction(
      TransactionId::generate(entropy)?,
      current.revision().clone(),
      operations,
    )?;
    let _ = store.commit(transaction).await?;
    Ok(())
  }

  /// The highest-revision snapshot for one issuer over the running node's
  /// metadata store, scoped to the issuer's own key prefix.
  pub(crate) async fn latest_snapshot_ctx(
    store: &MetadataStore, trusted_issuer: &NodeId,
  ) -> Result<Option<TrustSnapshotV1>> {
    let namespace = snapshot_namespace()?;
    let snapshot = store.snapshot().await?;
    // Scan only this issuer's keys ({issuer}/{revision:020}): a higher
    // revision snapshot from another issuer must never shadow the trusted
    // issuer's latest snapshot.
    let mut scan = snapshot
      .scan(&namespace, trusted_issuer.as_str().as_bytes())
      .await?;
    let mut latest: Option<(u64, Vec<u8>)> = None;
    while let Some(entry) = scan.next().await? {
      let bytes = entry.value().as_bytes().to_vec();
      let key = entry.key();
      let revision = revision_from_key(key)?;
      if latest
        .as_ref()
        .is_none_or(|(current, _)| revision > *current)
      {
        latest = Some((revision, bytes));
      }
    }
    let Some((_, bytes)) = latest else {
      return Ok(None);
    };
    Ok(Some(TrustSnapshotV1::decode(&bytes)?))
  }

  /// The stored trust-binding format: one version byte followed by the
  /// 32-byte public key. Version and length are checked strictly so a
  /// corrupted or future-format value fails closed instead of being skipped.
  const TRUST_BINDING_VERSION: u8 = 1;

  fn decode_binding_value(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != 33 || bytes[0] != TRUST_BINDING_VERSION {
      return Err(crate::Error::invalid_input("trust binding format"));
    }
    let key: [u8; 32] = bytes[1..33]
      .try_into()
      .map_err(|_| crate::Error::invalid_input("trust binding key"))?;
    Ok(PublicKey::from_bytes(key))
  }

  /// The revision parsed out of a snapshot key (`{issuer}/{revision:020}`).
  /// A malformed suffix is schema corruption, never revision zero.
  fn revision_from_key(key: &StoreKey) -> Result<u64> {
    let text = std::str::from_utf8(key.as_bytes())
      .map_err(|_| crate::Error::invalid_input("trust snapshot key"))?;
    let revision = text
      .rsplit('/')
      .next()
      .ok_or_else(|| crate::Error::invalid_input("trust snapshot key"))?;
    if revision.len() != REVISION_KEY_DIGITS {
      return Err(crate::Error::invalid_input("trust snapshot key"));
    }
    revision
      .parse::<u64>()
      .map_err(|_| crate::Error::invalid_input("trust snapshot revision"))
  }

  /// Persists one verified nonconflicting binding over the running node's
  /// metadata store. Idempotent: an already-present binding is left in
  /// place, so concurrent snapshot deliveries and re-deliveries cannot
  /// conflict and abort the remaining bindings of the snapshot.
  pub(crate) async fn persist_binding_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, node: &NodeId, key: &PublicKey,
  ) -> Result<()> {
    let _permit = store.write_permit().await;
    let namespace = binding_namespace()?;
    let store_key = StoreKey::new(Arc::from(node.as_str().as_bytes().to_vec()));
    let snapshot = store.snapshot().await?;
    if let Some(existing) = snapshot.get(&namespace, &store_key).await? {
      // A re-keyed binding must not silently diverge: a known node with a
      // different key is conflicting evidence and fails closed.
      if decode_binding_value(existing.as_bytes())?.as_bytes() != key.as_bytes() {
        return Err(crate::Error::not_trusted("trust binding key substitution"));
      }
      return Ok(());
    }
    let mut bytes = Vec::with_capacity(33);
    bytes.push(TRUST_BINDING_VERSION);
    bytes.extend_from_slice(key.as_bytes());
    let transaction = store.prepare_transaction(
      TransactionId::generate(entropy)?,
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace.clone(),
        key: store_key,
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(bytes)),
      }],
    )?;
    let _ = store.commit(transaction).await?;
    Ok(())
  }

  /// Paged trust observations over the running node's metadata store:
  /// distinct bindings from verified snapshots, deterministically ordered
  /// and bounded. The scan order is the canonical node-text order, so the
  /// page is taken by skipping `offset` entries during one streamed pass -
  /// no whole-population allocation.
  pub(crate) async fn paged_trust_ctx(
    store: &MetadataStore, offset: usize, limit: usize,
  ) -> Result<TrustPage> {
    let namespace = binding_namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut skipped = 0_usize;
    let mut page: Vec<TrustBinding> = Vec::with_capacity(limit);
    let mut more_after_page = false;
    while let Some(entry) = scan.next().await? {
      let node = NodeId::parse(&String::from_utf8_lossy(entry.key().as_bytes()))?;
      let key = decode_binding_value(entry.value().as_bytes())?;
      if skipped < offset {
        skipped += 1;
        continue;
      }
      if page.len() >= limit {
        // This entry was fetched and deferred: at least one further
        // binding exists beyond the page.
        more_after_page = true;
        break;
      }
      page.push(TrustBinding::new(node, key));
    }
    // The next cursor is exact only when the page filled and a further
    // entry was already fetched past it.
    let next = if page.len() == limit && more_after_page {
      Some(offset + limit)
    } else {
      None
    };
    Ok(TrustPage::new(page, next))
  }

  /// The durable trusted bindings as observed from the local identity
  /// store (`identity_binding_namespace`): every binding this node has
  /// committed from a verified grant or snapshot adoption. This is the
  /// authoritative trusted-keys map for membership page verification and
  /// the recovery online set.
  pub(crate) async fn trusted_bindings(
    store: &MetadataStore,
  ) -> Result<BTreeMap<NodeId, PublicKey>> {
    let namespace = crate::identity::records::identity_binding_namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut bindings = BTreeMap::new();
    while let Some(entry) = scan.next().await? {
      let binding = crate::identity::records::IdentityBindingV1::decode(entry.value().as_bytes())
        .map_err(|_| crate::Error::invalid_input("trust binding decode"))?;
      bindings.insert(binding.node().clone(), binding.public_key().clone());
    }
    Ok(bindings)
  }

  /// Whether the store holds more than `count` trusted bindings, resolved
  /// with an early-exit bounded read instead of a whole-population map
  /// (the anti-entropy tick only needs to know whether membership exists).
  pub(crate) async fn has_more_than_bindings(store: &MetadataStore, count: usize) -> Result<bool> {
    let namespace = crate::identity::records::identity_binding_namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut seen = 0_usize;
    while let Some(entry) = scan.next().await? {
      crate::identity::records::IdentityBindingV1::decode(entry.value().as_bytes())
        .map_err(|_| crate::Error::invalid_input("trust binding decode"))?;
      seen += 1;
      if seen > count {
        return Ok(true);
      }
    }
    Ok(false)
  }

  /// Commits one verified snapshot-adjacent binding into the authoritative
  /// identity store so member-mode dialing and page verification can use
  /// it (the grant-carrying reconnect path). A node already bound to a
  /// different key is a key-substitution conflict and fails closed. A
  /// locally revoked identity never gains a new binding through this
  /// path: re-delivery of its existing binding stays idempotent, but a
  /// fresh adoption is refused (revocation removes the authority to gain
  /// trust through this node).
  pub(crate) async fn adopt_binding_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, node: &NodeId, key: &PublicKey,
  ) -> Result<()> {
    let _permit = store.write_permit().await;
    let (namespace, store_key) = crate::identity::records::identity_binding_key(node)?;
    let snapshot = store.snapshot().await?;
    if let Some(existing) = snapshot.get(&namespace, &store_key).await? {
      let existing = crate::identity::records::IdentityBindingV1::decode(existing.as_bytes())
        .map_err(|_| crate::Error::invalid_input("identity binding decode"))?;
      if existing.public_key() != key {
        return Err(crate::Error::not_trusted("trust binding key substitution"));
      }
      return Ok(());
    }
    if crate::identity::revocation::revoked_key_ctx(store, node)
      .await?
      .is_some()
    {
      return Err(crate::Error::revoked("trust binding adoption"));
    }
    let binding = crate::identity::records::IdentityBindingV1::new(node.clone(), key.clone());
    let transaction = store.prepare_transaction(
      TransactionId::generate(entropy)?,
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace.clone(),
        key: store_key,
        expected: StoreExpectation::Absent,
        value: StoreValue::new(Arc::from(binding.encode()?)),
      }],
    )?;
    let _ = store.commit(transaction).await?;
    Ok(())
  }

  /// Persists one verified snapshot as a plain store value over a
  /// standalone factory handle (test-only restart harness; the runtime
  /// path always goes through the `_ctx` variants on the open store).
  #[cfg(test)]
  pub(crate) async fn persist_snapshot(
    factory: &Arc<dyn StorageFactory>, snapshot: &TrustSnapshotV1,
  ) -> Result<()> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    persist_snapshot_ctx(&store, &crate::api::SystemEntropy, snapshot).await
  }

  /// The highest-revision snapshot for one issuer over a standalone
  /// factory handle (test-only restart harness).
  #[cfg(test)]
  pub(crate) async fn latest_snapshot(
    factory: &Arc<dyn StorageFactory>, trusted_issuer: &NodeId,
  ) -> Result<Option<TrustSnapshotV1>> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    latest_snapshot_ctx(&store, trusted_issuer).await
  }

  /// Persists one verified nonconflicting binding over a standalone
  /// factory handle (test-only restart harness).
  #[cfg(test)]
  pub(crate) async fn persist_binding(
    factory: &Arc<dyn StorageFactory>, node: &NodeId, key: &PublicKey,
  ) -> Result<()> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    persist_binding_ctx(&store, &crate::api::SystemEntropy, node, key).await
  }

  /// Paged trust observations over a standalone factory handle (test-only
  /// restart harness).
  #[cfg(test)]
  pub(crate) async fn paged_trust(
    factory: &Arc<dyn StorageFactory>, offset: usize, limit: usize,
  ) -> Result<TrustPage> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    paged_trust_ctx(&store, offset, limit).await
  }
}

/// The durable namespace of one snapshot binding observation.
pub(crate) use crate::storage::families::TRUST_BINDING_NAMESPACE;
