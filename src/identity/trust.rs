//! The durable trust surface consumed by the membership sync lane: one
//! `NodeId`-to-`PublicKey` binding per node, held in the authoritative
//! identity-binding family.
//!
//! [`TrustBinding`] is the read view of one binding.
//! `store::trusted_bindings` resolves the whole set — the verification
//! basis for membership pages, cleanup tombstones, and session
//! establishment — `store::paged_trust_ctx` pages it for the trust view,
//! and `store::adopt_binding_ctx` commits one verified binding. There is
//! no whole-set snapshot record: the bindings are the record, and a
//! leave wipes them with the old identity.

use crate::{NodeId, PublicKey};

/// One trusted `(node, key)` binding: the read view of the durable
/// identity-binding record.
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

#[cfg(test)]
mod tests {
  use super::TrustBinding;
  use crate::NodeId;

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node-{value:021}")).unwrap()
  }

  fn key(value: u8) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value.into());
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  fn factory() -> std::sync::Arc<dyn crate::provider::StorageFactory> {
    std::sync::Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  /// The paged trust view serves the adopted bindings in canonical node
  /// order across an offline restart: each store call opens and drops its
  /// own storage handle, so the second page reads a fresh open of the same
  /// provider — the adopted bindings are the durable record, nothing else.
  #[tokio::test]
  async fn paged_trust_pages_the_adopted_bindings_after_restart() {
    use super::store;
    let factory = factory();
    store::adopt_binding(&factory, &node(2), &key(2))
      .await
      .unwrap();
    store::adopt_binding(&factory, &node(3), &key(3))
      .await
      .unwrap();

    let page = store::paged_trust(&factory, None, 1).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0], TrustBinding::new(node(2), key(2)));
    assert!(page.next.is_some());
    let page = store::paged_trust(&factory, page.next.as_deref(), 8)
      .await
      .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0], TrustBinding::new(node(3), key(3)));
    assert!(page.next.is_none());
  }
}

/// The trust observation store: the durable identity-binding family,
/// served as a whole-set resolution and as bounded paged views.
pub(crate) mod store {
  use std::{collections::BTreeMap, sync::Arc};

  use super::TrustBinding;
  #[cfg(test)]
  use crate::provider::StorageFactory;
  use crate::{
    NodeId, PublicKey, Result, StoreExpectation, StoreOperation, TransactionId,
    api::Entropy,
    storage::{MetadataStore, RowEnvelope},
  };

  /// Whether the node carries terminal departure evidence — an
  /// owner-signed leave record or an issuer-signed cleanup tombstone.
  /// Terminal members are excluded from session establishment, and every
  /// admission-sensitive read shares this one gate. The evidence is
  /// operational, not permanent: the checkpoint GC reclaims a collected
  /// tombstone together with the pinned binding, and after that the
  /// subject is simply unknown here — a fresh merge (the join-credential
  /// path) under a new key is the only revival.
  pub(crate) async fn peer_is_terminal(store: &MetadataStore, node: &NodeId) -> Result<bool> {
    Ok(
      crate::identity::leave::is_left_ctx(store, node).await?
        || crate::identity::cleanup::is_cleaned_ctx(store, node).await?,
    )
  }

  /// Resolves the trusted member-mode binding for `peer` from durable
  /// storage: terminal departure evidence fails closed before any signing
  /// work (a locally revoked binding fails the same way, after the
  /// decode), the single authoritative binding decodes once, and the
  /// revocation gate has the final word. The one admission-time binding
  /// resolution — session establishment signs against exactly this key.
  /// Reads the trusted member-mode binding for `peer` from durable
  /// storage.
  ///
  /// The typed contract distinguishes the two failure modes a dialer
  /// must not conflate: an **absent** binding is
  /// [`ErrorKind::NotFound`](crate::ErrorKind::NotFound) — the peer is not
  /// (yet) known here, which is a retryable convergence state while bindings
  /// spread over sync, and the healing planes (recovery, connection-degree
  /// maintenance) and caller retry policies treat it exactly that way — while
  /// a binding that exists but fails to decode, contradicts the presented
  /// key, or is revoked stays an authentication or revocation failure, which
  /// is never retryable.
  pub(crate) async fn trusted_binding(store: &MetadataStore, peer: &NodeId) -> Result<PublicKey> {
    if peer_is_terminal(store, peer).await? {
      return Err(crate::Error::not_trusted("peer left"));
    }
    let (namespace, key) = crate::identity::records::identity_binding_key(peer)?;
    let snapshot = store.snapshot().await?;
    let value = snapshot
      .get(&namespace, &key)
      .await?
      .ok_or_else(|| crate::Error::not_found("session binding"))?;
    let binding = crate::identity::records::IdentityBindingV1::decode(
      &RowEnvelope::open(value.as_bytes())
        .map_err(|_| crate::Error::authentication_failed("session binding"))?,
    )
    .map_err(|_| crate::Error::authentication_failed("session binding"))?;
    let public_key = binding.public_key().clone();
    if crate::identity::revocation::is_revoked_ctx(store, peer, &public_key).await? {
      return Err(crate::Error::revoked("session binding"));
    }
    Ok(public_key)
  }

  /// Paged trust observations over the running node's metadata store:
  /// distinct bindings from the authoritative identity-binding family —
  /// the one durable binding representation — keyset-paginated in the
  /// canonical node-text key order through the shared
  /// [`crate::paging::scan_paged`] loop: the continuation cursor is the
  /// page's last raw key, resumed strictly past it (one end-of-stream
  /// rule for every paged read).
  pub(crate) async fn paged_trust_ctx(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<crate::paging::Paged<TrustBinding>> {
    let namespace = crate::identity::records::identity_binding_namespace()?;
    let snapshot = store.snapshot().await?;
    crate::paging::scan_paged(
      snapshot.as_ref(),
      &namespace,
      &[],
      cursor,
      limit,
      |_key, bytes| {
        let binding = crate::identity::records::IdentityBindingV1::decode(
          &RowEnvelope::open(bytes)
            .map_err(|_| crate::Error::invalid_input("trust binding decode"))?,
        )
        .map_err(|_| crate::Error::invalid_input("trust binding decode"))?;
        Ok(Some(TrustBinding::new(
          binding.node().clone(),
          binding.public_key().clone(),
        )))
      },
    )
    .await
  }

  /// The durable trusted bindings from the authoritative identity-binding
  /// family (`identity_binding_namespace`): every binding this node has
  /// committed from a verified grant or a binding adoption. This is the
  /// single trusted-keys representation — it feeds membership page
  /// verification, the recovery online set, and the paged trust view
  /// alike.
  pub(crate) async fn trusted_bindings(
    store: &MetadataStore,
  ) -> Result<BTreeMap<NodeId, PublicKey>> {
    let namespace = crate::identity::records::identity_binding_namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut bindings = BTreeMap::new();
    while let Some(entry) = scan.next().await? {
      let binding = crate::identity::records::IdentityBindingV1::decode(
        &RowEnvelope::open(entry.value().as_bytes())
          .map_err(|_| crate::Error::invalid_input("trust binding decode"))?,
      )
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
      crate::identity::records::IdentityBindingV1::decode(
        &RowEnvelope::open(entry.value().as_bytes())
          .map_err(|_| crate::Error::invalid_input("trust binding decode"))?,
      )
      .map_err(|_| crate::Error::invalid_input("trust binding decode"))?;
      seen += 1;
      if seen > count {
        return Ok(true);
      }
    }
    Ok(false)
  }

  /// Commits one verified binding into the authoritative identity-binding
  /// family — the single durable binding representation — so member-mode
  /// dialing, page verification, and the trust view can all use it (the
  /// grant-carrying reconnect path). A node already bound to a different
  /// key is a key-substitution conflict and fails closed. A locally
  /// revoked identity never gains a new binding through this path:
  /// re-delivery of its existing binding stays idempotent, but a fresh
  /// adoption is refused (revocation removes the authority to gain trust
  /// through this node).
  pub(crate) async fn adopt_binding_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, node: &NodeId, key: &PublicKey,
  ) -> Result<()> {
    let _permit = store.write_permit().await;
    let (namespace, store_key) = crate::identity::records::identity_binding_key(node)?;
    let snapshot = store.snapshot().await?;
    if let Some(existing) = snapshot.get(&namespace, &store_key).await? {
      let existing = crate::identity::records::IdentityBindingV1::decode(
        &RowEnvelope::open(existing.as_bytes())
          .map_err(|_| crate::Error::invalid_input("identity binding decode"))?,
      )
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
    let transaction = store.prepare_core_verb_transaction(
      TransactionId::generate(entropy)?,
      snapshot.revision().clone(),
      vec![StoreOperation::Put {
        namespace: namespace.clone(),
        key: store_key.clone(),
        expected: StoreExpectation::Absent,
        value: RowEnvelope::seal(
          &namespace,
          &store_key,
          snapshot.revision(),
          &crate::LabelSet::new(),
          Arc::from(binding.encode()?),
        )?,
      }],
    )?;
    // A discarded commit outcome would report the binding as adopted
    // without a committed outcome behind it: Conflict/Aborted
    // definitively did not land, and Unknown leaves durability
    // indeterminate — the reconcile trust lane treats a surfaced
    // conflict as skippable and everything else as evidence failure.
    crate::provider::commit_verdict(store.commit(transaction).await?, "trust binding adoption")?;
    // The adopted binding changes what every plane sends (descriptors
    // of the bound node become healable, the grant set grew): the write
    // epoch arms the walks for a next-tick push.
    store.note_local_write_tag(crate::storage::families::IDENTITY_BINDING_NAMESPACE);
    Ok(())
  }

  /// Adopts one verified nonconflicting binding over a standalone
  /// factory handle (test-only restart harness).
  #[cfg(test)]
  pub(crate) async fn adopt_binding(
    factory: &Arc<dyn StorageFactory>, node: &NodeId, key: &PublicKey,
  ) -> Result<()> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    adopt_binding_ctx(&store, &crate::api::SystemEntropy, node, key).await
  }

  /// Paged trust observations over a standalone factory handle (test-only
  /// restart harness).
  #[cfg(test)]
  pub(crate) async fn paged_trust(
    factory: &Arc<dyn StorageFactory>, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<crate::paging::Paged<TrustBinding>> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    paged_trust_ctx(&store, cursor, limit).await
  }
}
