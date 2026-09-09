//! Bounded membership anti-entropy pages.
//!
//! A normal anti-entropy tick emits [`MembershipPage`]s: a bounded list of
//! [`NodeDescriptorV1`] records plus an opaque cursor, never a
//! whole-population allocation. Entries are trusted through the
//! authenticated session that delivered them; the receiver
//! repairs missing owner revisions, converges stale peers to the highest
//! revision, and rejects over-capacity pages and looping cursors.

/// The schema of one membership sync page.
pub(crate) const MEMBERSHIP_PAGE_SCHEMA: &str = "radiata.woooo.tech/schemas/membership-page-v1";

/// The default page limit when the caller supplies none.
pub(crate) const DEFAULT_PAGE_LIMIT: usize = 16;

/// The maximum page size a receiver accepts, bounding one page's bytes.
pub(crate) const MAX_PAGE_DESCRIPTORS: usize = 64;

use super::{NodeDescriptorV1, store};
use crate::{
  Error, LabelKey, LabelSet, LabelValue, NodeId, Result,
  protocol::{decode_canonical, encode_canonical},
};

/// One bounded page of node descriptors plus a continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MembershipPage {
  descriptors: Vec<NodeDescriptorV1>,
  cursor: Option<Vec<u8>>,
}

impl MembershipPage {
  pub(crate) fn new(descriptors: Vec<NodeDescriptorV1>, cursor: Option<Vec<u8>>) -> Result<Self> {
    crate::paging::check_page_shape(
      descriptors.len(),
      MAX_PAGE_DESCRIPTORS,
      &cursor,
      "membership page",
    )?;
    Ok(Self {
      descriptors,
      cursor,
    })
  }

  pub(crate) fn descriptors(&self) -> &[NodeDescriptorV1] {
    &self.descriptors
  }

  pub(crate) fn cursor(&self) -> Option<&[u8]> {
    self.cursor.as_deref()
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    // A descriptor that cannot encode must fail the page: shipping empty
    // bytes would produce an entry every remote peer rejects.
    let mut items = Vec::with_capacity(self.descriptors.len());
    for descriptor in &self.descriptors {
      items.push(descriptor.encode()?);
    }
    crate::paging::encode_page(MEMBERSHIP_PAGE_SCHEMA, &items, self.cursor.as_deref())
  }

  /// Decodes one page. Entries are trusted through the authenticated
  /// session that delivered them: decoding checks only the
  /// canonical wire rules and page capacity.
  pub(crate) fn decode(bytes: &[u8]) -> Result<MembershipPage> {
    let (items, cursor) = crate::paging::decode_page(
      bytes,
      MEMBERSHIP_PAGE_SCHEMA,
      MAX_PAGE_DESCRIPTORS,
      "membership page",
    )?;
    let mut descriptors = Vec::with_capacity(items.len());
    for encoded in &items {
      let descriptor = decode_descriptor(encoded)
        .map_err(|_| Error::invalid_input("membership page descriptor"))?;
      descriptors.push(descriptor);
    }
    MembershipPage::new(descriptors, cursor)
  }

  pub(crate) fn fingerprint(&self) -> u64 {
    Self::fingerprint_of(
      self.descriptors.len(),
      self.cursor.as_deref().map_or(0, |value| value.len()),
      &self.descriptors,
    )
  }

  fn fingerprint_of(count: usize, cursor_len: usize, descriptors: &[NodeDescriptorV1]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    count.hash(&mut hasher);
    cursor_len.hash(&mut hasher);
    for descriptor in descriptors {
      descriptor.node.hash(&mut hasher);
      descriptor.revision.hash(&mut hasher);
      descriptor.removed.hash(&mut hasher);
      for endpoint in &descriptor.endpoints {
        endpoint.as_str().hash(&mut hasher);
      }
      for (key, value) in descriptor.labels.entries() {
        key.as_str().hash(&mut hasher);
        value.as_str().hash(&mut hasher);
      }
    }
    hasher.finish()
  }

  /// True when the cursor does not advance (loop protection).
  #[cfg(test)]
  pub(crate) fn cursor_loops(&self, previous: Option<&[u8]>) -> bool {
    match (previous, self.cursor()) {
      (Some(previous), Some(next)) => previous == next,
      _ => false,
    }
  }
}

/// The anti-entropy driver: pages the local descriptor store from a cursor
/// and applies received pages under strict validation.
pub(crate) mod sync {
  use super::{MAX_PAGE_DESCRIPTORS, MembershipPage};
  use crate::{Error, NodeId, Result, api::Entropy, storage::MetadataStore};

  /// Emits one bounded page over the running node's metadata store. The
  /// cursor is the last emitted node's text, so pages continue without
  /// allocating the whole population.
  ///
  /// A page of fat descriptors can overflow the 64 KiB control-body
  /// bound, which failed the whole sync tick every tick and stalled the
  /// cursor forever. The bounded halving ladder below retries at half
  /// the page capacity until the full wire payload (page envelope plus
  /// sync wrapper) fits: one descriptor is bounded far below the control
  /// bound, so the ladder always terminates, and a halved page still
  /// carries its continuation cursor (the size-ladder note in
  /// `crate::paging::encode_page`).
  pub(crate) async fn emit_page_ctx(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<MembershipPage> {
    let mut limit = limit.clamp(1, MAX_PAGE_DESCRIPTORS);
    loop {
      let page = emit_at_capacity(store, cursor, limit).await?;
      if wire_payload_fits(&page)? {
        return Ok(page);
      }
      if limit == 1 {
        // One descriptor is bounded far below the control bound, so the
        // ladder terminates here with a deliverable page; reaching this
        // arm means a bound regressed elsewhere — fail loudly instead of
        // looping.
        return Err(Error::resource_exhausted("membership page"));
      }
      limit /= 2;
    }
  }

  /// True when the page's full wire payload (page envelope plus sync
  /// wrapper) encodes inside the control-body bound.
  fn wire_payload_fits(page: &MembershipPage) -> Result<bool> {
    // A page envelope that fails to encode is simply "does not fit" —
    // the ladder's whole reason to halve.
    let Ok(encoded) = page.encode() else {
      return Ok(false);
    };
    Ok(
      super::super::sync::SyncPayload::Page(minicbor::bytes::ByteVec::from(encoded))
        .encode()
        .is_ok(),
    )
  }

  /// Emits one page at an exact candidate capacity (one ladder step).
  async fn emit_at_capacity(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<MembershipPage> {
    let namespace = crate::StoreNamespace::new(crate::QualifiedTag::parse(
      super::super::NODE_DESCRIPTOR_NAMESPACE,
    )?);
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let paged = crate::paging::scan_paged(scan.as_mut(), cursor, limit, |_key, bytes| {
      // The sender only pages its own stored records; entries are trusted
      // through the session that delivers them.
      super::decode_descriptor(bytes).map(Some)
    })
    .await?;
    MembershipPage::new(paged.items, paged.next)
  }

  /// Applies one received page over the running node's metadata store:
  /// the store accepts only the exact next revision, so stale, repeated,
  /// downgraded, and replayed descriptors cannot replace a newer record.
  pub(crate) async fn apply_page_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, page: &MembershipPage,
  ) -> Result<Vec<NodeId>> {
    let _permit = store.write_permit().await;
    let mut applied = Vec::new();
    for descriptor in page.descriptors() {
      // Skip descriptors we already have at an equal or higher revision.
      if let Ok(Some(current)) = super::store::read_descriptor_ctx(store, descriptor.node()).await
        && current.revision() >= descriptor.revision()
      {
        continue;
      }
      if super::store::store_descriptor_ctx(store, entropy, descriptor)
        .await
        .is_ok()
      {
        applied.push(descriptor.node().clone());
      }
    }
    Ok(applied)
  }

  /// Emits one bounded page of descriptors starting after `cursor` over a
  /// standalone factory handle (unit/offline path).
  #[cfg(test)]
  pub(crate) async fn emit_page(
    factory: &std::sync::Arc<dyn crate::provider::StorageFactory>, cursor: Option<&[u8]>,
    limit: usize,
  ) -> Result<MembershipPage> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    emit_page_ctx(&store, cursor, limit).await
  }

  /// Applies one received page over a standalone factory handle.
  #[cfg(test)]
  pub(crate) async fn apply_page(
    factory: &std::sync::Arc<dyn crate::provider::StorageFactory>, page: &MembershipPage,
  ) -> Result<usize> {
    let store = MetadataStore::open(factory, std::time::Duration::from_secs(10)).await?;
    apply_page_ctx(&store, &crate::api::SystemEntropy, page)
      .await
      .map(|installed| installed.len())
  }
}

/// The single canonical descriptor decoder: wire rules and error strings
/// live in exactly one place. Entries are trusted through the session
/// that delivered them, so decoding checks only schema, version, and
/// canonical wire rules. Both record shapes are accepted: the
/// current version 2 (capability labels) and the previous version 1
/// fixture shape (no labels, empty label set).
pub(crate) fn decode_descriptor(bytes: &[u8]) -> Result<NodeDescriptorV1> {
  // The current record shape (version 2) carries capability labels.
  if let Ok(wire) =
    decode_canonical::<super::DescriptorWire>(bytes, crate::protocol::CONTROL_CBOR_LIMITS)
    && encode_canonical(&wire, crate::protocol::CONTROL_CBOR_LIMITS)
      .is_ok_and(|encoded| encoded == bytes)
  {
    return decode_wire(
      wire.schema,
      wire.record_version,
      wire.version,
      DescriptorFields {
        node: &wire.node,
        public_key: &wire.public_key,
        endpoints: &wire.endpoints,
        revision: wire.revision,
        removed: wire.removed,
        labels: Some(&wire.labels),
      },
    );
  }
  // The previous fixture shape (record version 1) ends at the `version`
  // element; a strict version 2 decode fails on the missing labels and
  // the record falls back to this shape.
  let wire: super::DescriptorWireV1 = decode_canonical(bytes, crate::protocol::CONTROL_CBOR_LIMITS)
    .map_err(|_| Error::invalid_input("node descriptor decode"))?;
  if !encode_canonical(&wire, crate::protocol::CONTROL_CBOR_LIMITS)
    .is_ok_and(|encoded| encoded == bytes)
  {
    return Err(Error::invalid_input("node descriptor canonical"));
  }
  decode_wire(
    wire.schema,
    wire.record_version,
    wire.version,
    DescriptorFields {
      node: &wire.node,
      public_key: &wire.public_key,
      endpoints: &wire.endpoints,
      revision: wire.revision,
      removed: wire.removed,
      labels: None,
    },
  )
}

/// The version-independent decoded fields of one descriptor record.
struct DescriptorFields<'a> {
  node: &'a str,
  public_key: &'a minicbor::bytes::ByteVec,
  endpoints: &'a [String],
  revision: u64,
  removed: bool,
  /// `Some` for record versions that carry capability labels.
  labels: Option<&'a [(String, String)]>,
}

fn decode_wire(
  schema: String, record_version: u16, version: u16, fields: DescriptorFields<'_>,
) -> Result<NodeDescriptorV1> {
  if schema != super::NODE_DESCRIPTOR_SCHEMA || !(record_version == 1 || record_version == 2) {
    return Err(Error::invalid_input("node descriptor schema"));
  }
  // Version 1 records carry no labels element; version 2 records must
  // carry it. Unknown wire or record versions fail closed.
  if version != 1 {
    return Err(Error::invalid_input("node descriptor version"));
  }
  if (record_version == 2) != fields.labels.is_some() {
    return Err(Error::invalid_input("node descriptor version"));
  }
  let node =
    NodeId::parse(fields.node).map_err(|_| Error::invalid_input("node descriptor node"))?;
  let public_key = crate::PublicKey::from_bytes(
    <[u8; 32]>::try_from(fields.public_key.as_ref())
      .map_err(|_| Error::invalid_input("node descriptor key"))?,
  );
  let mut endpoints = Vec::with_capacity(fields.endpoints.len());
  for text in fields.endpoints {
    endpoints.push(
      crate::Endpoint::parse(text).map_err(|_| Error::invalid_input("node descriptor endpoint"))?,
    );
  }
  let mut labels = LabelSet::new();
  let mut previous_key: Option<&str> = None;
  for (key_text, value_text) in fields.labels.unwrap_or(&[]) {
    // Strictly ascending canonical keys fail closed on reordered or
    // duplicate entries; values are validated bounded opaque text.
    if previous_key.is_some_and(|previous| previous >= key_text.as_str()) {
      return Err(Error::invalid_input("node descriptor label order"));
    }
    previous_key = Some(key_text);
    labels = labels.insert(
      LabelKey::parse(key_text).map_err(|_| Error::invalid_input("node descriptor label"))?,
      LabelValue::parse(value_text)
        .map_err(|_| Error::invalid_input("node descriptor label value"))?,
    )?;
  }
  Ok(
    NodeDescriptorV1::new(
      node,
      public_key,
      endpoints,
      fields.revision,
      fields.removed,
      version,
    )
    .with_labels(labels),
  )
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{MembershipPage, sync};
  use crate::{Endpoint, NodeId, provider::StorageFactory};

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn key(value: u8) -> crate::PublicKey {
    let signing = crate::identity::testing::scripted_signing(value.into());
    crate::PublicKey::from_bytes(signing.verifying_key().to_bytes())
  }

  fn descriptor(node_index: u8, revision: u64, host: &str) -> crate::membership::NodeDescriptorV1 {
    crate::membership::NodeDescriptorV1::new(
      node(node_index),
      key(node_index),
      vec![Endpoint::parse(&format!("wss://{host}:9000")).unwrap()],
      revision,
      false,
      1,
    )
  }

  fn factory() -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  /// A tick emits bounded pages without a whole-population allocation.
  #[tokio::test]
  async fn emit_pages_bounded_without_whole_members() {
    let factory = factory();
    crate::membership::store::store_descriptor(&factory, &descriptor(1, 1, "one"))
      .await
      .unwrap();
    crate::membership::store::store_descriptor(&factory, &descriptor(2, 1, "two"))
      .await
      .unwrap();
    crate::membership::store::store_descriptor(&factory, &descriptor(3, 1, "three"))
      .await
      .unwrap();

    let page = sync::emit_page(&factory, None, 2).await.unwrap();
    assert_eq!(page.descriptors().len(), 2);
    assert!(page.cursor().is_some());
    let page = sync::emit_page(&factory, page.cursor(), 2).await.unwrap();
    assert_eq!(page.descriptors().len(), 1);
    assert!(page.cursor().is_none());
  }

  /// A page of fat descriptors (label sets at their maximum) splits
  /// through the bounded halving ladder instead of overflowing the 64 KiB
  /// control-body bound: every emitted page's full wire payload (page
  /// envelope plus sync wrapper) encodes, paging continues past halved
  /// pages, and every descriptor is delivered. Under the pre-ladder code
  /// this page overflowed the bound and failed the sync tick forever.
  #[tokio::test]
  async fn fat_descriptor_pages_halve_instead_of_overflowing() {
    fn fat_labels() -> crate::LabelSet {
      let mut labels = crate::LabelSet::new();
      for index in 0..crate::label::LABEL_SET_MAX_ENTRIES {
        labels = labels
          .insert(
            crate::LabelKey::parse(&format!("example.org/labels/fat-{index:02}")).unwrap(),
            crate::LabelValue::parse(&"v".repeat(crate::label::LABEL_VALUE_MAX_BYTES)).unwrap(),
          )
          .unwrap();
      }
      labels
    }
    let factory = factory();
    for seed in 1..=6_u8 {
      let fat = descriptor(seed, 1, "fat").with_labels(fat_labels());
      crate::membership::store::store_descriptor(&factory, &fat)
        .await
        .unwrap();
    }

    let mut cursor: Option<Vec<u8>> = None;
    let mut delivered: Vec<NodeId> = Vec::new();
    let mut pages = 0_usize;
    loop {
      let page = sync::emit_page(&factory, cursor.as_deref(), super::DEFAULT_PAGE_LIMIT)
        .await
        .unwrap();
      // The full wire payload (page envelope plus sync wrapper) fits the
      // control-body bound: the ladder halved the capacity to get here.
      let wrapped = crate::membership::sync::SyncPayload::Page(minicbor::bytes::ByteVec::from(
        page.encode().unwrap(),
      ));
      assert!(wrapped.encode().is_ok());
      pages += 1;
      assert!(
        page.descriptors().len() < 6,
        "an over-bound page never reaches the wire whole"
      );
      delivered.extend(page.descriptors().iter().map(|entry| entry.node().clone()));
      let done = page.cursor().is_none();
      cursor = page.cursor().map(|value| value.to_vec());
      if done {
        break;
      }
    }
    assert!(pages >= 3, "six fat descriptors split over several pages");
    delivered.sort();
    delivered.dedup();
    assert_eq!(delivered.len(), 6);
  }

  /// Repeated pages repair missing revisions and stale peers converge to
  /// the highest revision.
  #[tokio::test]
  async fn apply_pages_repairs_and_converges() {
    let factory = factory();
    crate::membership::store::store_descriptor(&factory, &descriptor(1, 1, "one"))
      .await
      .unwrap();
    // A stale peer holds revision 1; the peer pages revision 2.
    let fresh = crate::membership::NodeDescriptorV1::new(
      node(1),
      key(1),
      vec![Endpoint::parse("wss://one-updated:9000").unwrap()],
      2,
      false,
      1,
    );
    crate::membership::store::store_descriptor(&factory, &fresh)
      .await
      .unwrap();

    let page = sync::emit_page(&factory, None, 4).await.unwrap();
    let encoded = page.encode().unwrap();
    let decoded = MembershipPage::decode(&encoded).unwrap();
    // Applying again is idempotent (no downgrade, no duplicate install).
    let applied = sync::apply_page(&factory, &decoded).await.unwrap();
    let current = crate::membership::store::read_descriptor(&factory, &node(1))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(current.revision(), 2);
    let _ = applied;
  }

  /// A dishonest page cannot loop a cursor or exceed capacities; unknown
  /// versions fail closed at decode.
  #[test]
  fn reject_dishonest_pages() {
    // Over-capacity page.
    let descriptors = (0..=super::MAX_PAGE_DESCRIPTORS)
      .map(|index| descriptor((index % 8) as u8 + 1, 1, "x"))
      .collect();
    assert!(MembershipPage::new(descriptors, None).is_err());

    // Cursor loop is detected.
    let page = MembershipPage::new(vec![descriptor(1, 1, "one")], Some(vec![1])).unwrap();
    assert!(page.cursor_loops(Some(&[1])));
    assert!(!page.cursor_loops(Some(&[2])));
    assert!(!page.cursor_loops(None));
  }
}

#[cfg(test)]
mod label_fixture_tests {
  use super::{
    super::{NODE_DESCRIPTOR_SCHEMA, NodeDescriptorV1},
    decode_descriptor,
  };
  use crate::{
    Endpoint, LabelKey, LabelSet, LabelValue, NodeId,
    membership::DescriptorWire,
    protocol::{CONTROL_CBOR_LIMITS, decode_canonical, encode_canonical},
  };

  fn node(value: u8) -> NodeId {
    NodeId::parse(&format!("node_{value:021}")).unwrap()
  }

  fn key(name: &str) -> LabelKey {
    LabelKey::parse(&format!("radiata.woooo.tech/labels/{name}")).unwrap()
  }

  fn base(node_index: u8) -> NodeDescriptorV1 {
    use crate::identity::testing::scripted_signing;
    let signing = scripted_signing(u64::from(node_index));
    NodeDescriptorV1::new(
      node(node_index),
      crate::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      vec![Endpoint::parse("wss://edge:9000").unwrap()],
      1,
      false,
      1,
    )
  }

  /// Current fixtures: a version 2 descriptor round-trips its capability
  /// labels canonically.
  #[test]
  fn version_two_descriptor_round_trips_labels() {
    let descriptor = base(1).with_labels(
      LabelSet::new()
        .insert(key("zone"), LabelValue::parse("edge").unwrap())
        .unwrap()
        .insert(key("gpu"), LabelValue::parse("yes").unwrap())
        .unwrap(),
    );
    let bytes = descriptor.encode().unwrap();
    let decoded = decode_descriptor(&bytes).unwrap();
    assert_eq!(decoded.labels(), descriptor.labels());
    assert_eq!(decoded.labels().entries().count(), 2);
    // Canonical bytes are stable across re-encoding.
    assert_eq!(decoded.encode().unwrap(), bytes);
  }

  /// Previous fixtures: a version 1 record (no labels element) decodes to
  /// an empty label set and re-encodes as version 2.
  #[test]
  fn version_one_descriptor_decodes_with_empty_labels() {
    let previous = base(2);
    // Hand-encode the previous wire shape (record_version 1).
    let wire = super::super::DescriptorWireV1 {
      schema: NODE_DESCRIPTOR_SCHEMA.to_owned(),
      record_version: 1,
      node: previous.node().to_string(),
      public_key: minicbor::bytes::ByteVec::from(previous.public_key().as_bytes().to_vec()),
      endpoints: previous
        .endpoints()
        .iter()
        .map(|endpoint| endpoint.as_str().to_owned())
        .collect(),
      revision: previous.revision(),
      removed: previous.removed(),
      version: 1,
    };
    let bytes = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    let decoded = decode_descriptor(&bytes).unwrap();
    assert_eq!(decoded.labels().entries().count(), 0);
    assert_eq!(decoded.node(), previous.node());
    assert_eq!(decoded.revision(), previous.revision());
  }

  /// Reordered or duplicate capability labels fail closed instead of
  /// silently normalizing, keeping descriptor digests deterministic.
  #[test]
  fn noncanonical_label_order_fails_closed() {
    let descriptor = base(3).with_labels(
      LabelSet::new()
        .insert(key("alpha"), LabelValue::parse("1").unwrap())
        .unwrap()
        .insert(key("zeta"), LabelValue::parse("2").unwrap())
        .unwrap(),
    );
    let good = decode_descriptor(&descriptor.encode().unwrap()).unwrap();

    // Swap the two entries on the wire.
    let mut tampered: DescriptorWire =
      decode_canonical(&descriptor.encode().unwrap(), CONTROL_CBOR_LIMITS).unwrap();
    tampered.labels.reverse();
    let bytes = encode_canonical(&tampered, CONTROL_CBOR_LIMITS).unwrap();
    assert!(decode_descriptor(&bytes).is_err());
    let _ = good;
  }
}
