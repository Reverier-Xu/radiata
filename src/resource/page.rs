//! Bounded resource-metadata pages for ordinary anti-entropy repair
//! (T-G07-04, ADR-0007).
//!
//! One page carries a bounded list of whole signed records plus a
//! continuation cursor, so population-sized catalogs stream without ever
//! materializing the full catalog. Emission pages the local store from a
//! cursor; application validates each record's digest at decode and its
//! writer's signature against the locally trusted member descriptors
//! before any comparison, then installs it through the conditional
//! register commit — losing permutations stay harmless and duplicates are
//! idempotent, so duplicate, reordered, truncated, and changing pages all
//! converge to one stable winner set.

use super::ResourceRecordV1;
use crate::{Error, Result};

pub(crate) const RESOURCE_PAGE_SCHEMA: &str = "radiata.woooo.tech/schemas/resource-page-v1";

/// The default records-per-page emission limit.
pub(crate) const DEFAULT_RESOURCE_PAGE_LIMIT: usize = 16;

/// The receiver-side per-page capacity: a page above this bound fails
/// closed instead of being truncated.
pub(crate) const MAX_PAGE_RECORDS: usize = 64;

/// One bounded page of signed resource records plus a continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourcePage {
  records: Vec<ResourceRecordV1>,
  cursor: Option<Vec<u8>>,
}

impl ResourcePage {
  pub(crate) fn new(records: Vec<ResourceRecordV1>, cursor: Option<Vec<u8>>) -> Result<Self> {
    crate::paging::check_page_shape(records.len(), MAX_PAGE_RECORDS, &cursor, "resource page")?;
    Ok(Self { records, cursor })
  }

  pub(crate) fn records(&self) -> &[ResourceRecordV1] {
    &self.records
  }

  pub(crate) fn cursor(&self) -> Option<&[u8]> {
    self.cursor.as_deref()
  }

  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    // A record that cannot encode must fail the page: shipping empty bytes
    // would produce an entry every remote peer rejects.
    let mut items = Vec::with_capacity(self.records.len());
    for record in &self.records {
      items.push(record.encode()?);
    }
    crate::paging::encode_page(RESOURCE_PAGE_SCHEMA, &items, self.cursor.as_deref())
  }

  /// Decodes one page. Every entry is fully decoded and digest-checked
  /// here; writer-signature validation happens against the local trust
  /// anchors during application, before comparison.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let (items, cursor) = crate::paging::decode_page(
      bytes,
      RESOURCE_PAGE_SCHEMA,
      MAX_PAGE_RECORDS,
      "resource page",
    )?;
    let mut records = Vec::with_capacity(items.len());
    for encoded in &items {
      let record = ResourceRecordV1::decode(encoded)
        .map_err(|_| Error::invalid_input("resource page record"))?;
      records.push(record);
    }
    Self::new(records, cursor)
  }
}

/// The anti-entropy driver for resource pages: pages the local register
/// from a cursor and applies received pages under strict validation.
pub(crate) mod sync {
  use super::{MAX_PAGE_RECORDS, ResourcePage, ResourceRecordV1};
  use crate::{Error, Result, api::Entropy, storage::MetadataStore};

  /// Emits one bounded page of resource records starting after `cursor`.
  /// The cursor is the last emitted name's text, so paging continues
  /// across ticks without allocating the whole catalog.
  pub(crate) async fn emit_page_ctx(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<ResourcePage> {
    let limit = limit.clamp(1, MAX_PAGE_RECORDS);
    let namespace = super::super::store::namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let paged = crate::paging::scan_paged(scan.as_mut(), cursor, limit, |_key, bytes| {
      ResourceRecordV1::decode(bytes).map(Some)
    })
    .await?;
    ResourcePage::new(paged.items, paged.next)
  }

  /// A cheap change fingerprint over the raw stored bytes of the page
  /// range [`Self::emit_page_ctx`] would produce. Records are stored
  /// canonically, so the raw bytes carry every content change without
  /// decoding any record: the quiet-state tick pays one scan and one
  /// hash instead of a decode, re-encode, and digest per record. The
  /// slow resend cadence heals the (non-cryptographic) collision case,
  /// exactly like the decoded fingerprint it replaces.
  pub(crate) async fn page_fingerprint_ctx(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<u64> {
    use std::hash::{Hash, Hasher};
    let limit = limit.clamp(1, MAX_PAGE_RECORDS);
    let namespace = super::super::store::namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan(&namespace, &[]).await?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let paged = crate::paging::scan_paged(scan.as_mut(), cursor, limit, |_key, bytes| {
      bytes.len().hash(&mut hasher);
      bytes.hash(&mut hasher);
      Ok(Some(()))
    })
    .await?;
    paged.items.len().hash(&mut hasher);
    paged
      .next
      .as_ref()
      .map_or(0_usize, Vec::len)
      .hash(&mut hasher);
    Ok(hasher.finish())
  }

  /// Applies one received page over the running node's metadata store.
  /// Every record's writer signature is validated against the locally
  /// trusted member descriptors **before** comparison; records with an
  /// unknown writer or a bad signature are skipped fail-closed (the next
  /// anti-entropy pass retries after membership metadata delivers the
  /// writer's descriptor). Installation goes through the conditional
  /// register commit, so stale, duplicated, and losing permutations cannot
  /// replace a greater stored winner.
  pub(crate) async fn apply_page_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, page: &ResourcePage,
  ) -> Result<usize> {
    let mut applied = 0;
    for record in page.records() {
      let writer_key = match writer_key(store, record.writer()).await {
        Ok(key) => key,
        // Unknown writers fail closed: without the writer's trusted key no
        // signature check is possible, so nothing is compared or stored.
        Err(error) => {
          tracing::debug!(
            writer = %record.writer(),
            kind = ?error.kind(),
            "resource page record skipped: writer not yet trusted"
          );
          continue;
        }
      };
      match record.verify(&writer_key) {
        Ok(()) => {}
        Err(error) => {
          tracing::debug!(writer = %record.writer(), kind = ?error.kind(), "resource page record skipped: bad signature");
          continue;
        }
      }
      if matches!(
        super::super::store::commit_record_ctx(store, entropy, record).await?,
        super::super::store::ResourceCommitOutcome::Installed(_)
      ) {
        applied += 1;
      }
    }
    Ok(applied)
  }

  /// The trusted public key of `writer`, resolved from the locally stored
  /// member descriptors that ordinary membership synchronization maintains.
  async fn writer_key(store: &MetadataStore, writer: &crate::NodeId) -> Result<crate::PublicKey> {
    let descriptor = crate::membership::store::read_descriptor_ctx(store, writer)
      .await?
      .ok_or_else(|| Error::not_trusted("resource page writer"))?;
    if descriptor.removed() {
      return Err(Error::not_trusted("resource page writer"));
    }
    Ok(descriptor.public_key().clone())
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use ed25519_dalek::SigningKey;

  use super::{ResourcePage, ResourceRecordV1, sync};
  use crate::{
    Endpoint, LabelKey, LabelSet, LabelValue, NodeId, api::SystemEntropy,
    membership::store as descriptor_store, provider::StorageFactory, resource::ResourceName,
    storage::MetadataStore,
  };

  const SEED: [u8; 32] = [31; 32];
  const OTHER_SEED: [u8; 32] = [33; 32];

  fn writer() -> NodeId {
    NodeId::parse("node_000000000000000000001").unwrap()
  }

  fn other_writer() -> NodeId {
    NodeId::parse("node_000000000000000000002").unwrap()
  }

  fn name(seed: u8) -> ResourceName {
    ResourceName::parse(&format!("radiata.woooo.tech/resources/sync-{seed}")).unwrap()
  }

  fn labels() -> LabelSet {
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/zone").unwrap(),
        LabelValue::parse("z1").unwrap(),
      )
      .unwrap()
  }

  fn record(
    name: &ResourceName, timestamp_millis: u64, writer: &NodeId, uri: &str, seed: [u8; 32],
  ) -> ResourceRecordV1 {
    ResourceRecordV1::sign(
      name.clone(),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse(uri).unwrap(),
      labels(),
      timestamp_millis,
      writer.clone(),
      0,
      false,
      &SigningKey::from_bytes(&seed),
    )
    .unwrap()
  }

  async fn open_store() -> (Arc<dyn StorageFactory>, MetadataStore) {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let store = MetadataStore::open(&factory, std::time::Duration::from_secs(10))
      .await
      .unwrap();
    (factory, store)
  }

  /// Stores one trusted writer descriptor through the ordinary membership
  /// path, so the resource page lane can resolve and verify signatures.
  async fn trust(store: &MetadataStore, node: &NodeId, seed: [u8; 32]) {
    let key =
      crate::PublicKey::from_bytes(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node.clone(),
      key,
      vec![Endpoint::parse("wss://127.0.0.1:0").unwrap()],
      1,
      false,
      1,
    );
    descriptor_store::store_descriptor_ctx(store, &SystemEntropy, &descriptor)
      .await
      .unwrap();
  }

  /// SC-G07-P0-10: pages enforce record, byte, and schema capacities — an
  /// oversized page, a wrong schema, and a truncated record all fail
  /// closed at decode.
  #[test]
  fn page_decode_enforces_capacity_and_canonical_rules() {
    let records: Vec<ResourceRecordV1> = (1..=65)
      .map(|seed| {
        record(
          &name(u8::try_from(seed).unwrap()),
          1_000,
          &writer(),
          "u://x",
          SEED,
        )
      })
      .collect();
    assert!(ResourcePage::new(records, None).is_err());

    let page = ResourcePage::new(
      vec![record(&name(1), 1_000, &writer(), "u://x", SEED)],
      None,
    )
    .unwrap();
    let bytes = page.encode().unwrap();
    assert_eq!(ResourcePage::decode(&bytes).unwrap(), page);

    // Wrong schema fails closed.
    let mut tampered = bytes.clone();
    tampered[3] ^= 0xFF;
    assert!(ResourcePage::decode(&tampered).is_err());
    // A truncated record entry fails closed.
    assert!(ResourcePage::decode(&bytes[..bytes.len() - 4]).is_err());
  }

  /// SC-G07-P0-10 + SC-G07-P1-12: duplicate, reordered, and changing
  /// pages converge to one stable winner set; a second completed pass
  /// transfers no authoritative changes.
  #[tokio::test]
  async fn permuted_pages_converge_to_one_winner_set() {
    let (_source_factory, source) = open_store().await;

    // Two writers write competing permutations for three names.
    let mut truth = Vec::new();
    for seed in 1..=3_u8 {
      truth.push(record(&name(seed), 1_000, &writer(), "u://a", SEED));
      truth.push(record(
        &name(seed),
        2_000,
        &other_writer(),
        "u://b",
        OTHER_SEED,
      ));
      truth.push(record(&name(seed), 3_000, &writer(), "u://c", SEED));
    }
    for record in &truth {
      match super::super::store::commit_record_ctx(&source, &SystemEntropy, record)
        .await
        .unwrap()
      {
        super::super::store::ResourceCommitOutcome::Installed(_) => {}
        other => panic!("source commit must install, got {other:?}"),
      }
    }

    // Page the whole catalog with a tiny limit.
    let mut pages = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
      let page = sync::emit_page_ctx(&source, cursor.as_deref(), 2)
        .await
        .unwrap();
      let done = page.cursor().is_none();
      cursor = page.cursor().map(|value| value.to_vec());
      pages.push(page);
      if done {
        break;
      }
    }
    assert!(
      pages.len() >= 2,
      "three winners at limit two need at least two pages"
    );

    // Two receivers apply the pages in opposite orders onto fresh stores
    // seeded with the same trusted writers.
    let (_factory_a, store_a) = open_store().await;
    trust(&store_a, &writer(), SEED).await;
    trust(&store_a, &other_writer(), OTHER_SEED).await;
    let (_factory_b, store_b) = open_store().await;
    trust(&store_b, &writer(), SEED).await;
    trust(&store_b, &other_writer(), OTHER_SEED).await;
    for page in &pages {
      sync::apply_page_ctx(&store_a, &SystemEntropy, page)
        .await
        .unwrap();
    }
    for page in pages.iter().rev() {
      sync::apply_page_ctx(&store_b, &SystemEntropy, page)
        .await
        .unwrap();
    }

    // Both receivers converge to exactly the source winner set, without
    // materializing the full catalog during any single emit.
    for name_seed in 1..=3_u8 {
      let expected = read_current(&source, &name(name_seed)).await;
      let got_a = read_current(&store_a, &name(name_seed)).await;
      let got_b = read_current(&store_b, &name(name_seed)).await;
      assert_eq!(got_a, expected);
      assert_eq!(got_b, expected);
    }

    // A second completed pass transfers no authoritative changes.
    let mut applied_second_pass = 0;
    let mut cursor: Option<Vec<u8>> = None;
    loop {
      let page = sync::emit_page_ctx(&source, cursor.as_deref(), 2)
        .await
        .unwrap();
      let done = page.cursor().is_none();
      cursor = page.cursor().map(|value| value.to_vec());
      applied_second_pass += sync::apply_page_ctx(&store_a, &SystemEntropy, &page)
        .await
        .unwrap();
      if done {
        break;
      }
    }
    assert_eq!(applied_second_pass, 0);
  }

  async fn read_current(store: &MetadataStore, name: &ResourceName) -> Option<ResourceRecordV1> {
    super::super::store::read_record_ctx(store, name)
      .await
      .unwrap()
  }

  /// SC-G07-P0-10: signature validation happens before comparison — a
  /// record from an unknown writer or with a broken signature is skipped
  /// fail-closed and never stored.
  #[tokio::test]
  async fn unverified_records_fail_closed_before_comparison() {
    let (_factory, receiver) = open_store().await;

    // Unknown writer: nothing is compared or stored. The receiver stores
    // no descriptor for the writer, so the record must be skipped even
    // though its tuple would win an empty register.
    let unknown = record(&name(9), 5_000, &writer(), "u://unknown", SEED);
    let page = ResourcePage::new(vec![unknown], None).unwrap();
    assert_eq!(
      sync::apply_page_ctx(&receiver, &SystemEntropy, &page)
        .await
        .unwrap(),
      0
    );
    assert!(read_current(&receiver, &name(9)).await.is_none());
  }

  /// A known writer with a bad signature is also skipped fail-closed.
  #[tokio::test]
  async fn bad_signature_from_known_writer_is_skipped() {
    let (_factory, receiver) = open_store().await;
    trust(&receiver, &writer(), SEED).await;
    let good = record(&name(4), 5_000, &writer(), "u://good", SEED);
    // Re-sign the same body with a different key so the record shape is
    // valid but the signature does not verify under the trusted key.
    let forged_body = ResourceRecordV1::encode_signed_body(
      good.name(),
      good.resource_type(),
      good.resource_uri(),
      good.labels(),
      good.timestamp_millis(),
      good.writer(),
      good.removal_rank(),
      good.removed(),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&OTHER_SEED);
    use ed25519_dalek::Signer as _;
    let signature = crate::Signature::from_bytes(
      key
        .sign(&crate::identity::signature::signature_message(
          crate::resource::RESOURCE_RECORD_V1_DOMAIN,
          &forged_body,
        ))
        .to_bytes(),
    );
    let forged = ResourceRecordV1::seal(
      good.name().clone(),
      good.resource_type().clone(),
      good.resource_uri().clone(),
      good.labels().clone(),
      good.timestamp_millis(),
      good.writer().clone(),
      good.removal_rank(),
      good.removed(),
      signature,
    )
    .unwrap();
    let page = ResourcePage::new(vec![forged], None).unwrap();
    assert_eq!(
      sync::apply_page_ctx(&receiver, &SystemEntropy, &page)
        .await
        .unwrap(),
      0
    );
    assert!(read_current(&receiver, &name(4)).await.is_none());
  }
}
