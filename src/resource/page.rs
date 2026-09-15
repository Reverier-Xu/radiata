//! Bounded resource-metadata pages for ordinary anti-entropy repair.
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

/// The default records-per-page emission limit (single-sourced in the
/// paging module; lane-local name for readable call sites).
pub(crate) use crate::paging::PAGE_DEFAULT_LIMIT as DEFAULT_RESOURCE_PAGE_LIMIT;
/// The receiver-side per-page capacity: a page above this bound fails
/// closed instead of being truncated.
pub(crate) use crate::paging::PAGE_MAX_ITEMS as MAX_PAGE_RECORDS;

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

  #[cfg(any(test, fuzzing))]
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
  use std::collections::HashMap;

  use super::{MAX_PAGE_RECORDS, ResourcePage, ResourceRecordV1};
  use crate::{Digest, Error, NodeId, Result, api::Entropy, storage::MetadataStore};

  /// How long one record's writer-descriptor lookup waits for the
  /// membership lane to converge before the record skips: the descriptor
  /// rides the same anti-entropy tick as the page, so a healthy
  /// convergence lands within one or two ticks — the bound only has to
  /// outlast that race.
  const WRITER_TRUST_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

  /// The descriptor re-poll interval inside the bounded wait.
  const WRITER_TRUST_POLL: std::time::Duration = std::time::Duration::from_millis(50);

  /// Emits one bounded page of resource records starting after `cursor`,
  /// filtered through the peer's delivered-version watermark table: an
  /// entry whose stored digest matches the peer's watermark is unchanged
  /// for that peer and is skipped, so a page carries only records the
  /// peer has never seen. The cursor is the last scanned name's text
  /// (changed or skipped), so paging continues across ticks without
  /// allocating the whole catalog.
  ///
  /// A page of fat records can overflow the 64 KiB control-body bound,
  /// which failed the whole sync tick every tick and stalled the cursor
  /// forever. The bounded halving ladder below retries at half the page
  /// capacity until the full wire payload (page envelope plus sync
  /// wrapper) fits: one record is bounded far below the control bound,
  /// so the ladder always terminates, and a halved page still carries
  /// its continuation cursor (the size-ladder note in
  /// `crate::paging::encode_page`).
  pub(crate) async fn emit_page_filtered_ctx(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize, scan_budget: usize,
    watermarks: &std::collections::BTreeMap<Vec<u8>, Digest>,
  ) -> Result<FilteredEmission> {
    crate::paging::emit_with_size_ladder(
      limit.clamp(1, MAX_PAGE_RECORDS),
      "resource page",
      |changed_limit| {
        emit_filtered_at_capacity(store, cursor, changed_limit, scan_budget, watermarks)
      },
      |emission: &FilteredEmission| match &emission.page {
        Some(page) => wire_payload_fits(page),
        None => Ok(true),
      },
    )
    .await
  }

  /// True when the page's full wire payload (page envelope plus sync
  /// wrapper) encodes inside the control-body bound.
  fn wire_payload_fits(page: &ResourcePage) -> Result<bool> {
    crate::sync_common::page_wire_fits(page.encode(), |bytes| {
      super::super::sync::ResourceSyncPayload(minicbor::bytes::ByteVec::from(bytes)).encode()
    })
  }

  /// Emits one filtered detection/emission step at an exact candidate
  /// capacity (one ladder step): scans a bounded budget of entries from
  /// `cursor`, collecting records whose stored digest differs from the
  /// peer's watermark. Skipped (unchanged) entries advance the scan
  /// without entering the page.
  ///
  /// The returned emission distinguishes a budget window that closed
  /// change-free mid-catalog (the walk continues from its boundary on
  /// the next tick) from the scan reaching the catalog end (the pass is
  /// complete). Conflating the two would strand every record behind the
  /// first quiet window: the pass would "close" at entry 256 of 4096
  /// and never reach the tail.
  async fn emit_filtered_at_capacity(
    store: &MetadataStore, cursor: Option<&[u8]>, changed_limit: usize, scan_budget: usize,
    watermarks: &std::collections::BTreeMap<Vec<u8>, Digest>,
  ) -> Result<FilteredEmission> {
    let namespace = super::super::store::namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan_from(&namespace, &[], cursor).await?;
    let mut changed: Vec<ResourceRecordV1> = Vec::new();
    let mut marks: Vec<(Vec<u8>, Digest)> = Vec::new();
    let mut last_included = Option::<Vec<u8>>::None;
    // The walk boundary: the key of the last scanned entry, changed or
    // not. The pass resumes strictly after it on the next tick.
    let mut boundary;
    let mut scanned = 0_usize;
    while let Some(entry) = scan.next().await? {
      scanned += 1;
      let key = entry.key().as_bytes().to_vec();
      let record = ResourceRecordV1::decode(entry.value().as_bytes())?;
      let digest = record.digest.clone();
      boundary = Some(key.clone());
      // Changed records enter the page and update the page's wire
      // cursor (the last included record). Unchanged records only
      // advance the boundary: re-scanning them on later steps is
      // harmless because application is idempotent.
      if watermarks.get(&key) != Some(&digest) {
        changed.push(record);
        last_included = Some(key.clone());
        marks.push((key, digest));
        if changed.len() >= changed_limit {
          return FilteredEmission::page(
            changed,
            last_included,
            boundary,
            cursor.map(|value| value.to_vec()),
            marks,
          );
        }
      }
      if scanned >= scan_budget {
        // The scan budget is spent: the pass continues after the
        // boundary on the next tick, with or without a page.
        return FilteredEmission::page(
          changed,
          last_included,
          boundary,
          cursor.map(|value| value.to_vec()),
          marks,
        );
      }
    }
    // The scan reached the catalog end: the pass is complete. The page
    // (if any) still delivers the collected tail records; an empty
    // emission closes the pass and the cadence restarts.
    FilteredEmission::finish(
      changed,
      last_included,
      cursor.map(|value| value.to_vec()),
      marks,
    )
  }

  /// One filtered detection/emission step: the bounded changed-record
  /// page plus the scan bookkeeping the caller needs to commit the walk
  /// on delivery or rewind on failure.
  pub(crate) struct FilteredEmission {
    /// The page of changed records; `None` when the step found nothing
    /// to deliver.
    pub(crate) page: Option<ResourcePage>,
    /// The walk continuation: `Some(boundary key)` while the pass is in
    /// flight — the next step resumes strictly after it, and a delivered
    /// page commits exactly here — or `None` when the scan reached the
    /// catalog end and the pass is complete.
    pub(crate) walk_cursor: Option<Vec<u8>>,
    /// The scan position where this step started: an undelivered page
    /// rewinds to exactly here.
    pub(crate) scan_start: Option<Vec<u8>>,
    /// The page records' (store key, digest) delivery marks: committed
    /// into the peer's watermark table when the page is delivered.
    pub(crate) marks: Vec<(Vec<u8>, Digest)>,
  }

  impl FilteredEmission {
    fn page(
      changed: Vec<ResourceRecordV1>, last_included: Option<Vec<u8>>, boundary: Option<Vec<u8>>,
      scan_start: Option<Vec<u8>>, marks: Vec<(Vec<u8>, Digest)>,
    ) -> Result<Self> {
      let page = match changed.is_empty() {
        true => None,
        false => Some(ResourcePage::new(changed, last_included)?),
      };
      Ok(Self {
        page,
        walk_cursor: boundary,
        scan_start,
        marks,
      })
    }

    /// The scan reached the catalog end: with collected records the
    /// step still emits their page (the pass completes after its
    /// delivery); without any the pass closes change-free.
    fn finish(
      changed: Vec<ResourceRecordV1>, last_included: Option<Vec<u8>>, scan_start: Option<Vec<u8>>,
      marks: Vec<(Vec<u8>, Digest)>,
    ) -> Result<Self> {
      let page = match changed.is_empty() {
        true => None,
        false => Some(ResourcePage::new(changed, last_included)?),
      };
      Ok(Self {
        page,
        walk_cursor: None,
        scan_start,
        marks,
      })
    }
  }

  /// The unfiltered test/select emit: identical to a filtered pass with
  /// an empty watermark table (every record is changed) and an
  /// unbounded scan budget. A catalog shorter than the limit yields a
  /// page whose cursor is `None` (pass complete).
  #[cfg(any(test, fuzzing))]
  pub(crate) async fn emit_page_ctx(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<ResourcePage> {
    let empty = std::collections::BTreeMap::new();
    let emission = emit_page_filtered_ctx(store, cursor, limit, usize::MAX, &empty).await?;
    Ok(
      emission
        .page
        .unwrap_or_else(|| ResourcePage::new(Vec::new(), None).expect("empty page is well-formed")),
    )
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
    // Resolve each distinct writer once per page: the bounded
    // descriptor-convergence wait is a per-writer cost, not a per-record
    // cost — a page of N records from one not-yet-converged writer waits
    // once, not N times.
    let mut resolved: HashMap<NodeId, Option<crate::PublicKey>> = HashMap::new();
    for writer in page
      .records()
      .iter()
      .map(|record| record.writer())
      .collect::<Vec<_>>()
    {
      if resolved.contains_key(writer) {
        continue;
      }
      // The fast path is the same read `writer_key` starts with: a
      // converged writer resolves without any wait.
      let key = match crate::membership::store::read_descriptor_ctx(store, writer).await {
        Ok(Some(descriptor)) if !descriptor.removed() => Some(descriptor.public_key().clone()),
        _ => None,
      };
      resolved.insert(writer.clone(), key);
    }
    let mut applied = 0;
    for record in page.records() {
      let writer_key = match resolved.get(record.writer()) {
        Some(Some(key)) => key.clone(),
        Some(None) => {
          // Unknown writer: the bounded wait runs once per writer (the
          // result is cached above for the rest of the page). Without
          // the writer's trusted key no signature check is possible, so
          // nothing is compared or stored. The wait already absorbed the
          // normal descriptor-convergence race; past it the skip is
          // final for this pass and the periodic watermark refresh
          // re-delivers the record. Past-the-bound skips are an
          // internal-consistency anomaly (the membership lane stalled)
          // and warn.
          match writer_key(store, record.writer()).await {
            Ok(key) => {
              resolved.insert(record.writer().clone(), Some(key.clone()));
              key
            }
            Err(error) => {
              tracing::warn!(
                writer = %record.writer(),
                kind = ?error.kind(),
                "resource page writer never converged; page records skipped"
              );
              continue;
            }
          }
        }
        None => continue,
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
  ///
  /// A page may legitimately arrive before its writer's descriptor: both
  /// ride the same anti-entropy tick in either order. The resolution
  /// therefore waits a bounded time for the descriptor to converge
  /// instead of skipping immediately — a skip here would strand the
  /// record behind an already-delivered watermark. Past the bound the
  /// lookup fails closed and the periodic watermark refresh re-delivers
  /// the record later.
  async fn writer_key(store: &MetadataStore, writer: &crate::NodeId) -> Result<crate::PublicKey> {
    let deadline = std::time::Instant::now() + WRITER_TRUST_WAIT;
    loop {
      let descriptor = crate::membership::store::read_descriptor_ctx(store, writer).await?;
      match descriptor {
        Some(descriptor) if !descriptor.removed() => {
          return Ok(descriptor.public_key().clone());
        }
        _ if std::time::Instant::now() >= deadline => {
          return Err(Error::not_trusted("resource page writer"));
        }
        _ => tokio::time::sleep(WRITER_TRUST_POLL).await,
      }
    }
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
    NodeId::parse("node-000000000000000000001").unwrap()
  }

  fn other_writer() -> NodeId {
    NodeId::parse("node-000000000000000000002").unwrap()
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

  /// Pages enforce record, byte, and schema capacities — an
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

  /// Duplicate, reordered, and changing
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

  /// Signature validation happens before comparison — a
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
