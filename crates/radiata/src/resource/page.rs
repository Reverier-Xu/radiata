//! Bounded resource-metadata pages for ordinary anti-entropy repair.
//!
//! One page carries a bounded list of whole records plus a continuation
//! cursor, so population-sized catalogs stream without ever materializing
//! the full catalog. The test emit pages the local store from a cursor;
//! application validates each record's digest at decode — the row is
//! trusted through the authenticated session that delivered it, exactly
//! as member descriptors are, so there is no per-record signature to
//! check — and then installs it through the conditional register commit:
//! losing permutations stay harmless and duplicates are idempotent, so
//! duplicate, reordered, truncated, and changing pages all converge to one
//! stable winner set.

use super::ResourceRecordV1;
#[cfg(test)]
use crate::Error;
use crate::Result;

/// The schema of one resource page record envelope (tests pin the wire
/// shape the page round-trips through).
#[cfg(test)]
pub(crate) const RESOURCE_PAGE_SCHEMA: &str = "radiata.woooo.tech/schemas/v1/resource-page";

/// The per-page capacity: a page above this bound fails closed instead
/// of being truncated.
pub(crate) use crate::paging::PAGE_MAX_ITEMS as MAX_PAGE_RECORDS;

/// One bounded page of resource records plus a continuation cursor.
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

  #[cfg(test)]
  pub(crate) fn cursor(&self) -> Option<&[u8]> {
    self.cursor.as_deref()
  }

  #[cfg(test)]
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
  /// here, before any comparison.
  #[cfg(test)]
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
  use super::{ResourcePage, ResourceRecordV1};
  use crate::{Result, api::Entropy, storage::MetadataStore};

  /// The unfiltered page emit for the page round-trip tests: one page
  /// over the store's current records after `cursor`. A **test
  /// fixture** — production pages come from the reconcile plane, which
  /// packs rows under its own byte budget. A catalog shorter than the
  /// limit yields a page whose cursor is `None` (pass complete).
  #[cfg(test)]
  pub(crate) async fn emit_test_page(
    store: &MetadataStore, cursor: Option<&[u8]>, limit: usize,
  ) -> Result<ResourcePage> {
    let namespace = super::super::store::namespace()?;
    let snapshot = store.snapshot().await?;
    let mut scan = snapshot.scan_from(&namespace, &[], cursor).await?;
    let mut records = Vec::new();
    let mut last: Option<Vec<u8>> = None;
    let mut exhausted = true;
    while let Some(entry) = scan.next().await? {
      if let Ok(record) = super::super::store::decode_stored_row(entry.value().as_bytes()) {
        if records.len() >= limit.clamp(1, super::MAX_PAGE_RECORDS) {
          exhausted = false;
          break;
        }
        records.push(record);
      }
      last = Some(entry.key().as_bytes().to_vec());
    }
    let cursor = if exhausted { None } else { last };
    ResourcePage::new(records, cursor)
  }

  /// The outcome of one received page's apply: the committed records, in
  /// commit order — the caller reports each one as a peer-converged
  /// resource change.
  pub(crate) struct PageApply {
    /// The committed records, in commit order.
    pub(crate) installed: Vec<ResourceRecordV1>,
  }

  /// Applies one received page over the running node's metadata store
  /// and reports only the committed count — the form the test harnesses
  /// and offline pagers consume (the production caller is the
  /// reconciliation plane, which takes the reported form below).
  ///
  /// The row is trusted through the authenticated session that delivered
  /// it, the same stance member descriptors take: there is no per-record
  /// signature to check and no writer descriptor to resolve. Installation
  /// goes through the conditional register commit, so stale, duplicated,
  /// and losing permutations cannot replace a greater stored winner.
  #[cfg(test)]
  pub(crate) async fn apply_page_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, page: &ResourcePage,
  ) -> Result<usize> {
    Ok(
      apply_page_reported_ctx(store, entropy, page)
        .await?
        .installed
        .len(),
    )
  }

  /// The reported form of [`apply_page_ctx`] the reconciliation plane's
  /// resources arm consumes: the same commits plus the installed records.
  pub(crate) async fn apply_page_reported_ctx(
    store: &MetadataStore, entropy: &dyn Entropy, page: &ResourcePage,
  ) -> Result<PageApply> {
    // One batched register commit for the whole page: it lands in a
    // single durable transaction instead of one per record (the
    // per-record commit queue at join fan-out was the minutes-long
    // roster-convergence tail).
    let records: Vec<&ResourceRecordV1> = page.records().iter().collect();
    let installed = super::super::store::commit_page_batch_ctx(store, entropy, &records).await?;
    Ok(PageApply { installed })
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{ResourcePage, ResourceRecordV1, sync};
  use crate::{
    LabelKey, LabelSet, LabelValue, NodeId, api::SystemEntropy, provider::StorageFactory,
    resource::ResourceName, storage::MetadataStore,
  };

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
    name: &ResourceName, timestamp_millis: i64, writer: &NodeId, uri: &str,
  ) -> ResourceRecordV1 {
    ResourceRecordV1::new(
      name.clone(),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse(uri).unwrap(),
      labels(),
      timestamp_millis,
      writer.clone(),
      0,
      false,
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
        )
      })
      .collect();
    assert!(ResourcePage::new(records, None).is_err());

    let page = ResourcePage::new(vec![record(&name(1), 1_000, &writer(), "u://x")], None).unwrap();
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
  /// installs no authoritative change while re-transferring the full
  /// winner pages byte-for-byte (the emit side pages its whole catalog
  /// with no receiver knowledge — the test measures those bytes).
  #[tokio::test]
  async fn permuted_pages_converge_to_one_winner_set() {
    let (_source_factory, source) = open_store().await;

    // Two writers write competing permutations for three names.
    let mut truth = Vec::new();
    for seed in 1..=3_u8 {
      truth.push(record(&name(seed), 1_000, &writer(), "u://a"));
      truth.push(record(&name(seed), 2_000, &other_writer(), "u://b"));
      truth.push(record(&name(seed), 3_000, &writer(), "u://c"));
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
      let page = sync::emit_test_page(&source, cursor.as_deref(), 2)
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

    // Two receivers apply the pages in opposite orders onto fresh stores.
    let (_factory_a, store_a) = open_store().await;
    let (_factory_b, store_b) = open_store().await;
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

    // A second completed pass installs no authoritative change — but the
    // emit side pages its whole catalog with no knowledge of the
    // receiver, so "zero install" is not "zero transfer": measure the
    // bytes the pass actually re-sends and pin the real cost shape.
    let first_pass_bytes: usize = pages.iter().map(|page| page.encode().unwrap().len()).sum();
    let mut applied_second_pass = 0;
    let mut second_pass_bytes = 0;
    let mut second_pass_records = 0;
    let mut second_pass_pages = 0;
    let mut cursor: Option<Vec<u8>> = None;
    loop {
      let page = sync::emit_test_page(&source, cursor.as_deref(), 2)
        .await
        .unwrap();
      let done = page.cursor().is_none();
      cursor = page.cursor().map(|value| value.to_vec());
      second_pass_bytes += page.encode().unwrap().len();
      second_pass_records += page.records().len();
      second_pass_pages += 1;
      applied_second_pass += sync::apply_page_ctx(&store_a, &SystemEntropy, &page)
        .await
        .unwrap();
      if done {
        break;
      }
    }
    assert_eq!(applied_second_pass, 0, "a changeless pass installs nothing");
    assert_eq!(
      second_pass_records, 3,
      "a changeless pass re-sends the full winner set"
    );
    assert_eq!(
      second_pass_pages,
      pages.len(),
      "a changeless pass pages the catalog identically"
    );
    assert_eq!(
      second_pass_bytes, first_pass_bytes,
      "a changeless pass re-transfers the full pages byte-for-byte — zero install is not zero transfer"
    );
  }

  async fn read_current(store: &MetadataStore, name: &ResourceName) -> Option<ResourceRecordV1> {
    super::super::store::read_record_ctx(store, name)
      .await
      .unwrap()
  }

  /// The session is the trust boundary: a row delivered over an
  /// authenticated session is accepted with no per-record signature and
  /// no local descriptor for its writer, exactly as member descriptors
  /// are. The register's tuple order still decides the winner, and a row
  /// whose digest does not match its fields never reaches it — the page
  /// decode refuses the whole page.
  #[tokio::test]
  async fn rows_are_accepted_through_the_session_without_a_writer_descriptor() {
    let (_factory, receiver) = open_store().await;

    // The receiver holds no descriptor for this writer at all.
    let delivered = record(&name(9), 5_000, &writer(), "u://delivered");
    let page = ResourcePage::new(vec![delivered.clone()], None).unwrap();
    let outcome = sync::apply_page_reported_ctx(&receiver, &SystemEntropy, &page)
      .await
      .unwrap();
    assert_eq!(outcome.installed.len(), 1, "the delivered row installs");
    assert_eq!(
      outcome.installed.as_slice(),
      std::slice::from_ref(&delivered)
    );
    assert_eq!(read_current(&receiver, &name(9)).await, Some(delivered));
    // A mutated row is still rejected: flipping a byte inside the record
    // body leaves a digest that no longer matches the fields, so the
    // page fails to decode and nothing is compared or stored.
    let mut tampered = page.encode().unwrap();
    let position = tampered
      .windows("u://delivered".len())
      .position(|window| window == b"u://delivered")
      .unwrap();
    tampered[position] ^= 0x01;
    assert!(ResourcePage::decode(&tampered).is_err());
  }

  /// Regression: one corrupt stored incumbent must not fail the whole
  /// page batch. The register treats the corrupt value as non-evidence
  /// and installs the incoming record over it with an exact
  /// CAS, so the page applies, the corrupt bytes are replaced, and a
  /// second apply finds the incoming record already stored (no
  /// re-install).
  #[tokio::test]
  async fn an_undecodable_stored_incumbent_is_replaced_by_the_valid_record() {
    let (_factory, store) = open_store().await;

    // Poison one register row with bytes no resource record decodes from.
    let poisoned = name(7);
    let namespace = super::super::store::namespace().unwrap();
    let key = crate::StoreKey::new(Arc::from(poisoned.as_str().as_bytes().to_vec()));
    let corrupt = vec![0xFF_u8, 0x00];
    let snapshot = store.snapshot().await.unwrap();
    let transaction = store
      .prepare_transaction(
        crate::TransactionId::generate(&SystemEntropy).unwrap(),
        snapshot.revision().clone(),
        vec![crate::StoreOperation::Put {
          namespace: namespace.clone(),
          key: key.clone(),
          expected: crate::StoreExpectation::Absent,
          value: crate::StoreValue::new(Arc::from(corrupt.clone())),
        }],
      )
      .unwrap();
    drop(snapshot);
    assert!(matches!(
      store.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));

    let poisoned_record = record(&poisoned, 5_000, &writer(), "u://poisoned");
    let good = record(&name(8), 5_000, &writer(), "u://good");
    let page = ResourcePage::new(vec![poisoned_record.clone(), good], None).unwrap();
    let outcome = sync::apply_page_reported_ctx(&store, &SystemEntropy, &page)
      .await
      .unwrap();
    assert_eq!(
      outcome.installed.len(),
      2,
      "both records apply over the corrupt incumbent"
    );

    // The corrupt incumbent is replaced by the incoming record; the
    // stored row is the envelope, so the assertion compares payloads.
    let stored = store
      .snapshot()
      .await
      .unwrap()
      .get(&namespace, &key)
      .await
      .unwrap()
      .expect("the register holds the incoming record");
    assert_eq!(
      super::super::store::decode_stored_row(stored.as_bytes()).unwrap(),
      poisoned_record
    );
    assert_eq!(read_current(&store, &poisoned).await, Some(poisoned_record));

    // A second apply of the same page installs nothing: the register
    // already holds the record.
    let outcome = sync::apply_page_reported_ctx(&store, &SystemEntropy, &page)
      .await
      .unwrap();
    assert_eq!(
      outcome.installed.len(),
      0,
      "a converged page does not re-install"
    );
  }
}
