//! Keyset-cursor paging over unsigned-byte ordered entries (single
//! source): membership pages, resource pages, candidate reads, and the
//! public paged views share one loop and one end-of-stream rule — a page
//! at capacity yields a continuation cursor only when at least one
//! further raw entry provably exists, so no trailing empty page
//! terminates the stream. Every page starts from a positioned entry
//! point strictly past the cursor (`StoreSnapshot::scan_from` for
//! storage scans, one `partition_point` for in-memory tables), so a
//! page costs O(page) reads instead of replaying the namespace head.

use minicbor::{Decode, Encode, bytes::ByteVec};

use crate::{Error, Result};

/// The one bounded-page wire envelope every anti-entropy lane encodes:
/// positional array layout, so membership pages and resource pages share
/// the exact byte shape (golden vectors pin both).
#[derive(Encode, Decode)]
#[cbor(array)]
struct PageEnvelopeWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  items: Vec<ByteVec>,
  #[n(2)]
  cursor: Option<ByteVec>,
}

/// The page shape policy (single source): capacity is a typed resource
/// exhaustion and an empty page cannot carry a continuation cursor.
pub(crate) fn check_page_shape(
  count: usize, max: usize, cursor: &Option<Vec<u8>>, context: &'static str,
) -> Result<()> {
  if count > max {
    return Err(Error::resource_exhausted(context));
  }
  if count == 0 && cursor.is_some() {
    return Err(Error::invalid_input(context));
  }
  Ok(())
}

/// Encodes one bounded page envelope over pre-encoded items.
///
/// The sync size ladder (three bounds, each layer its own job):
///
/// 1. **64 KiB encode bound** ([`crate::protocol::CONTROL_CBOR_LIMITS`]): a
///    page envelope (and every other control body) must encode inside it. The
///    lane `emit_page_ctx` functions enforce this at emission with a bounded
///    halving ladder over the page capacity, so a page of fat records splits
///    instead of failing the tick.
/// 2. **32 KiB chunk bound** ([`crate::packet::MAX_CHUNK_BYTES`]): the pump
///    forwards each body chunk as one frame. The sender splits an encoded
///    payload at this bound (`crate::sync_common::chunk_payload`); the receiver
///    reassembles the chunk stream.
/// 3. **256 KiB receive bound** ([`crate::sync_common::MAX_SYNC_BYTES`] with
///    [`crate::sync_common::MAX_SYNC_CHUNKS`]): the receiver-side defense for
///    one drained sync body.
pub(crate) fn encode_page(
  schema: &str, items: &[Vec<u8>], cursor: Option<&[u8]>,
) -> Result<Vec<u8>> {
  crate::protocol::encode_canonical(
    &PageEnvelopeWire {
      schema: schema.to_owned(),
      items: items
        .iter()
        .map(|item| ByteVec::from(item.clone()))
        .collect(),
      cursor: cursor.map(|value| ByteVec::from(value.to_vec())),
    },
    crate::protocol::CONTROL_CBOR_LIMITS,
  )
}

/// The decoded content of one page envelope: pre-decoded items plus the
/// continuation cursor.
type PageEnvelope = (Vec<Vec<u8>>, Option<Vec<u8>>);

/// Decodes one bounded page envelope, rejecting unknown schemas,
/// non-canonical encodings, and over-capacity item lists (fail closed).
pub(crate) fn decode_page(
  bytes: &[u8], schema: &str, max_items: usize, context: &'static str,
) -> Result<PageEnvelope> {
  let wire: PageEnvelopeWire =
    crate::protocol::decode_canonical_strict(bytes, crate::protocol::CONTROL_CBOR_LIMITS, context)?;
  if wire.schema != schema {
    return Err(Error::invalid_input(context));
  }
  check_page_shape(wire.items.len(), max_items, &None, context)?;
  Ok((
    wire
      .items
      .iter()
      .map(|item| {
        let bytes: &[u8] = item.as_ref();
        bytes.to_vec()
      })
      .collect(),
    wire.cursor.map(|value| {
      let bytes: &[u8] = value.as_ref();
      bytes.to_vec()
    }),
  ))
}

/// One decoded page of items plus the continuation cursor (the last
/// processed raw key; pages resume strictly after it).
pub(crate) struct Paged<T> {
  pub(crate) items: Vec<T>,
  pub(crate) next: Option<Vec<u8>>,
}

/// Collects up to `limit` items past `cursor` from one positioned
/// snapshot scan, decoding and filtering each raw entry through `select`
/// (`Ok(None)` skips the entry without counting it toward the page). The
/// scan starts at [`crate::provider::StoreSnapshot::scan_from`]'s
/// strictly-greater positioning, so a page never replays the namespace
/// head, and the end-of-stream probe is one further step on the
/// already-positioned scan.
pub(crate) async fn scan_paged<T>(
  snapshot: &(dyn crate::provider::StoreSnapshot + '_), namespace: &crate::StoreNamespace,
  prefix: &[u8], cursor: Option<&[u8]>, limit: usize,
  mut select: impl FnMut(&[u8], &[u8]) -> Result<Option<T>>,
) -> Result<Paged<T>> {
  let mut scan = snapshot.scan_from(namespace, prefix, cursor).await?;
  let mut items = Vec::new();
  while let Some(entry) = scan.next().await? {
    let key = entry.key().as_bytes().to_vec();
    if let Some(item) = select(&key, entry.value().as_bytes())? {
      items.push(item);
      if items.len() >= limit {
        // A page at capacity continues only when another raw entry
        // follows; peeking one entry keeps the stream honest about its
        // end. The peeked entry is re-read by the next page because the
        // cursor resumes strictly after the last *processed* key.
        let has_more = scan.next().await?.is_some();
        return Ok(Paged {
          items,
          next: has_more.then_some(key),
        });
      }
    }
  }
  Ok(Paged { items, next: None })
}

/// The synchronous twin of [`scan_paged`] for in-memory ordered entry
/// tables: identical cursor and end-of-stream rules, positioned by one
/// `partition_point` over the sorted keys instead of a per-entry skip.
pub(crate) fn page_keys<T>(
  entries: Vec<(Vec<u8>, T)>, cursor: Option<&[u8]>, limit: usize,
) -> Paged<T> {
  let start = cursor.map_or(0, |cursor| {
    entries.partition_point(|(key, _)| key.as_slice() <= cursor)
  });
  let mut items = Vec::new();
  let mut entries = entries.into_iter().skip(start);
  for (key, item) in entries.by_ref() {
    items.push(item);
    if items.len() >= limit {
      let has_more = entries.next().is_some();
      return Paged {
        items,
        next: has_more.then_some(key),
      };
    }
  }
  Paged { items, next: None }
}

/// The bound for public paged views (members, topology, trust): one
/// named constant so the facade's page clamps cannot drift apart.
pub(crate) const MAX_VIEW_PAGE_ITEMS: usize = 64;

/// Emits one wire-deliverable page through the size ladder (single
/// source for the membership and resource lanes): emit at the candidate
/// capacity, halve until the lane's `fits` predicate accepts the page
/// (a fat record set can overflow the control-body bound), and fail
/// closed when even a single-record page does not fit — a record is
/// bounded far below the control bound, so reaching that arm means a
/// bound regressed elsewhere.
pub(crate) async fn emit_with_size_ladder<T, F, Fut>(
  mut limit: usize, context: &'static str, mut emit: F, fits: impl Fn(&T) -> Result<bool>,
) -> Result<T>
where
  F: FnMut(usize) -> Fut,
  Fut: std::future::Future<Output = Result<T>>, {
  loop {
    let page = emit(limit).await?;
    if fits(&page)? {
      return Ok(page);
    }
    if limit == 1 {
      return Err(Error::resource_exhausted(context));
    }
    limit /= 2;
  }
}

#[cfg(test)]
mod tests {
  use std::{
    collections::VecDeque,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
  };

  use super::{Paged, page_keys, scan_paged};
  use crate::{
    BoxFuture, CommitOutcome, QualifiedTag, Result, StoreEntry, StoreExpectation, StoreKey,
    StoreNamespace, StoreOperation, StoreRequirements, StoreRevision, StoreTransaction, StoreValue,
    TransactionId,
    provider::{StorageFactory, StoreScan, StoreSnapshot},
  };

  fn paging_namespace() -> StoreNamespace {
    StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/test/paging").unwrap())
  }

  #[derive(Debug)]
  struct VecScan {
    entries: VecDeque<StoreEntry>,
  }

  impl VecScan {
    fn new(count: usize) -> Self {
      let namespace = paging_namespace();
      let entries = (0..count)
        .map(|index| {
          StoreEntry::new(
            namespace.clone(),
            StoreKey::new(format!("{index:03}").into_bytes().into()),
            StoreValue::new(format!("value-{index:03}").into_bytes().into()),
          )
        })
        .collect();
      Self { entries }
    }
  }

  impl StoreScan for VecScan {
    fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
      Box::pin(async move { Ok(self.entries.pop_front()) })
    }
  }

  /// The snapshot twin of [`VecScan`]: every scan replays the whole
  /// entry list, so cursor skipping happens in the SPI's default
  /// `scan_from` path exactly as it would for a non-positioning backend.
  #[derive(Debug)]
  struct VecSnapshot {
    revision: StoreRevision,
    entries: VecDeque<StoreEntry>,
  }

  impl VecSnapshot {
    fn new(count: usize) -> Self {
      let scan = VecScan::new(count);
      Self {
        revision: StoreRevision::new(Arc::from([1_u8])).unwrap(),
        entries: scan.entries,
      }
    }
  }

  impl StoreSnapshot for VecSnapshot {
    fn revision(&self) -> &StoreRevision {
      &self.revision
    }

    fn get<'a>(
      &'a self, _namespace: &'a StoreNamespace, _key: &'a StoreKey,
    ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
      Box::pin(async move { Ok(None) })
    }

    fn scan<'a>(
      &'a self, _namespace: &'a StoreNamespace, _prefix: &'a [u8],
    ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
      Box::pin(async move {
        Ok(Box::new(VecScan {
          entries: self.entries.clone(),
        }) as Box<dyn StoreScan>)
      })
    }
  }

  fn bytes(paged: &Paged<Vec<u8>>) -> &[u8] {
    paged.items.first().map(Vec::as_slice).unwrap_or(&[])
  }

  /// The end-of-stream rule: a page that ends exactly at the store's last
  /// entry yields no continuation cursor, so no trailing empty page.
  #[tokio::test]
  async fn exact_end_page_yields_no_cursor() {
    let snapshot = VecSnapshot::new(4);
    let paged: Paged<Vec<u8>> = scan_paged(
      &snapshot,
      &paging_namespace(),
      &[],
      None,
      2,
      |_key, value| Ok(Some(value.to_vec())),
    )
    .await
    .unwrap();
    assert_eq!(paged.items.len(), 2);
    let cursor = paged.next.expect("two entries remain");
    // The second page consumes the final two entries exactly.
    let paged: Paged<Vec<u8>> = scan_paged(
      &snapshot,
      &paging_namespace(),
      &[],
      Some(&cursor),
      2,
      |_key, value| Ok(Some(value.to_vec())),
    )
    .await
    .unwrap();
    assert_eq!(paged.items.len(), 2);
    assert_eq!(bytes(&paged), b"value-002");
    assert!(paged.next.is_none(), "no trailing empty page");
  }

  /// Filtered entries never count toward the page and never leak into the
  /// continuation cursor's item set.
  #[tokio::test]
  async fn filtered_entries_do_not_fill_the_page() {
    let snapshot = VecSnapshot::new(5);
    let paged: Paged<Vec<u8>> = scan_paged(
      &snapshot,
      &paging_namespace(),
      &[],
      None,
      2,
      |_key, value| {
        if value == b"value-001" || value == b"value-003" {
          return Ok(None);
        }
        Ok(Some(value.to_vec()))
      },
    )
    .await
    .unwrap();
    assert_eq!(
      paged.items,
      vec![b"value-000".to_vec(), b"value-002".to_vec()]
    );
    assert!(paged.next.is_some(), "more raw entries follow the page");
  }

  /// The synchronous twin follows the identical end-of-stream rule.
  #[test]
  fn page_keys_matches_the_scan_rule() {
    let entries = || {
      (0..3)
        .map(|index| (format!("{index:03}").into_bytes(), index))
        .collect::<Vec<_>>()
    };
    let first = page_keys(entries(), None, 3);
    assert_eq!(first.items.len(), 3);
    assert!(
      first.next.is_none(),
      "exact-end in-memory page ends the stream"
    );
    let second = page_keys(entries(), None, 2);
    assert_eq!(second.items.len(), 2);
    let cursor = second.next.expect("one entry remains");
    let third = page_keys(entries(), Some(&cursor), 2);
    assert_eq!(third.items, vec![2]);
    assert!(third.next.is_none());
  }

  /// A paging snapshot that counts every `next()` step its scans take:
  /// the complexity harness for the positioned-paging contract.
  #[derive(Debug)]
  struct CountingSnapshot {
    inner: Box<dyn StoreSnapshot>,
    steps: Arc<AtomicUsize>,
  }

  #[derive(Debug)]
  struct CountingScan<'a> {
    inner: Box<dyn StoreScan + 'a>,
    steps: Arc<AtomicUsize>,
  }

  impl StoreScan for CountingScan<'_> {
    fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
      Box::pin(async move {
        self.steps.fetch_add(1, Ordering::SeqCst);
        self.inner.next().await
      })
    }
  }

  impl StoreSnapshot for CountingSnapshot {
    fn revision(&self) -> &StoreRevision {
      self.inner.revision()
    }

    fn get<'a>(
      &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
    ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
      self.inner.get(namespace, key)
    }

    fn scan<'a>(
      &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
    ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
      self.inner.scan(namespace, prefix)
    }

    fn scan_from<'a>(
      &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8], from: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
      Box::pin(async move {
        let inner = self.inner.scan_from(namespace, prefix, from).await?;
        Ok(Box::new(CountingScan {
          inner,
          steps: Arc::clone(&self.steps),
        }) as Box<dyn StoreScan + 'a>)
      })
    }
  }

  /// The positioned-paging complexity contract: paging N entries at page
  /// size L over the reference backend's native positioned scans performs
  /// ~N + pages `next()` steps. The replay-per-page loop this guards
  /// against re-reads the namespace head every page (~N²/2L ≈ 50_600
  /// steps for N = 1000, L = 10).
  #[tokio::test]
  async fn positioned_paging_steps_once_per_entry_plus_one_probe_per_page() {
    const ENTRY_COUNT: usize = 1000;
    const PAGE_LIMIT: usize = 10;

    let storage = crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    )
    .open(StoreRequirements::metadata())
    .await
    .unwrap();
    let namespace = paging_namespace();
    let initial = storage.snapshot().await.unwrap();
    let operations = (0..ENTRY_COUNT)
      .map(|index| StoreOperation::Put {
        namespace: namespace.clone(),
        key: StoreKey::new(format!("{index:020}").into_bytes().into()),
        expected: StoreExpectation::Absent,
        value: StoreValue::new(format!("value-{index:020}").into_bytes().into()),
      })
      .collect();
    let transaction = StoreTransaction::new(
      TransactionId::parse(&format!("txn_{:021}", 1)).unwrap(),
      initial.revision().clone(),
      operations,
    )
    .unwrap();
    assert!(matches!(
      storage.commit(transaction).await.unwrap(),
      CommitOutcome::Committed(_)
    ));

    let steps = Arc::new(AtomicUsize::new(0));
    let counting = CountingSnapshot {
      inner: storage.snapshot().await.unwrap(),
      steps: Arc::clone(&steps),
    };
    let mut cursor: Option<Vec<u8>> = None;
    let mut pages = 0_usize;
    let mut items = 0_usize;
    loop {
      let paged: Paged<Vec<u8>> = scan_paged(
        &counting,
        &namespace,
        &[],
        cursor.as_deref(),
        PAGE_LIMIT,
        |_key, value| Ok(Some(value.to_vec())),
      )
      .await
      .unwrap();
      items += paged.items.len();
      pages += 1;
      let Some(next) = paged.next else {
        break;
      };
      cursor = Some(next);
    }
    assert_eq!(items, ENTRY_COUNT);
    assert_eq!(pages, ENTRY_COUNT / PAGE_LIMIT);

    // Every entry is read once plus one probe (and one final terminator)
    // per page; the bound absorbs the O(1)-per-page overhead without
    // ever admitting a per-page replay of the namespace head.
    let bound = ENTRY_COUNT + pages * (PAGE_LIMIT + 2);
    let steps = steps.load(Ordering::SeqCst);
    assert!(
      steps <= bound,
      "positioned paging took {steps} steps, bound is {bound}"
    );
  }
}
