//! Keyset-cursor paging over unsigned-byte ordered entries (single
//! source): membership pages, resource pages, candidate reads, and the
//! public paged views share one loop and one end-of-stream rule — a page
//! at capacity yields a continuation cursor only when at least one
//! further raw entry provably exists, so no trailing empty page
//! terminates the stream.

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

/// Collects up to `limit` items past `cursor` from an ordered snapshot
/// scan, decoding and filtering each raw entry through `select`
/// (`Ok(None)` skips the entry without counting it toward the page).
pub(crate) async fn scan_paged<T>(
  scan: &mut (dyn crate::provider::StoreScan + '_), cursor: Option<&[u8]>, limit: usize,
  mut select: impl FnMut(&[u8], &[u8]) -> Result<Option<T>>,
) -> Result<Paged<T>> {
  let mut items = Vec::new();
  while let Some(entry) = scan.next().await? {
    let key = entry.key().as_bytes();
    if let Some(cursor) = cursor
      && key <= cursor
    {
      continue;
    }
    let key = key.to_vec();
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
          next: if has_more { Some(key) } else { None },
        });
      }
    }
  }
  Ok(Paged { items, next: None })
}

/// The synchronous twin of [`scan_paged`] for in-memory ordered tables
/// (the session table): identical cursor and end-of-stream rules over
/// already-decoded items.
pub(crate) fn page_keys<T>(
  entries: impl Iterator<Item = (Vec<u8>, T)>, cursor: Option<&[u8]>, limit: usize,
) -> Paged<T> {
  let mut items = Vec::new();
  let mut entries = entries;
  for (key, item) in entries.by_ref() {
    if let Some(cursor) = cursor
      && key.as_slice() <= cursor
    {
      continue;
    }
    items.push(item);
    if items.len() >= limit {
      let has_more = entries.next().is_some();
      return Paged {
        items,
        next: if has_more { Some(key) } else { None },
      };
    }
  }
  Paged { items, next: None }
}

/// The bound for public paged views (members, topology, trust): one
/// named constant so the facade's page clamps cannot drift apart.
pub(crate) const MAX_VIEW_PAGE_ITEMS: usize = 64;

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;

  use super::{Paged, page_keys, scan_paged};
  use crate::{
    BoxFuture, QualifiedTag, Result, StoreEntry, StoreKey, StoreNamespace, StoreValue,
    provider::StoreScan,
  };

  #[derive(Debug)]
  struct VecScan {
    entries: VecDeque<StoreEntry>,
  }

  impl VecScan {
    fn new(count: usize) -> Self {
      let namespace =
        StoreNamespace::new(QualifiedTag::parse("radiata.woooo.tech/test/paging").unwrap());
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

  fn bytes(paged: &Paged<Vec<u8>>) -> &[u8] {
    paged.items.first().map(Vec::as_slice).unwrap_or(&[])
  }

  /// The end-of-stream rule: a page that ends exactly at the store's last
  /// entry yields no continuation cursor, so no trailing empty page.
  #[tokio::test]
  async fn exact_end_page_yields_no_cursor() {
    let mut scan = VecScan::new(4);
    let paged: Paged<Vec<u8>> =
      scan_paged(&mut scan, None, 2, |_key, value| Ok(Some(value.to_vec())))
        .await
        .unwrap();
    assert_eq!(paged.items.len(), 2);
    let cursor = paged.next.expect("two entries remain");
    // The second page consumes the final two entries exactly.
    let mut scan = VecScan::new(4);
    let paged: Paged<Vec<u8>> = scan_paged(&mut scan, Some(&cursor), 2, |_key, value| {
      Ok(Some(value.to_vec()))
    })
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
    let mut scan = VecScan::new(5);
    let paged: Paged<Vec<u8>> = scan_paged(&mut scan, None, 2, |_key, value| {
      if value == b"value-001" || value == b"value-003" {
        return Ok(None);
      }
      Ok(Some(value.to_vec()))
    })
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
        .into_iter()
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
}
