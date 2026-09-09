//! Selector-driven paged resource selection.
//!
//! Selection evaluates a bounded [`Selector`] against each winner's full
//! label space — the reserved type and URI labels plus the custom labels —
//! and streams the matching catalog in canonical name order through the
//! store's ordered scans. Pages are bounded and cursor-continued, so a
//! population-sized catalog never materializes as one allocation. A record
//! whose current winner is a signed removal reads as absent: removal
//! evidence stays internal.

use std::sync::Arc;

use super::{RESERVED_TYPE_LABEL_KEY, RESERVED_URI_LABEL_KEY, ResourceRecordV1};
use crate::{
  QualifiedTag, ResourceLabels, ResourceVersion, Result, Selector, storage::MetadataStore,
};

/// Whether `record`'s full label space satisfies `selector`: the reserved
/// type/URI labels resolve to the record's reserved fields and every other
/// key resolves against the custom labels.
pub(crate) fn record_matches(record: &ResourceRecordV1, selector: &Selector) -> bool {
  fn lookup<'a>(record: &'a ResourceRecordV1) -> impl Fn(&QualifiedTag) -> Option<&'a str> {
    move |tag| {
      if tag.as_str() == RESERVED_TYPE_LABEL_KEY {
        Some(record.resource_type().as_str())
      } else if tag.as_str() == RESERVED_URI_LABEL_KEY {
        Some(record.resource_uri().as_str())
      } else {
        crate::LabelKey::from_label_tag(tag)
          .and_then(|key| record.labels().get(&key))
          .map(|value| value.as_str())
      }
    }
  }
  selector.matches_with(lookup(record))
}

/// The public view of one live winner record.
pub(crate) fn resource_view(record: &ResourceRecordV1) -> crate::ResourceView {
  crate::ResourceView::new(
    record.name().clone(),
    ResourceLabels::from_record(record),
    ResourceVersion::from_record(record),
  )
}

/// Pages the live resource winners matching `selector` in canonical name
/// order: deterministic unsigned-byte key order, bounded
/// pages, cursor continuation, and no whole-population output.
pub(crate) async fn select_page_ctx(
  store: &MetadataStore, selector: &Selector, cursor: Option<&crate::PageCursor>, limit: usize,
) -> Result<crate::ResourcePage> {
  let limit = limit.clamp(1, crate::paging::MAX_VIEW_PAGE_ITEMS);
  let namespace = super::store::namespace()?;
  let snapshot = store.snapshot().await?;
  let paged = crate::paging::scan_paged(
    snapshot.as_ref(),
    &namespace,
    &[],
    cursor.map(|cursor| cursor.as_bytes()),
    limit,
    |_key, bytes| {
      let Ok(record) = ResourceRecordV1::decode(bytes) else {
        return Ok(None);
      };
      if record.removed() || !record_matches(&record, selector) {
        return Ok(None);
      }
      Ok(Some(resource_view(&record)))
    },
  )
  .await?;
  let next = paged.next.map(|key| crate::PageCursor::new(Arc::from(key)));
  Ok(crate::ResourcePage::new(paged.items, next))
}

#[cfg(test)]
mod tests {
  use std::{collections::BTreeSet, sync::Arc, time::Duration};

  use ed25519_dalek::SigningKey;

  use super::{super::store, select_page_ctx};
  use crate::{
    LabelKey, LabelSet, LabelValue, NodeId, ResourceName, ResourceUri, Selector,
    api::SystemEntropy, provider::StorageFactory, storage::MetadataStore,
  };

  const SEED: [u8; 32] = [41; 32];
  const OTHER_SEED: [u8; 32] = [42; 32];

  fn writer() -> NodeId {
    NodeId::parse("node_000000000000000000041").unwrap()
  }

  fn other_writer() -> NodeId {
    NodeId::parse("node_000000000000000000042").unwrap()
  }

  fn name(seed: u8) -> ResourceName {
    ResourceName::parse(&format!("radiata.woooo.tech/resources/sel-{seed:03}")).unwrap()
  }

  /// One signed record with a distinguishable reserved type, URI, and
  /// custom label per seed.
  #[allow(clippy::too_many_arguments)]
  fn record(
    seed: u8, timestamp_millis: u64, writer: &NodeId, removal_rank: u64, removed: bool,
    key_seed: [u8; 32],
  ) -> super::ResourceRecordV1 {
    let labels = LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/lane").unwrap(),
        LabelValue::parse(if seed.is_multiple_of(2) {
          "even"
        } else {
          "odd"
        })
        .unwrap(),
      )
      .unwrap();
    super::ResourceRecordV1::sign(
      name(seed),
      LabelValue::parse(if seed.is_multiple_of(2) {
        "document"
      } else {
        "blob"
      })
      .unwrap(),
      ResourceUri::parse(&format!("file:///sel/{seed:03}")).unwrap(),
      labels,
      timestamp_millis,
      writer.clone(),
      removal_rank,
      removed,
      &SigningKey::from_bytes(&key_seed),
    )
    .unwrap()
  }

  async fn open_store() -> MetadataStore {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap()
  }

  async fn install(store: &MetadataStore, record: &super::ResourceRecordV1) {
    match store::commit_record_ctx(store, &SystemEntropy, record)
      .await
      .unwrap()
    {
      store::ResourceCommitOutcome::Installed(_) | store::ResourceCommitOutcome::Superseded(_) => {}
      other => panic!("seed record must commit deterministically, got {other:?}"),
    }
  }

  /// Trusts `node` with the public key of `key_seed` so synced records
  /// verify (the membership descriptor is the trust anchor).
  async fn trust(store: &MetadataStore, node: &NodeId, key_seed: [u8; 32]) {
    let public_key =
      crate::PublicKey::from_bytes(SigningKey::from_bytes(&key_seed).verifying_key().to_bytes());
    let descriptor = crate::membership::NodeDescriptorV1::new(
      node.clone(),
      public_key,
      vec![crate::Endpoint::parse("wss://sel:9000").unwrap()],
      1,
      false,
      1,
    );
    crate::membership::store::store_descriptor_ctx(store, &SystemEntropy, &descriptor)
      .await
      .unwrap();
  }

  /// Every selected name across the full cursor walk.
  async fn select_all(store: &MetadataStore, selector: &Selector, limit: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = None;
    loop {
      let page = select_page_ctx(store, selector, cursor.as_ref(), limit)
        .await
        .unwrap();
      names.extend(
        page
          .items()
          .iter()
          .map(|view| view.name().as_str().to_owned()),
      );
      match page.next() {
        Some(next) => cursor = Some(next.clone()),
        None => break,
      }
    }
    names
  }

  /// Selection evaluates the reserved type/URI labels and the custom
  /// labels through every grammar operator against stored records.
  #[tokio::test]
  async fn selection_matches_reserved_and_custom_labels() {
    let store = open_store().await;
    for seed in 1..=4_u8 {
      install(&store, &record(seed, 1_000, &writer(), 0, false, SEED)).await;
    }

    let cases: [(&str, &[u8]); 7] = [
      // Reserved type equality / inequality / set / non-set.
      ("radiata.woooo.tech/resources/type=document", &[2, 4]),
      ("radiata.woooo.tech/resources/type!=document", &[1, 3]),
      (
        "radiata.woooo.tech/resources/type in (blob,document)",
        &[1, 2, 3, 4],
      ),
      ("radiata.woooo.tech/resources/type notin (blob)", &[2, 4]),
      // Reserved URI equality and non-existence of a custom key.
      ("radiata.woooo.tech/resources/uri=file:///sel/001", &[1]),
      // Custom label operators, including absence semantics.
      (
        "example.org/labels/lane=odd !radiata.woooo.tech/labels/zone",
        &[1, 3],
      ),
      ("example.org/labels/lane notin (odd)", &[2, 4]),
    ];
    for (selector_text, expected_seeds) in cases {
      let selector = Selector::parse(selector_text).unwrap();
      let selected = select_all(&store, &selector, 64).await;
      let expected: Vec<String> = expected_seeds
        .iter()
        .map(|seed| name(*seed).as_str().to_owned())
        .collect();
      assert_eq!(selected, expected, "selector {selector_text:?}");
    }
  }

  /// Pages are bounded and cursor-complete: no page exceeds the limit,
  /// the limit clamps to the public view bound, and the walk covers the
  /// catalog exactly once in canonical name order without a
  /// whole-population output.
  #[tokio::test]
  async fn selection_pages_are_bounded_and_cursor_complete() {
    let store = open_store().await;
    for seed in 1..=70_u8 {
      install(&store, &record(seed, 1_000, &writer(), 0, false, SEED)).await;
    }
    let all = Selector::parse("radiata.woooo.tech/resources/type").unwrap();

    // Requesting more than the view bound clamps to it: one 64-item page
    // plus one 6-item page.
    let first = select_page_ctx(&store, &all, None, 1_000).await.unwrap();
    assert_eq!(first.items().len(), crate::paging::MAX_VIEW_PAGE_ITEMS);
    let second = select_page_ctx(&store, &all, first.next(), 1_000)
      .await
      .unwrap();
    assert_eq!(second.items().len(), 6);
    assert!(second.next().is_none());

    // A limit-3 walk covers the catalog exactly once, in canonical order.
    let walked = select_all(&store, &all, 3).await;
    assert_eq!(walked.len(), 70);
    let unique: BTreeSet<&String> = walked.iter().collect();
    assert_eq!(unique.len(), 70, "no page repeats or skips an entry");
    let mut sorted = walked.clone();
    sorted.sort();
    assert_eq!(walked, sorted, "selection order is canonical name order");
  }

  /// A winner that is a signed removal reads as absent; a losing removal
  /// never hides the live winner.
  #[tokio::test]
  async fn removed_winners_read_as_absent() {
    let store = open_store().await;
    install(&store, &record(1, 1_000, &writer(), 0, false, SEED)).await;
    // A removal with a greater tuple wins and hides the resource.
    install(&store, &record(1, 2_000, &writer(), 1, true, SEED)).await;
    // A removal with a losing tuple leaves the live record observable.
    install(&store, &record(2, 1_000, &writer(), 0, false, SEED)).await;
    install(&store, &record(2, 500, &writer(), 1, true, SEED)).await;

    let all = Selector::parse("radiata.woooo.tech/resources/type").unwrap();
    let walked = select_all(&store, &all, 64).await;
    assert_eq!(walked, [name(2).as_str().to_owned()]);
  }

  /// After concurrent label writes converge through ordinary pages, both
  /// members return the same deterministically ordered names for every
  /// selector; neither side's stale local observation is authoritative.
  #[tokio::test]
  async fn converged_members_return_identical_ordered_selections() {
    let store_a = open_store().await;
    let store_b = open_store().await;
    trust(&store_a, &writer(), SEED).await;
    trust(&store_a, &other_writer(), OTHER_SEED).await;
    trust(&store_b, &writer(), SEED).await;
    trust(&store_b, &other_writer(), OTHER_SEED).await;

    // Concurrent writers publish overlapping names with competing tuples.
    for seed in 1..=6_u8 {
      install(&store_a, &record(seed, 1_000, &writer(), 0, false, SEED)).await;
      install(
        &store_b,
        &record(seed, 2_000, &other_writer(), 0, false, OTHER_SEED),
      )
      .await;
    }

    // Converge through the same emit/apply path the anti-entropy driver
    // uses, until neither side applies any change.
    loop {
      let mut applied = 0;
      for (emitter, receiver) in [(&store_a, &store_b), (&store_b, &store_a)] {
        let mut cursor: Option<Vec<u8>> = None;
        loop {
          let page = super::super::page::sync::emit_page_ctx(
            emitter,
            cursor.as_deref(),
            super::super::page::DEFAULT_RESOURCE_PAGE_LIMIT,
          )
          .await
          .unwrap();
          let done = page.cursor().is_none();
          cursor = page.cursor().map(|value| value.to_vec());
          applied += super::super::page::sync::apply_page_ctx(receiver, &SystemEntropy, &page)
            .await
            .unwrap();
          if done {
            break;
          }
        }
      }
      if applied == 0 {
        break;
      }
    }

    for (selector_text, expected_count) in [
      ("radiata.woooo.tech/resources/type", 6),
      ("radiata.woooo.tech/resources/type=document", 3),
      ("example.org/labels/lane in (even,odd)", 6),
      (
        "example.org/labels/lane=odd !radiata.woooo.tech/labels/zone",
        3,
      ),
      ("radiata.woooo.tech/resources/uri!=file:///sel/003", 5),
    ] {
      let selector = Selector::parse(selector_text).unwrap();
      let names_a = select_all(&store_a, &selector, 2).await;
      let names_b = select_all(&store_b, &selector, 3).await;
      assert_eq!(
        names_a, names_b,
        "selector {selector_text:?} must converge to one ordered answer"
      );
      assert_eq!(names_a.len(), expected_count, "selector {selector_text:?}");
      let mut sorted = names_a.clone();
      sorted.sort();
      assert_eq!(names_a, sorted, "selector {selector_text:?} order");
    }
  }
}
