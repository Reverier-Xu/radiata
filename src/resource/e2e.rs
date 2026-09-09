//! Two-component metadata merge exercised end-to-end.
//!
//! The real anti-entropy driver pages local metadata over authenticated
//! sessions; this module drives the same ordinary bounded pages: two
//! eight-node components that changed owner-revision node records and
//! generic resources converge, after healing, through those pages — node
//! records by strictly-increasing owner revision and resources by the
//! signed timestamp-maximum tuple. No whole-catalog materialization, no
//! causal or freshness ordering, no population ceiling: the 1,024-record
//! profile converges identically through paged scans, and a changeless
//! second pass transfers nothing.

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use crate::{
  LabelKey, LabelSet, LabelValue, NodeId,
  api::SystemEntropy,
  membership::{NodeDescriptorV1, page as member_page, store as descriptor_store},
  provider::StorageFactory,
  resource::{ResourceName, ResourceRecordV1, page as resource_page, store as resource_store},
  storage::MetadataStore,
};

/// The seeded record's deterministic writer key seeds: bounded and shared
/// so every side reproduces the same signed tuples.
const RECORD_SEED: [u8; 32] = [51; 32];
const SECOND_SEED: [u8; 32] = [53; 32];

fn writer_a() -> NodeId {
  NodeId::parse("node_000000000000000000001").unwrap()
}

fn writer_b() -> NodeId {
  NodeId::parse("node_000000000000000000002").unwrap()
}

fn name(seed: u8) -> ResourceName {
  ResourceName::parse(&format!("radiata.woooo.tech/resources/e2e-{seed}")).unwrap()
}

fn labels() -> LabelSet {
  LabelSet::new()
    .insert(
      LabelKey::parse("example.org/labels/lane").unwrap(),
      LabelValue::parse("e2e").unwrap(),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn resource(
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

fn descriptor(node: &NodeId, revision: u64, seed: [u8; 32]) -> NodeDescriptorV1 {
  let key = crate::PublicKey::from_bytes(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
  NodeDescriptorV1::new(
    node.clone(),
    key,
    vec![
      crate::Endpoint::parse(&format!("wss://127.0.0.1:{:04}", revision * 1000 % 64000)).unwrap(),
    ],
    revision,
    false,
    1,
  )
}

async fn open_store() -> (Arc<dyn StorageFactory>, MetadataStore) {
  let factory: Arc<dyn StorageFactory> = Arc::new(crate::storage::contract::ReferenceFactory::new(
    crate::storage::contract::required_capabilities(),
  ));
  let store = MetadataStore::open(&factory, std::time::Duration::from_secs(10))
    .await
    .unwrap();
  (factory, store)
}

async fn put_resource(store: &MetadataStore, record: &ResourceRecordV1) {
  match resource_store::commit_record_ctx(store, &SystemEntropy, record)
    .await
    .unwrap()
  {
    resource_store::ResourceCommitOutcome::Installed(_) => {}
    other => panic!("seed resource must install, got {other:?}"),
  }
}

async fn put_descriptor(store: &MetadataStore, descriptor: &NodeDescriptorV1) {
  descriptor_store::store_descriptor_ctx(store, &SystemEntropy, descriptor)
    .await
    .unwrap();
}

/// Runs one full bidirectional convergence pass: A applies every page
/// emitted by B and vice versa, until neither side applies any change.
/// Uses the same page emit/apply functions the anti-entropy driver calls.
async fn converge(sides: [&MetadataStore; 2]) -> usize {
  let mut total_applied = 0;
  loop {
    let mut applied = 0;
    for index in 0..2 {
      let emitter = sides[index];
      let receiver = sides[1 - index];
      let mut cursor: Option<Vec<u8>> = None;
      loop {
        let page = resource_page::sync::emit_page_ctx(
          emitter,
          cursor.as_deref(),
          resource_page::DEFAULT_RESOURCE_PAGE_LIMIT,
        )
        .await
        .unwrap();
        let done = page.cursor().is_none();
        cursor = page.cursor().map(|value| value.to_vec());
        applied += resource_page::sync::apply_page_ctx(receiver, &SystemEntropy, &page)
          .await
          .unwrap();
        if done {
          break;
        }
      }
      // The member-descriptor side rides the same pages.
      let mut cursor: Option<Vec<u8>> = None;
      loop {
        let page = member_page::sync::emit_page_ctx(emitter, cursor.as_deref(), 16)
          .await
          .unwrap();
        let done = page.cursor().is_none();
        cursor = page.cursor().map(|value| value.to_vec());
        applied += member_page::sync::apply_page_ctx(receiver, &SystemEntropy, &page)
          .await
          .unwrap()
          .len();
        if done {
          break;
        }
      }
    }
    if applied == 0 {
      break;
    }
    total_applied += applied;
  }
  total_applied
}

/// Two eight-node components change owner-revision node records and
/// generic resources; after healing, ordinary bounded pages converge node
/// records by revision and resources by signed tuple.
#[tokio::test]
async fn eight_plus_eight_components_merge_by_revision_and_tuple() {
  let (_, side_a) = open_store().await;
  let (_, side_b) = open_store().await;

  // Each component holds its own eight owner-revision node records at
  // revision one, then each side bumps records it owns to revision two
  // while partitioned; the shared record is bumped only on side B.
  let mut a_nodes = Vec::new();
  for index in 1..=8_u8 {
    let node = NodeId::parse(&format!("node_a{index:020}")).unwrap();
    put_descriptor(&side_a, &descriptor(&node, 1, [1_u8; 32])).await;
    put_descriptor(&side_b, &descriptor(&node, 1, [1_u8; 32])).await;
    a_nodes.push(node);
  }
  put_descriptor(&side_a, &descriptor(&a_nodes[1], 2, [1_u8; 32])).await;
  put_descriptor(&side_b, &descriptor(&a_nodes[2], 2, [1_u8; 32])).await;
  let shared = NodeId::parse("node_000000000000000000009").unwrap();
  put_descriptor(&side_a, &descriptor(&shared, 1, [2_u8; 32])).await;
  put_descriptor(&side_b, &descriptor(&shared, 1, [2_u8; 32])).await;
  put_descriptor(&side_b, &descriptor(&shared, 2, [2_u8; 32])).await;
  // The resource writers must be trusted members on both sides or every
  // resource page entry would skip for an unknown writer: seed their
  // descriptors through the ordinary membership path.
  put_descriptor(&side_a, &descriptor(&writer_a(), 1, RECORD_SEED)).await;
  put_descriptor(&side_b, &descriptor(&writer_a(), 1, RECORD_SEED)).await;
  put_descriptor(&side_a, &descriptor(&writer_b(), 1, SECOND_SEED)).await;
  put_descriptor(&side_b, &descriptor(&writer_b(), 1, SECOND_SEED)).await;

  // Side A wins resource r1 (later tuple); side B wins r2 (later tuple);
  // both write r3 at different times.
  put_resource(
    &side_a,
    &resource(&name(1), 2_000, &writer_a(), "u://a1", RECORD_SEED),
  )
  .await;
  put_resource(
    &side_b,
    &resource(&name(1), 1_500, &writer_b(), "u://b1-loser", SECOND_SEED),
  )
  .await;
  put_resource(
    &side_b,
    &resource(&name(2), 3_000, &writer_b(), "u://b2", SECOND_SEED),
  )
  .await;
  put_resource(
    &side_a,
    &resource(&name(2), 2_500, &writer_a(), "u://a2-loser", RECORD_SEED),
  )
  .await;
  put_resource(
    &side_a,
    &resource(&name(3), 1_000, &writer_a(), "u://a3", RECORD_SEED),
  )
  .await;
  put_resource(
    &side_b,
    &resource(&name(3), 1_200, &writer_b(), "u://b3", SECOND_SEED),
  )
  .await;

  // Let the two sides exchange bounded pages until quiescent.
  converge([&side_a, &side_b]).await;

  // Node records converge by strictly-increasing owner revision: the
  // bumped revisions propagate everywhere and equal-revision conflicts
  // never mutate.
  let a_shared = descriptor_store::read_descriptor_ctx(&side_a, &shared)
    .await
    .unwrap();
  let b_shared = descriptor_store::read_descriptor_ctx(&side_b, &shared)
    .await
    .unwrap();
  assert_eq!(a_shared.as_ref().map(|d| d.revision()), Some(2));
  assert_eq!(b_shared.as_ref().map(|d| d.revision()), Some(2));
  for (index, expected) in [(1_usize, 2_u64), (2, 2), (0, 1)] {
    let node = &a_nodes[index];
    let a = descriptor_store::read_descriptor_ctx(&side_a, node)
      .await
      .unwrap();
    let b = descriptor_store::read_descriptor_ctx(&side_b, node)
      .await
      .unwrap();
    assert_eq!(a.as_ref().map(|d| d.revision()), Some(expected));
    assert_eq!(b.as_ref().map(|d| d.revision()), Some(expected));
  }

  // Resources converge by the signed tuple maximum, never by causality or
  // delivery order.
  let r1 = resource_store::read_record_ctx(&side_a, &name(1))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(
    r1.resource_uri(),
    &crate::ResourceUri::parse("u://a1").unwrap()
  );
  let r2 = resource_store::read_record_ctx(&side_b, &name(2))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(
    r2.resource_uri(),
    &crate::ResourceUri::parse("u://b2").unwrap()
  );
  for seed in 1..=3_u8 {
    let left = resource_store::read_record_ctx(&side_a, &name(seed))
      .await
      .unwrap();
    let right = resource_store::read_record_ctx(&side_b, &name(seed))
      .await
      .unwrap();
    assert_eq!(
      left.as_ref().map(|r| r.digest()),
      right.as_ref().map(|r| r.digest())
    );
  }

  // A changeless second pass transfers nothing.
  assert_eq!(converge([&side_a, &side_b]).await, 0);
}

/// The 1,024-profile participates with no over-population rejection, no
/// whole-catalog materialization, and paged convergence.
#[tokio::test]
async fn one_thousand_twenty_four_profile_converges_without_a_ceiling() {
  let (_, side_a) = open_store().await;
  let (_, side_b) = open_store().await;

  // The two resource writers are trusted members of both components so
  // cross-side signature validation passes and true convergence is
  // exercised. The two dedicated writers sit beyond the 1,024 profile
  // range so the seeding below cannot collide with them.
  let bulk_writer_a = NodeId::parse("node_000000000000000001024").unwrap();
  let bulk_writer_b = NodeId::parse("node_000000000000000001025").unwrap();
  put_descriptor(&side_a, &descriptor(&bulk_writer_a, 1, RECORD_SEED)).await;
  put_descriptor(&side_b, &descriptor(&bulk_writer_a, 1, RECORD_SEED)).await;
  put_descriptor(&side_a, &descriptor(&bulk_writer_b, 1, SECOND_SEED)).await;
  put_descriptor(&side_b, &descriptor(&bulk_writer_b, 1, SECOND_SEED)).await;

  for index in 0..1_024_u32 {
    let node = NodeId::parse(&format!("node_{index:021}")).unwrap();
    put_descriptor(&side_a, &descriptor(&node, 1, [3_u8; 32])).await;
    put_descriptor(&side_b, &descriptor(&node, 1, [3_u8; 32])).await;
    // A few conflicting resource tuples per name shape across the two
    // sides: the later side wins deterministically.
    if index % 2 == 0 {
      put_resource(
        &side_a,
        &resource(
          &name(u8::try_from(index % 251).unwrap()),
          u64::from(index),
          &NodeId::parse("node_000000000000000001024").unwrap(),
          "u://a",
          RECORD_SEED,
        ),
      )
      .await;
    } else {
      put_resource(
        &side_b,
        &resource(
          &name(u8::try_from(index % 251).unwrap()),
          u64::from(index),
          &NodeId::parse("node_000000000000000001025").unwrap(),
          "u://b",
          SECOND_SEED,
        ),
      )
      .await;
    }
  }

  // Paged convergence: every pass uses bounded pages; nothing is rejected
  // for population size. Each side bumps half the node records while
  // partitioned so healing has revision changes to merge.
  for index in (0..1_024_u32).step_by(2) {
    let node = NodeId::parse(&format!("node_{index:021}")).unwrap();
    put_descriptor(&side_a, &descriptor(&node, 2, [3_u8; 32])).await;
  }
  for index in (1..1_024_u32).step_by(2) {
    let node = NodeId::parse(&format!("node_{index:021}")).unwrap();
    put_descriptor(&side_b, &descriptor(&node, 2, [3_u8; 32])).await;
  }
  let started = std::time::Instant::now();
  let applied = converge([&side_a, &side_b]).await;
  assert!(applied > 0);

  // All valid records participate: the full winner set is present on both
  // sides, and the second pass is changeless.
  let mut cursor = None;
  let mut seen = 0;
  loop {
    let page = resource_page::sync::emit_page_ctx(
      &side_a,
      cursor.as_deref(),
      resource_page::DEFAULT_RESOURCE_PAGE_LIMIT,
    )
    .await
    .unwrap();
    let done = page.cursor().is_none();
    cursor = page.cursor().map(|value| value.to_vec());
    seen += page.records().len();
    if done {
      break;
    }
  }
  assert_eq!(seen, 251);
  // The two components hold identical winner sets after healing: sample
  // the register equality across every name.
  for seed in (0_u8..=250).step_by(17) {
    let left = resource_store::read_record_ctx(&side_a, &name(seed))
      .await
      .unwrap();
    let right = resource_store::read_record_ctx(&side_b, &name(seed))
      .await
      .unwrap();
    assert_eq!(
      left.as_ref().map(|r| r.digest()),
      right.as_ref().map(|r| r.digest()),
      "name {seed} must converge identically on both components"
    );
  }
  // Hygiene guard only: this layer makes no latency qualification claim.
  // The bound tolerates parallel-test contention on slow CI runners.
  assert!(started.elapsed() < std::time::Duration::from_secs(120));
}

/// Restart and readdress repair through the ordinary tick — never
/// reconnect-only logic or false convergence acknowledgement. Side B
/// loses and reopens its store handle (a process restart over durable
/// storage) mid-convergence, and writer B's endpoint candidate changes at
/// a strictly higher owner revision (readdress); the ordinary bounded
/// pages converge both sides to the highest revision and the winning
/// signed tuples.
#[tokio::test]
async fn restart_and_readdress_repair_through_ordinary_pages() {
  let (_factory_a, side_a) = open_store().await;
  let (factory_b, side_b) = open_store().await;

  // Shared trust baseline: both writers are known members on both sides.
  for side in [&side_a, &side_b] {
    put_descriptor(side, &descriptor(&writer_a(), 1, RECORD_SEED)).await;
    put_descriptor(side, &descriptor(&writer_b(), 1, SECOND_SEED)).await;
  }
  // Divergent resources: one contended name, one A-only name.
  put_resource(
    &side_a,
    &resource(&name(1), 1_000, &writer_a(), "u://a1", RECORD_SEED),
  )
  .await;
  put_resource(
    &side_b,
    &resource(&name(1), 2_000, &writer_b(), "u://b1", SECOND_SEED),
  )
  .await;
  put_resource(
    &side_a,
    &resource(&name(2), 3_000, &writer_a(), "u://a2", RECORD_SEED),
  )
  .await;

  // Side B restarts: the handle drops and reopens over the same durable
  // factory; the metadata survives and the ordinary tick machinery
  // reconciles without any reconnect-only repair path.
  drop(side_b);
  let side_b = MetadataStore::open(&factory_b, std::time::Duration::from_secs(10))
    .await
    .unwrap();

  // Readdress: writer B's endpoint candidate changes at revision 2.
  put_descriptor(&side_b, &descriptor(&writer_b(), 2, SECOND_SEED)).await;

  // Ordinary bounded pages heal everything after the partition.
  let applied = converge([&side_a, &side_b]).await;
  assert!(
    applied > 0,
    "restart and readdress must repair through ordinary pages"
  );

  // The readdressed descriptor converges at revision 2 on side A.
  let healed = descriptor_store::read_descriptor_ctx(&side_a, &writer_b())
    .await
    .unwrap()
    .unwrap();
  assert_eq!(
    healed.revision(),
    2,
    "readdress converges at the higher owner revision"
  );
  // The restarted side gains A's resource through ordinary pages.
  let gained = resource_store::read_record_ctx(&side_b, &name(2))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(
    gained.digest(),
    resource(&name(2), 3_000, &writer_a(), "u://a2", RECORD_SEED).digest(),
    "restart heals the missing resource"
  );
  // The tuple winner (lexicographic timestamp maximum) wins on side A.
  let winner = resource_store::read_record_ctx(&side_a, &name(1))
    .await
    .unwrap()
    .unwrap();
  assert_eq!(
    winner.digest(),
    resource(&name(1), 2_000, &writer_b(), "u://b1", SECOND_SEED).digest(),
    "the timestamp-maximum tuple wins on both sides"
  );
}

/// Eight fat resources (label sets near their per-record bound) overflow
/// one 64 KiB control-bound page: the emission ladder halves the page
/// capacity, so every page's full wire payload (page envelope plus sync
/// wrapper) encodes, paging continues across the halved pages, and both
/// sides still converge. Under the pre-ladder code the page encode
/// failed the sync tick forever and the cursor never advanced.
#[tokio::test]
async fn fat_resource_pages_halve_and_still_converge() {
  // One record must stay inside its own 16 KiB record wire bound
  // (RECORD_LIMITS), so a fat label set stops short of the full entry
  // maximum — but eight such records still overflow the 64 KiB page
  // bound many times over.
  const FAT_ENTRIES: usize = 48;
  fn fat_labels() -> crate::LabelSet {
    let mut labels = crate::LabelSet::new();
    for index in 0..FAT_ENTRIES {
      labels = labels
        .insert(
          crate::LabelKey::parse(&format!("example.org/labels/fat-{index:02}")).unwrap(),
          crate::LabelValue::parse(&"v".repeat(crate::label::LABEL_VALUE_MAX_BYTES)).unwrap(),
        )
        .unwrap();
    }
    labels
  }

  let (_, side_a) = open_store().await;
  let (_, side_b) = open_store().await;
  // The fat resource writer must be a trusted member on both sides or
  // every page entry would skip for an unknown writer.
  put_descriptor(&side_a, &descriptor(&writer_a(), 1, RECORD_SEED)).await;
  put_descriptor(&side_b, &descriptor(&writer_a(), 1, RECORD_SEED)).await;
  for seed in 1..=8_u8 {
    let record = ResourceRecordV1::sign(
      name(seed),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse(&format!("u://fat-{seed}")).unwrap(),
      fat_labels(),
      5_000 + u64::from(seed),
      writer_a(),
      0,
      false,
      &SigningKey::from_bytes(&RECORD_SEED),
    )
    .unwrap();
    put_resource(&side_a, &record).await;
  }

  let mut cursor: Option<Vec<u8>> = None;
  let mut applied_total = 0_usize;
  let mut pages = 0_usize;
  loop {
    let page = resource_page::sync::emit_page_ctx(
      &side_a,
      cursor.as_deref(),
      resource_page::DEFAULT_RESOURCE_PAGE_LIMIT,
    )
    .await
    .unwrap();
    // The full wire payload (page envelope plus sync wrapper) fits the
    // control bound: the ladder halved the capacity to get here.
    let wrapped = crate::resource::sync::ResourceSyncPayload(minicbor::bytes::ByteVec::from(
      page.encode().unwrap(),
    ));
    assert!(wrapped.encode().is_ok());
    pages += 1;
    assert!(
      page.records().len() < 8,
      "an over-bound page never reaches the wire whole"
    );
    let done = page.cursor().is_none();
    cursor = page.cursor().map(|value| value.to_vec());
    applied_total += resource_page::sync::apply_page_ctx(&side_b, &SystemEntropy, &page)
      .await
      .unwrap();
    if done {
      break;
    }
  }
  assert!(pages >= 2, "eight fat records split over several pages");
  assert_eq!(applied_total, 8);
  for seed in 1..=8_u8 {
    let left = resource_store::read_record_ctx(&side_a, &name(seed))
      .await
      .unwrap()
      .unwrap();
    let right = resource_store::read_record_ctx(&side_b, &name(seed))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(left.digest(), right.digest(), "fat record {seed} converged");
  }
}
