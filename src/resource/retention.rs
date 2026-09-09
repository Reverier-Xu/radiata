//! Signed removal retention and exact core-metadata cleanup.
//!
//! A removal is a signed resource record like any other: it stays the
//! register's convergence-eligible winner until this exact-metadata policy
//! evicts it. The policy cleans only `removed()` records — never live
//! metadata — by conditional deletes whose expectation is the exact stored
//! value digest: a stale expectation (a concurrent writer already moved
//! the register) conflicts without mutating anything, and an eviction is
//! old-or-new at every crash boundary. The URI value carried by a record
//! is opaque bytes to this module: cleanup never dereferences it, never
//! follows it, and never touches anything outside the single core record
//! key, so upper-layer objects and caller data are untouched.

use std::time::Duration;

use crate::{
  Result, StoreKey, StoreOperation,
  api::Entropy,
  storage::{MetadataStore, receipt::WallClock},
};

/// The caller-selected default removal-evidence retention window: a signed
/// removal record survives this long after its own timestamp before the
/// ordinary retention pass may drop it. Mirrors the trace-metadata default.
pub(crate) const RESOURCE_REMOVAL_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The caller-selected default cap on stored removal records: once the
/// removal population exceeds this bound, the oldest evict first.
pub(crate) const RESOURCE_REGISTER_CAP: usize = 262_144;

/// One fresh removal seen during the scan, ordered by timestamp so a
/// heap bounded by the cap can track the oldest candidates without
/// materializing the removal population.
struct RemovalCandidate {
  stamped: std::time::SystemTime,
  key: StoreKey,
  digest: crate::Digest,
}

impl PartialEq for RemovalCandidate {
  fn eq(&self, other: &Self) -> bool {
    self.stamped == other.stamped
  }
}
impl Eq for RemovalCandidate {}
impl PartialOrd for RemovalCandidate {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}
impl Ord for RemovalCandidate {
  // Max-heap by timestamp: popping evicts the *newest* candidate, so a
  // heap bounded at `cap` always retains the `cap` oldest fresh removals.
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.stamped.cmp(&other.stamped)
  }
}

/// Runs one bounded retention pass over the resource namespace:
/// `removed()` records expire at their retention deadline and the removal
/// population stays within the cap, oldest-first. Every removal leaves by
/// one conditional delete against the exact stored digest; a record whose
/// expectation no longer matches is left untouched (a conflicting stale
/// expectation is never mutated away).
///
/// The pass is bounded by construction: the scan streams records and a
/// max-heap bounded by `cap` tracks the oldest fresh removals so the cap
/// applies during the scan instead of after collecting everything. The
/// expired removals and the cap overflow leave together in one
/// conditional multi-delete transaction built on the scan's revision, so
/// a single pass lands every due deletion; any conflict leaves the whole
/// batch untouched for the next bounded pass. The cap itself applies only
/// when `cap > 0`: with `cap == 0` the candidate heap stays empty and the
/// population bound never evicts.
///
/// Live records are never evicted, matching the trace lane's active-record
/// rule. Returns the number of removal records actually cleaned.
pub(crate) async fn sweep_removed_ctx(
  store: &MetadataStore, entropy: &dyn Entropy, clock: &dyn WallClock, retention: Duration,
  cap: usize,
) -> Result<usize> {
  let _permit = store.write_permit().await;
  let namespace = super::store::namespace()?;
  let now = clock.now();
  let snapshot = store.snapshot().await?;
  let mut scan = snapshot.scan(&namespace, &[]).await?;
  // The due deletes collect during the scan and leave in one batch; the
  // batch size is bounded by the removal population the cap maintains.
  let mut due: Vec<StoreOperation> = Vec::new();
  let mut fresh_total = 0_usize;
  let mut oldest: std::collections::BinaryHeap<RemovalCandidate> =
    std::collections::BinaryHeap::new();
  while let Some(entry) = scan.next().await? {
    let record = super::ResourceRecordV1::decode(entry.value().as_bytes())?;
    if !record.removed() {
      // Live metadata is never evicted by retention.
      continue;
    }
    let key = StoreKey::new(std::sync::Arc::from(entry.key().as_bytes().to_vec()));
    let digest = entry.value().digest().clone();
    let expired = now
      .duration_since(record.timestamp())
      .is_ok_and(|age| age >= retention);
    if expired {
      due.push(StoreOperation::Delete {
        namespace: namespace.clone(),
        key,
        expected: digest,
      });
      continue;
    }
    fresh_total = fresh_total.saturating_add(1);
    oldest.push(RemovalCandidate {
      stamped: record.timestamp(),
      key,
      digest,
    });
    if oldest.len() > cap {
      // Pop the newest candidate: the heap always holds the `cap` oldest.
      oldest.pop();
    }
  }
  drop(scan);

  // Enforce the cap oldest-first: the overflow is the oldest
  // `fresh_total - cap` fresh removals, capped at one heap per pass.
  let overflow = fresh_total.saturating_sub(cap).min(oldest.len());
  if overflow > 0 {
    let mut candidates = oldest.into_vec();
    candidates.sort_by_key(|candidate| candidate.stamped);
    due.extend(
      candidates
        .into_iter()
        .take(overflow)
        .map(|candidate| StoreOperation::Delete {
          namespace: namespace.clone(),
          key: candidate.key,
          expected: candidate.digest,
        }),
    );
  }
  if due.is_empty() {
    return Ok(0);
  }

  // One conditional multi-delete transaction on the scan's revision: the
  // whole pass is old-or-new at every crash boundary, and every delete
  // carries the exact digest it was scanned with. Landing the deletes in
  // one commit keeps the pass from stranding its second-and-later
  // deletions behind a revision the pass itself advanced.
  let removed = due.len();
  let transaction = store.prepare_transaction(
    crate::TransactionId::generate(entropy)?,
    snapshot.revision().clone(),
    due,
  )?;
  match store.commit(transaction).await? {
    crate::CommitOutcome::Committed(_) => Ok(removed),
    // A conflict or abort mutates nothing: the newer winner (or the
    // moved base revision) stays untouched, and the next bounded pass
    // retries the whole batch.
    crate::CommitOutcome::Conflict | crate::CommitOutcome::Aborted => Ok(0),
    crate::CommitOutcome::Unknown { .. } => {
      // The pending identity is discoverable through the store's
      // recovery surface; leave the records in place rather than
      // guessing, and let the next pass finish the job.
      tracing::debug!("resource removal sweep ended indeterminate; retried next pass");
      Ok(0)
    }
  }
}
#[cfg(test)]
mod tests {
  use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
  };

  use ed25519_dalek::SigningKey;

  use super::sweep_removed_ctx;
  use crate::{
    LabelKey, LabelSet, LabelValue, NodeId,
    api::SystemEntropy,
    provider::StorageFactory,
    resource::{ResourceName, ResourceRecordV1},
    storage::{MetadataStore, contract::helpers::ManualClock},
  };

  const SEED: [u8; 32] = [41; 32];

  fn name(seed: u8) -> ResourceName {
    ResourceName::parse(&format!("radiata.woooo.tech/resources/retention-{seed}")).unwrap()
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
    name: &ResourceName, timestamp_millis: u64, removed: bool, uri: &str,
  ) -> ResourceRecordV1 {
    ResourceRecordV1::sign(
      name.clone(),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse(uri).unwrap(),
      labels(),
      timestamp_millis,
      NodeId::parse("node_000000000000000000001").unwrap(),
      if removed { 1 } else { 0 },
      removed,
      &SigningKey::from_bytes(&SEED),
    )
    .unwrap()
  }

  async fn open_store() -> (Arc<dyn StorageFactory>, MetadataStore, Arc<ManualClock>) {
    let factory: Arc<dyn StorageFactory> =
      Arc::new(crate::storage::contract::ReferenceFactory::new(
        crate::storage::contract::required_capabilities(),
      ));
    let store = MetadataStore::open(&factory, Duration::from_secs(10))
      .await
      .unwrap();
    let clock = Arc::new(ManualClock::new(UNIX_EPOCH + Duration::from_secs(10_000)));
    (factory, store, clock)
  }

  async fn install(store: &MetadataStore, record: &ResourceRecordV1) {
    match crate::resource::store::commit_record_ctx(store, &SystemEntropy, record)
      .await
      .unwrap()
    {
      crate::resource::store::ResourceCommitOutcome::Installed(_) => {}
      other => panic!("install must commit, got {other:?}"),
    }
  }

  /// Expired removal records leave by exact conditional
  /// deletes; live records and fresh removals stay; the sweep returns the
  /// exact count cleaned.
  #[tokio::test]
  async fn sweep_expires_aged_removals_and_never_touches_live_records() {
    let (_factory, store, clock) = open_store().await;
    // Timestamps are epoch millis: 8_000 ms is 8 s, while the sweep clock
    // reads 9_500 s, so the first removal is far past the 1_000 s window
    // and the second is genuinely fresh (9_600 s is after the clock).
    let stale_removal = record(&name(1), 8_000, true, "file:///gone");
    let fresh_removal = record(&name(2), 9_600_000, true, "file:///recent");
    let live = record(&name(3), 9_600_000, false, "file:///live");
    for value in [&stale_removal, &fresh_removal, &live] {
      install(&store, value).await;
    }
    clock.set(UNIX_EPOCH + Duration::from_secs(9_500));
    let removed = sweep_removed_ctx(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      Duration::from_secs(1_000),
      128,
    )
    .await
    .unwrap();
    assert_eq!(removed, 1);
    assert!(
      crate::resource::store::read_record_ctx(&store, &name(1))
        .await
        .unwrap()
        .is_none()
    );
    assert!(
      crate::resource::store::read_record_ctx(&store, &name(2))
        .await
        .unwrap()
        .is_some()
    );
    assert!(
      crate::resource::store::read_record_ctx(&store, &name(3))
        .await
        .unwrap()
        .is_some()
    );
  }

  /// One pass lands every expired removal, not only the first: two aged
  /// removal records leave together in the same sweep through the single
  /// conditional multi-delete transaction.
  #[tokio::test]
  async fn one_pass_expires_multiple_aged_removals() {
    let (_factory, store, clock) = open_store().await;
    // Timestamps are epoch millis: both records are hours past the
    // 1_000 s retention window when the sweep clock reads 10_000 s.
    let first = record(&name(7), 7_000, true, "file:///first");
    let second = record(&name(8), 7_500, true, "file:///second");
    install(&store, &first).await;
    install(&store, &second).await;
    clock.set(UNIX_EPOCH + Duration::from_secs(10_000));
    let removed = sweep_removed_ctx(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      Duration::from_secs(1_000),
      128,
    )
    .await
    .unwrap();
    assert_eq!(removed, 2);
    assert!(
      crate::resource::store::read_record_ctx(&store, &name(7))
        .await
        .unwrap()
        .is_none()
    );
    assert!(
      crate::resource::store::read_record_ctx(&store, &name(8))
        .await
        .unwrap()
        .is_none()
    );
  }

  /// Removal evidence stays convergence-eligible until
  /// policy removes it, and a cap evicts the oldest removals first while
  /// live winners stay put.
  #[tokio::test]
  async fn cap_evicts_oldest_removals_first_and_never_live_winners() {
    let (_factory, store, clock) = open_store().await;
    for seed in 1..=3_u8 {
      install(
        &store,
        &record(&name(seed), u64::from(seed) * 1_000, true, "u://r"),
      )
      .await;
    }
    install(&store, &record(&name(4), 6_000, false, "u://live")).await;
    let removed = sweep_removed_ctx(
      &store,
      &SystemEntropy,
      clock.as_ref(),
      Duration::from_secs(3_600 * 24 * 365),
      2,
    )
    .await
    .unwrap();
    assert_eq!(removed, 1);
    assert!(
      crate::resource::store::read_record_ctx(&store, &name(1))
        .await
        .unwrap()
        .is_none()
    );
    for seed in 2..=4_u8 {
      assert!(
        crate::resource::store::read_record_ctx(&store, &name(seed))
          .await
          .unwrap()
          .is_some()
      );
    }
  }

  /// A stale delete expectation fails closed as a typed
  /// conflict without mutating the stored winner, exactly as the sweep's
  /// conditional delete does when a concurrent writer moved the register.
  #[tokio::test]
  async fn stale_expectation_conflicts_without_mutation() {
    let (factory, store, _clock) = open_store().await;
    install(&store, &record(&name(5), 2_000, true, "u://newer")).await;
    // Release the metadata handle so the raw provider lane can reopen the
    // store (one exclusive handle per store).
    drop(store);

    // At the raw provider layer (no MetadataStore wrapper), a delete whose
    // expectation does not match the stored value must fail closed as a
    // typed conflict and leave the winner untouched.
    let provider = factory
      .open(crate::StoreRequirements::metadata())
      .await
      .unwrap();
    let snapshot = provider.snapshot().await.unwrap();
    let namespace = crate::StoreNamespace::new(
      crate::QualifiedTag::parse(crate::resource::store::RESOURCE_RECORD_NAMESPACE).unwrap(),
    );
    let key = crate::StoreKey::new(Arc::from(name(5).as_str().as_bytes().to_vec()));
    let stale = crate::StoreTransaction::new(
      crate::TransactionId::generate(&SystemEntropy).unwrap(),
      snapshot.revision().clone(),
      vec![crate::StoreOperation::Delete {
        namespace,
        key,
        expected: crate::Digest::from_bytes([0xFF; 32]), // stale by construction
      }],
    )
    .unwrap();
    match provider.commit(stale).await.unwrap() {
      crate::CommitOutcome::Conflict => {}
      other => panic!("stale expectation must conflict, got {other:?}"),
    }
  }

  /// Cleanup never dereferences or follows the resource
  /// URI — the referenced file survives untouched while the core record
  /// is removed.
  #[tokio::test]
  async fn sweep_never_follows_the_resource_uri() {
    let dir = tempfile::TempDir::new().unwrap();
    let sentinel = dir.path().join("caller-object.bin");
    std::fs::write(&sentinel, b"caller data").unwrap();
    let uri = format!("file://{}", sentinel.display());

    let (_factory, store, clock) = open_store().await;
    install(&store, &record(&name(6), 1_000, true, &uri)).await;
    clock.set(UNIX_EPOCH + Duration::from_secs(20_000));
    let removed = sweep_removed_ctx(&store, &SystemEntropy, clock.as_ref(), Duration::ZERO, 0)
      .await
      .unwrap();
    assert_eq!(removed, 1);
    assert!(
      crate::resource::store::read_record_ctx(&store, &name(6))
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"caller data");
  }
}
