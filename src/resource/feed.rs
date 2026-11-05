//! The durable resource change feed: one monotonic `resourceVersion` per
//! committed resource change.
//!
//! The feed is a dedicated metadata namespace holding a single head
//! counter plus one entry per committed change. The append is part of the
//! register commit's own transaction — the record put and its feed entry
//! (and the counter bump) land together or not at all — so no crash can
//! commit a record without its feed entry, and a losing, superseded, or
//! aborted commit appends nothing. An indeterminate commit that later
//! resolves to installed carries its entry with it, because the entry was
//! in the same transaction.
//!
//! Versions start at 1 and are assigned in commit order under the store's
//! writer exclusion, so the feed is gap-free and totally ordered. The
//! retained window is [`RESOURCE_FEED_RETENTION`] entries: each append
//! evicts every entry that falls out of the window (a page batch evicts
//! as many as it pushed out, so the window stays the contiguous tail of
//! the version sequence), and a consumer resuming below the oldest
//! retained version gets the typed [`ResourceFeedError::Compacted`]
//! carrying that floor so it can re-list the register and resume.
//!
//! The feed is node-local: it is not a replicated lane, because its
//! versions follow this store's own commit order. A peer-converged install
//! still appends its own local entry (the reconcile lane applies through
//! the same commit path), so a watcher sees every change this node's
//! register accepted, whoever wrote it.
//!
//! [`ResourceWatch`] replays from a caller-chosen version and then follows
//! live commits. It reads the durable feed (never an in-memory buffer), so
//! a watch created after a restart resumes from the persisted head, and a
//! slow consumer is bounded by the retained window instead of applying
//! backpressure to the commit path: the commit only wakes parked watches.
//! The wake-up is an optimization, never the source of truth — a parked
//! watch re-reads the durable feed on a bounded interval too, so a commit
//! whose notification was lost (an indeterminate commit that resolves to
//! installed outside the commit path) is still observed. A feed whose head
//! moved behind the watch's cursor — a leave wipe, a store restored to an
//! older state — is the typed [`ResourceFeedError::Reset`] instead of a
//! silent park.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::{ResourceName, ResourceRecordV1};
/// The durable namespace holding the feed head and its entries.
pub(crate) use crate::storage::families::RESOURCE_CHANGE_FEED_NAMESPACE;
use crate::{
  Error, ProviderErrorContext, Result, StoreExpectation, StoreKey, StoreNamespace, StoreOperation,
  StoreValue,
  protocol::{CborLimits, decode_canonical_strict, encode_canonical},
  provider::StoreSnapshot,
  storage::MetadataStore,
};

/// The retained window: the feed keeps the newest
/// `RESOURCE_FEED_RETENTION` entries, so a consumer that falls further
/// behind than this observes [`ResourceFeedError::Compacted`] and
/// re-lists instead of replaying a gap.
pub(crate) const RESOURCE_FEED_RETENTION: u64 = 1024;

/// The bounded re-check interval of one parked watch: the commit path's
/// wake-up is the fast path, and this bounds how long a lost wake-up can
/// keep a consumer parked. It is a re-read of the durable head, not a
/// change source, so a longer interval costs latency and never a change.
const FEED_RECHECK_INTERVAL: Duration = Duration::from_millis(100);

const FEED_SCHEMA: &str = "radiata.woooo.tech/schemas/v1/resource-change";
const FEED_ENTRY_VERSION: u16 = 1;
/// One entry is a version, a name, and one whole record: the record's own
/// decode bound plus the small envelope.
const FEED_LIMITS: CborLimits = CborLimits::new(4, 256, 32 * 1024);

/// Entry keys carry this prefix and then the version big-endian, so an
/// ordered scan of the prefix streams entries in version order and a
/// positioned scan resumes exactly after a cursor version.
const ENTRY_KEY_PREFIX: u8 = b'e';
/// The head counter's key: outside the entry prefix, so the entry scan
/// never sees it.
const HEAD_KEY: &[u8] = b"head";

/// The feed's provider namespace.
pub(crate) fn namespace() -> Result<StoreNamespace> {
  crate::storage::families::namespace(RESOURCE_CHANGE_FEED_NAMESPACE)
}

fn entry_key(version: u64) -> StoreKey {
  let mut key = Vec::with_capacity(9);
  key.push(ENTRY_KEY_PREFIX);
  key.extend_from_slice(&version.to_be_bytes());
  StoreKey::new(Arc::from(key))
}

fn head_key() -> StoreKey {
  StoreKey::new(Arc::from(HEAD_KEY))
}

/// The oldest version the retained window still holds for a feed whose
/// last assigned version is `head` (0 for an empty feed).
fn oldest_retained(head: u64) -> u64 {
  head
    .saturating_sub(RESOURCE_FEED_RETENTION)
    .saturating_add(1)
    .max(1)
}

/// Reads the feed head: the last assigned `resourceVersion`, 0 when no
/// change has ever committed.
pub(crate) async fn read_head(snapshot: &dyn StoreSnapshot) -> Result<u64> {
  let namespace = namespace()?;
  let Some(value) = snapshot.get(&namespace, &head_key()).await? else {
    return Ok(0);
  };
  let bytes: [u8; 8] = value
    .as_bytes()
    .try_into()
    .map_err(|_| crate::storage::storage_corrupt(ProviderErrorContext::StorageSnapshot))?;
  Ok(u64::from_be_bytes(bytes))
}

/// Builds the feed operations for one commit that installs `records` in
/// order: one entry put per record, the head-counter bump, and the
/// eviction delete that keeps the window bounded.
///
/// The caller merges these into the transaction that puts the records
/// themselves, built from the same snapshot, so the record and its feed
/// entry share one atomic commit and the counter's exact-version
/// expectation cannot race the writer exclusion.
pub(crate) async fn append_operations(
  snapshot: &dyn StoreSnapshot, records: &[ResourceRecordV1],
) -> Result<Vec<StoreOperation>> {
  if records.is_empty() {
    return Ok(Vec::new());
  }
  let namespace = namespace()?;
  let prev_head = read_head(snapshot).await?;
  let mut version = prev_head;
  let mut operations = Vec::with_capacity(records.len() + 2);
  for record in records {
    version = version
      .checked_add(1)
      .ok_or_else(|| Error::resource_exhausted("resource feed version"))?;
    operations.push(StoreOperation::Put {
      namespace: namespace.clone(),
      key: entry_key(version),
      expected: StoreExpectation::Absent,
      value: StoreValue::new(Arc::from(
        ResourceChangeV1::new(version, record.clone()).encode()?,
      )),
    });
  }
  let key = head_key();
  let expected = crate::provider::snapshot_expectation(snapshot, &namespace, &key).await?;
  operations.push(StoreOperation::Put {
    namespace: namespace.clone(),
    key,
    expected,
    value: StoreValue::new(Arc::from(version.to_be_bytes())),
  });
  // Every entry the batch pushed out of the window leaves in the same
  // transaction: a batch of `n` records evicts the whole range
  // `prev_head + 1 - RETENTION ..= version - RETENTION`, so the retained
  // set stays the contiguous tail of the version sequence and
  // `oldest_retained` is the exact compaction floor. Evicting only the
  // newest expired key would leave the older ones behind and make the
  // floor a lie.
  let first_evicted = prev_head
    .saturating_add(1)
    .saturating_sub(RESOURCE_FEED_RETENTION)
    .max(1);
  for evicted in first_evicted..oldest_retained(version) {
    let key = entry_key(evicted);
    // An entry already evicted by an earlier append is simply absent.
    if let Some(value) = snapshot.get(&namespace, &key).await? {
      operations.push(StoreOperation::Delete {
        namespace: namespace.clone(),
        key,
        expected: value.digest().clone(),
      });
    }
  }
  Ok(operations)
}

/// The canonical body of one feed entry: the assigned version, the
/// resource name, and the whole committed record (which carries whether
/// the change is a put or a removal).
#[derive(Encode, Decode)]
#[cbor(array)]
struct ResourceChangeWire {
  #[n(0)]
  schema: String,
  #[n(1)]
  entry_version: u16,
  #[n(2)]
  version: u64,
  #[n(3)]
  name: String,
  #[n(4)]
  record: ByteVec,
}

/// One stored feed entry: the assigned `resourceVersion` and the exact
/// record the register committed under it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceChangeV1 {
  version: u64,
  record: ResourceRecordV1,
}

impl ResourceChangeV1 {
  pub(crate) const fn new(version: u64, record: ResourceRecordV1) -> Self {
    Self { version, record }
  }

  pub(crate) const fn version(&self) -> u64 {
    self.version
  }

  /// Encodes the canonical entry bytes, reusing the record's own canonical
  /// encoding for the payload.
  pub(crate) fn encode(&self) -> Result<Vec<u8>> {
    encode_canonical(
      &ResourceChangeWire {
        schema: FEED_SCHEMA.to_owned(),
        entry_version: FEED_ENTRY_VERSION,
        version: self.version,
        name: self.record.name().as_str().to_owned(),
        record: ByteVec::from(self.record.encode()?),
      },
      FEED_LIMITS,
    )
  }

  /// Decodes one entry, rejecting noncanonical bytes, an unknown schema or
  /// entry version, a version of zero, and a name that disagrees with the
  /// carried record.
  pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
    let wire: ResourceChangeWire =
      decode_canonical_strict(bytes, FEED_LIMITS, "resource change canonical")?;
    if wire.schema != FEED_SCHEMA || wire.entry_version != FEED_ENTRY_VERSION {
      return Err(Error::invalid_input("resource change schema"));
    }
    if wire.version == 0 {
      return Err(Error::invalid_input("resource change version"));
    }
    let record = ResourceRecordV1::decode(&wire.record)?;
    if wire.name != record.name().as_str() {
      return Err(Error::invalid_input("resource change name"));
    }
    Ok(Self {
      version: wire.version,
      record,
    })
  }

  /// The public view of this entry: a put carries the record's public
  /// observation, a removal carries only the name (removal evidence stays
  /// internal, exactly as a removed register reads as absent).
  fn into_view(self) -> ResourceChange {
    let name = self.record.name().clone();
    let change = if self.record.removed() {
      ResourceChangeKind::Removed
    } else {
      ResourceChangeKind::Put(super::select::resource_view(&self.record))
    };
    ResourceChange {
      version: self.version,
      name,
      change,
    }
  }
}

/// One committed change in the durable resource feed.
///
/// `version` is the feed's monotonic `resourceVersion`: a consumer resumes
/// with the last version it processed and receives exactly the later
/// entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceChange {
  version: u64,
  name: ResourceName,
  change: ResourceChangeKind,
}

impl ResourceChange {
  /// The feed version assigned to this change inside the commit that
  /// installed it.
  pub const fn version(&self) -> u64 {
    self.version
  }

  /// The resource name the change applies to.
  pub const fn name(&self) -> &ResourceName {
    &self.name
  }

  /// The change itself: the committed record, or the removal of the name.
  pub const fn kind(&self) -> &ResourceChangeKind {
    &self.change
  }

  /// Whether the committed record removes the name.
  pub const fn is_removal(&self) -> bool {
    matches!(self.change, ResourceChangeKind::Removed)
  }
}

/// The change one feed entry commits.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceChangeKind {
  /// The record became the register's stored winner.
  Put(crate::ResourceView),
  /// The removal record became the register's stored winner: the name is
  /// no longer live.
  Removed,
}

/// The typed failure of one [`ResourceWatch::next`] step.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ResourceFeedError {
  /// The watch's resume point fell out of the retained window: every
  /// entry up to `oldest - 1` is gone. Re-list the register and resume
  /// from `oldest`.
  #[error("resource feed compacted below version {oldest}")]
  Compacted { oldest: u64 },
  /// The feed head moved behind the watch's cursor: the feed was wiped or
  /// reset (a leave wipe, a store restored to an older state), so the
  /// cursor no longer names a version this feed assigned. Re-list the
  /// register and resume from `head`.
  #[error("resource feed reset to head {head}")]
  Reset { head: u64 },
  /// The durable feed could not be read.
  #[error(transparent)]
  Storage(#[from] Error),
}

/// A resumable cursor over the durable resource change feed.
///
/// A watch created with `from = None` starts at the feed's current head (it
/// observes commits from now on); `from = Some(version)` first replays every
/// entry with a version greater than `version` and then follows live
/// commits. The watch reads the durable feed on demand, so it survives a
/// restart: reopening the store and resuming from the last processed
/// version continues the sequence with no gap and no reordering.
///
/// A slow consumer never blocks the commit path: the commit only wakes
/// parked watches, and a consumer that falls further behind than the
/// retained window observes [`ResourceFeedError::Compacted`]. A watch
/// whose cursor the feed no longer reaches — the feed was wiped or reset —
/// observes [`ResourceFeedError::Reset`].
///
/// The watch holds the store open, exactly like any other live handle: drop
/// it before reopening the same storage, or the provider's exclusive
/// lifetime lock keeps the reopen out.
#[derive(Debug)]
pub struct ResourceWatch {
  store: Arc<MetadataStore>,
  /// The last version this watch delivered (or the initial resume point).
  cursor: u64,
  /// Entries read from the feed but not yet delivered.
  buffered: VecDeque<ResourceChange>,
}

impl ResourceWatch {
  /// Creates one watch over `store`, resuming after `from` (or at the
  /// current head for `None`).
  pub(crate) async fn subscribe(store: Arc<MetadataStore>, from: Option<u64>) -> Result<Self> {
    let cursor = match from {
      Some(version) => version,
      None => {
        let snapshot = store.snapshot().await?;
        read_head(snapshot.as_ref()).await?
      }
    };
    Ok(Self {
      store,
      cursor,
      buffered: VecDeque::new(),
    })
  }

  /// The next committed change, in feed-version order.
  ///
  /// Cancel-safe: entries read from the store stay buffered on the watch,
  /// so dropping the future loses no change.
  pub async fn next(&mut self) -> std::result::Result<ResourceChange, ResourceFeedError> {
    loop {
      if let Some(change) = self.buffered.pop_front() {
        return Ok(change);
      }
      // Register the wake-up before reading: a commit landing after this
      // point is either observed by the read below or wakes the wait.
      let store = Arc::clone(&self.store);
      let notified = store.metadata_changed();
      tokio::pin!(notified);
      notified.as_mut().enable();
      self.fill().await?;
      if let Some(change) = self.buffered.pop_front() {
        return Ok(change);
      }
      // The wake-up is the fast path, not the source of truth: a commit
      // whose notification was lost (an indeterminate commit that resolves
      // to installed outside the commit path) must still be observed, so
      // the wait is bounded and the loop re-reads the durable feed.
      tokio::select! {
        _ = notified => {}
        _ = tokio::time::sleep(FEED_RECHECK_INTERVAL) => {}
      }
    }
  }

  /// Reads every entry past the cursor into the buffer, or reports the
  /// compaction floor when the cursor fell out of the retained window.
  async fn fill(&mut self) -> std::result::Result<(), ResourceFeedError> {
    let snapshot = self.store.snapshot().await?;
    let namespace = namespace()?;
    let head = read_head(snapshot.as_ref()).await?;
    if self.cursor > head {
      // The head moved behind the cursor: the feed was wiped or reset, so
      // the cursor names a version this feed never assigned (any more).
      // Parking here would stall the watch forever on a change that cannot
      // arrive; the typed signal lets the consumer re-list and resume.
      return Err(ResourceFeedError::Reset { head });
    }
    let oldest = oldest_retained(head);
    if self.cursor.saturating_add(1) < oldest {
      return Err(ResourceFeedError::Compacted { oldest });
    }
    if self.cursor >= head {
      return Ok(());
    }
    let from = entry_key(self.cursor);
    let mut scan = snapshot
      .scan_from(&namespace, &[ENTRY_KEY_PREFIX], Some(from.as_bytes()))
      .await?;
    while let Some(entry) = scan.next().await? {
      let change = ResourceChangeV1::decode(entry.value().as_bytes())?;
      // The key is the entry's own version key: a row stored under any
      // other key would break the version order the scan promises.
      if entry.key().as_bytes() != entry_key(change.version()).as_bytes()
        || change.version() <= self.cursor
      {
        return Err(ResourceFeedError::Storage(crate::storage::storage_corrupt(
          ProviderErrorContext::StorageScan,
        )));
      }
      self.cursor = change.version();
      self.buffered.push_back(change.into_view());
    }
    // Every version between the cursor and the head is retained by
    // construction, so a scan that stops short means the window itself is
    // damaged: fail loudly instead of parking on a change that will never
    // arrive.
    if self.cursor < head {
      return Err(ResourceFeedError::Storage(crate::storage::storage_corrupt(
        ProviderErrorContext::StorageScan,
      )));
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use std::{sync::Arc, time::Duration};

  use super::{
    RESOURCE_FEED_RETENTION, ResourceChangeKind, ResourceChangeV1, ResourceFeedError,
    ResourceWatch, append_operations, entry_key, namespace, read_head,
  };
  use crate::{
    LabelKey, LabelSet, LabelValue, NodeId,
    api::SystemEntropy,
    provider::StorageFactory,
    resource::{
      ResourceName, ResourceRecordV1,
      store::{ResourceCommitOutcome, commit_expected_record_ctx, commit_page_batch_ctx},
    },
  };

  fn name(seed: u8) -> ResourceName {
    ResourceName::parse(&format!("radiata.woooo.tech/resources/feed-{seed:03}")).unwrap()
  }

  fn labels() -> LabelSet {
    LabelSet::new()
      .insert(
        LabelKey::parse("example.org/labels/zone").unwrap(),
        LabelValue::parse("z1").unwrap(),
      )
      .unwrap()
  }

  fn record(name: &ResourceName, timestamp_millis: u64, removed: bool) -> ResourceRecordV1 {
    ResourceRecordV1::new(
      name.clone(),
      LabelValue::parse("document").unwrap(),
      crate::ResourceUri::parse("file:///feed").unwrap(),
      labels(),
      timestamp_millis,
      NodeId::parse("node-000000000000000000001").unwrap(),
      if removed { 1 } else { 0 },
      removed,
    )
    .unwrap()
  }

  fn factory() -> Arc<dyn StorageFactory> {
    Arc::new(crate::storage::contract::ReferenceFactory::new(
      crate::storage::contract::required_capabilities(),
    ))
  }

  /// Opens (or reopens) the store over `factory`: the same provider state
  /// across calls, so a drop-and-reopen is the store-level restart.
  async fn open(factory: &Arc<dyn StorageFactory>) -> Arc<crate::storage::MetadataStore> {
    Arc::new(
      crate::storage::MetadataStore::open(factory, Duration::from_secs(10))
        .await
        .unwrap(),
    )
  }

  async fn install(
    store: &crate::storage::MetadataStore, record: &ResourceRecordV1,
  ) -> ResourceCommitOutcome {
    commit_expected_record_ctx(store, &SystemEntropy, record, None)
      .await
      .unwrap()
  }

  async fn next(
    watch: &mut ResourceWatch,
  ) -> std::result::Result<crate::ResourceChange, ResourceFeedError> {
    tokio::time::timeout(Duration::from_secs(10), watch.next())
      .await
      .expect("the feed step must not park on a durable entry")
  }

  /// Puts and removals append one ordered entry each, and a removal entry
  /// carries the name without exposing removal evidence.
  #[tokio::test]
  async fn puts_and_removals_append_ordered_entries() {
    let factory = factory();
    let store = open(&factory).await;
    for (seed, timestamp) in [(1_u8, 1_000_u64), (2, 2_000)] {
      assert!(matches!(
        install(&store, &record(&name(seed), timestamp, false)).await,
        ResourceCommitOutcome::Installed(_)
      ));
    }
    assert!(matches!(
      install(&store, &record(&name(1), 3_000, true)).await,
      ResourceCommitOutcome::Installed(_)
    ));

    let mut watch = ResourceWatch::subscribe(Arc::clone(&store), Some(0))
      .await
      .unwrap();
    let first = next(&mut watch).await.unwrap();
    assert_eq!(first.version(), 1);
    assert_eq!(first.name(), &name(1));
    assert!(!first.is_removal());
    match first.kind() {
      ResourceChangeKind::Put(view) => {
        assert_eq!(view.name(), &name(1));
        assert_eq!(view.version().timestamp(), crate::time::from_millis(1_000));
      }
      other => panic!("expected a put entry, got {other:?}"),
    }

    let second = next(&mut watch).await.unwrap();
    assert_eq!(second.version(), 2);
    assert_eq!(second.name(), &name(2));

    let third = next(&mut watch).await.unwrap();
    assert_eq!(third.version(), 3);
    assert_eq!(third.name(), &name(1));
    assert!(third.is_removal());
    assert_eq!(third.kind(), &ResourceChangeKind::Removed);
  }

  /// Resuming from a version returns exactly the later entries, in order.
  #[tokio::test]
  async fn resume_from_a_version_returns_exactly_the_later_entries() {
    let factory = factory();
    let store = open(&factory).await;
    for (seed, timestamp) in [(1_u8, 1_000_u64), (2, 2_000), (3, 3_000)] {
      install(&store, &record(&name(seed), timestamp, false)).await;
    }

    let mut watch = ResourceWatch::subscribe(Arc::clone(&store), Some(1))
      .await
      .unwrap();
    let resumed: Vec<u64> = vec![
      next(&mut watch).await.unwrap().version(),
      next(&mut watch).await.unwrap().version(),
    ];
    assert_eq!(resumed, vec![2, 3]);
  }

  /// A reopened store keeps the persisted feed: the sequence continues
  /// without a gap and a new watch replays the whole persisted history.
  #[tokio::test]
  async fn restart_recovery_continues_the_sequence_without_gaps() {
    let factory = factory();
    let store = open(&factory).await;
    install(&store, &record(&name(1), 1_000, false)).await;
    install(&store, &record(&name(2), 2_000, false)).await;
    drop(store);

    let reopened = open(&factory).await;
    let head = read_head(reopened.snapshot().await.unwrap().as_ref())
      .await
      .unwrap();
    assert_eq!(head, 2, "the persisted head is the last committed version");
    // A fresh watch on the reopened store starts at the persisted head.
    let mut live = ResourceWatch::subscribe(Arc::clone(&reopened), None)
      .await
      .unwrap();
    assert!(matches!(
      install(&reopened, &record(&name(3), 3_000, false)).await,
      ResourceCommitOutcome::Installed(_)
    ));
    assert_eq!(next(&mut live).await.unwrap().version(), 3);

    let mut replay = ResourceWatch::subscribe(Arc::clone(&reopened), Some(0))
      .await
      .unwrap();
    let versions: Vec<u64> = vec![
      next(&mut replay).await.unwrap().version(),
      next(&mut replay).await.unwrap().version(),
      next(&mut replay).await.unwrap().version(),
    ];
    assert_eq!(versions, vec![1, 2, 3]);
  }

  /// A resume below the retained window reports the compaction floor, and
  /// the oldest retained version still replays.
  #[tokio::test]
  async fn a_below_retention_resume_reports_the_compaction_floor() {
    let factory = factory();
    let store = open(&factory).await;
    // One entry past the window: the oldest retained version is 2.
    for timestamp in 1..=RESOURCE_FEED_RETENTION + 1 {
      install(&store, &record(&name(1), timestamp, false)).await;
    }
    let head = read_head(store.snapshot().await.unwrap().as_ref())
      .await
      .unwrap();
    assert_eq!(head, RESOURCE_FEED_RETENTION + 1);

    let mut stale = ResourceWatch::subscribe(Arc::clone(&store), Some(0))
      .await
      .unwrap();
    match stale.next().await {
      Err(ResourceFeedError::Compacted { oldest }) => assert_eq!(oldest, 2),
      other => panic!("expected the typed compaction error, got {other:?}"),
    }

    // The evicted entry is gone from the store and the floor replays.
    let snapshot = store.snapshot().await.unwrap();
    let namespace = namespace().unwrap();
    assert!(
      snapshot
        .get(&namespace, &entry_key(1))
        .await
        .unwrap()
        .is_none()
    );
    let mut at_floor = ResourceWatch::subscribe(Arc::clone(&store), Some(1))
      .await
      .unwrap();
    assert_eq!(next(&mut at_floor).await.unwrap().version(), 2);
  }

  /// A page batch evicts every entry it pushed out of the retained window,
  /// not only the newest expired one: the window stays the contiguous tail
  /// of the version sequence, so the retained count is exactly the window
  /// and `oldest_retained` names a version that really is retained.
  #[tokio::test]
  async fn a_page_batch_evicts_every_entry_it_pushes_out_of_the_window() {
    let factory = factory();
    let store = open(&factory).await;
    // Fill the window one commit at a time: the window is exactly full at
    // the last install, so nothing has been evicted yet.
    for timestamp in 1..=RESOURCE_FEED_RETENTION {
      install(&store, &record(&name(1), timestamp, false)).await;
    }
    // A two-record page batch pushes two versions out of the window.
    let first = record(&name(2), 1_000, false);
    let second = record(&name(3), 1_000, false);
    let installed = commit_page_batch_ctx(&store, &SystemEntropy, &[&first, &second])
      .await
      .unwrap();
    assert_eq!(installed.len(), 2, "both page records install");

    let snapshot = store.snapshot().await.unwrap();
    let head = read_head(snapshot.as_ref()).await.unwrap();
    assert_eq!(head, RESOURCE_FEED_RETENTION + 2);
    let namespace = namespace().unwrap();
    let mut scan = snapshot
      .scan(&namespace, &[super::ENTRY_KEY_PREFIX])
      .await
      .unwrap();
    let mut retained = 0_u64;
    while scan.next().await.unwrap().is_some() {
      retained += 1;
    }
    assert_eq!(
      retained, RESOURCE_FEED_RETENTION,
      "the batch must evict every entry it pushed out of the window"
    );
    // The reported floor is truthful: the entry below it is gone and the
    // entry at it is retained.
    let floor = super::oldest_retained(head);
    assert_eq!(floor, 3);
    assert!(
      snapshot
        .get(&namespace, &entry_key(floor - 1))
        .await
        .unwrap()
        .is_none()
    );
    assert!(
      snapshot
        .get(&namespace, &entry_key(floor))
        .await
        .unwrap()
        .is_some()
    );
  }

  /// A watch parked before an indeterminate commit still observes the
  /// entry once the commit resolves to installed: the commit path notifies
  /// nothing on the `Unknown` arm, so the watch's bounded re-check is what
  /// carries the change.
  #[tokio::test]
  async fn a_parked_watch_observes_an_indeterminate_commit_after_reconcile() {
    use std::sync::atomic::AtomicUsize;

    use crate::storage::contract::{
      ReferenceFactory,
      reference::{UnknownFaultFactory, UnknownFaultMode},
      required_capabilities,
    };

    // Stamp the base schema through a plain reference open first: the
    // unknown fault must hit the register commit, not the open-time stamp.
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let plain: Arc<dyn StorageFactory> = reference.clone();
    drop(
      crate::storage::MetadataStore::open(&plain, Duration::from_secs(10))
        .await
        .unwrap(),
    );
    let fault: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference,
      // The faulted commit lands and reports Unknown.
      mode: UnknownFaultMode::Applied,
      commit_calls: Arc::new(AtomicUsize::new(0)),
    });
    let store = open(&fault).await;

    let mut watch = ResourceWatch::subscribe(Arc::clone(&store), None)
      .await
      .unwrap();
    let parked = tokio::spawn(async move { watch.next().await });
    // Park the watch before the commit: the first fill reads the empty
    // feed, and the wait below starts well inside one re-check interval.
    tokio::time::sleep(Duration::from_millis(20)).await;

    match commit_expected_record_ctx(
      &store,
      &SystemEntropy,
      &record(&name(1), 1_000, false),
      None,
    )
    .await
    .unwrap()
    {
      ResourceCommitOutcome::Indeterminate { .. } => {}
      other => panic!("the faulted commit must be indeterminate, got {other:?}"),
    }
    store.reconcile_if_frozen().await.unwrap();

    let change = tokio::time::timeout(Duration::from_secs(10), parked)
      .await
      .expect("the parked watch must not stall on a resolved commit")
      .unwrap()
      .unwrap();
    assert_eq!(change.version(), 1);
    assert_eq!(change.name(), &name(1));
  }

  /// A feed wiped under a live watch (a leave wipe, a store restored to an
  /// older state) is the typed reset signal, not a silent park: the head
  /// moved behind the cursor, so no entry can ever arrive.
  #[tokio::test]
  async fn a_wiped_feed_reports_the_reset_instead_of_parking() {
    let factory = factory();
    let store = open(&factory).await;
    install(&store, &record(&name(1), 1_000, false)).await;
    let mut watch = ResourceWatch::subscribe(Arc::clone(&store), Some(1))
      .await
      .unwrap();

    // Wipe the feed the way a leave does: the head counter and its entries
    // leave together, so the head reads 0 under a cursor of 1.
    let namespace = namespace().unwrap();
    let snapshot = store.snapshot().await.unwrap();
    let mut operations = Vec::new();
    for key in [super::head_key(), entry_key(1)] {
      if let Some(value) = snapshot.get(&namespace, &key).await.unwrap() {
        operations.push(crate::StoreOperation::Delete {
          namespace: namespace.clone(),
          key,
          expected: value.digest().clone(),
        });
      }
    }
    let transaction = store
      .prepare_transaction(
        crate::TransactionId::generate(&SystemEntropy).unwrap(),
        snapshot.revision().clone(),
        operations,
      )
      .unwrap();
    drop(snapshot);
    assert!(matches!(
      store.commit(transaction).await.unwrap(),
      crate::CommitOutcome::Committed(_)
    ));

    match watch.next().await {
      Err(ResourceFeedError::Reset { head }) => assert_eq!(head, 0),
      other => panic!("expected the typed reset signal, got {other:?}"),
    }
  }

  /// A live watch observes a commit that lands after it subscribed.
  #[tokio::test]
  async fn a_live_watch_observes_a_commit_after_subscribing() {
    let factory = factory();
    let store = open(&factory).await;
    install(&store, &record(&name(1), 1_000, false)).await;

    let mut watch = ResourceWatch::subscribe(Arc::clone(&store), None)
      .await
      .unwrap();
    let parked = tokio::spawn(async move { watch.next().await });
    tokio::task::yield_now().await;
    install(&store, &record(&name(2), 2_000, false)).await;
    let change = parked.await.unwrap().unwrap();
    assert_eq!(change.version(), 2);
    assert_eq!(change.name(), &name(2));
  }

  /// A removal record appends one `Removed` entry. The exact-version
  /// removal commit and this preconditioned put share the same commit tail
  /// in the register, so the append is the same one.
  #[tokio::test]
  async fn a_removal_record_appends_one_removed_entry() {
    let factory = factory();
    let store = open(&factory).await;
    let live = record(&name(1), 1_000, false);
    install(&store, &live).await;
    let removal = record(&name(1), 2_000, true);
    let expected = crate::ResourceVersion::from_record(&live);
    assert!(matches!(
      commit_expected_record_ctx(&store, &SystemEntropy, &removal, Some(&expected))
        .await
        .unwrap(),
      ResourceCommitOutcome::Installed(_)
    ));

    let mut watch = ResourceWatch::subscribe(Arc::clone(&store), Some(1))
      .await
      .unwrap();
    let change = next(&mut watch).await.unwrap();
    assert_eq!(change.version(), 2);
    assert_eq!(change.name(), &name(1));
    assert_eq!(change.kind(), &ResourceChangeKind::Removed);
  }

  /// A superseded write appends nothing: the feed head and the entry set
  /// stay exactly as the winning commit left them.
  #[tokio::test]
  async fn a_superseded_write_appends_nothing() {
    let factory = factory();
    let store = open(&factory).await;
    assert!(matches!(
      install(&store, &record(&name(1), 2_000, false)).await,
      ResourceCommitOutcome::Installed(_)
    ));
    assert!(matches!(
      install(&store, &record(&name(1), 1_000, false)).await,
      ResourceCommitOutcome::Superseded(_)
    ));
    let snapshot = store.snapshot().await.unwrap();
    assert_eq!(read_head(snapshot.as_ref()).await.unwrap(), 1);
    let namespace = namespace().unwrap();
    assert!(
      snapshot
        .get(&namespace, &entry_key(2))
        .await
        .unwrap()
        .is_none(),
      "a superseded write must not append a feed entry"
    );
  }

  /// An indeterminate commit that later resolves to installed appends
  /// exactly once: the entry rode the record's own transaction, so the
  /// pending-transaction reconciliation resolves both together.
  #[tokio::test]
  async fn an_indeterminate_commit_appends_exactly_once_when_it_resolves_installed() {
    use std::sync::atomic::AtomicUsize;

    use crate::storage::contract::{
      ReferenceFactory,
      reference::{UnknownFaultFactory, UnknownFaultMode},
      required_capabilities,
    };

    // Stamp the base schema through a plain reference open first: the
    // unknown fault must hit the register commit, not the open-time stamp.
    let reference = Arc::new(ReferenceFactory::new(required_capabilities()));
    let plain: Arc<dyn StorageFactory> = reference.clone();
    drop(
      crate::storage::MetadataStore::open(&plain, Duration::from_secs(10))
        .await
        .unwrap(),
    );

    let fault: Arc<dyn StorageFactory> = Arc::new(UnknownFaultFactory {
      reference,
      // The faulted commit lands and reports Unknown.
      mode: UnknownFaultMode::Applied,
      commit_calls: Arc::new(AtomicUsize::new(0)),
    });
    let store = open(&fault).await;
    match commit_expected_record_ctx(
      &store,
      &SystemEntropy,
      &record(&name(1), 1_000, false),
      None,
    )
    .await
    .unwrap()
    {
      ResourceCommitOutcome::Indeterminate { .. } => {}
      other => panic!("the faulted commit must be indeterminate, got {other:?}"),
    }
    // The record and its entry landed together; the reconciliation
    // resolves the frozen identity as committed.
    store.reconcile_if_frozen().await.unwrap();

    let snapshot = store.snapshot().await.unwrap();
    assert_eq!(
      read_head(snapshot.as_ref()).await.unwrap(),
      1,
      "the resolved commit appends exactly one entry"
    );
    let mut watch = ResourceWatch::subscribe(Arc::clone(&store), Some(0))
      .await
      .unwrap();
    let change = next(&mut watch).await.unwrap();
    assert_eq!(change.version(), 1);
    assert_eq!(change.name(), &name(1));
  }

  /// An empty batch appends nothing, and an entry round-trips canonically
  /// while a name/record disagreement fails closed at decode.
  #[tokio::test]
  async fn entry_encoding_round_trips_and_rejects_a_name_mismatch() {
    let factory = factory();
    let store = open(&factory).await;
    let snapshot = store.snapshot().await.unwrap();
    assert!(
      append_operations(snapshot.as_ref(), &[])
        .await
        .unwrap()
        .is_empty(),
      "an empty batch carries no feed operations"
    );

    let entry = ResourceChangeV1::new(7, record(&name(1), 1_000, false));
    let bytes = entry.encode().unwrap();
    let decoded = ResourceChangeV1::decode(&bytes).unwrap();
    assert_eq!(decoded, entry);
    assert_eq!(decoded.version(), 7);

    // The name is bound to the carried record: a mismatch fails closed.
    let mut wire: super::ResourceChangeWire = minicbor::decode(&bytes).unwrap();
    wire.name = name(2).as_str().to_owned();
    let forged = crate::protocol::encode_canonical(&wire, super::FEED_LIMITS).unwrap();
    assert_eq!(
      ResourceChangeV1::decode(&forged).unwrap_err().kind(),
      crate::ErrorKind::InvalidInput
    );
    // A zero version is never assigned and never decodes.
    let mut wire: super::ResourceChangeWire = minicbor::decode(&bytes).unwrap();
    wire.version = 0;
    let forged = crate::protocol::encode_canonical(&wire, super::FEED_LIMITS).unwrap();
    assert!(ResourceChangeV1::decode(&forged).is_err());
  }
}
