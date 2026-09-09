use std::sync::Arc;

use radiata::{
  DurabilityLevel, ErrorKind, GetNodeStatus, NodeBuilder, NodeStatus, ProviderErrorKind, Shutdown,
  StoreCapabilities,
  extension::{KeyProvider, StorageFactory},
};

mod common;

use common::{
  DropTracker, EventLog, KeyCall, MemoryStorageFactory, ScriptedKeys, SequenceEntropy,
  required_capabilities,
};

const FRESH_START_EVENTS: &[&str] = &[
  "entropy",
  "open",
  "capabilities",
  // The open-time schema gate reads (and fails closed on) the store's
  // schema record before anything discovers or recovers a journal.
  "snapshot",
  "get",
  "snapshot",
  "scan",
  "key-capabilities",
  "snapshot",
  "scan",
  "scan",
  "entropy",
  "entropy",
  "entropy",
  "get",
  "get",
  "scan",
  "commit",
  "create",
  "public-key",
  "snapshot",
  "get",
  "get",
  "entropy",
  "get",
  "get",
  "get",
  "get",
  "scan",
  "get",
  "get",
  "scan",
  "commit",
  "entropy",
  "snapshot",
  "scan",
  "get",
  "get",
  "get",
  "get",
  "scan",
  "commit",
  // The leave-intent discovery read closes startup: a pending
  // leave resumes before the node serves.
  "snapshot",
  "get",
  // Born-with-cluster: the self-binding check and its
  // conditional commit close startup.
  "snapshot",
  "get",
  "entropy",
  "commit",
];

struct Providers {
  events: Arc<EventLog>,
  factory: Arc<MemoryStorageFactory>,
  keys: Arc<ScriptedKeys>,
  factory_drops: Arc<DropTracker>,
  storage_drops: Arc<DropTracker>,
  key_drops: Arc<DropTracker>,
}

impl Providers {
  fn new(capabilities: StoreCapabilities, open_error: Option<ProviderErrorKind>) -> Self {
    let events = Arc::new(EventLog::default());
    let factory_drops = Arc::new(DropTracker::default());
    let storage_drops = Arc::new(DropTracker::default());
    let key_drops = Arc::new(DropTracker::default());
    let mut factory = MemoryStorageFactory::new(capabilities)
      .with_events(Arc::clone(&events))
      .with_factory_drops(Arc::clone(&factory_drops))
      .with_storage_drops(Arc::clone(&storage_drops));
    if let Some(kind) = open_error {
      factory = factory.with_open_error(kind);
    }
    Self {
      factory: Arc::new(factory),
      keys: Arc::new(
        ScriptedKeys::full()
          .with_events(Arc::clone(&events))
          .with_drops(Arc::clone(&key_drops)),
      ),
      events,
      factory_drops,
      storage_drops,
      key_drops,
    }
  }

  fn builder(&self) -> NodeBuilder {
    let factory: Arc<dyn StorageFactory> = Arc::<MemoryStorageFactory>::clone(&self.factory);
    let keys: Arc<dyn KeyProvider> = Arc::<ScriptedKeys>::clone(&self.keys);
    NodeBuilder::new(factory, keys).entropy(Arc::new(SequenceEntropy::with_events(Arc::clone(
      &self.events,
    ))))
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_runtime_success_orders_storage_probe_before_identity_and_releases_providers() {
  let providers = Providers::new(required_capabilities(), None);
  let handle = providers.builder().start().await.unwrap();

  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  assert_eq!(
    providers.events.events(),
    FRESH_START_EVENTS,
    "startup must open and probe storage, then probe key capabilities, then run identity calls",
  );
  assert_eq!(providers.factory.open_calls(), 1);
  assert_eq!(providers.factory.commit_calls(), 4);
  let calls = providers.keys.take_calls();
  assert!(
    matches!(
      calls.as_slice(),
      [KeyCall::Create(_), KeyCall::PublicKey(_)]
    ),
    "unexpected key calls: {calls:?}",
  );
  assert_eq!(providers.factory_drops.count(), 0);
  assert_eq!(providers.storage_drops.count(), 0);
  assert_eq!(providers.key_drops.count(), 0);

  handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(providers.storage_drops.count(), 1);
  assert_eq!(providers.factory.commit_calls(), 4);
  assert_eq!(providers.keys.take_calls(), vec![]);
  drop(providers.factory);
  drop(providers.keys);
  assert_eq!(providers.factory_drops.count(), 1);
  assert_eq!(providers.key_drops.count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_runtime_missing_capabilities_refused_at_open_without_key_calls() {
  let capabilities = [
    StoreCapabilities::new(DurabilityLevel::ProcessCrashAtomic)
      .conditional_batch(true)
      .ordered_scan(true)
      .reconciliation(true)
      .exclusive_lifetime_lock(true),
    required_capabilities().conditional_batch(false),
    required_capabilities().ordered_scan(false),
    required_capabilities().reconciliation(false),
    required_capabilities().exclusive_lifetime_lock(false),
  ];

  for capabilities in capabilities {
    let providers = Providers::new(capabilities, None);
    let error = providers.builder().start().await.err().unwrap();
    assert_eq!(error.kind(), ErrorKind::UnsupportedCapability);
    assert_eq!(error.context(), "storage open");
    assert_eq!(providers.events.events(), &["entropy", "open"]);
    assert_eq!(providers.factory.open_calls(), 1);
    assert_eq!(providers.factory.commit_calls(), 0);
    assert_eq!(
      providers.keys.take_calls(),
      vec![],
      "a storage capability refusal must produce zero key calls",
    );
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_runtime_open_error_is_typed_redacted_and_never_calls_keys() {
  let providers = Providers::new(
    required_capabilities(),
    Some(ProviderErrorKind::StorageLocked),
  );
  let error = providers.builder().start().await.err().unwrap();

  assert_eq!(error.kind(), ErrorKind::StorageLocked);
  assert_eq!(error.context(), "storage open");
  assert!(!format!("{error:?}").contains("provider-secret"));
  assert_eq!(providers.events.events(), &["entropy", "open"]);
  assert_eq!(providers.factory.open_calls(), 1);
  assert_eq!(providers.factory.commit_calls(), 0);
  assert_eq!(providers.keys.take_calls(), vec![]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn storage_runtime_exclusive_lifetime_lock_rejects_concurrent_open() {
  let providers = Providers::new(required_capabilities(), None);
  let handle = providers.builder().start().await.unwrap();
  providers.keys.take_calls();

  let error = providers.builder().start().await.err().unwrap();
  assert_eq!(error.kind(), ErrorKind::StorageLocked);
  assert_eq!(error.context(), "storage open");
  assert_eq!(providers.factory.open_calls(), 2);
  assert_eq!(
    providers.keys.take_calls(),
    vec![],
    "a locked store must produce zero key calls",
  );

  handle.command(Shutdown::new()).await.unwrap();
  let reopened = providers.builder().start().await.unwrap();
  assert_eq!(
    reopened.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  reopened.command(Shutdown::new()).await.unwrap();
}
