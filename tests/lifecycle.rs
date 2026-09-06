use std::{
  future::Future,
  sync::Arc,
  task::{Context, Poll, Waker},
  time::Duration,
};

use radiata::{
  Command, ErrorKind, GetNodeStatus, NodeBuilder, NodeHandle, NodeStatus, Query, Shutdown,
  ShutdownOutcome, ShutdownReason, WaitForShutdown,
  extension::{KeyProvider, StorageFactory},
};

mod common;

use common::{
  DropTracker, EventLog, KeyCall, MemoryStorageFactory, ScriptedKeys, SequenceEntropy,
  required_capabilities,
};

struct Providers {
  events: Arc<EventLog>,
  factory: Arc<MemoryStorageFactory>,
  keys: Arc<ScriptedKeys>,
  entropy: Arc<SequenceEntropy>,
  factory_drops: Arc<DropTracker>,
  storage_drops: Arc<DropTracker>,
  key_drops: Arc<DropTracker>,
}

impl Providers {
  fn new() -> Self {
    let events = Arc::new(EventLog::default());
    let factory_drops = Arc::new(DropTracker::default());
    let storage_drops = Arc::new(DropTracker::default());
    let key_drops = Arc::new(DropTracker::default());
    Self {
      factory: Arc::new(
        MemoryStorageFactory::new(required_capabilities())
          .with_events(Arc::clone(&events))
          .with_factory_drops(Arc::clone(&factory_drops))
          .with_storage_drops(Arc::clone(&storage_drops)),
      ),
      keys: Arc::new(
        ScriptedKeys::full()
          .with_events(Arc::clone(&events))
          .with_drops(Arc::clone(&key_drops)),
      ),
      entropy: Arc::new(SequenceEntropy::with_events(Arc::clone(&events))),
      events,
      factory_drops,
      storage_drops,
      key_drops,
    }
  }

  fn builder(&self) -> NodeBuilder {
    let factory: Arc<dyn StorageFactory> = Arc::<MemoryStorageFactory>::clone(&self.factory);
    let keys: Arc<dyn KeyProvider> = Arc::<ScriptedKeys>::clone(&self.keys);
    NodeBuilder::new(factory, keys).entropy(Arc::<SequenceEntropy>::clone(&self.entropy))
  }

  async fn start(&self) -> NodeHandle {
    self.builder().start().await.unwrap()
  }
}

#[test]
fn g1_lifecycle_sealed_operations_preserve_outputs() {
  fn assert_command<Operation: Command<Output = ShutdownOutcome>>() {}
  fn assert_status_query<Operation: Query<Output = NodeStatus>>() {}
  fn assert_wait_query<Operation: Query<Output = ShutdownReason>>() {}

  assert_command::<Shutdown>();
  assert_status_query::<GetNodeStatus>();
  assert_wait_query::<WaitForShutdown>();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_start_and_shutdown_provisions_identity_once() {
  let providers = Providers::new();
  let handle = providers.start().await;

  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  assert_eq!(
    providers.entropy.fills(),
    &[32, 16, 16, 16, 16, 16, 16],
    "startup fills the runtime seed, then generates node, operation, and transaction IDs (including the self-binding transaction)",
  );
  let calls = providers.keys.take_calls();
  assert!(
    matches!(
      calls.as_slice(),
      [KeyCall::Create(_), KeyCall::PublicKey(_)]
    ),
    "startup provisions and verifies the local identity: {calls:?}",
  );
  assert_eq!(providers.factory.commit_calls(), 4);

  let outcome = handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
  assert_eq!(providers.entropy.fills().len(), 7);
  assert_eq!(providers.factory.commit_calls(), 4);
  assert_eq!(providers.keys.take_calls(), vec![]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_cloned_handles_share_runtime_status() {
  let providers = Providers::new();
  let first = providers.start().await;
  let second = first.clone();

  assert_eq!(
    first.query(GetNodeStatus::new()).await.unwrap(),
    second.query(GetNodeStatus::new()).await.unwrap(),
  );
  first.command(Shutdown::new()).await.unwrap();
  assert_eq!(
    second.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Stopped,
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_shutdown_and_wait_are_idempotent() {
  let providers = Providers::new();
  let handle = providers.start().await;
  let waiter = handle.clone();
  let waiting = tokio::spawn(async move { waiter.query(WaitForShutdown::new()).await });
  tokio::task::yield_now().await;

  let first = handle.command(Shutdown::new()).await.unwrap();
  let reason = waiting.await.unwrap().unwrap();
  let second = handle.command(Shutdown::new()).await.unwrap();

  assert_eq!(first.reason(), &ShutdownReason::Explicit);
  assert_eq!(second.reason(), &ShutdownReason::Explicit);
  assert_eq!(reason, ShutdownReason::Explicit);
  assert_eq!(
    handle.query(WaitForShutdown::new()).await.unwrap(),
    ShutdownReason::Explicit,
  );
  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Stopped,
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_concurrent_shutdown_runs_one_drain() {
  let providers = Providers::new();
  let handle = providers.start().await;
  let barrier = Arc::new(tokio::sync::Barrier::new(16));
  let mut callers = Vec::new();
  for _ in 0..16 {
    let caller = handle.clone();
    let barrier = Arc::clone(&barrier);
    callers.push(tokio::spawn(async move {
      barrier.wait().await;
      caller.command(Shutdown::new()).await
    }));
  }

  for caller in callers {
    assert_eq!(
      caller.await.unwrap().unwrap().reason(),
      &ShutdownReason::Explicit,
    );
  }

  assert_eq!(
    providers.storage_drops.count(),
    1,
    "concurrent shutdown must run exactly one provider drain",
  );
  assert_eq!(providers.factory_drops.count(), 0);
  assert_eq!(providers.key_drops.count(), 0);
  drop(providers.factory);
  drop(providers.keys);
  assert_eq!(providers.factory_drops.count(), 1);
  assert_eq!(providers.key_drops.count(), 1);
}

#[test]
fn g1_lifecycle_start_without_tokio_returns_not_ready_without_provider_calls() {
  let providers = Providers::new();
  let mut start = Box::pin(providers.builder().start());
  let waker = Waker::noop();
  let mut context = Context::from_waker(waker);

  let result = Future::poll(start.as_mut(), &mut context);

  assert!(matches!(result, Poll::Ready(Err(error)) if error.kind() == ErrorKind::NotReady));
  assert_eq!(providers.entropy.fills(), &[] as &[usize]);
  assert_eq!(providers.events.events(), &[] as &[&str]);
  assert_eq!(providers.factory.open_calls(), 0);
  assert_eq!(providers.keys.take_calls(), vec![]);
}

#[test]
fn g1_lifecycle_runtime_loss_publishes_failed_terminal_state() {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let providers = Providers::new();
  let handle = runtime.block_on(providers.start());
  let calls = providers.keys.take_calls();
  assert!(
    matches!(
      calls.as_slice(),
      [KeyCall::Create(_), KeyCall::PublicKey(_)]
    ),
    "startup provisions the identity before runtime loss: {calls:?}",
  );
  drop(runtime);

  let observer = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  observer.block_on(async {
    assert_eq!(
      handle.query(GetNodeStatus::new()).await.unwrap(),
      NodeStatus::Failed,
    );
    assert_eq!(
      handle.query(WaitForShutdown::new()).await.unwrap(),
      ShutdownReason::Fatal(ErrorKind::Internal),
    );
  });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_shutdown_releases_retained_providers() {
  let providers = Providers::new();
  let handle = providers.start().await;

  handle.command(Shutdown::new()).await.unwrap();

  assert_eq!(providers.storage_drops.count(), 1);
  assert_eq!(providers.factory_drops.count(), 0);
  assert_eq!(providers.key_drops.count(), 0);
  drop(providers.factory);
  drop(providers.keys);
  assert_eq!(providers.factory_drops.count(), 1);
  assert_eq!(providers.key_drops.count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_lifecycle_last_handle_drop_stops_supervisor() {
  let providers = Providers::new();
  let handle = providers.start().await;

  drop(handle);
  tokio::time::timeout(Duration::from_secs(1), providers.storage_drops.wait_for(1))
    .await
    .unwrap();

  assert_eq!(providers.storage_drops.count(), 1);
  drop(providers.factory);
  drop(providers.keys);
  // The supervisor task tears down its driver after the storage release
  // resolves the wait above, so the remaining provider drops are awaited
  // instead of raced.
  tokio::time::timeout(Duration::from_secs(1), async {
    tokio::join!(
      providers.factory_drops.wait_for(1),
      providers.key_drops.wait_for(1),
    );
  })
  .await
  .unwrap();
  assert_eq!(providers.factory_drops.count(), 1);
  assert_eq!(providers.key_drops.count(), 1);
}

/// G9-02 facade wiring: the sealed `SelectResources` query pages the local
/// resource catalog through the public handle; an empty catalog returns an
/// empty bounded page with no continuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g9_select_resources_pages_the_empty_catalog() {
  let providers = Providers::new();
  let handle = providers.start().await;

  let selector = radiata::Selector::parse("radiata.woooo.tech/resources/type=document").unwrap();
  let page = handle
    .query(radiata::SelectResources::new(
      selector,
      radiata::PageSpec::first(8).unwrap(),
    ))
    .await
    .unwrap();
  assert!(page.items().is_empty());
  assert!(page.next().is_none());

  let outcome = handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(outcome.reason(), &ShutdownReason::Explicit);
}
