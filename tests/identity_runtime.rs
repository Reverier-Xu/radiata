use std::sync::Arc;

use radiata::{
  Error, ErrorKind, GetNodeStatus, KeyCapabilities, KeyOperationId, NodeBuilder, NodeHandle,
  NodeStatus, Shutdown, StoreKey,
  extension::{KeyProvider, StorageFactory},
};

mod common;

use common::{
  CommitFault, CreateScript, DropTracker, FaultingFactory, KEY_CREATION_INTENT_NAMESPACE, KeyCall,
  LOCAL_IDENTITY_NAMESPACE, MemoryStorageFactory, PENDING_NAMESPACE, ScriptedKeys, SequenceEntropy,
  namespace, required_capabilities, scripted_signing,
};

struct Providers {
  factory: Arc<MemoryStorageFactory>,
  keys: Arc<ScriptedKeys>,
  entropy: Arc<SequenceEntropy>,
  factory_drops: Arc<DropTracker>,
  storage_drops: Arc<DropTracker>,
  key_drops: Arc<DropTracker>,
}

impl Providers {
  fn new() -> Self {
    let factory_drops = Arc::new(DropTracker::default());
    let storage_drops = Arc::new(DropTracker::default());
    let key_drops = Arc::new(DropTracker::default());
    Self {
      factory: Arc::new(
        MemoryStorageFactory::new(required_capabilities())
          .with_factory_drops(Arc::clone(&factory_drops))
          .with_storage_drops(Arc::clone(&storage_drops)),
      ),
      keys: Arc::new(ScriptedKeys::full().with_drops(Arc::clone(&key_drops))),
      entropy: Arc::new(SequenceEntropy::default()),
      factory_drops,
      storage_drops,
      key_drops,
    }
  }

  fn builder(&self) -> NodeBuilder {
    builder(
      factory_arc(self),
      Arc::clone(&self.keys),
      Arc::clone(&self.entropy),
    )
  }
}

fn builder(
  factory: Arc<dyn StorageFactory>, keys: Arc<ScriptedKeys>, entropy: Arc<SequenceEntropy>,
) -> NodeBuilder {
  let provider: Arc<dyn KeyProvider> = keys;
  NodeBuilder::new(factory, provider).entropy(entropy)
}

fn factory_arc(providers: &Providers) -> Arc<dyn StorageFactory> {
  Arc::<MemoryStorageFactory>::clone(&providers.factory)
}

fn fault_factory(fault: &Arc<FaultingFactory>) -> Arc<dyn StorageFactory> {
  Arc::<FaultingFactory>::clone(fault)
}

async fn start(providers: &Providers) -> NodeHandle {
  let handle = providers.builder().start().await.unwrap();
  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  handle
}

fn local_identity_bytes(factory: &MemoryStorageFactory) -> Option<Vec<u8>> {
  factory
    .entries()
    .get(&(
      namespace(LOCAL_IDENTITY_NAMESPACE),
      StoreKey::new(Arc::from(b"self".as_slice())),
    ))
    .map(|value| value.as_bytes().to_vec())
}

fn intent_keys(factory: &MemoryStorageFactory) -> Vec<Vec<u8>> {
  factory
    .entries()
    .keys()
    .filter(|(entry_namespace, _)| entry_namespace == &namespace(KEY_CREATION_INTENT_NAMESPACE))
    .map(|(_, key)| key.as_bytes().to_vec())
    .collect()
}

fn pending_count(factory: &MemoryStorageFactory) -> usize {
  factory
    .entries()
    .keys()
    .filter(|(entry_namespace, _)| entry_namespace == &namespace(PENDING_NAMESPACE))
    .count()
}

fn hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_fresh_start_provisions_once_and_restart_reloads_same_identity() {
  let providers = Providers::new();

  let handle = start(&providers).await;
  let calls = providers.keys.take_calls();
  let [KeyCall::Create(operation), KeyCall::PublicKey(handle_bytes)] = calls.as_slice() else {
    panic!("unexpected key calls: {calls:?}");
  };
  let operation = operation.clone();
  let handle_bytes = handle_bytes.clone();
  assert!(providers.keys.lookup_operation(&operation).is_some());
  let stored = local_identity_bytes(&providers.factory).expect("local identity stored");
  assert!(intent_keys(&providers.factory).is_empty());
  assert_eq!(pending_count(&providers.factory), 0);
  assert_eq!(providers.factory.commit_calls(), 4);
  assert_eq!(providers.factory.receipt_count(), 4);
  handle.command(Shutdown::new()).await.unwrap();
  assert_eq!(providers.storage_drops.count(), 1);
  assert_eq!(providers.factory_drops.count(), 0);
  assert_eq!(providers.key_drops.count(), 0);

  let restarted = start(&providers).await;
  assert_eq!(
    providers.keys.take_calls(),
    vec![KeyCall::PublicKey(handle_bytes.clone())],
    "restart must verify the persisted key without creating",
  );
  assert!(
    !providers
      .keys
      .take_calls()
      .iter()
      .any(|call| matches!(call, KeyCall::Create(_)))
  );
  assert_eq!(providers.factory.commit_calls(), 4);
  assert_eq!(
    local_identity_bytes(&providers.factory).as_deref(),
    Some(stored.as_slice()),
    "restart must keep the exact persisted identity",
  );
  assert!(intent_keys(&providers.factory).is_empty());
  restarted.command(Shutdown::new()).await.unwrap();
  assert_eq!(providers.storage_drops.count(), 2);

  drop(handle);
  drop(restarted);
  drop(providers.factory);
  drop(providers.keys);
  assert_eq!(providers.factory_drops.count(), 1);
  assert_eq!(providers.key_drops.count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_missing_handle_stops_before_running_without_replacement() {
  let providers = Providers::new();
  let handle = start(&providers).await;
  let calls = providers.keys.take_calls();
  let [KeyCall::Create(_), KeyCall::PublicKey(handle_bytes)] = calls.as_slice() else {
    panic!("unexpected key calls: {calls:?}");
  };
  let handle_bytes = handle_bytes.clone();
  let stored = local_identity_bytes(&providers.factory).unwrap();
  handle.command(Shutdown::new()).await.unwrap();

  let missing = Arc::new(ScriptedKeys::full());
  let error: Error = builder(
    factory_arc(&providers),
    Arc::clone(&missing),
    Arc::clone(&providers.entropy),
  )
  .start()
  .await
  .err()
  .unwrap();

  assert_eq!(error.kind(), ErrorKind::Internal);
  assert_eq!(error.context(), "key public key");
  let rendered = format!("{error:?}");
  assert!(!rendered.contains(std::str::from_utf8(&handle_bytes).unwrap()));
  assert!(!rendered.contains(&hex(&handle_bytes)));
  assert_eq!(
    missing.take_calls(),
    vec![KeyCall::PublicKey(handle_bytes)],
    "no replacement create, sign, or delete may run",
  );
  assert_eq!(providers.factory.commit_calls(), 4);
  assert_eq!(
    local_identity_bytes(&providers.factory).as_deref(),
    Some(stored.as_slice()),
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_mismatched_public_key_stops_before_running_without_replacement() {
  let providers = Providers::new();
  let handle = start(&providers).await;
  let calls = providers.keys.take_calls();
  let [KeyCall::Create(_), KeyCall::PublicKey(handle_bytes)] = calls.as_slice() else {
    panic!("unexpected key calls: {calls:?}");
  };
  let handle_bytes = handle_bytes.clone();
  handle.command(Shutdown::new()).await.unwrap();

  let mismatched = ScriptedKeys::full();
  mismatched.override_public_key(radiata::PublicKey::from_bytes(
    scripted_signing(9_999).verifying_key().to_bytes(),
  ));
  let mismatched = Arc::new(mismatched);
  let error = builder(
    factory_arc(&providers),
    Arc::clone(&mismatched),
    Arc::clone(&providers.entropy),
  )
  .start()
  .await
  .err()
  .unwrap();

  assert_eq!(error.kind(), ErrorKind::Internal);
  assert_eq!(error.context(), "key public key");
  let rendered = format!("{error:?}");
  assert!(!rendered.contains(std::str::from_utf8(&handle_bytes).unwrap()));
  assert!(!rendered.contains(&hex(&handle_bytes)));
  assert_eq!(
    mismatched.take_calls(),
    vec![KeyCall::PublicKey(handle_bytes)],
  );
  assert_eq!(providers.factory.commit_calls(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_missing_key_capabilities_refused_after_storage_probe() {
  for capabilities in [
    KeyCapabilities::new()
      .ed25519(false)
      .reconciliation(true)
      .deletion(true),
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(false)
      .deletion(true),
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(false),
    KeyCapabilities::new(),
  ] {
    let providers = Providers::new();
    let incapable = Arc::new(ScriptedKeys::new(capabilities));
    let error = builder(
      factory_arc(&providers),
      incapable,
      Arc::clone(&providers.entropy),
    )
    .start()
    .await
    .err()
    .unwrap();

    assert_eq!(error.kind(), ErrorKind::UnsupportedCapability);
    assert_eq!(error.context(), "key create");
    assert_eq!(
      providers.factory.open_calls(),
      1,
      "storage must be probed before the capability refusal",
    );
    assert_eq!(providers.factory.commit_calls(), 0);
    assert!(local_identity_bytes(&providers.factory).is_none());
    assert!(intent_keys(&providers.factory).is_empty());
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_create_unknown_restart_reconciles_the_same_operation() {
  let providers = Providers::new();
  providers
    .keys
    .push_create_script(CreateScript::ApplyReportUnknown);

  let error = providers.builder().start().await.err().unwrap();
  assert_eq!(error.kind(), ErrorKind::CommitUnknown);
  assert_eq!(error.context(), "key create");
  let first_calls = providers.keys.take_calls();
  let [KeyCall::Create(operation)] = first_calls.as_slice() else {
    panic!("unexpected key calls: {first_calls:?}");
  };
  let operation: KeyOperationId = operation.clone();
  assert_eq!(
    intent_keys(&providers.factory),
    vec![operation.as_str().as_bytes().to_vec()],
    "exactly one intent must persist for the failed operation",
  );
  assert!(local_identity_bytes(&providers.factory).is_none());
  assert_eq!(pending_count(&providers.factory), 0);
  assert_eq!(providers.factory.commit_calls(), 1);

  let handle = start(&providers).await;
  let created = providers.keys.lookup_operation(&operation).unwrap();
  let restart_calls = providers.keys.take_calls();
  assert_eq!(
    restart_calls,
    vec![
      KeyCall::ReconcileCreate(operation),
      KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
    ],
    "restart must reconcile the same operation without a duplicate create",
  );
  assert!(local_identity_bytes(&providers.factory).is_some());
  assert!(intent_keys(&providers.factory).is_empty());
  assert_eq!(providers.factory.commit_calls(), 4);
  handle.command(Shutdown::new()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_finalize_unknown_applied_recovers_journal_on_restart() {
  let providers = Providers::new();
  let fault = Arc::new(FaultingFactory::new(
    Arc::clone(&providers.factory),
    vec![CommitFault::Pass, CommitFault::UnknownApplied],
  ));
  fault.add_reconcile_unknowns(1);

  let error = builder(
    fault_factory(&fault),
    Arc::clone(&providers.keys),
    Arc::clone(&providers.entropy),
  )
  .start()
  .await
  .err()
  .unwrap();
  assert_eq!(error.kind(), ErrorKind::CommitUnknown);
  assert_eq!(error.context(), "storage reconcile");
  let calls = providers.keys.take_calls();
  let [KeyCall::Create(_), KeyCall::PublicKey(handle_bytes)] = calls.as_slice() else {
    panic!("unexpected key calls: {calls:?}");
  };
  let handle_bytes = handle_bytes.clone();
  assert!(
    local_identity_bytes(&providers.factory).is_some(),
    "the applied finalize must persist the identity",
  );
  assert!(intent_keys(&providers.factory).is_empty());
  assert_eq!(pending_count(&providers.factory), 1);
  assert_eq!(providers.factory.commit_calls(), 2);

  let handle = builder(
    fault_factory(&fault),
    Arc::clone(&providers.keys),
    Arc::clone(&providers.entropy),
  )
  .start()
  .await
  .unwrap();
  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  assert_eq!(
    providers.keys.take_calls(),
    vec![KeyCall::PublicKey(handle_bytes)],
    "recovery reconciles the journal, cleans pending, and verifies the key",
  );
  assert_eq!(pending_count(&providers.factory), 0);
  assert_eq!(providers.factory.commit_calls(), 4);
  handle.command(Shutdown::new()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_finalize_unknown_not_applied_resumes_intent_on_restart() {
  let providers = Providers::new();
  let fault = Arc::new(FaultingFactory::new(
    Arc::clone(&providers.factory),
    vec![CommitFault::Pass, CommitFault::UnknownNotApplied],
  ));

  let error = builder(
    fault_factory(&fault),
    Arc::clone(&providers.keys),
    Arc::clone(&providers.entropy),
  )
  .start()
  .await
  .err()
  .unwrap();
  assert_eq!(error.kind(), ErrorKind::Conflict);
  assert_eq!(error.context(), "local identity finalize");
  let calls = providers.keys.take_calls();
  let [KeyCall::Create(operation), KeyCall::PublicKey(_)] = calls.as_slice() else {
    panic!("unexpected key calls: {calls:?}");
  };
  let operation = operation.clone();
  assert_eq!(intent_keys(&providers.factory).len(), 1);
  assert!(local_identity_bytes(&providers.factory).is_none());
  assert_eq!(pending_count(&providers.factory), 0);

  let handle = builder(
    fault_factory(&fault),
    Arc::clone(&providers.keys),
    Arc::clone(&providers.entropy),
  )
  .start()
  .await
  .unwrap();
  assert_eq!(
    handle.query(GetNodeStatus::new()).await.unwrap(),
    NodeStatus::Running,
  );
  let created = providers.keys.lookup_operation(&operation).unwrap();
  assert_eq!(
    providers.keys.take_calls(),
    vec![
      KeyCall::ReconcileCreate(operation),
      KeyCall::PublicKey(created.handle().expose_provider_handle().to_vec()),
    ],
    "restart must resume the intent without a duplicate create",
  );
  assert!(local_identity_bytes(&providers.factory).is_some());
  assert!(intent_keys(&providers.factory).is_empty());
  assert_eq!(providers.factory.commit_calls(), 4);
  handle.command(Shutdown::new()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_runtime_storage_corruption_error_never_leaks_handle_bytes() {
  let providers = Providers::new();
  let handle = start(&providers).await;
  let calls = providers.keys.take_calls();
  let [KeyCall::Create(_), KeyCall::PublicKey(handle_bytes)] = calls.as_slice() else {
    panic!("unexpected key calls: {calls:?}");
  };
  let handle_bytes = handle_bytes.clone();
  handle.command(Shutdown::new()).await.unwrap();

  providers.factory.inject_entry(
    namespace(KEY_CREATION_INTENT_NAMESPACE),
    StoreKey::new(Arc::from(b"orphaned-intent".as_slice())),
    b"not a key creation intent".to_vec(),
  );
  let error = providers.builder().start().await.err().unwrap();

  assert_eq!(error.kind(), ErrorKind::StorageCorrupt);
  assert_eq!(error.context(), "storage snapshot");
  let rendered = format!("{error:?}");
  assert!(!rendered.contains(std::str::from_utf8(&handle_bytes).unwrap()));
  assert!(!rendered.contains(&hex(&handle_bytes)));
  assert!(!rendered.contains("not a key creation intent"));
  assert_eq!(
    providers.keys.take_calls(),
    vec![],
    "corrupt discovery must fail before any key call",
  );
}
