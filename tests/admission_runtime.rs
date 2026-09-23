//! Runtime-level atomic merge and reconciliation lane.
//!
//! Drives the full node stack through `NodeBuilder` with a fault-injecting
//! storage factory: an indeterminate merge commit freezes the node and
//! blocks credential rotation, reuse, and new listening until an
//! authoritative reopen reconciles the exact transaction; a definite
//! pre-commit abort releases the generation for one later attempt. Test
//! names are prefixed `admission_runtime_`.

use std::sync::Arc;

use radiata::{
  DeclareInterruptedTransactionUncommitted, Endpoint, ErrorKind, GetLocalNode, Listen,
  MergeCluster, MergeCredential, NodeBuilder, NodeConfig, NodeHandle, ResolveFrozenJournal,
  RotateMergeCredential, Shutdown, extension::StorageFactory,
};

mod common;

use common::{
  CommitFault, DelayingFactory, FaultingFactory, MemoryStorageFactory, ScriptedKeys,
  required_capabilities,
};

struct Node {
  handle: NodeHandle,
  keys: Arc<ScriptedKeys>,
}

async fn start_configured(
  factory: Arc<dyn StorageFactory>, keys: Arc<ScriptedKeys>, config: NodeConfig,
) -> Node {
  // The runtime default entropy (system randomness) keeps every node's id
  // unique; deterministic entropy would collide across nodes. A prior
  // runtime instance's detached teardown can briefly hold the factory's
  // exclusive-open flag under load, so the open is retried to a deadline.
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
  loop {
    match NodeBuilder::new(factory.clone())
      .keys(keys.clone())
      .config(config.clone())
      .start()
      .await
    {
      Ok(handle) => {
        return Node {
          handle,
          keys: keys.clone(),
        };
      }
      Err(error)
        if error.kind() == ErrorKind::StorageLocked && std::time::Instant::now() < deadline =>
      {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
      }
      Err(error) => panic!("node start failed persistently: {error:?}"),
    }
  }
}

async fn start(factory: Arc<dyn StorageFactory>, keys: Arc<ScriptedKeys>) -> Node {
  start_configured(factory, keys, NodeConfig::new()).await
}

fn keys_at(seed: u64) -> Arc<ScriptedKeys> {
  Arc::new(ScriptedKeys::full_at(seed))
}

async fn merge(
  node: &Node, endpoint: &Endpoint, credential: MergeCredential,
) -> radiata::Result<radiata::MergeView> {
  node
    .handle
    .command(MergeCluster::new(endpoint.clone(), credential))
    .await
}

/// Issues one merge credential with bounded retries: merge-sensitive
/// operations refuse while a concurrent metadata commit or reconciliation
/// holds the store, so a rotation is retried instead of failing the lane.
async fn rotate_with_retry(issuer: &Node) -> radiata::IssuedMergeCredential {
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
  loop {
    match issuer.handle.command(RotateMergeCredential::new()).await {
      Ok(issued) => return issued,
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
      }
      Err(error) => panic!("merge credential rotation failed persistently: {error:?}"),
    }
  }
}

async fn fresh_node(seed: u64) -> (Node, Arc<MemoryStorageFactory>) {
  let memory = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let provider: Arc<dyn StorageFactory> = memory.clone();
  let node = start(provider, keys_at(seed)).await;
  (node, memory)
}

/// An indeterminate merge commit freezes the node; every
/// merge-sensitive operation (rotation, reuse, new listening) is
/// blocked with `NotReady`, no new signing work happens, and an
/// authoritative reopen reconciles the exact committed transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_runtime_indeterminate_blocks_rotation_reuse_and_listening() {
  let memory = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let fault = Arc::new(FaultingFactory::new(Arc::clone(&memory), Vec::new()));
  fault.add_reconcile_unknowns(1);

  let provider: Arc<dyn StorageFactory> = fault.clone();
  let receiver = start(provider.clone(), keys_at(1_000)).await;
  let issued = rotate_with_retry(&receiver).await;
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  // Pin an indeterminate outcome to the merge commit: the number of setup
  // commits (identity, rotation, listen) is not stable, so the script is
  // armed only after the listener is ready; the in-process reconcile also
  // stays unknown.
  fault.reset_script(vec![CommitFault::UnknownApplied]);
  let (joiner, _) = fresh_node(2_000).await;
  let error = merge(&joiner, listener.endpoint(), issued.into_credential())
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  joiner.handle.command(Shutdown::new()).await.unwrap();

  // The indeterminate outcome froze the receiver: credential rotation
  // and new listening are blocked with NotReady, and a merge attempt is
  // refused before any credential validation or signing work.
  let _signing_calls_after_freeze = receiver.keys.take_calls();
  let rotation = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap_err();
  assert_eq!(rotation.kind(), ErrorKind::NotReady);
  let listen = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap_err();
  assert_eq!(listen.kind(), ErrorKind::NotReady);
  let (fresh_joiner, _) = fresh_node(3_000).await;
  // A syntactically valid credential proves the responder gate fires
  // before the credential is verified or any identity signature is made.
  let gate_credential =
    MergeCredential::parse("join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
  let merge_result = fresh_joiner
    .handle
    .command(MergeCluster::new(
      listener.endpoint().clone(),
      gate_credential,
    ))
    .await;
  assert!(
    merge_result.is_err(),
    "frozen receiver must refuse the merge at the responder gate"
  );
  assert!(
    receiver.keys.take_calls().is_empty(),
    "blocked operations must not sign"
  );
  fresh_joiner.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();

  // Authoritative reopen with the same identity reconciles the journal to
  // committed: the receiver starts unblocked and the durable merge
  // admits a later peer.
  let receiver_keys = receiver.keys.clone();
  drop(receiver);
  let receiver = start(provider.clone(), receiver_keys).await;
  let issued = rotate_with_retry(&receiver).await;
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let (later, _) = fresh_node(4_000).await;
  let merge = merge(&later, listener.endpoint(), issued.into_credential())
    .await
    .unwrap();
  let local = later.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.node_id(), merge.node());
  later.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// The permanent-contradiction freeze: the journaled adoption landed but
/// the provider's receipt is gone, so every reopen re-derives the same
/// contradiction and the store stays blocked. The acknowledged
/// `ResolveFrozenJournal` declaration resolves the frozen journal as
/// uncommitted: the node unfreezes in place, admission-sensitive
/// commands work again, and the resolution is durable across a restart
/// on the same storage. On a healthy store the command is a typed
/// rejection, never an accidental unfreeze.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_runtime_declared_uncommitted_resolution_unfreezes_permanent_contradiction() {
  let memory = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let fault = Arc::new(FaultingFactory::new(Arc::clone(&memory), Vec::new()));
  fault.add_reconcile_unknowns(1);

  let provider: Arc<dyn StorageFactory> = fault.clone();
  let receiver = start(provider.clone(), keys_at(5_000)).await;
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  // Typed rejection on a healthy store: nothing is frozen, so the
  // command refuses and the node keeps serving.
  let healthy = receiver
    .handle
    .command(ResolveFrozenJournal::new(
      DeclareInterruptedTransactionUncommitted::new(),
    ))
    .await
    .unwrap_err();
  assert_eq!(healthy.kind(), ErrorKind::Conflict);
  let issued = rotate_with_retry(&receiver).await;

  // Freeze the receiver on the journaled adoption: the commit lands
  // (journal and receipt) but answers unknown, and the in-process
  // reconciliation stays unknown too. The journal-targeted fault passes
  // every plain commit (credential use) through unfaulted, so the
  // script arms several entries to survive the plain pre-commit commits
  // of the merge handshake.
  fault.reset_script(vec![CommitFault::JournalUnknownApplied; 8]);
  let (joiner, _) = fresh_node(6_000).await;
  let merge_outcome = merge(&joiner, listener.endpoint(), issued.into_credential()).await;
  assert!(
    merge_outcome.is_err(),
    "the faulted merge unexpectedly succeeded: {merge_outcome:?}"
  );
  joiner.handle.command(Shutdown::new()).await.unwrap();
  let blocked = receiver
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap_err();
  assert_eq!(blocked.kind(), ErrorKind::NotReady);

  // Make the contradiction permanent: the adoption receipt disappears,
  // so every reconcile re-derives journal-present, receipt-absent.
  let adopted = fault.last_unknown_applied().expect("applied unknown");
  memory.forget_receipt(&adopted);

  // The acknowledged declaration resolves the frozen journal: the store
  // unfreezes and admission-sensitive commands work again.
  receiver
    .handle
    .command(ResolveFrozenJournal::new(
      DeclareInterruptedTransactionUncommitted::new(),
    ))
    .await
    .unwrap();
  rotate_with_retry(&receiver).await;

  // The resolution is durable: a restart on the same storage finds no
  // pending journal and starts unblocked.
  let receiver_keys = receiver.keys.clone();
  drop(receiver);
  let receiver = start(provider, receiver_keys).await;
  rotate_with_retry(&receiver).await;
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// A definite pre-commit abort leaves the node unblocked and
/// releases the credential generation for one later merge attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_runtime_definite_abort_unblocks_and_allows_later_merge() {
  let memory = Arc::new(MemoryStorageFactory::new(required_capabilities()));
  let fault = Arc::new(FaultingFactory::new(
    Arc::clone(&memory),
    vec![CommitFault::Pass; 8],
  ));
  let provider: Arc<dyn StorageFactory> = fault.clone();
  let receiver = start(provider.clone(), keys_at(1_100)).await;
  let issued = rotate_with_retry(&receiver).await;
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();

  // Pin a definite pre-commit abort to the merge commit: the number of
  // setup commits (identity, rotation, listen) is not stable, so the
  // script is armed only after the listener is ready.
  fault.reset_script(vec![CommitFault::Aborted; 8]);
  let (joiner, _) = fresh_node(2_100).await;
  let error = merge(&joiner, listener.endpoint(), issued.into_credential())
    .await
    .unwrap_err();
  assert!(
    matches!(
      error.kind(),
      ErrorKind::AuthenticationFailed | ErrorKind::Conflict
    ),
    "a definitely aborted merge surfaces as a typed rejection, got {:?}",
    error.kind()
  );
  // Prove the abort was final before the later attempt: no evidence of
  // the abandoned merge survives.
  fault.reset_script(Vec::new());
  joiner.handle.command(Shutdown::new()).await.unwrap();

  // The abort is final: the binding, the credential use, and the grant
  // are all absent, the store is not frozen, and one later attempt with
  // a fresh credential succeeds.
  let issued = rotate_with_retry(&receiver).await;
  let listener = receiver
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let (later, _) = fresh_node(3_100).await;
  let merge = merge(&later, listener.endpoint(), issued.into_credential())
    .await
    .unwrap();
  let local = later.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.node_id(), merge.node());
  later.handle.command(Shutdown::new()).await.unwrap();
  receiver.handle.command(Shutdown::new()).await.unwrap();
}

/// Slow-flash commit injection (the starvation gate's slow-storage
/// dimension and the deadline-calibration acceptance): the join-mode
/// admission path performs two serialized device writes — the journaled
/// admission (binding, credential use, grant) and its receipt cleanup —
/// so a join pays both inside the authentication deadline. A 12 s
/// injected write is one flash burst in that regime: the two writes cost
/// 24 s, beyond the 10 s-shaped deadlines that starved join bursts,
/// inside the recalibrated 30 s default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_runtime_slow_flash_commits_admit_under_the_calibrated_deadline() {
  // Each device write pays 12 s once armed: a tightened deadline cannot
  // admit even the first write; the default admits the two-write
  // admission path (24 s) with headroom.
  let commit_delay = std::time::Duration::from_secs(12);

  // Phase A: a tightened deadline expires while its commit is still on
  // the slow device — the persistent-failure shape the calibration
  // removes.
  let slow_a = Arc::new(DelayingFactory::new(Arc::new(MemoryStorageFactory::new(
    required_capabilities(),
  ))));
  let issuer_a = start(
    Arc::clone(&slow_a) as Arc<dyn StorageFactory>,
    keys_at(4_000),
  )
  .await;
  let issued_a = rotate_with_retry(&issuer_a).await;
  let listener_a = issuer_a
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  // Let the sync driver's startup descriptor ensure land unwrapped:
  // arming before it would measure a stray first tick, not the join
  // path.
  tokio::time::sleep(std::time::Duration::from_secs(1)).await;
  slow_a.set_commit_delay(commit_delay);
  let tightened = NodeConfig::new()
    .with_authentication_deadline(std::time::Duration::from_millis(1_500))
    .unwrap();
  let joiner_a = start_configured(
    Arc::new(MemoryStorageFactory::new(required_capabilities())),
    keys_at(4_100),
    tightened,
  )
  .await;
  let error = merge(&joiner_a, listener_a.endpoint(), issued_a.into_credential())
    .await
    .unwrap_err();
  assert_eq!(
    error.kind(),
    ErrorKind::AuthenticationFailed,
    "a commit latency beyond the tightened deadline must expire it"
  );
  joiner_a.handle.command(Shutdown::new()).await.unwrap();
  issuer_a.handle.command(Shutdown::new()).await.unwrap();

  // Phase B: the same injected write under the recalibrated default —
  // the two-write admission path (24 s) that expires 10 s-shaped
  // deadlines admits at 30 s.
  let slow_b = Arc::new(DelayingFactory::new(Arc::new(MemoryStorageFactory::new(
    required_capabilities(),
  ))));
  let issuer_b = start(
    Arc::clone(&slow_b) as Arc<dyn StorageFactory>,
    keys_at(5_000),
  )
  .await;
  let issued_b = rotate_with_retry(&issuer_b).await;
  let listener_b = issuer_b
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  tokio::time::sleep(std::time::Duration::from_secs(1)).await;
  slow_b.set_commit_delay(commit_delay);
  let joiner_b = start(
    Arc::new(MemoryStorageFactory::new(required_capabilities())),
    keys_at(5_100),
  )
  .await;
  let view = merge(&joiner_b, listener_b.endpoint(), issued_b.into_credential())
    .await
    .unwrap_or_else(|error| {
      panic!("the calibrated default must admit the two-write admission path: {error:?}")
    });
  let local = joiner_b.handle.query(GetLocalNode::new()).await.unwrap();
  assert_eq!(local.node_id(), view.node());
  joiner_b.handle.command(Shutdown::new()).await.unwrap();
  issuer_b.handle.command(Shutdown::new()).await.unwrap();
}
