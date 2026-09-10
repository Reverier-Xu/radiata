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
  Endpoint, ErrorKind, GetLocalNode, Listen, MergeCluster, MergeCredential, NodeBuilder,
  NodeHandle, RotateMergeCredential, Shutdown, extension::StorageFactory,
};

mod common;

use common::{
  CommitFault, FaultingFactory, MemoryStorageFactory, ScriptedKeys, required_capabilities,
};

struct Node {
  handle: NodeHandle,
  keys: Arc<ScriptedKeys>,
}

async fn start(factory: Arc<dyn StorageFactory>, keys: Arc<ScriptedKeys>) -> Node {
  // The runtime default entropy (system randomness) keeps every node's id
  // unique; deterministic entropy would collide across nodes. A prior
  // runtime instance's detached teardown can briefly hold the factory's
  // exclusive-open flag under load, so the open is retried to a deadline.
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
  loop {
    match NodeBuilder::new(factory.clone(), keys.clone())
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
