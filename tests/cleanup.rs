//! Public-API integration tests for the dead-node cleanup family.
//!
//! Every test drives the facade only: `CleanupNode` issues a convergent
//! issuer-signed removal tombstone that syncs to every member, excludes
//! the subject from new sessions and re-merges, and keeps the subject's
//! binding as permanent verification evidence; `PurgeRevocation` clears a
//! local revocation record explicitly.

use std::{sync::Arc, time::Duration};

use radiata::{
  CleanupNode, ConnectMember, Endpoint, ErrorKind, Listen, MemberStatus, MergeCluster,
  MergeCredential, NodeBuilder, NodeConfig, NodeHandle, NodeId, PageMembers, PageSpec, PageTrust,
  PurgeRevocation, RevokeNode, RotateMergeCredential, Shutdown, extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
}

async fn start_node(seed: u64) -> Node {
  {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
      tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=trace"))
        .with_test_writer()
        .init();
    });
  }
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(900_000 + seed * 1_000));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap();
  let handle = NodeBuilder::new(storage, keys)
    .config(config)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
  }
}

async fn listen(node: &Node) -> Endpoint {
  let listener = node
    .handle
    .command(Listen::new(node.endpoint.clone()))
    .await
    .unwrap();
  listener.endpoint().clone()
}

async fn local_id(node: &NodeHandle) -> NodeId {
  node
    .query(radiata::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone()
}

/// The member's trusted public key as the issuer observes it, polled with
/// a bound (bindings converge through the merge and ordinary sync).
async fn trusted_key(issuer: &NodeHandle, member: &NodeId) -> radiata::PublicKey {
  // The bound covers loaded CI runners (the macOS lane shares one box
  // with the whole suite), where convergence samples are starved for
  // tens of seconds.
  let deadline = std::time::Instant::now() + Duration::from_secs(90);
  loop {
    // Schedule the next convergence observation: one deterministic
    // anti-entropy round on the observer instead of the wall-clock tick.
    issuer.command(radiata::RunSyncRound::new()).await.unwrap();
    let page = issuer
      .query(PageTrust::new(PageSpec::first(64).unwrap()))
      .await
      .unwrap();
    if let Some(view) = page.items().iter().find(|view| view.node_id() == member) {
      return view.public_key().clone();
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(90),
      "member {member} must be trusted"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
}

/// One cleanup tombstone converges to an observer through
/// ordinary sync, the subject's binding stays as permanent evidence, the
/// subject is refused new member sessions and re-merges everywhere, and
/// cleaning an unknown or the own node fails with a typed error.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn cleanup_converges_and_excludes_the_subject() {
  let issuer = start_node(1).await;
  let issuer_endpoint = listen(&issuer).await;
  let issuer_id = local_id(&issuer.handle).await;

  let subject = start_node(2).await;
  let subject_endpoint = listen(&subject).await;
  common::merge_with_retry(&subject.handle, &issuer.handle, issuer_endpoint.clone()).await;
  let subject_id = local_id(&subject.handle).await;
  let subject_key = trusted_key(&issuer.handle, &subject_id).await;

  let observer = start_node(3).await;
  common::merge_with_retry(&observer.handle, &issuer.handle, issuer_endpoint.clone()).await;
  // The observer converges the subject's binding before the cleanup, so
  // the tombstone applies on arrival rather than waiting a resend cycle.
  trusted_key(&observer.handle, &subject_id).await;

  // Self-cleanup and unknown-subject cleanup fail with typed errors.
  assert_eq!(
    issuer
      .handle
      .command(CleanupNode::new(issuer_id.clone()))
      .await
      .unwrap_err()
      .kind(),
    ErrorKind::InvalidInput
  );
  let stranger = NodeId::parse("node_999999999999999999999").unwrap();
  assert_eq!(
    issuer
      .handle
      .command(CleanupNode::new(stranger))
      .await
      .unwrap_err()
      .kind(),
    ErrorKind::NotFound
  );

  issuer
    .handle
    .command(CleanupNode::new(subject_id.clone()))
    .await
    .unwrap();

  // The tombstone converges to the observer through ordinary sync: a new
  // member session to the cleaned subject is refused once the record
  // arrives (the refusal happens before any dial).
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let refused = observer
      .handle
      .command(ConnectMember::new(
        subject_endpoint.clone(),
        subject_id.clone(),
      ))
      .await
      .is_err_and(|error| error.kind() == ErrorKind::NotTrusted);
    if refused {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "observer never refused the cleaned subject"
    );
    // The tombstone converges through ordinary sync: schedule the next
    // observation round on the observer.
    observer
      .handle
      .command(radiata::RunSyncRound::new())
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
  }

  // The member page annotates the cleaned subject instead of leaving it
  // indistinguishable from a live member: the record is on the observer,
  // so the page must report Cleaned, never Active.
  let annotated = tokio::time::timeout(Duration::from_secs(10), async {
    loop {
      let status = observer
        .handle
        .query(PageMembers::new(PageSpec::first(64).unwrap()))
        .await
        .unwrap()
        .items()
        .iter()
        .find(|member| member.node_id() == &subject_id)
        .map(|member| member.status());
      if status == Some(MemberStatus::Cleaned) {
        break;
      }
      assert!(
        status != Some(MemberStatus::Active),
        "the cleaned subject is still reported as an active member"
      );
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
  })
  .await;
  assert!(
    annotated.is_ok(),
    "the cleaned subject never surfaced as Cleaned on the member page"
  );

  // The issuer refuses the cleaned subject's re-merge even with a fresh
  // credential.
  let issued = issuer
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  let error = subject
    .handle
    .command(MergeCluster::new(
      issuer_endpoint.clone(),
      MergeCredential::parse(&secret).unwrap(),
    ))
    .await
    .unwrap_err();
  // The responder's cleaned-subject rejection crosses the wire as the
  // generic authentication failure (no handshake detail leaks).
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);

  // The subject's binding remains as permanent verification evidence.
  let page = issuer
    .handle
    .query(PageTrust::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap();
  assert!(
    page
      .items()
      .iter()
      .any(|view| view.node_id() == &subject_id && view.public_key() == &subject_key)
  );

  for node in [&issuer, &subject, &observer] {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

/// `PurgeRevocation` clears the local revocation record
/// explicitly and idempotently; the revoked member's sessions work again
/// afterwards (fat-finger recovery).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purge_revocation_clears_the_local_boundary() {
  let issuer = start_node(11).await;
  let issuer_endpoint = listen(&issuer).await;

  let member = start_node(12).await;
  let member_endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint.clone()).await;
  let member_id = local_id(&member.handle).await;
  let member_key = trusted_key(&issuer.handle, &member_id).await;

  issuer
    .handle
    .command(RevokeNode::new(member_id.clone(), member_key))
    .await
    .unwrap();
  let error = issuer
    .handle
    .command(ConnectMember::new(
      member_endpoint.clone(),
      member_id.clone(),
    ))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Revoked);

  // Purge is idempotent and restores the local boundary.
  issuer
    .handle
    .command(PurgeRevocation::new(member_id.clone()))
    .await
    .unwrap();
  issuer
    .handle
    .command(PurgeRevocation::new(member_id.clone()))
    .await
    .unwrap();
  issuer
    .handle
    .command(ConnectMember::new(member_endpoint.clone(), member_id))
    .await
    .unwrap();

  issuer.handle.command(Shutdown::new()).await.unwrap();
  member.handle.command(Shutdown::new()).await.unwrap();
}

/// The issuer cleans a member and starts the GC epoch;
/// the checkpoint command is idempotent under max-wins, and the cluster
/// stays fully compositional afterwards (a later merge still converges).
/// The sweep and filter mechanics themselves are unit-covered; through
/// the facade the observable contract is that checkpointing never breaks
/// convergence and never gates live entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn checkpoint_converges_and_keeps_the_cluster_compositional() {
  let issuer = start_node(21).await;
  let issuer_endpoint = listen(&issuer).await;

  let subject = start_node(22).await;
  common::merge_with_retry(&subject.handle, &issuer.handle, issuer_endpoint.clone()).await;
  let subject_id = local_id(&subject.handle).await;
  let subject_key = trusted_key(&issuer.handle, &subject_id).await;

  let observer = start_node(23).await;
  let _observer_endpoint = listen(&observer).await;
  common::merge_with_retry(&observer.handle, &issuer.handle, issuer_endpoint.clone()).await;
  let _observer_id = local_id(&observer.handle).await;

  // Clean the subject, then start the epoch. Max-wins: the second issue
  // never rolls the watermark back.
  issuer
    .handle
    .command(CleanupNode::new(subject_id.clone()))
    .await
    .unwrap();
  let first = issuer
    .handle
    .command(radiata::IssueCleanupCheckpoint::new())
    .await
    .unwrap();
  let second = issuer
    .handle
    .command(radiata::IssueCleanupCheckpoint::new())
    .await
    .unwrap();
  assert!(second >= first, "the watermark is monotonic");

  // The observer also issues: the epoch converges through sync and stays
  // monotonic across issuers (any member may checkpoint).
  let on_observer = observer
    .handle
    .command(radiata::IssueCleanupCheckpoint::new())
    .await
    .unwrap();
  assert!(on_observer >= first);

  // The cluster stays compositional after checkpointing: a fresh node
  // still merges in and converges.
  let late = start_node(24).await;
  common::merge_with_retry(&late.handle, &issuer.handle, issuer_endpoint.clone()).await;
  let late_id = local_id(&late.handle).await;
  let _ = trusted_key(&observer.handle, &late_id).await;

  // The cleaned subject's binding stays as permanent evidence everywhere.
  let page = observer
    .handle
    .query(PageTrust::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap();
  assert!(
    page
      .items()
      .iter()
      .any(|view| view.node_id() == &subject_id && view.public_key() == &subject_key),
    "the cleaned subject's binding stays as permanent evidence"
  );

  for node in [&issuer, &subject, &observer, &late] {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}
