//! Public-API integration tests for authorization revocation (T-G09-04,
//! SC-G09-P0-13/14).
//!
//! Every test drives the facade only: `RevokeNode` durably revokes one
//! exact binding, closes its sessions, and denies its new sessions,
//! admissions, and dials — while stored metadata stays eligible for
//! ordinary sync and unrelated members are untouched.

use std::{sync::Arc, time::Duration};

use radiata::{
  Endpoint, ErrorKind, EventOptions, EventReceive, Listen, MergeCluster, MergeCredential,
  NodeBuilder, NodeConfig, NodeHandle, NodeId, NodeRevoked, PageSpec, PageTrust, PutResource,
  ResourceLabels, ResourceName, ResourceUri, ResourceWrite, RevokeNode, RotateMergeCredential,
  SelectResources, Selector, Shutdown, TrustStatus, extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
  id: NodeId,
}

async fn start_node(seed: u64) -> Node {
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(800_000 + seed * 1_000));
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
    id: NodeId::parse("node_000000000000000000000").unwrap(), // replaced by node_id()
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

/// The member's trusted public key as the issuer observes it. Trust
/// bindings arrive through the admission commit and ordinary sync, so the
/// observation is polled with a bound.
async fn trusted_key(issuer: &NodeHandle, member: &NodeId) -> radiata::PublicKey {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let page = issuer
      .query(PageTrust::new(PageSpec::first(64).unwrap()))
      .await
      .unwrap();
    if let Some(view) = page.items().iter().find(|view| view.node_id() == member) {
      return view.public_key().clone();
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "member {member} must be trusted"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

/// The member's trust status as the issuer observes it.
async fn trust_status(issuer: &NodeHandle, member: &NodeId) -> Option<TrustStatus> {
  issuer
    .query(PageTrust::new(PageSpec::first(64).unwrap()))
    .await
    .unwrap()
    .items()
    .iter()
    .find(|view| view.node_id() == member)
    .map(|view| view.status())
}

fn write(name_seed: u8) -> PutResource {
  PutResource::new(ResourceWrite::new(
    ResourceName::parse(&format!(
      "radiata.woooo.tech/resources/revoke-{name_seed:03}"
    ))
    .unwrap(),
    ResourceLabels::new(
      radiata::LabelValue::parse("document").unwrap(),
      ResourceUri::parse(&format!("file:///revoke/{name_seed:03}")).unwrap(),
    ),
  ))
  .unwrap()
}

async fn selected_names(node: &NodeHandle) -> Vec<String> {
  let page = node
    .query(SelectResources::new(
      Selector::parse("radiata.woooo.tech/resources/type").unwrap(),
      PageSpec::first(64).unwrap(),
    ))
    .await
    .unwrap();
  page
    .items()
    .iter()
    .map(|view| view.name().as_str().to_owned())
    .collect()
}

/// SC-G09-P0-13/14: the durable revoke commits the exact binding, closes
/// the identity's session, emits one event, denies redial and rejoin, and
/// preserves the revoked member's committed metadata.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g9_revoke_closes_sessions_denies_reconnect_and_preserves_metadata() {
  let issuer = start_node(0).await;
  let issuer_endpoint = listen(&issuer).await;
  let issuer_id = local_id(&issuer.handle).await;

  let mut member = start_node(1).await;
  member.endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;
  member.id = local_id(&member.handle).await;

  // The member commits a resource the issuer converges on before the
  // revoke (delayed content must stay eligible afterwards).
  member.handle.command(write(1)).await.unwrap();
  let member_resource = "radiata.woooo.tech/resources/revoke-001".to_owned();
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  while !selected_names(&issuer.handle)
    .await
    .contains(&member_resource)
  {
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "no resource sync"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  let member_key = trusted_key(&issuer.handle, &member.id).await;
  let mut events = issuer
    .handle
    .events::<NodeRevoked>(EventOptions::new())
    .unwrap();

  let outcome = issuer
    .handle
    .command(RevokeNode::new(member.id.clone(), member_key.clone()))
    .await
    .unwrap();
  assert_eq!(outcome.subject(), &member.id);
  assert!(!outcome.was_already_revoked());

  // Exactly one event for the transition.
  let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .unwrap()
    .unwrap();
  match event {
    EventReceive::Item(revoked) => assert_eq!(revoked.subject(), &member.id),
    _ => panic!("expected the revocation event"),
  }
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));

  // The trust view marks the exact binding revoked; the binding stays.
  assert_eq!(
    trust_status(&issuer.handle, &member.id).await,
    Some(TrustStatus::Revoked)
  );
  assert_eq!(
    trust_status(&issuer.handle, &issuer_id).await,
    Some(TrustStatus::Trusted),
    "unrelated members are untouched"
  );

  // New dials to the revoked identity fail with the typed revocation.
  let error = issuer
    .handle
    .command(radiata::ConnectMember::new(
      member.endpoint.clone(),
      member.id.clone(),
    ))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Revoked);

  // The revoked identity's new join admission is rejected. The member's
  // own facade refuses first (one node joins one cluster), and the
  // responder-side revocation check rejects a revoked subject's join
  // after a leave (T-G09-06 exercises that path): every lane fails
  // closed, never with admission.
  let rejoin = async {
    let issued = issuer
      .handle
      .command(RotateMergeCredential::new())
      .await
      .unwrap();
    let credential = MergeCredential::parse(issued.credential().expose_secret()).unwrap();
    member
      .handle
      .command(MergeCluster::new(listen(&issuer).await, credential))
      .await
  };
  let error = rejoin.await.unwrap_err();
  assert!(
    matches!(
      error.kind(),
      ErrorKind::Revoked | ErrorKind::AuthenticationFailed | ErrorKind::Conflict
    ),
    "revoked rejoin must fail closed, got {error:?}"
  );
  // The failed rejoin consumed the credential generation's reservation
  // but admitted nothing: the member is still revoked and sessionless.
  assert_eq!(
    trust_status(&issuer.handle, &member.id).await,
    Some(TrustStatus::Revoked)
  );

  // The revoked member's committed resource stays selectable: revoke is
  // an authorization boundary, not content erasure.
  assert!(
    selected_names(&issuer.handle)
      .await
      .contains(&member_resource)
  );

  // The session stays down: after several maintenance intervals the
  // member is still not connected.
  tokio::time::sleep(SYNC_INTERVAL * 6).await;
  let members = issuer
    .handle
    .query(radiata::PageMembers::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  let member_view = members
    .items()
    .iter()
    .find(|view| view.node_id() == &member.id)
    .expect("the descriptor stays stored");
  assert_eq!(
    member_view.connectivity(),
    radiata::ConnectivityStatus::Reachable,
    "the revoked member keeps its stored descriptor without a session"
  );

  for node in [issuer, member] {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

/// SC-G09-P0-13: revocation is exact and idempotent — an unknown subject
/// is not found, a substituted key conflicts, and a repeated exact revoke
/// reports no new transition and emits no second event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g9_revoke_is_exact_and_idempotent() {
  let issuer = start_node(0).await;
  let issuer_endpoint = listen(&issuer).await;

  let mut member = start_node(1).await;
  member.endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;
  member.id = local_id(&member.handle).await;
  let member_key = trusted_key(&issuer.handle, &member.id).await;

  let mut events = issuer
    .handle
    .events::<NodeRevoked>(EventOptions::new())
    .unwrap();

  // Unknown subject: nothing trusted to revoke.
  let unknown = NodeId::parse("node_000000000000000000099").unwrap();
  assert_eq!(
    issuer
      .handle
      .command(RevokeNode::new(unknown, member_key.clone()))
      .await
      .unwrap_err()
      .kind(),
    ErrorKind::NotFound
  );
  // Substituted key: the exact-binding condition fails closed.
  let wrong_key = radiata::PublicKey::from_bytes([0xEE; 32]);
  assert_eq!(
    issuer
      .handle
      .command(RevokeNode::new(member.id.clone(), wrong_key))
      .await
      .unwrap_err()
      .kind(),
    ErrorKind::Conflict
  );
  // Self-revoke is refused: self-removal is the leave path.
  let issuer_id = local_id(&issuer.handle).await;
  let issuer_key = trusted_key(&issuer.handle, &issuer_id).await;
  assert_eq!(
    issuer
      .handle
      .command(RevokeNode::new(issuer_id, issuer_key))
      .await
      .unwrap_err()
      .kind(),
    ErrorKind::InvalidInput
  );
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));

  // The exact revoke commits once; the repeat is idempotent.
  let outcome = issuer
    .handle
    .command(RevokeNode::new(member.id.clone(), member_key.clone()))
    .await
    .unwrap();
  assert!(!outcome.was_already_revoked());
  let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(matches!(event, EventReceive::Item(_)));

  let outcome = issuer
    .handle
    .command(RevokeNode::new(member.id.clone(), member_key))
    .await
    .unwrap();
  assert!(outcome.was_already_revoked());
  assert!(matches!(
    events.try_recv().unwrap(),
    EventReceive::Empty | EventReceive::Closed
  ));

  for node in [issuer, member] {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}

/// SC-G09-P0-14: metadata signed before the revoke stays eligible — a
/// member that joins after the revoke still converges on the revoked
/// writer's historical resource through ordinary sync.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g9_delayed_content_converges_after_revoke() {
  let issuer = start_node(0).await;
  let issuer_endpoint = listen(&issuer).await;

  let member = start_node(1).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint.clone()).await;
  let member_id = local_id(&member.handle).await;

  member.handle.command(write(2)).await.unwrap();
  let member_resource = "radiata.woooo.tech/resources/revoke-002".to_owned();
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  while !selected_names(&issuer.handle)
    .await
    .contains(&member_resource)
  {
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "no resource sync"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // Revoke the member on the issuer, then join a third node: the revoked
  // writer's historical record converges to the new member through
  // ordinary anti-entropy.
  let member_key = trusted_key(&issuer.handle, &member_id).await;
  issuer
    .handle
    .command(RevokeNode::new(member_id.clone(), member_key))
    .await
    .unwrap();

  let third = start_node(2).await;
  common::merge_with_retry(&third.handle, &issuer.handle, issuer_endpoint).await;
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  while !selected_names(&third.handle)
    .await
    .contains(&member_resource)
  {
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "delayed content must converge to the new member"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  // The revoked writer's binding also converges to the third member —
  // and so does the revocation tombstone (ADR-0009 decision 6:
  // revocation is a convergent permanent removal tombstone, so the
  // expulsion is cluster-wide): content converges, the binding converges,
  // and every member treats the identity as unauthorized.
  let member_key_on_third = tokio::time::timeout(Duration::from_secs(30), async {
    loop {
      let page = third
        .handle
        .query(PageTrust::new(PageSpec::first(8).unwrap()))
        .await
        .unwrap();
      if let Some(view) = page
        .items()
        .iter()
        .find(|view| view.node_id() == &member_id)
      {
        break view.status();
      }
      assert!(
        deadline.elapsed() < Duration::from_secs(30),
        "binding never converged"
      );
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
  })
  .await
  .unwrap();
  assert_eq!(member_key_on_third, radiata::TrustStatus::Revoked);

  for node in [issuer, member, third] {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}
