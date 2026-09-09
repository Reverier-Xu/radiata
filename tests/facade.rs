//! External core-only facade proof.
//!
//! This test crate is an external consumer: it exercises the entire
//! core-only public surface — packet streams over label-selected
//! destinations, paged member/trust/topology/resource/listener/session
//! views, resource mutations, revocation, leave, and events — without any
//! business or deployment type ever entering core.

use std::{sync::Arc, time::Duration};

use radiata::{
  BoxFuture, Endpoint, ErrorKind, EventOptions, EventReceive, GetResource, Listen,
  LoadBalancingPolicy, NodeBuilder, NodeConfig, NodeHandle, NodeId, PageListeners, PageMembers,
  PageResources, PageSessions, PageSpec, PageTopology, PageTrust, ProtocolDefinition, ProtocolTag,
  PutResource, RemoveResource, ResourceChanged, ResourceLabels, ResourceName, ResourceUri,
  ResourceWrite, Result, RevokeNode, RoutingPolicy, SelectResources, Selector, SessionChanged,
  Shutdown, ShutdownReason, StreamMetadata, StreamPolicy, StreamTarget, UpdateNodeMetadata,
  extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);
const ECHO_PROTOCOL: &str = "radiata.woooo.tech/protocols/facade-echo";
const LOAD_BALANCER: &str = "example.org/balancers/first-match";

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
}

/// Counts fully drained echo packets.
#[derive(Debug, Default)]
struct EchoCollector {
  packets: std::sync::Mutex<usize>,
}

impl radiata::PacketConsumer for EchoCollector {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
      let mut body = packet.body();
      while std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
        .await
        .transpose()?
        .is_some()
      {}
      *self.packets.lock().unwrap() += 1;
      Ok(())
    })
  }
}

/// Selects the first matching candidate in canonical order.
#[derive(Debug)]
struct FirstMatch;

impl LoadBalancingPolicy for FirstMatch {
  fn select<'a>(
    &'a self, _selector: &'a Selector, candidates: &'a dyn radiata::CandidateNodeReader,
  ) -> BoxFuture<'a, Result<NodeId>> {
    Box::pin(async move {
      let page = candidates.next_matching_nodes(_selector, None, 1).await?;
      page
        .items()
        .first()
        .map(|member| member.node_id().clone())
        .ok_or_else(|| {
          radiata::Error::provider(
            radiata::ProviderErrorKind::Unsupported,
            radiata::ProviderErrorContext::LoadBalancingPolicy,
          )
        })
    })
  }
}

/// A small opaque body for the echo packet.
fn echo_body(
  chunk: &'static [u8],
) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static {
  futures_util::stream::once(async move { Ok(Arc::from(chunk) as Arc<[u8]>) })
}

async fn start_node(seed: u64, echo: bool) -> Node {
  let storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(1_100_000 + seed * 1_000));
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap();
  let mut builder = NodeBuilder::new(storage, keys).config(config);
  if echo {
    let mut extensions = radiata::ExtensionRegistry::new();
    extensions
      .register_protocol(
        ProtocolDefinition::new(
          ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
          radiata::FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
        ),
        Arc::new(EchoCollector::default()),
      )
      .unwrap();
    extensions
      .register_load_balancer(
        radiata::QualifiedTag::parse(LOAD_BALANCER).unwrap(),
        Arc::new(FirstMatch),
      )
      .unwrap();
    builder = builder.extensions(extensions);
  }
  let handle = builder.start().await.unwrap();
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

/// A deterministic key provider with working deletion: the leave's
/// custody lane needs a provider whose delete actually applies.
#[derive(Debug, Default)]
struct LeaveCapableKeys {
  records: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, ed25519_dalek::SigningKey>>,
  operations: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
  deleted: std::sync::Mutex<Vec<Vec<u8>>>,
  next: std::sync::Mutex<u64>,
}

impl LeaveCapableKeys {
  fn seed_for(base: u64) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&base.to_le_bytes().repeat(4)[..32].try_into().unwrap())
  }

  fn create_at(&self, operation: &radiata::KeyOperationId) -> radiata::KeyCreateState {
    let mut operations = self.operations.lock().unwrap();
    if let Some(handle) = operations.get(operation.as_str().as_bytes()) {
      let signing = self.records.lock().unwrap().get(handle).cloned();
      if let Some(signing) = signing {
        return radiata::KeyCreateState::Present(radiata::CreatedKey::new(
          radiata::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
          radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
        ));
      }
    }
    let mut next = self.next.lock().unwrap();
    let index = *next;
    *next += 1;
    let signing = Self::seed_for(index + 1);
    let handle = format!("facade-handle-{index}").into_bytes();
    let created = radiata::CreatedKey::new(
      radiata::KeyHandle::from_provider_bytes(Arc::from(handle.clone())).unwrap(),
      radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    );
    operations.insert(operation.as_str().as_bytes().to_vec(), handle.clone());
    self.records.lock().unwrap().insert(handle, signing);
    radiata::KeyCreateState::Present(created)
  }

  fn lookup(&self, operation: &radiata::KeyOperationId) -> Option<radiata::KeyCreateState> {
    let operations = self.operations.lock().unwrap();
    let handle = operations.get(operation.as_str().as_bytes())?.clone();
    drop(operations);
    let signing = self.records.lock().unwrap().get(&handle).cloned()?;
    Some(radiata::KeyCreateState::Present(radiata::CreatedKey::new(
      radiata::KeyHandle::from_provider_bytes(Arc::from(handle)).unwrap(),
      radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
    )))
  }

  fn public_key_of(&self, handle: &radiata::KeyHandle) -> Option<radiata::PublicKey> {
    let signing = self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .cloned()?;
    Some(radiata::PublicKey::from_bytes(
      signing.verifying_key().to_bytes(),
    ))
  }

  fn signing_of(&self, handle: &radiata::KeyHandle) -> Option<ed25519_dalek::SigningKey> {
    self
      .records
      .lock()
      .unwrap()
      .get(handle.expose_provider_handle())
      .cloned()
  }

  fn remove(&self, handle: &radiata::KeyHandle) -> bool {
    let removed = self
      .records
      .lock()
      .unwrap()
      .remove(handle.expose_provider_handle())
      .is_some();
    if removed {
      self
        .deleted
        .lock()
        .unwrap()
        .push(handle.expose_provider_handle().to_vec());
    }
    removed
  }

  fn deleted_count(&self) -> usize {
    self.deleted.lock().unwrap().len()
  }

  fn contains(&self, handle: &radiata::KeyHandle) -> bool {
    self
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle())
  }
}

impl KeyProvider for LeaveCapableKeys {
  fn capabilities(&self) -> radiata::KeyCapabilities {
    radiata::KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> BoxFuture<'a, Result<radiata::KeyCreateState>> {
    let created = self.create_at(operation);
    Box::pin(async move { Ok(created) })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a radiata::KeyOperationId,
  ) -> BoxFuture<'a, Result<radiata::KeyCreateState>> {
    let created = self.lookup(operation);
    Box::pin(async move { Ok(created.unwrap_or(radiata::KeyCreateState::Absent)) })
  }

  fn public_key<'a>(
    &'a self, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::PublicKey>> {
    let result = self.public_key_of(handle).ok_or_else(|| {
      radiata::Error::provider(
        radiata::ProviderErrorKind::Internal,
        radiata::ProviderErrorContext::KeyPublicKey,
      )
    });
    Box::pin(async move { result })
  }

  fn sign<'a>(
    &'a self, handle: &'a radiata::KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<radiata::Signature>> {
    use ed25519_dalek::Signer as _;
    let result = self
      .signing_of(handle)
      .map(|signing| radiata::Signature::from_bytes(signing.sign(message).to_bytes()))
      .ok_or_else(|| {
        radiata::Error::provider(
          radiata::ProviderErrorKind::Internal,
          radiata::ProviderErrorContext::KeySign,
        )
      });
    Box::pin(async move { result })
  }

  fn delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::KeyDeleteState>> {
    self.remove(handle);
    Box::pin(async move { Ok(radiata::KeyDeleteState::Absent) })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a radiata::KeyOperationId, handle: &'a radiata::KeyHandle,
  ) -> BoxFuture<'a, Result<radiata::KeyDeleteState>> {
    let present = self.contains(handle);
    Box::pin(async move {
      Ok(if present {
        radiata::KeyDeleteState::Present
      } else {
        radiata::KeyDeleteState::Absent
      })
    })
  }
}

fn resource_write(name_seed: u8, resource_type: &str) -> PutResource {
  PutResource::new(ResourceWrite::new(
    ResourceName::parse(&format!(
      "radiata.woooo.tech/resources/facade-{name_seed:03}"
    ))
    .unwrap(),
    ResourceLabels::new(
      radiata::LabelValue::parse(resource_type).unwrap(),
      ResourceUri::parse(&format!("file:///facade/{name_seed:03}")).unwrap(),
    ),
  ))
  .unwrap()
}

/// Generic capability resources flow through the facade, every member
/// converges on them, revocation preserves their content and never
/// follows the URI, and leave replaces identities — explicit operations
/// touch only core metadata.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resources_revoke_and_leave() {
  // The caller's object the resource URI points at: core must never
  // touch it.
  let caller_object = tempfile::tempdir().unwrap();
  let object_path = caller_object.path().join("caller-object");
  std::fs::write(&object_path, b"caller-owned").unwrap();

  let issuer_storage = Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let issuer_keys = Arc::new(LeaveCapableKeys::default());
  let provider: Arc<dyn KeyProvider> = issuer_keys.clone();
  let issuer_handle = NodeBuilder::new(issuer_storage, provider)
    .config(
      NodeConfig::new()
        .with_anti_entropy_interval(SYNC_INTERVAL)
        .unwrap(),
    )
    .start()
    .await
    .unwrap();
  let issuer = Node {
    handle: issuer_handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
  };
  let issuer_endpoint = listen(&issuer).await;

  let mut member = start_node(1, false).await;
  member.endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;
  let member_id = member
    .handle
    .query(radiata::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();

  // The member publishes a generic capability resource whose URI points
  // at the caller object.
  member
    .handle
    .command(resource_write(1, "gpu-worker"))
    .await
    .unwrap();

  // Both members observe it (only generic named resources with reserved
  // type/URI plus namespaced custom labels exist in core).
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    // Schedule the next convergence observation: one deterministic
    // anti-entropy round on the observer instead of the wall-clock tick.
    issuer
      .handle
      .command(radiata::RunSyncRound::new())
      .await
      .unwrap();
    let page = issuer
      .handle
      .query(SelectResources::new(
        Selector::parse("radiata.woooo.tech/resources/type=gpu-worker").unwrap(),
        PageSpec::first(8).unwrap(),
      ))
      .await
      .unwrap();
    if page.items().len() == 1 {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "no resource convergence"
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
  }

  // Revoke the publishing member: its committed resource stays eligible,
  // and the URI object is untouched (core never dereferences a URI).
  let member_key = {
    let page = issuer
      .handle
      .query(PageTrust::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    page
      .items()
      .iter()
      .find(|view| view.node_id() == &member_id)
      .expect("member must be trusted")
      .public_key()
      .clone()
  };
  issuer
    .handle
    .command(RevokeNode::new(member_id.clone(), member_key))
    .await
    .unwrap();

  let still_there = issuer
    .handle
    .query(SelectResources::new(
      Selector::parse("radiata.woooo.tech/resources/type=gpu-worker").unwrap(),
      PageSpec::first(8).unwrap(),
    ))
    .await
    .unwrap();
  assert_eq!(
    still_there.items().len(),
    1,
    "revocation is not content erasure"
  );
  assert_eq!(
    std::fs::read(&object_path).unwrap(),
    b"caller-owned",
    "core never follows the resource URI"
  );

  // The issuer leaves: identity replacement only, with the caller object
  // still intact afterwards.
  let mut events = issuer
    .handle
    .events::<radiata::IdentityReplaced>(EventOptions::new())
    .unwrap();
  let outcome = issuer
    .handle
    .command(radiata::LeaveCluster::new(
      radiata::ReplaceIdentityAndDeleteOldCoreMetadata::new(),
    ))
    .await
    .unwrap();
  let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(matches!(event, EventReceive::Item(_)));
  assert_ne!(outcome.former_identity(), outcome.replacement_identity());
  let reason = issuer
    .handle
    .query(radiata::WaitForShutdown::new())
    .await
    .unwrap();
  assert_eq!(reason, ShutdownReason::ActiveLeave);
  // The leave deleted exactly the former identity's key through the
  // custody protocol.
  assert_eq!(issuer_keys.deleted_count(), 1);

  assert_eq!(
    std::fs::read(&object_path).unwrap(),
    b"caller-owned",
    "leave never deletes caller objects"
  );

  member.handle.command(Shutdown::new()).await.unwrap();
}

/// Label-selected packet delivery, every paged view, the resource
/// lifecycle, and events — all through the public facade.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn facade_core_only_operations() {
  {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
      tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
        .with_test_writer()
        .init();
    });
  }
  let issuer = start_node(0, true).await;
  let issuer_endpoint = listen(&issuer).await;

  let mut member = start_node(1, true).await;
  member.endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;
  let member_id = member
    .handle
    .query(radiata::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();

  // The member's first-seen descriptor must reach the issuer at revision
  // 1 before any owner-revision bump (the store accepts only the exact
  // next revision; the SLO harness pins the same ordering).
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    // Schedule the next convergence observation: one deterministic
    // anti-entropy round on the observer instead of the wall-clock tick.
    issuer
      .handle
      .command(radiata::RunSyncRound::new())
      .await
      .unwrap();
    let members = issuer
      .handle
      .query(PageMembers::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    if members
      .items()
      .iter()
      .any(|member| member.node_id() == &member_id)
    {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "member descriptor never converged"
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
  }

  // The member labels itself as an echo-capable zone member.
  let patch = radiata::NodeMetadataPatch::new()
    .set_capability(
      radiata::LabelKey::parse("example.org/labels/zone").unwrap(),
      radiata::LabelValue::parse("edge").unwrap(),
    )
    .unwrap();
  // The exact expected revision is observed through the member's own
  // public page (a concurrent descriptor ensure may legitimately bump
  // the revision).
  let members_self = member
    .handle
    .query(radiata::PageMembers::new(
      radiata::PageSpec::first(8).unwrap(),
    ))
    .await
    .unwrap();
  let member_id = member
    .handle
    .query(radiata::GetLocalNode::new())
    .await
    .unwrap()
    .node_id()
    .clone();
  let revision = members_self
    .items()
    .iter()
    .find(|view| view.node_id() == &member_id)
    .map(|view| view.owner_revision())
    .unwrap_or(1);
  // A concurrent descriptor ensure may bump the revision between the
  // observation and the command: re-observe and retry within a bound.
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    match member
      .handle
      .command(UpdateNodeMetadata::new(revision, patch.clone()))
      .await
    {
      Ok(_) => break,
      Err(error) if error.kind() == ErrorKind::Conflict => {
        assert!(
          std::time::Instant::now() < deadline,
          "metadata update never succeeded"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
      Err(error) => panic!("update failed persistently: {error:?}"),
    }
  }

  // Wait until the label converges to the issuer's descriptor store: the
  // selector resolves over the issuer's authoritative descriptors.
  // Functional convergence wait: loaded runners converge slower than
  // the sample window, and this is a setup phase, not an SLO sample.
  let deadline = std::time::Instant::now() + Duration::from_secs(60);
  loop {
    let members = issuer
      .handle
      .query(PageMembers::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    let labeled = members.items().iter().any(|member| {
      member.node_id() == &member_id
        && member
          .labels()
          .get(&radiata::LabelKey::parse("example.org/labels/zone").unwrap())
          .is_some_and(|value| value.as_str() == "edge")
    });
    if labeled {
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "label never converged"
    );
    // Schedule the next convergence observation: one deterministic
    // anti-entropy round on the observer instead of the wall-clock tick.
    issuer
      .handle
      .command(radiata::RunSyncRound::new())
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
  }

  // Label-selected packet delivery: the issuer targets the matching-node
  // selector through the registered first-match policy.
  let selector = Selector::parse("example.org/labels/zone=edge").unwrap();
  let packet = issuer
    .handle
    .open_stream(
      StreamTarget::MatchingNodes(selector),
      ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 1)
        .unwrap()
        .load_balancer(radiata::QualifiedTag::parse(LOAD_BALANCER).unwrap()),
      StreamMetadata::new(),
    )
    .unwrap();
  let ack = packet.send_sync(echo_body(b"hello")).await.unwrap();
  assert_eq!(ack.destination(), &member_id);

  // Paged population views: members, trust, topology.
  let members = issuer
    .handle
    .query(PageMembers::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(members.items().len() >= 2);
  let trust = issuer
    .handle
    .query(PageTrust::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(trust.items().len() >= 2);
  let topology = issuer
    .handle
    .query(PageTopology::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(!topology.items().is_empty());

  // Resource lifecycle: put, read, page, remove.
  let mut resource_events = issuer
    .handle
    .events::<ResourceChanged>(EventOptions::new())
    .unwrap();
  issuer
    .handle
    .command(resource_write(2, "storage"))
    .await
    .unwrap();
  let view = issuer
    .handle
    .query(GetResource::new(
      ResourceName::parse("radiata.woooo.tech/resources/facade-002").unwrap(),
    ))
    .await
    .unwrap()
    .expect("the committed resource reads back");
  assert_eq!(view.labels().resource_type().as_str(), "storage");
  let resources = issuer
    .handle
    .query(PageResources::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert_eq!(resources.items().len(), 1);
  let event = tokio::time::timeout(Duration::from_secs(5), resource_events.recv())
    .await
    .unwrap()
    .unwrap();
  assert!(matches!(event, EventReceive::Item(_)));

  issuer
    .handle
    .command(RemoveResource::new(
      ResourceName::parse("radiata.woooo.tech/resources/facade-002").unwrap(),
      view.version().clone(),
    ))
    .await
    .unwrap();
  assert!(
    issuer
      .handle
      .query(GetResource::new(
        ResourceName::parse("radiata.woooo.tech/resources/facade-002").unwrap(),
      ))
      .await
      .unwrap()
      .is_none()
  );

  // Listener and session views.
  let listeners = issuer
    .handle
    .query(PageListeners::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert_eq!(listeners.items().len(), 1);
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let sessions = issuer
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    if sessions
      .items()
      .iter()
      .any(|session| session.peer() == &member_id)
    {
      // The negotiated features ride the session only.
      assert!(!sessions.items()[0].selected_features().is_empty());
      break;
    }
    assert!(
      deadline.elapsed() < Duration::from_secs(30),
      "no session view"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }

  // Session events: the member's shutdown retires its session.
  let mut session_events = issuer
    .handle
    .events::<SessionChanged>(EventOptions::new())
    .unwrap();
  member.handle.command(Shutdown::new()).await.unwrap();
  let event = tokio::time::timeout(Duration::from_secs(10), session_events.recv())
    .await
    .unwrap()
    .unwrap();
  match event {
    EventReceive::Item(changed) => assert_eq!(changed.peer(), &member_id),
    _ => panic!("expected the session change event"),
  }

  issuer.handle.command(Shutdown::new()).await.unwrap();
}

/// Resource labels never enable protocol behavior — a resource whose
/// type names a protocol does not make an unregistered protocol
/// deliverable; only the transcript-bound feature intersection
/// authorizes dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resource_labels_never_enable_protocols() {
  let issuer = start_node(0, false).await;
  let issuer_endpoint = listen(&issuer).await;

  let mut member = start_node(1, false).await;
  member.endpoint = listen(&member).await;
  common::merge_with_retry(&member.handle, &issuer.handle, issuer_endpoint).await;

  // A resource claiming to be the echo protocol.
  member
    .handle
    .command(resource_write(3, ECHO_PROTOCOL))
    .await
    .unwrap();
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let page = issuer
      .handle
      .query(SelectResources::new(
        Selector::parse(&format!(
          "radiata.woooo.tech/resources/type={ECHO_PROTOCOL}"
        ))
        .unwrap(),
        PageSpec::first(8).unwrap(),
      ))
      .await
      .unwrap();
    if page.items().len() == 1 {
      break;
    }
    assert!(deadline.elapsed() < Duration::from_secs(30));
    // Schedule the next convergence observation: one deterministic
    // anti-entropy round on the observer instead of the wall-clock tick.
    issuer
      .handle
      .command(radiata::RunSyncRound::new())
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
  }

  // The protocol is not registered on the issuer: the packet fails
  // regardless of the resource label.
  let error = issuer
    .handle
    .open_stream(
      StreamTarget::Exact(
        member
          .handle
          .query(radiata::GetLocalNode::new())
          .await
          .unwrap()
          .node_id()
          .clone(),
      ),
      ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 1).unwrap(),
      StreamMetadata::new(),
    )
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Unsupported);

  for node in [issuer, member] {
    node.handle.command(Shutdown::new()).await.unwrap();
  }
}
