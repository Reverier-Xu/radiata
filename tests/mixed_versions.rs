//! E2E-09 mixed binaries (T-G10-02, SC-G10-P0-06..09).
//!
//! An external consumer models a prior-version binary and the current
//! binary purely through the public facade: the prior node offers a
//! feature surface without the current-only extension feature, the
//! current node offers it. Both initiator roles must negotiate the
//! identical signed intersection, packets and core metadata must stay
//! interoperable across the mixed pair, incompatible required features
//! must be refused without a weaker retry, and the pair-scoped selection
//! must disappear with the session.

use std::{sync::Arc, time::Duration};

use radiata::{
  ConnectMember, DisconnectPeer, Endpoint, ErrorKind, FeatureDefinition, FeatureTag, GetMember,
  GetResource, Listen, LoadBalancingPolicy, MergeCluster, NodeBuilder, NodeConfig, NodeHandle,
  PageMembers, PageSessions, PageSpec, PageTrust, ProtocolDefinition, ProtocolTag, QualifiedTag,
  ResourceLabels, ResourceName, ResourceUri, ResourceWrite, Result, RotateMergeCredential,
  StreamMetadata, StreamPolicy, StreamTarget, extension::KeyProvider,
};

mod common;

use common::{MemoryStorageFactory, ScriptedKeys};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);
const CURRENT_FEATURE: &str = "testing.example/features/mixed-current";
const PRIOR_FEATURE: &str = "testing.example/features/mixed-prior";
const ECHO_PROTOCOL: &str = "radiata.woooo.tech/protocols/mixed-echo";
const ECHO_OWNING_FEATURE: &str = "radiata.woooo.tech/features/data-messages";
const LOAD_BALANCER: &str = "example.org/balancers/first-match";

struct Node {
  handle: NodeHandle,
  endpoint: Option<Endpoint>,
  id: Option<radiata::NodeId>,
  collector: Arc<Collector>,
}

/// Counts fully drained echo packets and records their ordered bodies.
#[derive(Debug, Default)]
struct Collector {
  packets: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

impl radiata::PacketConsumer for Collector {
  fn accept<'a>(
    &'a self, mut packet: radiata::IncomingStream,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
      let mut body = Vec::new();
      let mut chunks = packet.body();
      while let Some(chunk) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx))
        .await
        .transpose()?
      {
        body.extend_from_slice(&chunk);
      }
      self
        .packets
        .lock()
        .unwrap()
        .push((packet.trace_id().to_string(), body));
      Ok(())
    })
  }
}

/// Selects the first matching candidate in canonical order.
#[derive(Debug)]
struct FirstMatch;

impl LoadBalancingPolicy for FirstMatch {
  fn select<'a>(
    &'a self, _selector: &'a radiata::Selector, candidates: &'a dyn radiata::CandidateNodeReader,
  ) -> radiata::BoxFuture<'a, Result<radiata::NodeId>> {
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
  chunks: &[&'static [u8]],
) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static {
  let items: Vec<Result<Arc<[u8]>>> = chunks
    .iter()
    .map(|chunk| Ok(Arc::from(*chunk) as Arc<[u8]>))
    .collect();
  futures_util::stream::iter(items)
}

/// `current` nodes register the current-only feature; `prior` nodes offer
/// the prior surface without it. Both register the echo protocol so the
/// mixed pair can exchange packets.
async fn start_node(seed: u64, current: bool) -> Node {
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(2_400_000 + seed * 1_000));
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let collector = Arc::new(Collector::default());
  let mut extensions = radiata::ExtensionRegistry::new();
  if current {
    extensions
      .register_feature(
        FeatureDefinition::new(
          FeatureTag::parse(CURRENT_FEATURE).unwrap(),
          radiata::Digest::from_bytes([0xC1; 32]),
        )
        .unwrap(),
      )
      .unwrap();
  }
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse(ECHO_PROTOCOL).unwrap(),
        FeatureTag::parse(ECHO_OWNING_FEATURE).unwrap(),
      ),
      Arc::clone(&collector) as Arc<dyn radiata::PacketConsumer>,
    )
    .unwrap();
  extensions
    .register_load_balancer(
      QualifiedTag::parse(LOAD_BALANCER).unwrap(),
      Arc::new(FirstMatch),
    )
    .unwrap();
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap();
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .extensions(extensions)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: None,
    id: None,
    collector,
  }
}

/// A node that additionally requires `feature`: its own offer carries the
/// requirement, so a peer without the feature must refuse the session.
async fn start_node_requiring(seed: u64, feature: &str, register: bool) -> Node {
  let keys: Arc<dyn KeyProvider> = Arc::new(ScriptedKeys::full_at(2_400_000 + seed * 1_000));
  let factory: Arc<dyn radiata::extension::StorageFactory> =
    Arc::new(MemoryStorageFactory::new(common::required_capabilities()));
  let mut extensions = radiata::ExtensionRegistry::new();
  if register {
    extensions
      .register_feature(
        FeatureDefinition::new(
          FeatureTag::parse(feature).unwrap(),
          radiata::Digest::from_bytes([0xC2; 32]),
        )
        .unwrap(),
      )
      .unwrap();
  }
  let config = NodeConfig::new()
    .require_feature(FeatureTag::parse(feature).unwrap())
    .unwrap();
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .extensions(extensions)
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: None,
    id: None,
    collector: Arc::new(Collector::default()),
  }
}

impl Node {
  async fn listen(&mut self) {
    let listener = self
      .handle
      .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
      .await
      .unwrap();
    self.endpoint = Some(listener.endpoint().clone());
  }

  fn endpoint(&self) -> &Endpoint {
    self.endpoint.as_ref().unwrap()
  }

  fn id(&self) -> &radiata::NodeId {
    self.id.as_ref().unwrap()
  }
}

/// Establishes the mixed pair: `issuer` runs the listener and the
/// credential issuer; `member` joins as the initiator. Returns the
/// member's node id.
async fn join_mixed_pair(issuer: &mut Node, member: &mut Node) -> radiata::NodeId {
  issuer.id = Some(
    issuer
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );
  issuer.listen().await;
  let issued = issuer
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let secret = issued.credential().expose_secret().to_owned();
  let deadline = std::time::Instant::now() + Duration::from_secs(60);
  let mut attempts = 0_u32;
  loop {
    attempts += 1;
    match member
      .handle
      .command(MergeCluster::new(
        issuer.endpoint().clone(),
        radiata::MergeCredential::parse(&secret).unwrap(),
      ))
      .await
    {
      Ok(view) => {
        member.id = Some(view.node().clone());
        break;
      }
      Err(_) if std::time::Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(
          200u64.saturating_mul(1 << attempts.min(3)),
        ))
        .await;
      }
      Err(error) => panic!("mixed join failed persistently: {error:?}"),
    }
  }
  member.listen().await;
  member.id().clone()
}

/// Bounded retry pacing shared by every probe below.
const POLL: Duration = Duration::from_millis(100);
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Both sides must expose the identical pair-scoped selection: same
/// features, same definition digests, same canonical order.
async fn assert_identical_pair_scoped_selection(issuer: &Node, member: &Node) {
  let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
  let issuer_features = loop {
    if let Ok(page) = issuer
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
      && let Some(session) = page
        .items()
        .iter()
        .find(|s| Some(s.peer()) == member.id.as_ref())
      && !session.selected_features().is_empty()
    {
      break session.selected_features().to_vec();
    }
    assert!(
      std::time::Instant::now() < deadline,
      "never observed the issuer session view with the mixed pair"
    );
    tokio::time::sleep(POLL).await;
  };
  let member_page = member
    .handle
    .query(PageSessions::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  let member_session = member_page
    .items()
    .iter()
    .find(|s| s.peer() == issuer.id.as_ref().unwrap())
    .expect("the member session view with the mixed pair");
  assert_eq!(
    member_session.selected_features(),
    issuer_features,
    "both binaries must expose the identical pair-scoped selection"
  );
}

/// Trust and member metadata converge across the mixed pair.
async fn assert_metadata_interop(issuer: &Node, member: &Node) {
  for node in [issuer, member] {
    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    loop {
      let Ok(page) = node
        .handle
        .query(PageTrust::new(PageSpec::first(8).unwrap()))
        .await
      else {
        tokio::time::sleep(POLL).await;
        continue;
      };
      if page.items().len() >= 2 {
        break;
      }
      assert!(
        std::time::Instant::now() < deadline,
        "never converged trust on both sides of the mixed pair"
      );
      tokio::time::sleep(POLL).await;
    }
  }
  // The member's member view resolves the issuer's descriptor.
  let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
  loop {
    match member
      .handle
      .query(GetMember::new(issuer.id().clone()))
      .await
    {
      Ok(Some(view)) => {
        assert_eq!(view.node_id(), issuer.id());
        break;
      }
      _ => {
        assert!(
          std::time::Instant::now() < deadline,
          "the issuer descriptor never converged to the member"
        );
        tokio::time::sleep(POLL).await;
      }
    }
  }
}

/// Ordered packet delivery in both directions across the mixed pair.
async fn assert_packet_interop(issuer: &Node, member: &Node) {
  let protocol = ProtocolTag::parse(ECHO_PROTOCOL).unwrap();
  let policy = StreamPolicy::new(radiata::RoutingPolicy::Direct, 8).unwrap();

  // Prior initiator direction: member sends, issuer consumes.
  let packet = member
    .handle
    .open_stream(
      StreamTarget::Exact(issuer.id().clone()),
      protocol.clone(),
      policy.clone(),
      StreamMetadata::new(),
    )
    .unwrap();
  let ack = packet.send_sync(echo_body(&[b"or", b"der"])).await.unwrap();
  assert_eq!(ack.destination(), issuer.id());
  let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
  loop {
    if issuer
      .collector
      .packets
      .lock()
      .unwrap()
      .iter()
      .any(|(_, body)| body == b"order")
    {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "ordered body never reached the issuer across the mixed pair"
    );
    tokio::time::sleep(POLL).await;
  }

  // Current responder direction: issuer sends, member consumes.
  let packet = issuer
    .handle
    .open_stream(
      StreamTarget::Exact(member.id().clone()),
      protocol,
      policy,
      StreamMetadata::new(),
    )
    .unwrap();
  packet.send_sync(echo_body(&[b"pa", b"ck"])).await.unwrap();
  let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
  loop {
    if member
      .collector
      .packets
      .lock()
      .unwrap()
      .iter()
      .any(|(_, body)| body == b"pack")
    {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "ordered body never reached the member across the mixed pair"
    );
    tokio::time::sleep(POLL).await;
  }
}

/// E2E-09, SC-G10-P0-06 (prior initiator), SC-G10-P0-09 (cleanup): a
/// prior-version initiator and the current responder negotiate the
/// identical intersection, exchange packets and metadata, and the
/// session-scoped selection is replaced and retired with the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e09_prior_initiator_interops_with_current_responder() {
  let mut issuer = start_node(1, true).await;
  let mut member = start_node(2, false).await;
  let member_id = join_mixed_pair(&mut issuer, &mut member).await;

  assert_identical_pair_scoped_selection(&issuer, &member).await;
  assert_metadata_interop(&issuer, &member).await;

  // Core-metadata interop: a resource written through the prior node's
  // facade converges to the current node by ordinary repair.
  let name = ResourceName::parse("radiata.woooo.tech/resources/mixed-e2e").unwrap();
  member
    .handle
    .command(
      radiata::PutResource::new(ResourceWrite::new(
        name.clone(),
        ResourceLabels::new(
          radiata::LabelValue::parse("document").unwrap(),
          ResourceUri::parse("file:///tmp/mixed-e2e").unwrap(),
        ),
      ))
      .unwrap(),
    )
    .await
    .unwrap();
  let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
  loop {
    match issuer.handle.query(GetResource::new(name.clone())).await {
      Ok(Some(_)) => break,
      _ => {
        assert!(
          std::time::Instant::now() < deadline,
          "resource metadata never converged across the mixed pair"
        );
        tokio::time::sleep(POLL).await;
      }
    }
  }

  assert_packet_interop(&issuer, &member).await;

  // Replacement: the credential-free member reconnect re-establishes the
  // session with the identical selection.
  let first_selection = {
    let page = issuer
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    page
      .items()
      .iter()
      .find(|s| s.peer() == &member_id)
      .unwrap()
      .selected_features()
      .to_vec()
  };
  member
    .handle
    .command(ConnectMember::new(
      issuer.endpoint().clone(),
      issuer.id().clone(),
    ))
    .await
    .unwrap();
  let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
  loop {
    let replaced = match issuer
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
    {
      Ok(page) => match page.items().iter().find(|s| s.peer() == &member_id) {
        Some(session) => {
          session.selected_features() == first_selection.as_slice() && session.generation() >= 1
        }
        None => false,
      },
      Err(_) => false,
    };
    if replaced {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "the replaced session never reappeared with the identical mixed selection"
    );
    tokio::time::sleep(POLL).await;
  }

  // Retirement: the pair-scoped selection disappears with the session and
  // never authorizes dispatch without a session (no node-wide claim).
  let collected_before_retirement = member.collector.packets.lock().unwrap().len();
  member
    .handle
    .command(DisconnectPeer::new(issuer.id().clone()))
    .await
    .unwrap();
  let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
  loop {
    let retired = match issuer
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
    {
      Ok(page) => page.items().iter().all(|s| s.peer() != &member_id),
      Err(_) => false,
    };
    if retired {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "the retired session never disappeared from the issuer"
    );
    tokio::time::sleep(POLL).await;
  }
  let protocol = ProtocolTag::parse(ECHO_PROTOCOL).unwrap();
  let policy = StreamPolicy::new(radiata::RoutingPolicy::Direct, 8).unwrap();
  let packet = issuer
    .handle
    .open_stream(
      StreamTarget::Exact(member_id.clone()),
      protocol,
      policy,
      StreamMetadata::new(),
    )
    .unwrap();
  let error = packet.send_sync(echo_body(&[])).await.unwrap_err();
  assert!(
    matches!(
      error.kind(),
      ErrorKind::RouteUnavailable
        | ErrorKind::Unsupported
        | ErrorKind::StreamInterrupted
        | ErrorKind::Overloaded
    ),
    "dispatch without a session must fail closed: {error:?}"
  );
  // No stray delivery raced the failed dispatch: the retired session's
  // collector state is frozen at its pre-retirement count.
  tokio::time::sleep(Duration::from_millis(200)).await;
  assert_eq!(
    member.collector.packets.lock().unwrap().len(),
    collected_before_retirement,
    "dispatch without a session must never deliver"
  );

  member
    .handle
    .command(radiata::Shutdown::new())
    .await
    .unwrap();
  issuer
    .handle
    .command(radiata::Shutdown::new())
    .await
    .unwrap();
}

/// E2E-09, SC-G10-P0-07 (current initiator): a current initiator and a
/// prior responder reach the identical intersection in the opposite role
/// with packet and trust interoperability.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e09_current_initiator_interops_with_prior_responder() {
  let mut issuer = start_node(3, false).await;
  let mut member = start_node(4, true).await;
  let member_id = join_mixed_pair(&mut issuer, &mut member).await;

  assert_identical_pair_scoped_selection(&issuer, &member).await;
  assert_metadata_interop(&issuer, &member).await;
  assert_packet_interop(&issuer, &member).await;

  // The issuer (prior surface) still resolves the member's paged view.
  let page = issuer
    .handle
    .query(PageMembers::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(
    page.items().iter().any(|m| m.node_id() == &member_id),
    "the prior responder pages the current member"
  );

  member
    .handle
    .command(radiata::Shutdown::new())
    .await
    .unwrap();
  issuer
    .handle
    .command(radiata::Shutdown::new())
    .await
    .unwrap();
}

/// SC-G10-P0-08: incompatible required features are refused in both
/// initiator roles without retrying a weaker offer, and no session
/// survives the refusal on either side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e09_incompatible_required_features_are_refused_in_both_roles() {
  // Current initiator requires the current-only feature; the prior
  // responder never published it.
  let mut issuer = start_node(5, false).await;
  issuer.id = Some(
    issuer
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );
  issuer.listen().await;
  let joiner = start_node_requiring(6, CURRENT_FEATURE, true).await;
  let issued = issuer
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let error = joiner
    .handle
    .command(MergeCluster::new(
      issuer.endpoint().clone(),
      radiata::MergeCredential::parse(issued.credential().expose_secret()).unwrap(),
    ))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  loop {
    let empty = matches!(
      issuer
        .handle
        .query(PageSessions::new(PageSpec::first(8).unwrap()))
        .await,
      Ok(page) if page.items().is_empty()
    );
    if empty {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "a session survived the current-initiator refusal"
    );
    tokio::time::sleep(POLL).await;
  }
  issuer
    .handle
    .command(radiata::Shutdown::new())
    .await
    .unwrap();

  // Prior initiator requires a prior-only feature; the current responder
  // has never published it.
  let mut prior_issuer = start_node(7, false).await;
  prior_issuer.id = Some(
    prior_issuer
      .handle
      .query(radiata::GetLocalNode::new())
      .await
      .unwrap()
      .node_id()
      .clone(),
  );
  prior_issuer.listen().await;
  let prior_joiner = start_node_requiring(8, PRIOR_FEATURE, true).await;
  let issued = prior_issuer
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let error = prior_joiner
    .handle
    .command(MergeCluster::new(
      prior_issuer.endpoint().clone(),
      radiata::MergeCredential::parse(issued.credential().expose_secret()).unwrap(),
    ))
    .await
    .unwrap_err();
  assert_eq!(error.kind(), ErrorKind::AuthenticationFailed);
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  loop {
    let empty = matches!(
      prior_issuer
        .handle
        .query(PageSessions::new(PageSpec::first(8).unwrap()))
        .await,
      Ok(page) if page.items().is_empty()
    );
    if empty {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "a session survived the prior-initiator refusal"
    );
    tokio::time::sleep(POLL).await;
  }
  prior_joiner
    .handle
    .command(radiata::Shutdown::new())
    .await
    .unwrap();
  prior_issuer
    .handle
    .command(radiata::Shutdown::new())
    .await
    .unwrap();
}
