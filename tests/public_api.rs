//! External-crate proof of the frozen functional `0.1.0` public API
//! (T-G10-08, SC-G10-P0-25/26).
//!
//! This integration test is an ordinary external consumer of the published
//! facade: every supported manifest signature is constructed, dispatched,
//! or implemented from outside the crate, solely through `radiata::*`. A
//! signature that disappears, renames, or changes shape breaks this build;
//! a superseded export would appear here as an unsatisfied lane.
//!
//! The cluster-driving lane mounts the test-only JSON adapter, so the
//! file requires the `json` feature and the unix directory barrier (the
//! json_runtime precedent).

#![cfg(all(feature = "json", unix))]

use std::{
  sync::{Arc, Mutex},
  time::Duration,
};

#[cfg(all(feature = "json", unix))]
use radiata::adapters::json_store;
use radiata::{
  BoxFuture, ChannelBinding, CommitOutcome, CommitReceipt, ConnectMember, ConnectivityStatus,
  CreatedKey, DeliveryAck, Digest, DisconnectPeer, Discovery, DiscoveryPage, Endpoint,
  EndpointCandidate, EventOptions, EventReceive, EventSubscription, ExtensionRegistry,
  FeatureDefinition, FeatureTag, GetLocalNode, GetMember, GetNodeStatus, GetObservability,
  GetResource, GetRoute, IncomingStream, IssuedMergeCredential, KeyCapabilities, KeyCreateState,
  KeyDeleteState, KeyHandle, KeyOperationId, LabelKey, LabelSet, LabelValue, LeaveCluster,
  LeaveOutcome, Listen, LoadBalancingPolicy, LocalNodeView, MemberChanged, MemberView,
  MergeCluster, MergeCredential, MergeView, NodeBuilder, NodeConfig, NodeHandle, NodeId,
  NodeMetadataPatch, NodeRevoked, NodeStatus, ObservabilitySnapshot, OutboundStream,
  PacketConsumer, PageCursor, PageListeners, PageMembers, PageResources, PageSessions, PageSpec,
  PageTopology, PageTrust, ProtocolDefinition, ProtocolTag, PutResource, QualifiedTag,
  RecoveryChanged, RecoveryConfig, RecoveryView, RemoveResource,
  ReplaceIdentityAndDeleteOldCoreMetadata, ResourceChanged, ResourceLabels, ResourceMutationView,
  ResourceName, ResourcePage, ResourceUri, ResourceVersion, ResourceWrite, Result,
  RotateMergeCredential, RouteChanged, RouteHandle, RouteNextHop, RouteState, RoutingPolicy,
  SelectResources, Selector, SessionChanged, SessionView, Shutdown, ShutdownOutcome,
  ShutdownReason, Signature, StartRecovery, StopListener, StoreCapabilities, StoreEntry, StoreKey,
  StoreNamespace, StoreOperation, StoreRequirements, StoreRevision, StoreTransaction, StoreValue,
  StreamMetadata, StreamPolicy, StreamTarget, TraceId, TraceMetadataLimits, TransactionId,
  TransportTag, UpdateNodeMetadata, WaitForShutdown,
  extension::{Entropy, KeyProvider, Storage, StorageFactory, StoreScan, StoreSnapshot},
};

const SYNC_INTERVAL: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------- values

/// Every manifest value constructor and canonical accessor, exactly as the
/// API manifest freezes them.
#[test]
fn boundary_values_construct_parse_and_round_trip() {
  let node = NodeId::parse("node_0000000000000000000A1").unwrap();
  assert_eq!(node.as_str(), "node_0000000000000000000A1");
  assert_eq!(node.to_string().parse::<NodeId>().unwrap(), node);

  let txn = TransactionId::parse("txn_0000000000000000000C3").unwrap();
  assert_eq!(txn.as_str(), "txn_0000000000000000000C3");

  let digest = Digest::from_bytes([7; 32]);
  assert_eq!(digest.as_bytes(), &[7; 32]);

  let public_key = radiata::PublicKey::from_bytes([9; 32]);
  assert_eq!(public_key.as_bytes(), &[9; 32]);

  let signature = Signature::from_bytes([11; 64]);
  assert_eq!(signature.as_bytes(), &[11; 64]);

  let binding = ChannelBinding::from_tls_exporter([13; 32]);
  assert_eq!(binding.as_bytes(), &[13; 32]);

  let endpoint = Endpoint::parse("wss://127.0.0.1:0").unwrap();
  assert_eq!(endpoint.as_str(), "wss://127.0.0.1:0");

  let tag = QualifiedTag::parse("example.org/labels/lane").unwrap();
  assert_eq!(tag.domain(), "example.org");
  assert_eq!(tag.category(), "labels");
  assert_eq!(tag.name(), "lane");

  let feature = FeatureTag::parse("example.org/features/echo").unwrap();
  assert_eq!(feature.as_str(), "example.org/features/echo");
  let protocol = ProtocolTag::parse("example.org/protocols/echo").unwrap();
  assert_eq!(protocol.as_str(), "example.org/protocols/echo");
  let transport = TransportTag::parse("example.org/transports/wss").unwrap();
  assert_eq!(transport.as_str(), "example.org/transports/wss");
  let discovery = radiata::DiscoveryTag::parse("example.org/discovery/static").unwrap();
  assert_eq!(discovery.as_str(), "example.org/discovery/static");

  let name = ResourceName::parse("radiata.woooo.tech/resources/pub-api-001").unwrap();
  assert_eq!(name.as_str(), "radiata.woooo.tech/resources/pub-api-001");
  let uri = ResourceUri::parse("file:///pub-api").unwrap();
  assert_eq!(uri.as_str(), "file:///pub-api");

  let key = LabelKey::parse("example.org/labels/lane").unwrap();
  let value = LabelValue::parse("one").unwrap();
  let labels = LabelSet::new().insert(key.clone(), value.clone()).unwrap();
  assert_eq!(labels.get(&key), Some(&value));

  let credential =
    MergeCredential::parse("join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
  assert_eq!(
    credential.expose_secret(),
    "join_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  );

  let trace = TraceId::parse("trace_0000000000000000000E5").unwrap();
  assert_eq!(trace.as_str(), "trace_0000000000000000000E5");

  let key_operation = KeyOperationId::parse("keyop_0000000000000000000D4").unwrap();
  assert_eq!(key_operation.as_str(), "keyop_0000000000000000000D4");

  // Key-handle material is constructed from provider bytes exactly as an
  // external provider passes custody through the facade.
  let handle = KeyHandle::from_provider_bytes(Arc::from(b"pub-handle".to_vec())).unwrap();
  assert_eq!(handle.expose_provider_handle(), b"pub-handle");
}

// ------------------------------------------------------------ pages/views

/// Page specs, cursors, and the page accessor contract frozen by the
/// manifest. View types are core-constructed: external crates read them
/// through accessors, never struct literals.
#[test]
fn page_specs_and_cursors() {
  let spec = PageSpec::first(8).unwrap();
  let cursor_bytes: Arc<[u8]> = Arc::from(b"cursor-bytes".to_vec());
  let cursor = PageCursor::from_provider_bytes(cursor_bytes.clone()).unwrap();
  assert_eq!(cursor.as_bytes(), cursor_bytes.as_ref());
  let _after = PageSpec::after(cursor, 8).unwrap();
  let _first_again = spec;

  // Enumerations are non_exhaustive and matchable from outside.
  let connectivity = ConnectivityStatus::Connected;
  assert!(matches!(connectivity, ConnectivityStatus::Connected));
  let status = NodeStatus::Running;
  assert!(matches!(status, NodeStatus::Running));
}

// -------------------------------------------------------- provider traits

/// An external key provider implementing the complete open SPI with real
/// Ed25519 custody: deterministic keys from fixed seeds, exact handle
/// records, and genuine signatures (the merge protocol verifies them).
#[derive(Debug, Default)]
struct PubKeys {
  records: Mutex<std::collections::BTreeMap<Vec<u8>, ed25519_dalek::SigningKey>>,
  counter: Mutex<u64>,
}

impl PubKeys {
  fn new() -> Arc<Self> {
    Arc::new(Self::default())
  }

  fn signing_for(&self, handle_bytes: &[u8]) -> ed25519_dalek::SigningKey {
    let mut records = self.records.lock().unwrap();
    if let Some(signing) = records.get(handle_bytes) {
      return signing.clone();
    }
    let mut index = self.counter.lock().unwrap();
    *index += 1;
    let mut seed = [0_u8; 32];
    seed[..8].copy_from_slice(&index.to_be_bytes());
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    records.insert(handle_bytes.to_vec(), signing.clone());
    signing
  }
}

impl KeyProvider for PubKeys {
  fn capabilities(&self) -> KeyCapabilities {
    KeyCapabilities::new()
      .ed25519(true)
      .reconciliation(true)
      .deletion(true)
  }

  fn create_ed25519<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      let handle_bytes = operation.as_str().as_bytes().to_vec();
      let handle = KeyHandle::from_provider_bytes(Arc::from(handle_bytes.clone()))?;
      let signing = self.signing_for(&handle_bytes);
      Ok(KeyCreateState::Present(CreatedKey::new(
        handle,
        radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      )))
    })
  }

  fn reconcile_create<'a>(
    &'a self, operation: &'a KeyOperationId,
  ) -> BoxFuture<'a, Result<KeyCreateState>> {
    Box::pin(async move {
      let handle_bytes = operation.as_str().as_bytes().to_vec();
      let known = self.records.lock().unwrap().contains_key(&handle_bytes);
      if !known {
        return Ok(KeyCreateState::Absent);
      }
      let handle = KeyHandle::from_provider_bytes(Arc::from(handle_bytes))?;
      let signing = self.signing_for(operation.as_str().as_bytes());
      Ok(KeyCreateState::Present(CreatedKey::new(
        handle,
        radiata::PublicKey::from_bytes(signing.verifying_key().to_bytes()),
      )))
    })
  }

  fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<radiata::PublicKey>> {
    Box::pin(async move {
      let signing = self.signing_for(handle.expose_provider_handle());
      Ok(radiata::PublicKey::from_bytes(
        signing.verifying_key().to_bytes(),
      ))
    })
  }

  fn sign<'a>(
    &'a self, handle: &'a KeyHandle, message: &'a [u8],
  ) -> BoxFuture<'a, Result<Signature>> {
    Box::pin(async move {
      use ed25519_dalek::Signer as _;
      let signing = self.signing_for(handle.expose_provider_handle());
      Ok(Signature::from_bytes(signing.sign(message).to_bytes()))
    })
  }

  fn delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    // The provider performs the deletion and reports the post-state: a
    // deleted handle is gone from custody.
    let removed = self
      .records
      .lock()
      .unwrap()
      .remove(handle.expose_provider_handle());
    let removed = removed.is_some();
    Box::pin(async move {
      let _ = removed;
      Ok(KeyDeleteState::Absent)
    })
  }

  fn reconcile_delete<'a>(
    &'a self, _operation: &'a KeyOperationId, handle: &'a KeyHandle,
  ) -> BoxFuture<'a, Result<KeyDeleteState>> {
    let known = self
      .records
      .lock()
      .unwrap()
      .contains_key(handle.expose_provider_handle());
    Box::pin(async move {
      Ok(if known {
        KeyDeleteState::Present
      } else {
        KeyDeleteState::Unknown
      })
    })
  }
}

/// An external storage provider implementing the complete storage SPI:
/// factory, storage, snapshot, scan, capabilities, and outcomes.
#[derive(Debug)]
struct PubStore {
  entries: Mutex<Vec<(StoreNamespace, StoreKey, StoreValue)>>,
}

#[derive(Debug)]
struct PubSnapshot {
  entries: Vec<(StoreNamespace, StoreKey, StoreValue)>,
  revision: StoreRevision,
}

#[derive(Debug)]
struct PubScan {
  entries: Vec<StoreEntry>,
}

impl StoreScan for PubScan {
  fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>> {
    Box::pin(async move { Ok(self.entries.pop()) })
  }
}

impl StoreSnapshot for PubSnapshot {
  fn revision(&self) -> &StoreRevision {
    &self.revision
  }

  fn get<'a>(
    &'a self, namespace: &'a StoreNamespace, key: &'a StoreKey,
  ) -> BoxFuture<'a, Result<Option<StoreValue>>> {
    Box::pin(async move {
      Ok(
        self
          .entries
          .iter()
          .find(|(ns, k, _)| ns == namespace && k == key)
          .map(|(_, _, value)| value.clone()),
      )
    })
  }

  fn scan<'a>(
    &'a self, namespace: &'a StoreNamespace, prefix: &'a [u8],
  ) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>> {
    Box::pin(async move {
      let mut entries: Vec<StoreEntry> = self
        .entries
        .iter()
        .filter(|(ns, key, _)| ns == namespace && key.as_bytes().starts_with(prefix))
        .map(|(ns, key, value)| StoreEntry::new(ns.clone(), key.clone(), value.clone()))
        .collect();
      entries.reverse();
      Ok(Box::new(PubScan { entries }) as Box<dyn StoreScan + 'a>)
    })
  }
}

impl Storage for PubStore {
  fn capabilities(&self) -> StoreCapabilities {
    StoreCapabilities::new(radiata::DurabilityLevel::OsCrashDurable)
      .conditional_batch(true)
      .ordered_scan(true)
      .reconciliation(true)
      .exclusive_lifetime_lock(true)
  }

  fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>> {
    Box::pin(async move {
      Ok(Box::new(PubSnapshot {
        entries: self.entries.lock().unwrap().clone(),
        revision: StoreRevision::new(Arc::from(b"pub-revision".to_vec())).unwrap(),
      }) as Box<dyn StoreSnapshot>)
    })
  }

  fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>> {
    Box::pin(async move {
      for operation in transaction.operations() {
        if let StoreOperation::Put {
          namespace,
          key,
          value,
          ..
        } = operation
        {
          self
            .entries
            .lock()
            .unwrap()
            .push((namespace.clone(), key.clone(), value.clone()));
        }
      }
      Ok(CommitOutcome::Committed(CommitReceipt::new(
        transaction.id().clone(),
        transaction.operation_digest().clone(),
        StoreRevision::new(Arc::from(b"pub-revision-2".to_vec())).unwrap(),
      )))
    })
  }

  fn reconcile<'a>(
    &'a self, transaction: &'a radiata::TransactionId, digest: &'a Digest,
  ) -> BoxFuture<'a, Result<radiata::ReconcileOutcome>> {
    let _ = (transaction, digest);
    Box::pin(async move { Ok(radiata::ReconcileOutcome::Aborted) })
  }

  fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move { Ok(()) })
  }
}

impl StorageFactory for PubStoreFactory {
  fn open<'a>(
    &'a self, requirements: StoreRequirements,
  ) -> BoxFuture<'a, Result<Box<dyn Storage>>> {
    let _ = requirements.required_durability();
    let _ = (
      requirements.requires_conditional_batch(),
      requirements.requires_ordered_scan(),
      requirements.requires_reconciliation(),
      requirements.requires_exclusive_lifetime_lock(),
      requirements.requires_transactional_migration(),
    );
    Box::pin(async move {
      Ok(Box::new(PubStore {
        entries: Mutex::new(Vec::new()),
      }) as Box<dyn Storage>)
    })
  }
}

#[derive(Debug)]
struct PubStoreFactory;

/// A counter-based external entropy source: every fill yields a fresh,
/// unique byte stream so generated identifiers never collide (a constant
/// fill would make every generated ID identical).
#[derive(Debug)]
struct PubEntropy {
  offset: u128,
  counter: Mutex<u128>,
}

impl Default for PubEntropy {
  fn default() -> Self {
    static INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    Self {
      offset: u128::from(INSTANCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst)) << 64,
      counter: Mutex::new(0),
    }
  }
}

impl Entropy for PubEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    let mut counter = self.counter.lock().unwrap();
    *counter = counter.wrapping_add(1);
    let seed = (self.offset | *counter).to_le_bytes();
    for (index, byte) in output.iter_mut().enumerate() {
      *byte = seed[index % seed.len()] ^ (index as u8).wrapping_mul(31);
    }
    Ok(())
  }
}

/// The storage SPI shapes are constructible externally: requirements,
/// capabilities, namespaces, keys, values, transactions, and receipts.
/// `StoreRequirements` is core-constructed (the open factory receives it);
/// capabilities are provider-constructed.
#[test]
fn storage_spi_values_are_externally_constructible() {
  let namespace = StoreNamespace::new(QualifiedTag::parse("example.org/pubs/one").unwrap());
  assert_eq!(namespace.as_str(), "example.org/pubs/one");
  let key = StoreKey::new(Arc::from(b"pub-key".to_vec()));
  let value = StoreValue::new(Arc::from(b"pub-value".to_vec()));
  // The stored digest is the provider-visible integrity proof of the
  // exact bytes; it is stable across re-wraps of identical bytes.
  let rewrapped = StoreValue::new(Arc::from(b"pub-value".to_vec()));
  assert_eq!(value.digest(), rewrapped.digest());
  let entry = StoreEntry::new(namespace.clone(), key.clone(), value.clone());
  assert_eq!(entry.namespace(), &namespace);

  let _capabilities = StoreCapabilities::new(radiata::DurabilityLevel::OsCrashDurable)
    .conditional_batch(true)
    .ordered_scan(true)
    .reconciliation(true)
    .exclusive_lifetime_lock(true)
    .transactional_migration(true);
}

/// The `StoreScan` to `BoxStream` converter (R2) is externally drivable:
/// an external scan composes with the standard stream combinators.
#[tokio::test]
async fn store_scan_stream_is_externally_drivable() {
  use futures_util::StreamExt;

  let namespace = StoreNamespace::new(QualifiedTag::parse("example.org/pubs/scan").unwrap());
  let entries = vec![StoreEntry::new(
    namespace.clone(),
    StoreKey::new(Arc::from(b"scan-key".to_vec())),
    StoreValue::new(Arc::from(b"scan-value".to_vec())),
  )];
  let scan: Box<dyn StoreScan> = Box::new(PubScan {
    entries: entries.clone(),
  });
  let collected: Vec<StoreEntry> = radiata::store_scan_stream(scan)
    .map(|item| item.unwrap())
    .collect()
    .await;
  assert_eq!(collected, entries);
}

// ------------------------------------------------------- streams/policies

/// An external stream body: any standard `Stream` of ordered chunks is a
/// body (R1); the trivial one-shot case needs no trait ceremony.
fn pub_body(
  chunk: &'static [u8],
) -> impl futures_core::Stream<Item = Result<Arc<[u8]>>> + Send + 'static {
  futures_util::stream::once(async move { Ok(Arc::from(chunk) as Arc<[u8]>) })
}

#[derive(Debug, Default)]
struct PubConsumer {
  received: Mutex<usize>,
}

impl PacketConsumer for PubConsumer {
  fn accept<'a>(&'a self, mut packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
      let _ = packet.source();
      let _ = packet.destination();
      let _ = packet.trace_id();
      let _ = packet.protocol();
      let _ = packet.metadata();
      let mut body = packet.body();
      while std::future::poll_fn(|cx| body.as_mut().poll_next(cx))
        .await
        .transpose()?
        .is_some()
      {}
      *self.received.lock().unwrap() += 1;
      Ok(())
    })
  }
}

#[derive(Debug)]
struct PubLoadBalancer;

impl LoadBalancingPolicy for PubLoadBalancer {
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

#[derive(Debug)]
struct PubNextHop;

impl RouteNextHop for PubNextHop {
  fn next_hop<'a>(&'a self, view: radiata::NextHopView<'a>) -> BoxFuture<'a, Result<NodeId>> {
    Box::pin(async move {
      let _ = (view.destination(), view.local());
      view.peers().first().cloned().ok_or_else(|| {
        radiata::Error::provider(
          radiata::ProviderErrorKind::Unsupported,
          radiata::ProviderErrorContext::NeighborPolicy,
        )
      })
    })
  }
}

#[derive(Debug)]
struct PubDiscovery;

impl Discovery for PubDiscovery {
  fn discover<'a>(
    &'a self, cursor: Option<&PageCursor>, limit: usize,
  ) -> BoxFuture<'a, Result<DiscoveryPage>> {
    Box::pin(async move {
      let _ = cursor;
      let candidate =
        EndpointCandidate::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()).with_priority(3);
      assert_eq!(candidate.priority(), 3);
      let _endpoint = candidate.endpoint();
      let items = if limit > 0 {
        vec![candidate]
      } else {
        Vec::new()
      };
      DiscoveryPage::new(items, None)
    })
  }
}

/// The open Discovery contract is implementable and callable externally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_contract_is_externally_implementable() {
  let page = PubDiscovery.discover(None, 4).await.unwrap();
  assert_eq!(page.items().len(), 1);
  assert!(page.next().is_none());
  let empty = PubDiscovery.discover(None, 0).await.unwrap();
  assert!(empty.items().is_empty());
}

/// Stream policies, metadata, and targets are externally constructible.
#[test]
fn stream_surface_is_externally_constructible() {
  let policy = StreamPolicy::new(RoutingPolicy::Direct, 3)
    .unwrap()
    .load_balancer(QualifiedTag::parse("example.org/balancers/first").unwrap());
  assert_eq!(policy.max_hops(), 3);
  assert_eq!(
    policy.load_balancing_policy(),
    Some(&QualifiedTag::parse("example.org/balancers/first").unwrap())
  );
  assert_eq!(policy.routing_policy(), &RoutingPolicy::Direct);

  let key = QualifiedTag::parse("example.org/pubs/hint").unwrap();
  let metadata = StreamMetadata::new()
    .insert(key.clone(), Arc::from(b"hint-value".to_vec()))
    .unwrap();
  assert_eq!(metadata.get(&key), Some(b"hint-value".as_slice()));
  assert_eq!(metadata.entries().count(), 1);

  let node = NodeId::parse("node_0000000000000000000A1").unwrap();
  let _exact = StreamTarget::Exact(node.clone());
  let _matching =
    StreamTarget::MatchingNodes(Selector::parse("example.org/labels/lane=one").unwrap());
  let selector = Selector::parse("example.org/labels/lane=one").unwrap();
  assert_eq!(selector.as_str(), "example.org/labels/lane=one");
}

/// Configuration values, definitions, and the extension registry are
/// externally constructible.
#[test]
fn config_and_registry_are_externally_constructible() {
  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(250))
    .unwrap()
    .with_recovery_policy(
      RecoveryConfig::new(4, 8, Duration::from_secs(1), Duration::from_secs(300)).unwrap(),
    )
    .unwrap()
    .with_session_queue_limits(64, 1024)
    .unwrap()
    .with_parser_limits(radiata::ParserLimits::new(4096, 8, 128).unwrap())
    .unwrap()
    .with_trace_metadata_limits(
      TraceMetadataLimits::new(64, 256, Duration::from_secs(3600)).unwrap(),
    )
    .unwrap()
    .with_receipt_retention(Duration::from_secs(86400))
    .unwrap()
    .require_feature(FeatureTag::parse("example.org/features/echo").unwrap())
    .unwrap();
  let _default = NodeConfig::default();

  let feature = FeatureDefinition::new(
    FeatureTag::parse("example.org/features/echo").unwrap(),
    Digest::from_bytes([1; 32]),
  )
  .unwrap()
  .dependency(FeatureTag::parse("example.org/features/base").unwrap())
  .unwrap()
  .conflict(FeatureTag::parse("example.org/features/rival").unwrap())
  .unwrap()
  .protocol(ProtocolTag::parse("example.org/protocols/echo").unwrap())
  .unwrap();
  let _protocol_definition = ProtocolDefinition::new(
    ProtocolTag::parse("example.org/protocols/echo").unwrap(),
    FeatureTag::parse("example.org/features/echo").unwrap(),
  );

  let mut registry = ExtensionRegistry::new();
  registry.register_feature(feature).unwrap();
  registry
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("example.org/protocols/echo").unwrap(),
        FeatureTag::parse("example.org/features/echo").unwrap(),
      ),
      Arc::new(PubConsumer::default()),
    )
    .unwrap();
  registry
    .register_next_hop(
      QualifiedTag::parse("example.org/policies/next-hop").unwrap(),
      Arc::new(PubNextHop),
    )
    .unwrap();
  registry
    .register_load_balancer(
      QualifiedTag::parse("example.org/balancers/first").unwrap(),
      Arc::new(PubLoadBalancer),
    )
    .unwrap();
  let _config = config;
}

/// The full typed command/query/event surface drives one real two-node
/// cluster from outside the crate: every manifest command and query is
/// dispatched and every event kind is subscribed.
#[cfg(all(feature = "json", unix))]
#[cfg(all(feature = "json", unix))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_typed_facade_signature_drives_a_real_cluster() {
  use futures_core::Stream as _;
  init_tracing();
  let directory = tempfile::tempdir().unwrap();
  let factory = json_store(directory.path().to_path_buf());
  let keys: Arc<dyn KeyProvider> = PubKeys::new();

  let issuer = start(factory.clone(), keys.clone()).await;
  let endpoint = listen(&issuer).await;
  let local: LocalNodeView = issuer.handle.query(GetLocalNode::new()).await.unwrap();
  let issuer_id: NodeId = local.node_id().clone();
  assert_eq!(local.public_key().as_bytes().len(), 32);

  let status: NodeStatus = issuer.handle.query(GetNodeStatus::new()).await.unwrap();
  assert!(matches!(status, NodeStatus::Running));

  // External provider SPI is honored through a second node.
  let member_factory: Arc<dyn StorageFactory> = Arc::new(PubStoreFactory);
  let member = start(member_factory, keys).await;
  let issued: IssuedMergeCredential = issuer
    .handle
    .command(RotateMergeCredential::new())
    .await
    .unwrap();
  let expires = issued.expires_at();
  let _ = expires;
  let merge: MergeView = merge_with_retry(
    &member.handle,
    &endpoint,
    issued.into_credential().expose_secret(),
  )
  .await;
  let member_id: NodeId = merge.node().clone();

  // Sessions, members, trust, topology pages, and views.
  wait_for_session(&member).await;
  let sessions = member
    .handle
    .query(PageSessions::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  let session: &SessionView = sessions.items().first().unwrap();
  let _ = (
    session.id(),
    session.generation(),
    session.peer(),
    session.endpoint(),
  );
  let _ = session.selected_features();

  let listeners = issuer
    .handle
    .query(PageListeners::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  let listener_view = listeners.items().first().unwrap();
  let listener_id = listener_view.id().clone();
  let _ = listener_view.endpoint();

  let members = issuer
    .handle
    .query(PageMembers::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  let member_view: &MemberView = members.items().last().unwrap();
  assert_eq!(member_view.owner_revision(), 1);
  let _ = (
    member_view.node_id(),
    member_view.public_key(),
    member_view.digest(),
    member_view.connectivity(),
    member_view.endpoints(),
    member_view.labels(),
  );
  let one: Option<MemberView> = issuer
    .handle
    .query(GetMember::new(member_view.node_id().clone()))
    .await
    .unwrap();
  assert!(one.is_some());

  let trust = issuer
    .handle
    .query(PageTrust::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(
    trust
      .items()
      .iter()
      .all(|view| matches!(view.status(), radiata::TrustStatus::Trusted))
  );

  let topology = issuer
    .handle
    .query(PageTopology::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  for edge in topology.items() {
    let _ = (
      edge.source(),
      edge.destination(),
      edge.connected(),
      edge.observed_at(),
    );
  }

  // Node metadata revision through the typed patch builder: the exact
  // expected revision is observed through the public member page (the
  // descriptor ensure may legitimately bump revisions concurrently), and
  // each patch applies to that observed revision.
  async fn current_issuer_revision(handle: &NodeHandle, issuer_id: &NodeId) -> u64 {
    let members = handle
      .query(PageMembers::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    members
      .items()
      .iter()
      .find(|view| view.node_id() == issuer_id)
      .map(|view| view.owner_revision())
      .unwrap_or(1)
  }
  let revision = current_issuer_revision(&issuer.handle, &issuer_id).await;
  let patch = NodeMetadataPatch::new()
    .set_capability(
      LabelKey::parse("example.org/labels/lane").unwrap(),
      LabelValue::parse("pub-api").unwrap(),
    )
    .unwrap();
  let updated: MemberView = issuer
    .handle
    .command(UpdateNodeMetadata::new(revision, patch))
    .await
    .unwrap();
  assert_eq!(updated.owner_revision(), revision + 1);
  let patch2 = NodeMetadataPatch::new()
    .remove_capability(LabelKey::parse("example.org/labels/lane").unwrap())
    .unwrap();
  let revision2 = current_issuer_revision(&issuer.handle, &issuer_id).await;
  let _updated2: MemberView = issuer
    .handle
    .command(UpdateNodeMetadata::new(revision2, patch2))
    .await
    .unwrap();

  // Resource writes, paged reads, and selection.
  let _events = issuer
    .handle
    .events::<ResourceChanged>(EventOptions::new().capacity(8).unwrap())
    .unwrap();
  let write = PutResource::new(ResourceWrite::new(
    ResourceName::parse("radiata.woooo.tech/resources/pub-api-001").unwrap(),
    ResourceLabels::new(
      LabelValue::parse("document").unwrap(),
      ResourceUri::parse("file:///pub-api").unwrap(),
    )
    .custom(
      LabelKey::parse("example.org/labels/lane").unwrap(),
      LabelValue::parse("one").unwrap(),
    )
    .unwrap(),
  ))
  .unwrap();
  let mutation: ResourceMutationView = issuer.handle.command(write).await.unwrap();
  assert!(mutation.is_current_winner());
  let accepted = mutation.accepted();
  let version: &ResourceVersion = accepted.version();
  let _ = (
    version.timestamp(),
    version.writer(),
    version.is_removal(),
    version.digest(),
  );
  let _ = (accepted.name(), accepted.labels());

  let page: ResourcePage = issuer
    .handle
    .query(PageResources::new(PageSpec::first(8).unwrap()))
    .await
    .unwrap();
  assert!(!page.items().is_empty());
  let selected: ResourcePage = issuer
    .handle
    .query(SelectResources::new(
      Selector::parse("radiata.woooo.tech/resources/type=document").unwrap(),
      PageSpec::first(8).unwrap(),
    ))
    .await
    .unwrap();
  assert_eq!(selected.items().len(), 1);
  let one_resource = issuer
    .handle
    .query(GetResource::new(
      ResourceName::parse("radiata.woooo.tech/resources/pub-api-001").unwrap(),
    ))
    .await
    .unwrap();
  assert!(one_resource.is_some());

  // Stream with an exact-node target and a delivery ack.
  let packet: OutboundStream = issuer
    .handle
    .open_stream(
      StreamTarget::Exact(member_id.clone()),
      ProtocolTag::parse("example.org/protocols/echo").unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 1).unwrap(),
      StreamMetadata::new(),
    )
    .unwrap();
  let ack: DeliveryAck = packet.send_sync(pub_body(b"pub-body")).await.unwrap();
  let _ = ack.trace_id();
  let _ = ack.destination();
  let _ = ack.admitted_at();

  // Connect/disconnect member commands: the member publishes a listener,
  // the issuer dials it explicitly, then disconnects and lets the
  // recovery controller re-dial the published endpoint (the reconnect
  // path used by the membership harness).
  let member_listener = member
    .handle
    .command(Listen::new(Endpoint::parse("wss://127.0.0.1:0").unwrap()))
    .await
    .unwrap();
  let member_endpoint = member_listener.endpoint().clone();
  let _connected: NodeId = issuer
    .handle
    .command(ConnectMember::new(
      member_endpoint.clone(),
      member_id.clone(),
    ))
    .await
    .unwrap();
  let _disconnected: () = issuer
    .handle
    .command(DisconnectPeer::new(member_id.clone()))
    .await
    .unwrap();
  // A deliberately disconnected peer is reconnected deliberately: recovery
  // never dials it on its own.
  let reconnect_deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    match issuer
      .handle
      .command(ConnectMember::new(
        member_endpoint.clone(),
        member_id.clone(),
      ))
      .await
    {
      Ok(_reconnected) => break,
      Err(_) if std::time::Instant::now() < reconnect_deadline => {
        tokio::time::sleep(Duration::from_millis(500)).await;
      }
      Err(error) => panic!("reconnect never succeeded: {error:?}"),
    }
  }
  let recovery: RecoveryView = issuer.handle.command(StartRecovery::new()).await.unwrap();
  let _ = (
    recovery.is_connected(),
    recovery.unreachable_components(),
    recovery.next_attempt_at(),
  );

  // Async route handle and route status.
  let routed = issuer
    .handle
    .open_stream(
      StreamTarget::Exact(member_id.clone()),
      ProtocolTag::parse("example.org/protocols/echo").unwrap(),
      StreamPolicy::new(RoutingPolicy::Direct, 1).unwrap(),
      StreamMetadata::new(),
    )
    .unwrap();
  let handle: RouteHandle = routed.send_async(pub_body(b"pub-body")).unwrap();
  let _ = handle.trace_id();
  // An async route retires its record after the terminal state, so the
  // status query races completion: a live route exposes every accessor,
  // a retired one reports NotFound.
  match issuer.handle.query(GetRoute::new(handle.clone())).await {
    Ok(route_status) => {
      let _ = (
        route_status.handle(),
        route_status.trace_id(),
        route_status.selected_node(),
        route_status.bytes_forwarded(),
        route_status.updated_at(),
      );
      let state: &RouteState = route_status.state();
      assert!(matches!(
        state,
        RouteState::Selecting
          | RouteState::Routing
          | RouteState::Streaming
          | RouteState::Delivered
          | RouteState::Failed(_)
      ));
    }
    Err(error) => assert_eq!(error.kind(), radiata::ErrorKind::NotFound),
  }

  // Recovery, revocation, observability.
  let recovery: RecoveryView = issuer.handle.command(StartRecovery::new()).await.unwrap();
  let _ = (
    recovery.is_connected(),
    recovery.unreachable_components(),
    recovery.next_attempt_at(),
  );
  let observability: ObservabilitySnapshot =
    issuer.handle.query(GetObservability::new()).await.unwrap();
  let _ = observability.captured_at();
  let _counter =
    observability.counter(&QualifiedTag::parse(ObservabilitySnapshot::SESSIONS).unwrap());

  // Every event subscription type.
  let mut session_events: EventSubscription<SessionChanged> =
    issuer.handle.events(EventOptions::new()).unwrap();
  let mut member_events: EventSubscription<MemberChanged> =
    issuer.handle.events(EventOptions::new()).unwrap();
  let mut route_events: EventSubscription<RouteChanged> =
    issuer.handle.events(EventOptions::new()).unwrap();
  let mut revoked_events: EventSubscription<NodeRevoked> =
    issuer.handle.events(EventOptions::new()).unwrap();
  let mut recovery_events: EventSubscription<RecoveryChanged> =
    issuer.handle.events(EventOptions::new()).unwrap();
  let _closed = matches!(session_events.try_recv(), Ok(EventReceive::Empty));
  let _closed = matches!(member_events.try_recv(), Ok(EventReceive::Empty));
  let _closed = matches!(route_events.try_recv(), Ok(EventReceive::Empty));
  let _closed = matches!(revoked_events.try_recv(), Ok(EventReceive::Empty));
  let _closed = matches!(recovery_events.try_recv(), Ok(EventReceive::Empty));

  // The additive standard-stream view (R2): a subscription is a Stream of
  // the same EventReceive items; pending polls yield no Empty item.
  futures_util::future::poll_fn(|cx| {
    assert!(
      std::pin::Pin::new(&mut session_events)
        .poll_next(cx)
        .is_pending()
    );
    std::task::Poll::Ready(())
  })
  .await;

  // Listener stop command.
  let _stopped: () = issuer
    .handle
    .command(StopListener::new(listener_id))
    .await
    .unwrap();

  // Resource removal with the exact observed version: re-observe
  // immediately before the removal so the precondition is never stale.
  let expected = issuer
    .handle
    .query(GetResource::new(
      ResourceName::parse("radiata.woooo.tech/resources/pub-api-001").unwrap(),
    ))
    .await
    .unwrap()
    .unwrap()
    .version()
    .clone();
  let removal: ResourceMutationView = issuer
    .handle
    .command(RemoveResource::new(
      ResourceName::parse("radiata.woooo.tech/resources/pub-api-001").unwrap(),
      expected,
    ))
    .await
    .unwrap();
  assert!(removal.accepted().version().is_removal());

  // Leave through the acknowledged marker: the intent's Absent
  // expectation races concurrent background commits, so the typed
  // conflict retries with a bound (the harness precedent).
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  let outcome: LeaveOutcome = loop {
    match issuer
      .handle
      .command(LeaveCluster::new(
        ReplaceIdentityAndDeleteOldCoreMetadata::new(),
      ))
      .await
    {
      Ok(outcome) => break outcome,
      Err(error) if error.kind() == radiata::ErrorKind::Conflict => {
        assert!(
          std::time::Instant::now() < deadline,
          "leave never succeeded: {error:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
      }
      Err(error) => panic!("leave failed persistently: {error:?}"),
    }
  };
  assert_ne!(outcome.former_identity(), outcome.replacement_identity());

  let shutdown: ShutdownOutcome = issuer.handle.command(Shutdown::new()).await.unwrap();
  assert!(matches!(
    shutdown.reason(),
    ShutdownReason::Explicit | ShutdownReason::ActiveLeave | ShutdownReason::Fatal(_)
  ));
  let reason: ShutdownReason = issuer.handle.query(WaitForShutdown::new()).await.unwrap();
  assert!(matches!(
    reason,
    ShutdownReason::Explicit | ShutdownReason::ActiveLeave | ShutdownReason::Fatal(_)
  ));
  member.handle.command(Shutdown::new()).await.unwrap();
}

// --------------------------------------------------------------- helpers

fn init_tracing() {
  use std::sync::Once;
  static INIT: Once = Once::new();
  INIT.call_once(|| {
    tracing_subscriber::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
      .with_test_writer()
      .init();
  });
}

async fn start(factory: Arc<dyn StorageFactory>, keys: Arc<dyn KeyProvider>) -> Node {
  let config = NodeConfig::new()
    .with_anti_entropy_interval(SYNC_INTERVAL)
    .unwrap();
  // One shared echo protocol registration: the external consumer owns the
  // consumer and the protocol definition, owned by the core session
  // feature (the sessions already intersect it).
  let mut extensions = ExtensionRegistry::new();
  extensions
    .register_protocol(
      ProtocolDefinition::new(
        ProtocolTag::parse("example.org/protocols/echo").unwrap(),
        FeatureTag::parse("radiata.woooo.tech/features/session-core").unwrap(),
      ),
      Arc::new(PubConsumer::default()),
    )
    .unwrap();
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .extensions(extensions)
    .entropy(Arc::new(PubEntropy::default()))
    .start()
    .await
    .unwrap();
  Node {
    handle,
    endpoint: Endpoint::parse("wss://127.0.0.1:0").unwrap(),
  }
}

struct Node {
  handle: NodeHandle,
  endpoint: Endpoint,
}

async fn listen(node: &Node) -> Endpoint {
  let listener = node
    .handle
    .command(Listen::new(node.endpoint.clone()))
    .await
    .unwrap();
  listener.endpoint().clone()
}

async fn merge_with_retry(node: &NodeHandle, endpoint: &Endpoint, secret: &str) -> MergeView {
  let deadline = std::time::Instant::now() + Duration::from_secs(60);
  loop {
    match node
      .command(MergeCluster::new(
        endpoint.clone(),
        MergeCredential::parse(secret).unwrap(),
      ))
      .await
    {
      Ok(view) => return view,
      Err(_) if std::time::Instant::now() < deadline => {
        // Pace the retries outside the fixed per-source merge window
        // (sixteen attempts per minute).
        tokio::time::sleep(Duration::from_secs(5)).await;
      }
      Err(error) => panic!("merge never succeeded: {error:?}"),
    }
  }
}

async fn wait_for_session(node: &Node) {
  let deadline = std::time::Instant::now() + Duration::from_secs(30);
  loop {
    let sessions = node
      .handle
      .query(PageSessions::new(PageSpec::first(8).unwrap()))
      .await
      .unwrap();
    if !sessions.items().is_empty() {
      return;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "no session registered"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
}
