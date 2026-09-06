---
title: radiata Functional 0.1 Public API Manifest
status: accepted
owner: T-G00-06
source: ADR-0007
---

# radiata Functional 0.1 Public API Manifest

## Contract

This manifest freezes the connectivity-and-metadata facade. The crate owns authenticated
peer-to-peer connectivity, opaque streams, and core metadata. Under the peer-trust deployment model
(ADR-0009) every started node is born holding a singleton cluster: clusters compose exclusively by
credential-authorized merge, and cluster identity is the convergent binding set — the crate exposes no
machine cluster identity. It exposes no business record model, built-in conversation pattern, body
persistence, deployment behavior, peer-clock coordination, or product node limit.

The local facade uses sealed commands, queries, and events. Provider and policy traits are open. No
public signature contains Tokio channel or task handles, TLS implementation types, CBOR
implementation types, redb types, JSON values, wire envelopes, private-key bytes, or an upper-layer
object model.

Amendment (T-G11-03, ADR-0009 rebaseline): Tokio is the crate's sole supported async ecosystem.
`futures-core` and Tokio traits/interfaces (`futures_core::Stream`, `BoxStream`, tokio-stream
adapters, `tokio::io` traits where they fit) may appear in public signatures. Tokio channel and
task handles (mpsc/broadcast senders and receivers, `JoinHandle`, and friends) remain excluded —
they are runtime internals, not interfaces.

Population-sized member, trust, resource, topology, and policy inputs are paged or incremental. Local
session/listener lists also use pages for a uniform bounded contract.

## Common ABI

```rust
pub type Result<T, E = Error> = std::result::Result<T, E>;
pub type BoxFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
use std::pin::Pin;

pub struct Error { /* private */ }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidInput,
    Conflict,
    NotFound,
    NotReady,
    NotTrusted,
    Revoked,
    Unsupported,
    UnsupportedSchema,
    UnsupportedCapability,
    AuthenticationFailed,
    RouteUnavailable,
    StreamInterrupted,
    Overloaded,
    ResourceExhausted,
    StorageLocked,
    StorageCorrupt,
    PermissionDenied,
    Io,
    CommitUnknown,
    Cancelled,
    ShuttingDown,
    Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    Unsupported,
    UnsupportedSchema,
    UnsupportedCapability,
    CommitUnknown,
    Overloaded,
    ResourceExhausted,
    StorageLocked,
    StorageCorrupt,
    PermissionDenied,
    Io,
    Cancelled,
    Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorContext {
    StorageOpen,
    StorageSnapshot,
    StorageScan,
    StorageCommit,
    StorageReconcile,
    StorageFlush,
    KeyCreate,
    KeyReconcile,
    KeyPublicKey,
    KeySign,
    KeyDelete,
    Entropy,
    TransportBind,
    TransportConnect,
    TransportAccept,
    TransportSend,
    TransportReceive,
    TransportClose,
    Discovery,
    PacketConsumer,
    LoadBalancingPolicy,
}

impl Error {
    pub fn provider(kind: ProviderErrorKind, context: ProviderErrorContext) -> Self;
    pub fn kind(&self) -> ErrorKind;
    pub fn context(&self) -> &'static str;
}
```

Provider errors contain typed context only. `Error` implements `std::error::Error`, `Display`, and a
redacted `Debug` that cannot include credentials, private material, handles, packet bytes, paths, or
addresses.

## Values

```rust
pub struct NodeId { /* private */ }
pub struct TraceId { /* private */ }
pub struct TransactionId { /* private canonical text */ }
pub struct OperationId { /* private */ }
pub struct ListenerId { /* private */ }
pub struct SessionId { /* private */ }
pub struct RouteHandle { /* private */ }
pub struct Digest { /* private [u8; 32] */ }
pub struct PublicKey { /* private [u8; 32] */ }
pub struct Signature { /* private [u8; 64] */ }

impl NodeId {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl TraceId {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl TransactionId {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl Digest {
    pub const fn from_bytes(value: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}
impl PublicKey {
    pub const fn from_bytes(value: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}
impl Signature {
    pub const fn from_bytes(value: [u8; 64]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 64];
}
```

Identity and operation types implement canonical `Clone`, `Eq`, `Ord`, `Hash`, `Debug`, `Display`, and
`FromStr` as appropriate. `TransactionId` is exactly `txn_` followed by 21 ASCII base62 characters;
`TransactionId::parse(id.to_string())` reproduces the same value and rejects noncanonical text so
external providers can persist receipts safely.

```rust
pub struct QualifiedTag { /* private */ }
pub struct FeatureTag { /* private */ }
pub struct ProtocolTag { /* private */ }
pub struct TransportTag { /* private */ }
pub struct DiscoveryTag { /* private */ }
pub struct ResourceName { /* private stable name */ }
pub struct LabelKey { /* private */ }
pub struct LabelValue { /* private */ }
pub struct ResourceUri { /* private caller-owned URI text */ }
pub struct Endpoint { /* private */ }

impl QualifiedTag {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
    pub fn domain(&self) -> &str;
    pub fn category(&self) -> &str;
    pub fn name(&self) -> &str;
}
impl ResourceName {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl ResourceUri {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl Endpoint {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
```

Every tag and label type has `parse`, `as_str`, and canonical value traits. Reserved resource labels are
`radiata.woooo.tech/resources/type` and `radiata.woooo.tech/resources/uri`; caller values remain opaque to core.
Core never dereferences a `ResourceUri`.

```rust
pub struct MergeCredential { /* private secret */ }
impl MergeCredential {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn expose_secret(&self) -> &str;
}
```

`MergeCredential` implements neither `Clone`, `Copy`, serialization, `Display`, nor revealing `Debug`.

## Configuration and Builder

```rust
pub struct NodeConfig { /* private */ }
impl NodeConfig {
    pub fn new() -> Self;
    pub fn with_anti_entropy_interval(self, value: std::time::Duration) -> Result<Self>;
    pub fn with_recovery_policy(self, value: RecoveryConfig) -> Result<Self>;
    pub fn with_session_queue_limits(self, messages: usize, bytes: usize) -> Result<Self>;
    pub fn with_parser_limits(self, value: ParserLimits) -> Result<Self>;
    pub fn with_trace_metadata_limits(self, value: TraceMetadataLimits) -> Result<Self>;
    pub fn with_receipt_retention(self, value: std::time::Duration) -> Result<Self>;
    pub fn require_feature(self, value: FeatureTag) -> Result<Self>;
}
impl Default for NodeConfig { fn default() -> Self; }

pub struct ParserLimits { /* private caller-selected nonzero limits */ }
impl ParserLimits {
    pub fn new(frame_bytes: usize, depth: usize, collection_items: usize) -> Result<Self>;
}

pub struct TraceMetadataLimits { /* private */ }
impl TraceMetadataLimits {
    pub fn new(active: usize, terminal: usize, retention: std::time::Duration) -> Result<Self>;
}

pub struct RecoveryConfig { /* private */ }
impl RecoveryConfig {
    pub fn new(
        neighbors: usize,
        fan_out: usize,
        initial_backoff: std::time::Duration,
        maximum_backoff: std::time::Duration,
    ) -> Result<Self>;
}

pub struct ExtensionRegistry { /* private */ }
impl ExtensionRegistry {
    pub fn new() -> Self;
    pub fn register_feature(&mut self, value: FeatureDefinition) -> Result<&mut Self>;
    pub fn register_protocol(&mut self, value: ProtocolDefinition, consumer: std::sync::Arc<dyn PacketConsumer>) -> Result<&mut Self>;
    pub fn register_load_balancer(&mut self, tag: QualifiedTag, value: std::sync::Arc<dyn LoadBalancingPolicy>) -> Result<&mut Self>;
    pub fn register_next_hop(&mut self, tag: QualifiedTag, value: std::sync::Arc<dyn RouteNextHop>) -> Result<&mut Self>;
}

pub struct NodeBuilder { /* private */ }
impl NodeBuilder {
    pub fn new(storage: std::sync::Arc<dyn StorageFactory>, keys: std::sync::Arc<dyn KeyProvider>) -> Self;
    pub fn config(self, value: NodeConfig) -> Self;
    pub fn extensions(self, value: ExtensionRegistry) -> Self;
    pub fn entropy(self, value: std::sync::Arc<dyn Entropy>) -> Self;
    pub async fn start(self) -> Result<NodeHandle>;
}
```

All representable nonzero capacities satisfying relational/allocation checks are legal. Defaults are
convenience policy, not universal ceilings: anti-entropy 250 ms; parser frame 65,536 bytes, depth 16,
and 1,024 collection items; session queue 256 messages and 8 MiB; recovery target four neighbors,
fan-out 64, and one-second to five-minute backoff; trace metadata 8,192 active and 262,144 terminal
records retained for 24 hours, and transaction receipts retained for 30 days after their final durable
reference disappears. The fixed admission policy is not configurable or weakenable.

## Typed Facade

```rust
mod private { pub trait Sealed {} }

pub trait Command: private::Sealed + Send + 'static { type Output: Send + 'static; }
pub trait Query: private::Sealed + Send + 'static { type Output: Send + 'static; }
pub trait Event: private::Sealed + Clone + Send + Sync + 'static {}

#[derive(Clone)]
pub struct NodeHandle { /* private */ }
impl NodeHandle {
    pub async fn command<C: Command>(&self, command: C) -> Result<C::Output>;
    pub async fn query<Q: Query>(&self, query: Q) -> Result<Q::Output>;
    pub fn events<E: Event>(&self, options: EventOptions) -> Result<EventSubscription<E>>;
    pub fn open_stream(&self, target: StreamTarget, protocol: ProtocolTag, policy: StreamPolicy, metadata: StreamMetadata) -> Result<OutboundStream>;
}
```

`open_stream` allocates a core-generated `TraceId` synchronously and performs no body delivery. The
returned packet exposes that ID before `send_sync` or `send_async` starts consuming the body. An exact
node target rejects a load-balancer selection; a matching-node target requires one. Every referenced
policy tag must resolve in the registry, and the caller-selected nonzero hop budget bounds route work
without becoming a product-wide routing constant.

## Commands

```rust
pub struct Shutdown { /* private */ }
impl Shutdown { pub fn new() -> Self; }
impl Command for Shutdown { type Output = ShutdownOutcome; }

pub struct RotateMergeCredential { /* private */ }
impl RotateMergeCredential { pub fn new() -> Self; }
impl Command for RotateMergeCredential { type Output = IssuedMergeCredential; }

pub struct Listen { /* private */ }
impl Listen { pub fn new(endpoint: Endpoint) -> Self; }
impl Command for Listen { type Output = ListenerView; }

pub struct StopListener { /* private */ }
impl StopListener { pub fn new(listener: ListenerId) -> Self; }
impl Command for StopListener { type Output = (); }

pub struct MergeCluster { /* private */ }
impl MergeCluster { pub fn new(receiver: Endpoint, credential: MergeCredential) -> Self; }
impl Command for MergeCluster { type Output = MergeView; }

pub struct CleanupNode { /* private */ }
impl CleanupNode { pub fn new(subject: NodeId) -> Self; }
impl Command for CleanupNode { type Output = (); }

pub struct PurgeRevocation { /* private */ }
impl PurgeRevocation { pub fn new(subject: NodeId) -> Self; }
impl Command for PurgeRevocation { type Output = (); }

pub struct IssueCleanupCheckpoint { /* private */ }
impl IssueCleanupCheckpoint { pub fn new() -> Self; }
impl Command for IssueCleanupCheckpoint { type Output = u64; }

pub struct ConnectMember { /* private */ }
impl ConnectMember { pub fn new(receiver: Endpoint, peer: NodeId) -> Self; }
impl Command for ConnectMember { type Output = NodeId; }

pub struct DisconnectPeer { /* private */ }
impl DisconnectPeer { pub fn new(peer: NodeId) -> Self; }
impl Command for DisconnectPeer { type Output = (); }

pub struct UpdateNodeMetadata { /* private */ }
impl UpdateNodeMetadata { pub fn new(expected_revision: u64, patch: NodeMetadataPatch) -> Self; }
impl Command for UpdateNodeMetadata { type Output = MemberView; }

pub struct StartRecovery { /* private */ }
impl StartRecovery { pub fn new() -> Self; }
impl Command for StartRecovery { type Output = RecoveryView; }

pub struct PutResource { /* private */ }
impl PutResource { pub fn new(record: ResourceWrite) -> Result<Self>; }
impl Command for PutResource { type Output = ResourceMutationView; }

pub struct RemoveResource { /* private */ }
impl RemoveResource {
    pub fn new(name: ResourceName, expected: ResourceVersion) -> Self;
}
impl Command for RemoveResource { type Output = ResourceMutationView; }

pub struct RevokeNode { /* private */ }
impl RevokeNode { pub fn new(subject: NodeId, expected_key: PublicKey) -> Self; }
impl Command for RevokeNode { type Output = RevokeOutcome; }

pub struct LeaveCluster { /* private */ }
impl LeaveCluster { pub fn new(acknowledgement: ReplaceIdentityAndDeleteOldCoreMetadata) -> Self; }
impl Command for LeaveCluster { type Output = LeaveOutcome; }
```

Leave signs an owner-signed terminal leave record, announces it to the connected sessions with a
bounded first-admission-acknowledgement wait, then rotates the identity through the crash-safe
journaled pipeline. Leave and cleanup affect only core metadata and key intents. They never follow a
resource URI or delete an upper-layer object. The cleanup family (`CleanupNode`,
`PurgeRevocation`, `IssueCleanupCheckpoint`) issues convergent signed removal tombstones, clears one
local revocation record explicitly, and starts checkpoint GC epochs; revocation records are permanent
and never collected.

## Queries and Pages

```rust
pub struct PageCursor { /* private opaque continuation */ }
impl PageCursor {
    pub fn from_provider_bytes(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn as_bytes(&self) -> &[u8];
}
pub struct PageSpec { /* private */ }
impl PageSpec {
    pub fn first(limit: usize) -> Result<Self>;
    pub fn after(cursor: PageCursor, limit: usize) -> Result<Self>;
}

pub struct GetLocalNode { /* private */ }
impl GetLocalNode { pub fn new() -> Self; }
impl Query for GetLocalNode { type Output = LocalNodeView; }

pub struct GetNodeStatus { /* private */ }
impl GetNodeStatus { pub fn new() -> Self; }
impl Query for GetNodeStatus { type Output = NodeStatus; }

pub struct WaitForShutdown { /* private */ }
impl WaitForShutdown { pub fn new() -> Self; }
impl Query for WaitForShutdown { type Output = ShutdownReason; }

pub struct PageListeners { /* private */ }
impl PageListeners { pub fn new(page: PageSpec) -> Self; }
impl Query for PageListeners { type Output = ListenerPage; }

pub struct PageSessions { /* private */ }
impl PageSessions { pub fn new(page: PageSpec) -> Self; }
impl Query for PageSessions { type Output = SessionPage; }

pub struct GetMember { /* private */ }
impl GetMember { pub fn new(node: NodeId) -> Self; }
impl Query for GetMember { type Output = Option<MemberView>; }

pub struct PageMembers { /* private */ }
impl PageMembers { pub fn new(page: PageSpec) -> Self; }
impl Query for PageMembers { type Output = MemberPage; }

pub struct PageTrust { /* private */ }
impl PageTrust { pub fn new(page: PageSpec) -> Self; }
impl Query for PageTrust { type Output = TrustPage; }

pub struct PageTopology { /* private */ }
impl PageTopology { pub fn new(page: PageSpec) -> Self; }
impl Query for PageTopology { type Output = TopologyPage; }

pub struct GetRoute { /* private */ }
impl GetRoute { pub fn new(handle: RouteHandle) -> Self; }
impl Query for GetRoute { type Output = RouteStatusView; }

pub struct GetResource { /* private */ }
impl GetResource { pub fn new(name: ResourceName) -> Self; }
impl Query for GetResource { type Output = Option<ResourceView>; }

pub struct PageResources { /* private */ }
impl PageResources { pub fn new(page: PageSpec) -> Self; }
impl Query for PageResources { type Output = ResourcePage; }

pub struct SelectResources { /* private */ }
impl SelectResources { pub fn new(selector: Selector, page: PageSpec) -> Self; }
impl Query for SelectResources { type Output = ResourcePage; }

pub struct GetObservability { /* private */ }
impl GetObservability { pub fn new() -> Self; }
impl Query for GetObservability { type Output = ObservabilitySnapshot; }
```

Every page has `items(&self) -> &[T]` and `next(&self) -> Option<&PageCursor>`. A page is only one bounded
observation and does not claim a stable whole-population snapshot while metadata changes.

## Streams

```rust
#[non_exhaustive]
pub enum StreamTarget {
    Exact(NodeId),
    MatchingNodes(Selector),
}

pub struct StreamPolicy { /* private explicit policy selection */ }
impl StreamPolicy {
    pub fn new(routing_policy: RoutingPolicy, max_hops: u32) -> Result<Self>;
    pub fn load_balancer(self, value: QualifiedTag) -> Self;
    pub fn routing_policy(&self) -> &RoutingPolicy;
    pub fn load_balancing_policy(&self) -> Option<&QualifiedTag>;
    pub fn max_hops(&self) -> u32;
}

#[non_exhaustive]
pub enum RoutingPolicy {
    Direct,
}

pub struct StreamMetadata { /* private bounded canonical map */ }
impl StreamMetadata {
    pub fn new() -> Self;
    pub fn insert(self, key: QualifiedTag, value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn get(&self, key: &QualifiedTag) -> Option<&[u8]>;
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (&QualifiedTag, &[u8])>;
}

/// The body of one stream: a standard [] of opaque
/// chunk results. Core never inspects chunk content or boundaries.
pub type BodyStream = dyn futures_core::Stream<Item = Result<std::sync::Arc<[u8]>>> + Send;

pub struct OutboundStream { /* private, owns trace and route context */ }
impl OutboundStream {
    pub fn trace_id(&self) -> &TraceId;
    pub fn send_sync<S>(self, body: S) -> BoxFuture<'static, Result<DeliveryAck>>
    where
        S: futures_core::Stream<Item = Result<std::sync::Arc<[u8]>>> + Send + 'static;
    pub fn send_async<S>(self, body: S) -> Result<RouteHandle>
    where
        S: futures_core::Stream<Item = Result<std::sync::Arc<[u8]>>> + Send + 'static;
}

impl RouteHandle {
    pub fn trace_id(&self) -> &TraceId;
}

pub struct IncomingStream { /* private */ }
impl IncomingStream {
    pub fn source(&self) -> &NodeId;
    pub fn destination(&self) -> &NodeId;
    pub fn trace_id(&self) -> &TraceId;
    pub fn protocol(&self) -> &ProtocolTag;
    pub fn metadata(&self) -> &StreamMetadata;
    pub fn body(&mut self) -> Pin<&mut (dyn futures_core::Stream<Item = Result<std::sync::Arc<[u8]>>> + Send)>;
    pub fn derive_return_stream(&self, protocol: ProtocolTag, metadata: StreamMetadata) -> Result<OutboundStream>;
}

pub struct DeliveryAck { /* private */ }
impl DeliveryAck {
    pub fn trace_id(&self) -> &TraceId;
    pub fn destination(&self) -> &NodeId;
    pub fn admitted_at(&self) -> std::time::SystemTime;
}

#[non_exhaustive]
pub enum RouteState { Selecting, Routing, Streaming, Delivered, Failed(ErrorKind) }
pub struct RouteStatusView { /* private */ }
impl RouteStatusView {
    pub fn handle(&self) -> &RouteHandle;
    pub fn trace_id(&self) -> &TraceId;
    pub fn selected_node(&self) -> Option<&NodeId>;
    pub fn state(&self) -> &RouteState;
    pub fn bytes_forwarded(&self) -> u64;
    pub fn updated_at(&self) -> std::time::SystemTime;
}
```

Core preserves byte order along the selected established route and uses constant memory with
backpressure. Route/session interruption ends the stream with `StreamInterrupted`. Core never stores
body bytes and never automatically continues an interrupted stream after disconnect or restart.

`DeliveryAck` proves authenticated admission to the destination process's bounded incoming stream only.
A caller may use `derive_return_stream` to swap endpoints and reuse the same `TraceId`; core assigns no
meaning to that packet and owns no correlation policy.

## Node and Resource Metadata Views

```rust
pub struct LocalNodeView { /* private */ }
impl LocalNodeView {
    pub fn node_id(&self) -> &NodeId;
    pub fn public_key(&self) -> &PublicKey;
}

pub struct NodeMetadataPatch { /* private */ }
impl NodeMetadataPatch {
    pub fn new() -> Self;
    pub fn add_endpoint(self, endpoint: Endpoint) -> Result<Self>;
    pub fn remove_endpoint(self, endpoint: Endpoint) -> Result<Self>;
    pub fn set_capability(self, key: LabelKey, value: LabelValue) -> Result<Self>;
    pub fn remove_capability(self, key: LabelKey) -> Result<Self>;
}

pub struct MemberView { /* private */ }
impl MemberView {
    pub fn node_id(&self) -> &NodeId;
    pub fn public_key(&self) -> &PublicKey;
    pub fn owner_revision(&self) -> u64;
    pub fn digest(&self) -> &Digest;
    pub fn connectivity(&self) -> ConnectivityStatus;
    pub fn endpoints(&self) -> &[Endpoint];
    pub fn labels(&self) -> &LabelSet;
}

pub struct LabelSet { /* private canonical map */ }
impl LabelSet {
    pub fn new() -> Self;
    pub fn insert(self, key: LabelKey, value: LabelValue) -> Result<Self>;
    pub fn get(&self, key: &LabelKey) -> Option<&LabelValue>;
}

pub struct ResourceLabels { /* private canonical map */ }
impl ResourceLabels {
    pub fn new(resource_type: LabelValue, uri: ResourceUri) -> Self;
    pub fn custom(self, key: LabelKey, value: LabelValue) -> Result<Self>;
    pub fn resource_type(&self) -> &LabelValue;
    pub fn uri(&self) -> &ResourceUri;
    pub fn custom_labels(&self) -> &LabelSet;
}

pub struct ResourceWrite { /* private, stamped and signed by core */ }
impl ResourceWrite {
    pub fn new(name: ResourceName, labels: ResourceLabels) -> Self;
}

pub struct ResourceVersion { /* private */ }
impl ResourceVersion {
    pub fn timestamp(&self) -> std::time::SystemTime;
    pub fn writer(&self) -> &NodeId;
    pub fn is_removal(&self) -> bool;
    pub fn digest(&self) -> &Digest;
}

pub struct ResourceView { /* private */ }
impl ResourceView {
    pub fn name(&self) -> &ResourceName;
    pub fn labels(&self) -> &ResourceLabels;
    pub fn version(&self) -> &ResourceVersion;
}

pub struct ResourceMutationView { /* private */ }
impl ResourceMutationView {
    pub fn accepted(&self) -> &ResourceView;
    pub fn is_current_winner(&self) -> bool;
}

pub struct Selector { /* private */ }
impl Selector {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
```

Resource winner order is lexicographic maximum of signed `SystemTime`, canonical writer `NodeId`,
removal rank, and canonical digest. Acceptance does not promise that a write wins or stays current. The
order gives no causal, freshness, or real-time guarantee. Rollback may make later local work lose and a
future-dated writer may dominate until a greater signed tuple appears.

```rust
pub struct ListenerPage { /* private */ }
impl ListenerPage {
    pub fn items(&self) -> &[ListenerView];
    pub fn next(&self) -> Option<&PageCursor>;
}
pub struct SessionPage { /* private */ }
impl SessionPage {
    pub fn items(&self) -> &[SessionView];
    pub fn next(&self) -> Option<&PageCursor>;
}
pub struct MemberPage { /* private */ }
impl MemberPage {
    pub fn items(&self) -> &[MemberView];
    pub fn next(&self) -> Option<&PageCursor>;
}
pub struct TrustPage { /* private */ }
impl TrustPage {
    pub fn items(&self) -> &[TrustedIdentityView];
    pub fn next(&self) -> Option<&PageCursor>;
}
pub struct TopologyPage { /* private */ }
impl TopologyPage {
    pub fn items(&self) -> &[TopologyEdgeView];
    pub fn next(&self) -> Option<&PageCursor>;
}
pub struct ResourcePage { /* private */ }
impl ResourcePage {
    pub fn items(&self) -> &[ResourceView];
    pub fn next(&self) -> Option<&PageCursor>;
}

pub struct ListenerView { /* private */ }
impl ListenerView {
    pub fn id(&self) -> &ListenerId;
    pub fn endpoint(&self) -> &Endpoint;
}
pub struct SessionView { /* private */ }
impl SessionView {
    pub fn id(&self) -> &SessionId;
    pub fn generation(&self) -> u64;
    pub fn peer(&self) -> &NodeId;
    pub fn endpoint(&self) -> &Endpoint;
    pub fn selected_features(&self) -> &[SessionFeatureView];
}
pub struct SessionFeatureView { /* private */ }
impl SessionFeatureView {
    pub fn feature(&self) -> &FeatureTag;
    pub fn definition_digest(&self) -> &Digest;
}
pub struct TrustedIdentityView { /* private */ }
impl TrustedIdentityView {
    pub fn node_id(&self) -> &NodeId;
    pub fn public_key(&self) -> &PublicKey;
    pub fn status(&self) -> TrustStatus;
}
pub struct TopologyEdgeView { /* private */ }
impl TopologyEdgeView {
    pub fn source(&self) -> &NodeId;
    pub fn destination(&self) -> &NodeId;
    pub fn connected(&self) -> bool;
    pub fn observed_at(&self) -> std::time::SystemTime;
}
pub struct RecoveryView { /* private */ }
impl RecoveryView {
    pub fn is_connected(&self) -> bool;
    pub fn unreachable_components(&self) -> usize;
    pub fn next_attempt_at(&self) -> Option<std::time::SystemTime>;
}

#[non_exhaustive]
pub enum ConnectivityStatus { Unknown, Offline, Reachable, Connected }
#[non_exhaustive]
pub enum TrustStatus { Trusted, Revoked }
#[non_exhaustive]
pub enum NodeStatus { Starting, Running, ShuttingDown, Stopped, Failed }
```

Page accessors return slices only for that bounded page. Topology edges and policy observations are
incremental, not a complete graph allocation.

## Lifecycle, Events, and Observability

```rust
pub struct ReplaceIdentityAndDeleteOldCoreMetadata { /* no Default */ }
impl ReplaceIdentityAndDeleteOldCoreMetadata { pub fn new() -> Self; }
pub struct ShutdownOutcome { /* private */ }
impl ShutdownOutcome { pub fn reason(&self) -> &ShutdownReason; }
pub struct IssuedMergeCredential { /* private secret */ }
impl IssuedMergeCredential {
    pub fn credential(&self) -> &MergeCredential;
    pub fn expires_at(&self) -> std::time::SystemTime;
    pub fn into_credential(self) -> MergeCredential;
}
pub struct MergeView { /* private */ }
impl MergeView {
    pub fn node(&self) -> &NodeId;
    pub fn peer(&self) -> &NodeId;
}
pub struct RevokeOutcome { /* private */ }
impl RevokeOutcome {
    pub fn subject(&self) -> &NodeId;
    pub fn was_already_revoked(&self) -> bool;
}
pub struct LeaveOutcome { /* private */ }
impl LeaveOutcome {
    pub fn former_identity(&self) -> &NodeId;
    pub fn replacement_identity(&self) -> &NodeId;
}

#[non_exhaustive]
pub enum ShutdownReason { Explicit, ActiveLeave, Fatal(ErrorKind) }

pub struct EventOptions { /* private finite capacity */ }
impl EventOptions {
    pub fn new() -> Self;
    pub fn capacity(self, value: usize) -> Result<Self>;
}

pub struct EventSubscription<E: Event> { /* private */ }
impl<E: Event> EventSubscription<E> {
    pub async fn recv(&mut self) -> Result<EventReceive<E>>;
    pub fn try_recv(&mut self) -> Result<EventReceive<E>>;
}
#[non_exhaustive]
pub enum EventReceive<E> { Item(E), Empty, Lagged { missed: u64 }, Closed }

pub struct SessionChanged { /* private */ }
impl SessionChanged { pub fn peer(&self) -> &NodeId; }
impl Event for SessionChanged {}
pub struct MemberChanged { /* private */ }
impl MemberChanged { pub fn node_id(&self) -> &NodeId; }
impl Event for MemberChanged {}
pub struct ResourceChanged { /* private */ }
impl ResourceChanged { pub fn resource(&self) -> &ResourceName; }
impl Event for ResourceChanged {}
pub struct RouteChanged { /* private */ }
impl RouteChanged { pub fn handle(&self) -> &RouteHandle; }
impl Event for RouteChanged {}
pub struct NodeRevoked { /* private */ }
impl NodeRevoked { pub fn subject(&self) -> &NodeId; }
impl Event for NodeRevoked {}
pub struct IdentityReplaced { /* private */ }
impl IdentityReplaced {
    pub fn former_identity(&self) -> &NodeId;
    pub fn replacement_identity(&self) -> &NodeId;
}
impl Event for IdentityReplaced {}
pub struct RecoveryChanged { /* private */ }
impl RecoveryChanged { pub fn recovery(&self) -> &RecoveryView; }
impl Event for RecoveryChanged {}

pub struct ObservabilitySnapshot { /* private bounded counters/status */ }
impl ObservabilitySnapshot {
    pub fn counter(&self, tag: &QualifiedTag) -> Option<u64>;
    pub fn captured_at(&self) -> std::time::SystemTime;
}
```

Events are transient and lag requires a new page/query. Observability includes no packet body, secret,
provider handle, unredacted path/address, or upper-layer object.

## Open Extension Contracts

```rust
pub trait Entropy: std::fmt::Debug + Send + Sync + 'static {
    fn fill(&self, output: &mut [u8]) -> Result<()>;
}
```

Production reads the host system clock directly. Tests virtualize those reads through a private seam.
Executor timers are wake mechanisms only; every wake re-reads wall time. Rollback, freeze, and forward
jumps can delay work indefinitely or make it immediately due.

```rust
pub struct KeyCapabilities { /* private provider capabilities */ }
pub struct KeyOperationId { /* private canonical text */ }
pub struct KeyHandle { /* private secret provider handle */ }
pub struct CreatedKey { /* private */ }

impl KeyCapabilities {
    pub fn new() -> Self;
    pub fn ed25519(self, supported: bool) -> Self;
    pub fn reconciliation(self, supported: bool) -> Self;
    pub fn deletion(self, supported: bool) -> Self;
    pub fn has_ed25519(&self) -> bool;
    pub fn has_reconciliation(&self) -> bool;
    pub fn has_deletion(&self) -> bool;
}
impl KeyOperationId {
    pub fn parse(value: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
impl KeyHandle {
    pub fn from_provider_bytes(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn expose_provider_handle(&self) -> &[u8];
}
impl CreatedKey {
    pub fn new(handle: KeyHandle, public_key: PublicKey) -> Self;
    pub fn handle(&self) -> &KeyHandle;
    pub fn public_key(&self) -> &PublicKey;
}

#[non_exhaustive]
pub enum KeyCreateState { Present(CreatedKey), Absent, Unknown }
#[non_exhaustive]
pub enum KeyDeleteState { Present, Absent, Unknown }

pub trait KeyProvider: std::fmt::Debug + Send + Sync + 'static {
    fn capabilities(&self) -> KeyCapabilities;
    fn create_ed25519<'a>(&'a self, operation: &'a KeyOperationId) -> BoxFuture<'a, Result<KeyCreateState>>;
    fn reconcile_create<'a>(&'a self, operation: &'a KeyOperationId) -> BoxFuture<'a, Result<KeyCreateState>>;
    fn public_key<'a>(&'a self, handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>>;
    fn sign<'a>(&'a self, handle: &'a KeyHandle, message: &'a [u8]) -> BoxFuture<'a, Result<Signature>>;
    fn delete<'a>(&'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle) -> BoxFuture<'a, Result<KeyDeleteState>>;
    fn reconcile_delete<'a>(&'a self, operation: &'a KeyOperationId, handle: &'a KeyHandle) -> BoxFuture<'a, Result<KeyDeleteState>>;
}
```

Core owns operation protocol and identity verification. `KeyOperationId` is exactly `keyop_` plus 21
ASCII base62 characters and round-trips through `parse`, `Display`, and `FromStr`. Node startup requires
Ed25519 creation, reconciliation, and deletion capabilities and refuses a provider missing any one of
them. Providers own private custody, capacity, physical durability, and capability reporting.
Private-key bytes never enter ordinary metadata.

```rust
pub struct StoreRequirements { /* private required capability set */ }
pub struct StoreCapabilities { /* private provider capabilities */ }
pub struct StoreRevision { /* private opaque nonempty bytes */ }
pub struct StoreNamespace { /* private domain-qualified tag */ }
pub struct StoreKey { /* private opaque bytes */ }
pub struct StoreValue { /* private opaque bytes and digest */ }
pub struct StoreTransaction { /* private conditional operations */ }
pub struct StoreEntry { /* private */ }
pub struct CommitReceipt { /* private */ }

impl StoreRequirements {
    pub fn required_durability(&self) -> DurabilityLevel;
    pub fn requires_conditional_batch(&self) -> bool;
    pub fn requires_ordered_scan(&self) -> bool;
    pub fn requires_reconciliation(&self) -> bool;
    pub fn requires_exclusive_lifetime_lock(&self) -> bool;
    pub fn requires_transactional_migration(&self) -> bool;
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityLevel { ProcessCrashAtomic, OsCrashDurable }

impl StoreCapabilities {
    pub fn new(durability: DurabilityLevel) -> Self;
    pub fn conditional_batch(self, supported: bool) -> Self;
    pub fn ordered_scan(self, supported: bool) -> Self;
    pub fn reconciliation(self, supported: bool) -> Self;
    pub fn exclusive_lifetime_lock(self, supported: bool) -> Self;
    pub fn transactional_migration(self, supported: bool) -> Self;
    pub fn durability(&self) -> DurabilityLevel;
    pub fn has_conditional_batch(&self) -> bool;
    pub fn has_ordered_scan(&self) -> bool;
    pub fn has_reconciliation(&self) -> bool;
    pub fn has_exclusive_lifetime_lock(&self) -> bool;
    pub fn has_transactional_migration(&self) -> bool;
}
impl StoreRevision {
    pub fn new(value: std::sync::Arc<[u8]>) -> Result<Self>;
    pub fn as_bytes(&self) -> &[u8];
}
impl StoreNamespace {
    pub const fn new(value: QualifiedTag) -> Self;
    pub fn as_str(&self) -> &str;
}
impl StoreKey {
    pub fn new(value: std::sync::Arc<[u8]>) -> Self;
    pub fn as_bytes(&self) -> &[u8];
}
impl StoreValue {
    pub fn new(value: std::sync::Arc<[u8]>) -> Self;
    pub fn as_bytes(&self) -> &[u8];
    pub fn digest(&self) -> &Digest;
}
impl StoreEntry {
    pub fn new(namespace: StoreNamespace, key: StoreKey, value: StoreValue) -> Self;
    pub fn namespace(&self) -> &StoreNamespace;
    pub fn key(&self) -> &StoreKey;
    pub fn value(&self) -> &StoreValue;
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreExpectation { Absent, Exact(Digest) }

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreOperation {
    Check { namespace: StoreNamespace, key: StoreKey, expected: StoreExpectation },
    Put { namespace: StoreNamespace, key: StoreKey, expected: StoreExpectation, value: StoreValue },
    Delete { namespace: StoreNamespace, key: StoreKey, expected: Digest },
    ForgetReceipt { transaction: TransactionId, expected_operation_digest: Digest },
}

impl StoreTransaction {
    pub fn id(&self) -> &TransactionId;
    pub fn operation_digest(&self) -> &Digest;
    pub fn computed_operation_digest(&self) -> Digest;
    pub fn base_revision(&self) -> &StoreRevision;
    pub fn operations(&self) -> &[StoreOperation];
}
impl CommitReceipt {
    pub fn new(
        transaction: TransactionId,
        operation_digest: Digest,
        committed_revision: StoreRevision,
    ) -> Self;
    pub fn transaction(&self) -> &TransactionId;
    pub fn operation_digest(&self) -> &Digest;
    pub fn committed_revision(&self) -> &StoreRevision;
}

#[non_exhaustive]
pub enum CommitOutcome {
    Committed(CommitReceipt),
    Aborted,
    Conflict,
    Unknown { transaction: TransactionId, operation_digest: Digest },
}
#[non_exhaustive]
pub enum ReconcileOutcome { Committed(CommitReceipt), Aborted, DigestConflict, Unknown }

pub trait StoreScan: std::fmt::Debug + Send {
    fn next<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<StoreEntry>>>;
}

pub trait StoreSnapshot: std::fmt::Debug + Send + Sync + 'static {
    fn revision(&self) -> &StoreRevision;
    fn get<'a>(&'a self, namespace: &'a StoreNamespace, key: &'a StoreKey) -> BoxFuture<'a, Result<Option<StoreValue>>>;
    fn scan<'a>(&'a self, namespace: &'a StoreNamespace, prefix: &'a [u8]) -> BoxFuture<'a, Result<Box<dyn StoreScan + 'a>>>;
}

pub trait StorageFactory: std::fmt::Debug + Send + Sync + 'static {
    fn open<'a>(&'a self, requirements: StoreRequirements) -> BoxFuture<'a, Result<Box<dyn Storage>>>;
}
pub trait Storage: std::fmt::Debug + Send + Sync + 'static {
    fn capabilities(&self) -> StoreCapabilities;
    fn snapshot<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn StoreSnapshot>>>;
    fn commit<'a>(&'a self, transaction: StoreTransaction) -> BoxFuture<'a, Result<CommitOutcome>>;
    fn reconcile<'a>(&'a self, transaction: &'a TransactionId, digest: &'a Digest) -> BoxFuture<'a, Result<ReconcileOutcome>>;
    fn flush<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
}
```

Snapshots are immutable and provider-owned. Scans yield entries in unsigned-byte key order and never
require whole-store materialization. A revision is nonempty, stable across reopen, and is never reused
for different logical states; no ordering between revisions is implied. Core constructs transactions,
and `computed_operation_digest` applies the single domain-separated canonical encoding of the base
revision and ordered operations so providers do not duplicate digest rules. Core defines conditional
base/per-key checks, atomic receipts, outcomes, reconciliation, capabilities, corruption, and migrations.
Every returned receipt or unknown tuple must match the submitted transaction ID and operation digest.
`Unknown` freezes later commits on that storage instance; immutable snapshots remain readable, and
`reconcile` performs any provider-owned locked refresh. Matching `Committed` or `Aborted` resolution
clears the freeze; `Unknown` or `DigestConflict` retains it. Receipt cleanup is an explicit conditional
transaction: core proves absence from its durable reference index with ordinary checks, then
`ForgetReceipt` removes only the exact transaction/digest receipt. A forgotten transaction ID is never
reused. Providers own layout, capacity, quotas, flush policy, and operational configuration. Typed
resource exhaustion is not corruption and must never cause truncation. This SPI is private
infrastructure for core metadata, not a caller data service.

```rust
pub struct ChannelBinding { /* private [u8; 32] */ }
impl ChannelBinding {
    pub const fn from_tls_exporter(value: [u8; 32]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 32];
}

pub struct EndpointCandidate { /* private */ }
impl EndpointCandidate {
    pub fn new(endpoint: Endpoint) -> Self;
    pub fn priority(self, value: i32) -> Self;
    pub fn endpoint(&self) -> &Endpoint;
    pub fn priority_value(&self) -> i32;
}

pub struct DiscoveryPage { /* private bounded candidates and cursor */ }
impl DiscoveryPage {
    pub fn new(items: Vec<EndpointCandidate>, next: Option<PageCursor>) -> Result<Self>;
    pub fn items(&self) -> &[EndpointCandidate];
    pub fn next(&self) -> Option<&PageCursor>;
}
pub trait Discovery: std::fmt::Debug + Send + Sync + 'static {
    fn discover<'a>(&'a self, cursor: Option<PageCursor>, limit: usize) -> BoxFuture<'a, Result<DiscoveryPage>>;
}

pub struct ProtocolDefinition { /* private */ }
impl ProtocolDefinition {
    pub fn new(tag: ProtocolTag, owning_feature: FeatureTag) -> Self;
}
pub struct FeatureDefinition { /* private canonical digest */ }
impl FeatureDefinition {
    pub fn new(tag: FeatureTag, fingerprint: Digest) -> Result<Self>;
    pub fn dependency(self, tag: FeatureTag) -> Result<Self>;
    pub fn conflict(self, tag: FeatureTag) -> Result<Self>;
    pub fn protocol(self, tag: ProtocolTag) -> Result<Self>;
}
pub trait PacketConsumer: std::fmt::Debug + Send + Sync + 'static {
    fn accept<'a>(&'a self, packet: IncomingStream) -> BoxFuture<'a, Result<()>>;
}

pub struct RouteContext { /* private current route observation */ }
impl RouteContext {
    pub fn trace_id(&self) -> &TraceId;
    pub fn source(&self) -> &NodeId;
    pub fn destination(&self) -> &NodeId;
    pub fn current(&self) -> &NodeId;
    pub fn visited(&self) -> &[NodeId];
}

pub struct NextHopView<'a> { /* private sealed per-hop decision inputs */ }
impl NextHopView<'_> {
    pub fn destination(&self) -> &NodeId;
    pub fn local(&self) -> &NodeId;
    pub fn peers(&self) -> &[NodeId];
}
pub trait RouteNextHop: std::fmt::Debug + Send + Sync + 'static {
    fn next_hop<'a>(&'a self, view: NextHopView<'a>) -> BoxFuture<'a, Result<NodeId>>;
}

pub trait CandidateNodeReader: private::Sealed + std::fmt::Debug + Send + Sync + 'static {
    fn next_matching_nodes<'a>(
        &'a self,
        selector: &'a Selector,
        cursor: Option<&PageCursor>,
        limit: usize,
    ) -> BoxFuture<'a, Result<MemberPage>>;
}

pub trait LoadBalancingPolicy: std::fmt::Debug + Send + Sync + 'static {
    fn select<'a>(&'a self, selector: &'a Selector, candidates: &'a dyn CandidateNodeReader) -> BoxFuture<'a, Result<NodeId>>;
}
```

`CandidateNodeReader` is a sealed, core-implemented incremental view passed to the open
load-balancing policy; external policies consume it but cannot substitute an unvalidated population.
Policy inputs use caller-selected finite pages. Core validates selected nodes, active edges, loop/hop
constraints, and authenticated feature compatibility. A `RouteNextHop` returning a `NodeId` outside
`NextHopView::peers` fails closed at the route boundary.

## Adapter Constructors

```rust
pub mod adapters {
    #[cfg(feature = "json")]
    pub fn json_store(path: std::path::PathBuf) -> std::sync::Arc<dyn crate::extension::StorageFactory>;

    #[cfg(feature = "redb")]
    pub fn redb_store(path: std::path::PathBuf) -> std::sync::Arc<dyn crate::extension::StorageFactory>;
}
```

JSON is test-only. redb is the feature-gated production backend. Concrete adapter types stay private.

## Operation Ownership

| Surface | Primary task |
| --- | --- |
| Values, errors, finite configuration | T-G01-01 |
| Builder, lifecycle, wall clock, typed facade | T-G01-02 |
| Storage/key SPI semantics and JSON | T-G02-01..T-G02-05 |
| Admission, TLS, exact-node streams | T-G03-02..T-G03-06 |
| Session, endpoint, trust pages | T-G04-02..T-G04-06 |
| Node revisions, population pages, recovery | T-G05-01..T-G05-06 |
| Multi-hop stream routes and trace metadata | T-G06-01..T-G06-05 |
| Resource tuple convergence and wall time | T-G07-01..T-G07-06 |
| redb and migrations | T-G08-01..T-G08-05 |
| Resource operations and facade closure | T-G09-01..T-G09-07 |
| Compatibility and final API approval | T-G10-01/T-G10-08 |

## Compatibility Rules

- Before the functional `0.1.0` candidate, amendments occur only through owned plan/API/scenario review.
- After `0.1.0`, removing or renaming public items, changing signatures/bounds, exposing implementation
  types, or adding a required object-safe trait method is breaking.
- Delivery acknowledgement always means current-process incoming-stream admission only.
- Resource labels are metadata; authenticated feature intersection alone authorizes protocol behavior.
- Packet body and upper-layer object durability remain outside the compatibility contract.
