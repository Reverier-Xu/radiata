//! The task-oriented integration guide: the decisions every business
//! integration makes before the first node boots, each with a
//! compiling example. The deeper reference material lives on the
//! involved types; the two `examples/` directories (cluster, chat)
//! are the end-to-end proof that these patterns work over real
//! transports and storage.
//!
//! # Contents
//!
//! 1. [Resource versions across process
//!    boundaries](#1-resource-versions-across-process-boundaries)
//! 2. [The any-one-route connectivity
//!    contract](#2-the-any-one-route-connectivity-contract)
//! 3. [Routing packets: `RouteNextHop`](#3-routing-packets-routenexthop)
//! 4. [Receiving packets:
//!    `PacketConsumer`](#4-receiving-packets-packetconsumer)
//! 5. [Holding identity keys:
//!    `KeyProvider`](#5-holding-identity-keys-keyprovider)
//!
//! # 1. Resource versions across process boundaries
//!
//! Every resource is a last-writer-wins register ordered by the signed
//! [`ResourceVersion`](crate::ResourceVersion) tuple: wall-clock
//! timestamp, writer [`NodeId`](crate::NodeId), removal flag, record
//! digest. A plain [`PutResource`](crate::PutResource) replaces the
//! winner unconditionally — a concurrent read-modify-write can silently
//! lose its update.
//!
//! Business read-modify-write therefore pins the exact observed tuple
//! as a precondition. The tuple survives process boundaries: read it
//! off a [`ResourceView`](crate::ResourceView), store or forward the
//! four parts (an HTTP body, a job queue message), rebuild it with
//! [`ResourceVersion::from_parts`](crate::ResourceVersion::from_parts),
//! and commit conditionally. A raced write fails as
//! [`ErrorKind::Conflict`](crate::ErrorKind::Conflict) instead of
//! landing quietly; removal is conditional the same way through
//! [`RemoveResource`](crate::RemoveResource).
//!
//! ```
//! use radiata::{PutResource, ResourceLabels, ResourceName, ResourceVersion, ResourceWrite};
//!
//! /// Builds the conditional write a worker performs after the
//! /// observed version traveled through a queue: the tuple is rebuilt
//! /// exactly, and a raced write surfaces as `ErrorKind::Conflict`.
//! fn enqueue_update(
//!     observed: &ResourceVersion,
//!     name: ResourceName,
//!     labels: ResourceLabels,
//! ) -> radiata::Result<PutResource> {
//!     let expected = ResourceVersion::from_parts(
//!         observed.timestamp(),
//!         observed.writer().clone(),
//!         observed.is_removal(),
//!         observed.digest().clone(),
//!     );
//!     PutResource::with_expected(ResourceWrite::new(name, labels), expected)
//! }
//! ```
//!
//! # 2. The any-one-route connectivity contract
//!
//! A node is connected when **at least one** authenticated path to the
//! cluster exists — never only when a specific topology is up. The
//! recovery plane never expands the topology of a connected node; it
//! dials candidates from the member table only while the node is fully
//! isolated, with bounded fan-out and backoff. Once any route works,
//! anti-entropy (membership descriptors, resources, trust bindings)
//! converges the rest over that route.
//!
//! [`RecoveryView`](crate::RecoveryView) reports this contract:
//! `is_connected` means "at least one path", and `unreachable_members`
//! is a bounded diagnostic counter of members the recovery plane has
//! not reached yet — not a loss list and not a connectivity verdict.
//! Convergence after a partition is bounded by the anti-entropy tick
//! period times the recovery backoff, not by any fixed topology.
//!
//! ```no_run
//! # async fn demo(node: &radiata::NodeHandle) -> radiata::Result<()> {
//! let view = node.query(radiata::GetRecovery::new()).await?;
//! if view.is_connected() {
//!     // At least one authenticated path exists: business traffic
//!     // flows, and background anti-entropy converges the rest.
//! } else {
//!     // Fully isolated: recovery is dialing the member table with
//!     // bounded fan-out; `unreachable_members` tracks its progress.
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # 3. Routing packets: `RouteNextHop`
//!
//! The routing plane delivers a packet to a destination the sender may
//! not hold a session with. Direct delivery to a connected destination
//! is resolved before any policy runs; the registered
//! [`RouteNextHop`](crate::RouteNextHop) picks the single
//! relay for everything else, at every forwarding node, under bounded
//! work. Returning a [`NodeId`](crate::NodeId) outside
//! [`NextHopView::peers`](crate::NextHopView::peers) fails
//! closed at the route boundary.
//!
//! The built-in [`DefaultNextHop`](crate::DefaultNextHop)
//! relays through the lowest live peer id — deterministic, loop-free,
//! and a sensible first choice. Implement the trait to replace it (a
//! hub-and-spoke relay, a latency-aware pick, a shard-affine route):
//!
//! ```
//! use radiata::{BoxFuture, NextHopView, NodeId, Result, RouteNextHop};
//!
//! /// Relays every unconnected destination through the lowest live
//! /// peer — the same deterministic choice the built-in
//! /// `DefaultNextHop` makes, spelled out as a starting point.
//! #[derive(Debug)]
//! struct LowestPeerFirst;
//!
//! impl RouteNextHop for LowestPeerFirst {
//!     fn next_hop<'a>(&'a self, view: NextHopView<'a>) -> BoxFuture<'a, Result<NodeId>> {
//!         Box::pin(async move {
//!             view.peers()
//!                 .first()
//!                 .cloned()
//!                 .ok_or_else(|| radiata::Error::caller("no live peer as next hop"))
//!         })
//!     }
//! }
//! ```
//!
//! Registration is two steps: install the implementation under a
//! qualified tag, then select that tag in the node configuration.
//!
//! ```no_run
//! # use radiata::{ExtensionRegistry, QualifiedTag, RouteNextHop};
//! # use std::sync::Arc;
//! # fn demo() -> radiata::Result<()> {
//! let mut registry = ExtensionRegistry::new();
//! let tag = QualifiedTag::parse("example.woooo.tech/route-policies/lowest")?;
//! // Arc::new(LowestPeerFirst) — or the built-in DefaultNextHop:
//! let policy: Arc<dyn RouteNextHop> = Arc::new(radiata::DefaultNextHop);
//! registry.register_next_hop(tag.clone(), policy)?;
//! // NodeConfig::new().with_route_policy(tag) selects it at build time;
//! // NodeBuilder::extensions(registry) installs the registry.
//! # Ok(())
//! # }
//! ```
//!
//! # 4. Receiving packets: `PacketConsumer`
//!
//! A protocol is one wire contract: a [`ProtocolTag`](crate::ProtocolTag)
//! plus the [`PacketConsumer`](crate::PacketConsumer) that receives its
//! streams. `accept` runs once per admitted stream, after TLS-level
//! authentication and admission control — everything inside is
//! application meaning. Failing `accept` rejects that delivery; origin
//! failures are caller errors, raised through
//! [`Error::caller`](crate::Error::caller) (or the typed
//! [`Error::provider`](crate::Error::provider) form) so the runtime
//! never mistakes them for its own faults.
//!
//! ```
//! use radiata::{BoxFuture, IncomingStream, PacketConsumer, Result};
//!
//! /// Audits one admitted stream and hands the body to application
//! /// logic. The consumer owns all meaning of the packet.
//! #[derive(Debug)]
//! struct AuditConsumer;
//!
//! impl PacketConsumer for AuditConsumer {
//!     fn accept<'a>(&'a self, packet: IncomingStream) -> BoxFuture<'a, Result<()>> {
//!         Box::pin(async move {
//!             let source = packet.source().clone();
//!             let protocol = packet.protocol().clone();
//!             let _ = (source, protocol, packet); // deliver to your logic
//!             Ok(())
//!         })
//!     }
//! }
//! ```
//!
//! Register the pair before building the node:
//! [`ExtensionRegistry::register_protocol`](crate::ExtensionRegistry::register_protocol)
//! takes the [`ProtocolDefinition`](crate::ProtocolDefinition) (tag and
//! owning feature) and the consumer; the runtime starts dispatching
//! streams once the first matching session admits them.
//!
//! # 5. Holding identity keys: `KeyProvider`
//!
//! Identity is only as durable as its private keys. The
//! [`KeyProvider`](crate::extension::KeyProvider) trait hands the node
//! creation, signing, and deletion over your keystore; the two
//! `reconcile_*` methods are the crash-recovery contract — after a
//! restart they report what actually landed, without assuming the
//! outcome of an interrupted operation. Errors mean "this provider
//! cannot answer right now": the runtime fails the operation closed
//! and the caller retries; they never mean "the key is gone".
//!
//! The examples ship `FileKeyProvider` (a reference implementation
//! with the three-state lifecycle) under `examples/*/src/keys.rs`;
//! the skeleton below shows the shape every implementation fills in:
//!
//! ```no_run
//! # use radiata::extension::KeyProvider;
//! # use radiata::{
//! #     BoxFuture, Error, KeyCapabilities, KeyCreateState, KeyDeleteState, KeyHandle,
//! #     KeyOperationId, PublicKey, Result, Signature,
//! # };
//! /// A provider skeleton: replace each body with keystore calls.
//! /// `create` is idempotent per operation id; the `reconcile_*`
//! /// paths report durable truth after a crash.
//! #[derive(Debug)]
//! struct MyKeyProvider;
//!
//! impl KeyProvider for MyKeyProvider {
//!     fn capabilities(&self) -> KeyCapabilities {
//!         KeyCapabilities::new().ed25519(true).reconciliation(true)
//!     }
//!
//!     fn create_ed25519<'a>(
//!         &'a self, _operation: &'a KeyOperationId,
//!     ) -> BoxFuture<'a, Result<KeyCreateState>> {
//!         Box::pin(async { Err(Error::caller("key create not wired")) })
//!     }
//!
//!     fn reconcile_create<'a>(
//!         &'a self, _operation: &'a KeyOperationId,
//!     ) -> BoxFuture<'a, Result<KeyCreateState>> {
//!         Box::pin(async { Err(Error::caller("key create reconcile not wired")) })
//!     }
//!
//!     fn public_key<'a>(&'a self, _handle: &'a KeyHandle) -> BoxFuture<'a, Result<PublicKey>> {
//!         Box::pin(async { Err(Error::caller("public key not wired")) })
//!     }
//!
//!     fn sign<'a>(
//!         &'a self, _handle: &'a KeyHandle, _message: &'a [u8],
//!     ) -> BoxFuture<'a, Result<Signature>> {
//!         Box::pin(async { Err(Error::caller("sign not wired")) })
//!     }
//!
//!     fn delete<'a>(
//!         &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
//!     ) -> BoxFuture<'a, Result<KeyDeleteState>> {
//!         Box::pin(async { Err(Error::caller("key delete not wired")) })
//!     }
//!
//!     fn reconcile_delete<'a>(
//!         &'a self, _operation: &'a KeyOperationId, _handle: &'a KeyHandle,
//!     ) -> BoxFuture<'a, Result<KeyDeleteState>> {
//!         Box::pin(async { Err(Error::caller("key delete reconcile not wired")) })
//!     }
//! }
//! ```
//!
//! Pass the provider to
//! [`NodeBuilder::new`](crate::NodeBuilder::new) together with the
//! storage factory; the same provider must back every restart of the
//! node, or the persisted identity can no longer sign.
//!
//! # Storage
//!
//! Storage selection is explicit:
//! [`adapters::json_store`](crate::adapters::json_store) (test-only) or
//! [`adapters::redb_store`](crate::adapters::redb_store) (production), or your
//! own [`StorageFactory`](crate::extension::StorageFactory) for other
//! backends. Custom adapters that scan the store directly bridge
//! through [`store_scan_stream`](crate::store_scan_stream).
