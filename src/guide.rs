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
//! 6. [Leaving the cluster:
//!    `LeaveCluster`](#6-leaving-the-cluster-leavecluster)
//! 7. [Deploying on low-performance
//!    devices](#7-deploying-on-low-performance-devices)
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
//! relays through the live peer a trace-keyed hash ranks first — a
//! stable shuffle per delivery attempt, loop-free, and the default: the
//! node registers it under its well-known tag and selects it unless the
//! configuration names another policy, so multi-hop relay works out of
//! the box. Because a retry opens a fresh trace, each retry attempt
//! takes a different relay path instead of repeating a failed one, so
//! caller-level retries deliver over branching topologies where a
//! fixed pick could keep walking into a dead-end subtree. Implement the
//! trait to replace it (a hub-and-spoke relay, a latency-aware pick, a
//! shard-affine route):
//!
//! ```
//! use radiata::{BoxFuture, NextHopView, NodeId, Result, RouteNextHop};
//!
//! /// Relays every unconnected destination through the first live
//! /// peer in canonical order — a deterministic pick spelled out as
//! /// a starting point.
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
//! Replacing the default is two steps: install the implementation under
//! a qualified tag, then select that tag in the node configuration.
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
//! // without a selection the built-in DefaultNextHop stays the default.
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
//! # 5. Holding identity keys: the built-in custody and `KeyProvider`
//!
//! Identity is only as durable as its private keys. By default you never
//! touch key custody at all: the node stores its identity seed inside the
//! metadata storage you already provide, in a reserved namespace that is
//! never synced and never exposed to features, so keys and metadata share
//! one backup, one exclusive lifetime lock, and one restart story.
//!
//! ```no_run
//! # use radiata::extension::StorageFactory;
//! # async fn demo(
//! #   storage: std::sync::Arc<dyn StorageFactory>,
//! # ) -> radiata::Result<()> {
//! // Default custody: the identity key lives in the metadata store.
//! let node = radiata::NodeBuilder::new(storage).start().await?;
//! # let _ = node;
//! # Ok(())
//! # }
//! ```
//!
//! The node's own custody follows the same crash contract as everything
//! else in the runtime: creates and deletions are conditional commits
//! whose durable evidence answers `reconcile_*` exactly, so an
//! interrupted bootstrap or leave resumes from storage, never from a
//! guess.
//!
//! ## Injecting a different custody provider
//!
//! When the key must live outside the metadata storage — on a separate
//! volume, in an HSM, or in a cloud KMS — inject a provider on the
//! builder. The same provider must back every restart of the node, or
//! the persisted identity can no longer sign.
//!
//! ```no_run
//! # use radiata::extension::StorageFactory;
//! # async fn demo(
//! #   storage: std::sync::Arc<dyn StorageFactory>,
//! # ) -> radiata::Result<()> {
//! # let data_dir = std::path::PathBuf::from("/data");
//! // Built-in file custody rooted wherever the operator mounts it.
//! let keys = radiata::adapters::file_key_store(data_dir.join("keys"));
//! let node = radiata::NodeBuilder::new(storage).keys(keys).start().await?;
//! # let _ = node;
//! # Ok(())
//! # }
//! ```
//!
//! Built-in constructors:
//! [`adapters::file_key_store`](crate::adapters::file_key_store) is the
//! durable file-backed store (one directory, fsynced writes, mode-0600
//! seeds from creation on unix, evidence-based reconciliation after
//! crashes). [`adapters::ephemeral_key_store`](crate::adapters::ephemeral_key_store)
//! holds keys in memory for tests and deliberately ephemeral nodes —
//! identity bindings built on it do **not** survive a restart.
//!
//! ## The `KeyProvider` extension point
//!
//! The [`KeyProvider`](crate::extension::KeyProvider) trait hands the
//! node creation, signing, and deletion over your keystore; the two
//! `reconcile_*` methods are the crash-recovery contract — after a
//! restart they report what actually landed, without assuming the
//! outcome of an interrupted operation. Errors mean "this provider
//! cannot answer right now": the runtime fails the operation closed
//! and the caller retries; they never mean "the key is gone".
//!
//! A real keystore (HSM, cloud KMS, OS keychain) implements the trait
//! over its operations, keeping the same idempotency per operation id.
//! The skeleton below shows the shape every implementation fills in:
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
//! [`NodeBuilder::keys`](crate::NodeBuilder::keys); the same provider
//! must back every restart of the node, or the persisted identity can
//! no longer sign. For `file_key_store` that means the same directory,
//! durably mounted.
//!
//! # 6. Leaving the cluster: `LeaveCluster`
//!
//! An active leave is three effects behind one command: the node's
//! identity is replaced with a fresh node id and key, the old
//! identity's local core metadata is deleted, and the node shuts down
//! with the active-leave reason. Constructing the
//! [`ReplaceIdentityAndDeleteOldCoreMetadata`](crate::ReplaceIdentityAndDeleteOldCoreMetadata)
//! acknowledgement is the confirmation — it has no `Default`, so the
//! replacement cannot be issued by accident.
//!
//! The leave is journaled before any network effect, and once the
//! journal commits there is no abort: a crash or a restart mid-leave
//! resumes from the durable record and completes the replacement, so
//! the node never boots as the former identity again. Treat
//! [`LeaveCluster`](crate::LeaveCluster) as the point of no return for
//! that node slot: the returned
//! [`LeaveOutcome`](crate::LeaveOutcome) names the exact former and
//! replacement identities, and the same storage restarted afterwards
//! boots the replacement.
//!
//! ```no_run
//! # async fn demo(node: &radiata::NodeHandle) -> radiata::Result<()> {
//! let outcome = node
//!     .command(radiata::LeaveCluster::new(
//!         radiata::ReplaceIdentityAndDeleteOldCoreMetadata::new(),
//!     ))
//!     .await?;
//! // Durable from here: the node shuts itself down with the
//! // active-leave reason and restarts as the replacement identity.
//! # let _ = (outcome.former_identity(), outcome.replacement_identity());
//! # Ok(())
//! # }
//! ```
//!
//! # 7. Deploying on low-performance devices
//!
//! There is exactly **one timing profile in this library: the
//! defaults**. Every timing constant is peer-visible — the other side
//! of each session enforces the same deadlines you do — so timing is a
//! cluster-wide contract, not a per-device choice. The defaults are
//! already calibrated for the slowest supported device (slow flash,
//! one or two cores, duty-cycled peers); a mixed cluster of fast and
//! slow nodes needs no configuration at all. Tuning direction is
//! "faster": tighten only for uniformly fast deployments, never loosen
//! per device.
//!
//! **Timing knobs — keep uniform across the cluster:**
//!
//! - `with_authentication_deadline` (30 s): bounds the full bootstrap exchange
//!   including the join admission commit, so a burst of joins paying slow-flash
//!   writes still admits its tail.
//! - `with_session_liveness` (90 s idle, 20 s ping, 60 s timeout): a
//!   duty-cycled peer may skip several pings without the faster side tearing
//!   its sessions down.
//! - `with_anti_entropy_interval` (1 s): the tick costs N × interval per-node
//!   load per round (N² aggregate over a cluster), so size the interval by the
//!   member count — 16 nodes ≈ 16 ticks/s of work cluster-wide at 1 s, and 64
//!   nodes is the practical ceiling at this cadence on two slow cores.
//! - `with_recovery_policy` (fan-out 16, 2 s initial backoff): the
//!   any-one-route contract needs exactly one route; larger bursts starve their
//!   own tails on slow cores.
//! - `with_relay_hop_deadline` (5 s): a routed stream that crosses k hops is
//!   acknowledged within k × this budget, and a stuck hop fails its branch
//!   locally instead of stranding the attempt.
//!
//! **Resource knobs — safe to tune per device:**
//!
//! These never cross the wire; scale them to the local hardware:
//!
//! - `with_session_queue_limits`: the memory formula is roughly `queue_bytes ×
//!   live neighbors + terminal route records` (plus storage). A 64-neighbor
//!   node with 1 MiB queues should budget at least 64 MiB for the data plane
//!   alone.
//! - `with_parser_limits`: shrinking frame bytes, depth, and collection items
//!   bounds every decode allocation on small devices.
//! - `with_trace_metadata_limits`: terminal route-record retention is pure
//!   local memory; one notch down frees it for queues.
//! - `with_dial_deadline`: bounds only this node's outbound connects; the
//!   dialed peer never observes it.
//!
//! **Application retries stay yours.** The data plane is at-most-once:
//! a `Failed` or interrupted stream is a typed, bounded observation,
//! not a silent loss, and delivery across restarts belongs to the
//! application (or durable resources). The chat example ships the
//! reference pattern — an outbound queue that re-drives on typed
//! stream outcomes — which is also the right shape for slow devices:
//! queue locally, retry with backoff, and let the bounded budgets
//! above turn congestion into fast failures instead of queueing.
//!
//! # Storage
//!
//! Storage selection is explicit: `adapters::json_store` (test-only,
//! built with the `json` feature), `adapters::redb_store` (production,
//! built with the `redb` feature), or your own
//! [`StorageFactory`](crate::extension::StorageFactory) for other
//! backends. Custom adapters that scan the store directly bridge
//! through [`store_scan_stream`](crate::store_scan_stream).
