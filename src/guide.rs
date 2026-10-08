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
//! 3. [How state converges: the reconciliation
//!    contract](#3-how-state-converges-the-reconciliation-contract)
//! 4. [Routing packets: `RouteNextHop`](#4-routing-packets-routenexthop)
//! 5. [Receiving packets:
//!    `PacketConsumer`](#5-receiving-packets-packetconsumer)
//! 6. [Holding identity keys:
//!    `KeyProvider`](#6-holding-identity-keys-keyprovider)
//! 7. [Leaving the cluster: `node.leave`](#7-leaving-the-cluster-nodeleave)
//! 8. [Operations are tasks](#8-operations-are-tasks)
//! 9. [Deploying on low-performance
//!    devices](#9-deploying-on-low-performance-devices)
//!
//! # 1. Resource versions across process boundaries
//!
//! Every resource is a last-writer-wins register ordered by the signed
//! [`ResourceVersion`](crate::ResourceVersion) tuple: wall-clock
//! timestamp, writer [`NodeId`](crate::NodeId), removal flag, record
//! digest. A plain
//! [`Resources::put`](crate::Resources::put) replaces the
//! winner unconditionally — a concurrent read-modify-write can silently
//! lose its update.
//!
//! Business read-modify-write therefore pins the exact observed tuple
//! as a precondition. The tuple survives process boundaries: read it
//! off a [`ResourceView`](crate::ResourceView), store or forward the
//! four parts (an HTTP body, a job queue message), rebuild it with
//! [`ResourceVersion::from_parts`](crate::ResourceVersion::from_parts),
//! and commit conditionally. A raced write fails as
//! [`ErrorKind::Conflict`](crate::ErrorKind::Conflict) from the admitted
//! task's `wait` instead of landing quietly; removal is conditional the
//! same way through [`node.leave`](crate::NodeHandle::leave)'s
//! resource-plane sibling [`Resources::delete`](crate::Resources::delete).
//!
//! ```
//! use radiata::{
//!     NodeHandle, ResourceLabels, ResourceMutationView, ResourceName, ResourceVersion,
//!     ResourceWrite,
//! };
//!
//! /// Commits the conditional write a worker performs after the
//! /// observed version traveled through a queue: the tuple is rebuilt
//! /// exactly, admission accepts the compare-and-swap, and the effect is
//! /// awaited through the task — a raced write surfaces as
//! /// `ErrorKind::Conflict` from `wait`.
//! async fn commit_update(
//!     node: &NodeHandle,
//!     observed: &ResourceVersion,
//!     name: ResourceName,
//!     labels: ResourceLabels,
//! ) -> radiata::Result<ResourceMutationView> {
//!     let expected = ResourceVersion::from_parts(
//!         observed.timestamp(),
//!         observed.writer().clone(),
//!         observed.is_removal(),
//!         observed.digest().clone(),
//!     );
//!     let task = node
//!         .resources()
//!         .put_expected(ResourceWrite::new(name, labels), expected)
//!         .await?;
//!     task.wait().await
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
//! the reconciliation plane
//! ([chapter 3](#3-how-state-converges-the-reconciliation-contract))
//! converges the rest over that route: membership descriptors, issuer
//! trust bindings, resource rows, and removal tombstones spread as
//! receiver-evidenced exchanges hop by hop, so a wider topology only
//! shortens paths — it is never a convergence requirement.
//!
//! The **connection-degree maintenance plane** complements that
//! contract: while a node's live session count sits below its target
//! degree, a periodic tick (30 seconds, purely local) dials uniformly
//! random unconnected members until the target is reached. The target
//! is the derived `k(n)` for a cluster of `n` active members — the
//! smallest `k` keeping the expected number of isolated vertices under
//! the ten-percent connectivity threshold — and
//! [`with_connection_degree`](crate::NodeConfig::with_connection_degree)
//! overrides it for topologies the library cannot know (a single
//! public-IP relay needs one link, not seven). The degree is a
//! maintenance target, never a functional gate: below target everything
//! keeps working, above target nothing is pruned, and only a fully
//! offline node falls back to the recovery plane's high-frequency
//! backoff.
//!
//! [`RecoveryView`](crate::RecoveryView) reports the any-one-route
//! contract: `is_connected` means "at least one path", and
//! `unreachable_members` is a bounded diagnostic counter of members the
//! recovery plane has not reached yet — not a loss list and not a
//! connectivity verdict.
//! [`node.connection_degree()`](crate::NodeHandle::connection_degree)
//! reports the
//! degree contract: the effective target, the live session count, and
//! whether the mesh is `Healthy`. A node stuck `Unhealthy` below target
//! is the operator's signal that the network (or the peers' published
//! endpoints) cannot carry the mesh the degree contract asks for.
//! Convergence after a partition is bounded by the recovery backoff
//! plus the sync plane's own cadence — a rejoined session opens with a
//! whole-lane summary exchange, changes ride the tick-debounced hints,
//! and whatever no message ever observed heals at the quiet detection
//! cadence of [chapter
//! 3](#3-how-state-converges-the-reconciliation-contract) — plus one
//! maintenance tick for the degree top-up, never by any fixed topology.
//!
//! ```no_run
//! # async fn demo(node: &radiata::NodeHandle) -> radiata::Result<()> {
//! let view = node.recovery().await?;
//! if view.is_connected() {
//!     // At least one authenticated path exists: business traffic
//!     // flows, and the reconciliation plane converges the rest.
//! } else {
//!     // Fully isolated: recovery is dialing the member table with
//!     // bounded fan-out; `unreachable_members` tracks its progress.
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # 3. How state converges: the reconciliation contract
//!
//! Membership descriptors, issuer trust bindings, resource rows, and
//! removal tombstones converge under one contract, the reconciliation
//! plane: peers compare **range fingerprints** over their row sets and
//! exchange row bytes only where the receiving side proves it lacks
//! them — the one bounded exception is the eager piggyback below. A
//! push to a peer that may already hold a row is exactly the per-edge
//! duplication this contract exists to eliminate, so a changed row
//! crosses each edge at most once per lacking receiver, whatever the
//! mesh looks like. There is nothing to configure: the plane runs over
//! the authenticated sessions the connection planes maintain.
//!
//! Each converged key space (a **lane**) is indexed by content: every
//! row's `(key, content)` pair is hashed by a frozen digest function —
//! the first eight bytes of SHA-256 over the canonical CBOR encoding
//! of the pair, a wire-contract constant pinned by golden vectors —
//! and any digest range aggregates to the pair `(count, xor of
//! digests)`. The pair forms a commutative group, so any range's
//! fingerprint is the difference of two prefix fingerprints, and two
//! peers that agree on a range's fingerprint hold the same rows there
//! (the remaining disagreement needs a digest collision *and* a
//! matching count, bounded far below any operational catalog). Merge
//! semantics stay where they always were — in the lane's row content
//! and its apply path — so reconciliation changes how rows travel,
//! never who wins.
//!
//! One protocol stream carries six message kinds, every message naming
//! its lane:
//!
//! - `ROOT` — the sender's whole-lane aggregate, exchanged when a session is
//!   established and on the quiet detection cadence.
//! - `HINT` — a best-effort notice that these ranges changed. Hints may be
//!   lost, duplicated, or ignored; one that matches the local fingerprints is
//!   answered with silence.
//! - `OFFER` — the sender's fingerprints for negotiated subranges.
//! - `NEED` — the ranges whose rows the sender lacks: the side that observes
//!   itself lacking asks, the other side answers.
//! - `ROWS` — row payloads, applied idempotently through the lane's merge
//!   semantics.
//! - `DONE` — the round-close receipt: the sender's whole-lane state digest.
//!   Matching tokens when both sides close the same round are a cheap agreement
//!   proof; completeness is always re-established by fingerprint evidence,
//!   never by counting messages.
//!
//! Divergence is isolated by multi-way search: each OFFER round splits
//! a divergent range into four children (the fan-out `b = 4`, a
//! constant, not a negotiation parameter), so every divergence
//! isolates in a bounded logarithmic descent — the whole digest space
//! isolates in 32 OFFER rounds, and any narrower range in at most 34
//! (the last split child inherits the division remainder). Two short circuits
//! skip the search entirely: a side whose range is empty sends its rows
//! directly (the peer's empty fingerprint is itself proof of lack),
//! and a side holding nothing in the range sends NEED. Those two
//! paths are the only ways row bytes cross a session — the
//! **receiver-evidenced payload rule**.
//!
//! Concurrency is bounded on both sides of an edge. Each session
//! holds at most one negotiated round per lane in flight, and each
//! node serializes further: while any engine of a lane has a round
//! open, the node holds sibling sessions' hints and its own queued
//! root initiations (the prime and cadence drives), while a peer's
//! inbound ROOT arriving mid-round is dropped rather than held (a
//! stale whole-lane claim must not initiate; the cadence refresh
//! replaces it) — all holds bounded at eight entries per lane;
//! responses are never held — a peer's initiation must always
//! answer, or two nodes holding each other's hints would deadlock). Whole-lane
//! initiations are ordered: the data-poorer side of an edge — the `(count,
//! xor)`-lesser root — initiates, so the richer side never pushes
//! from a stale claim. Lost messages always recover through the
//! cadence ROOT exchange, never through re-sending payloads.
//!
//! ## Triggers and adaptation
//!
//! The plane is change-driven, with a quiet backstop:
//!
//! - **Local writes** note their store namespace; the next sync tick rescans
//!   only the lanes whose key spaces changed (a quiet steady state scans
//!   nothing) and leaves each peer's engine as one coalesced HINT. Rows a
//!   consumer applies fan out to the sibling engines at apply time, so a change
//!   propagates hop by hop as hints — the epidemic wave carries summaries,
//!   never payloads.
//! - **Eager-delta**: on a healthy link, the originator's local-write path
//!   piggybacks the changed rows onto the HINT under a 4 KiB budget; applied
//!   idempotently, it usually makes the negotiation unnecessary. It is the
//!   plane's only unsolicited payload — bounded, and disabled on links the
//!   profile distrusts.
//! - **The quiet cadence**: every 32 sync ticks (32 seconds at the default
//!   one-second tick) a bounded rotation of peers exchanges ROOTs — the
//!   loss-recovery backstop that heals any drift no message ever observed. On a
//!   weak link the cadence runs four times as often, every 8 ticks.
//! - **Link profiles**: each session tracks an EWMA of admission round-trip
//!   time and dispatch loss. A link is *weak* when loss reaches 10% or RTT
//!   reaches 1.5 s, and the verdict drives exactly three knobs — the cadence
//!   multiplier above, an undelivered hint's retry on a doubling backoff of 1,
//!   2, 4, 8 ticks (then the cadence absorbs the loss), and the eager-delta
//!   toggle. All three spend summary redundancy only: the payload path is not a
//!   knob, and a weak link's premium is retry latency, never duplicate bytes.
//! - **Pruning and the epoch index**: the incremental scan also prunes engine
//!   rows the store superseded (a revision bump, a lost last-writer-wins race)
//!   and tombstones the cleanup checkpoint already collected, so a newly
//!   connected peer receives the lane's current truth, never its history.
//!
//! ```no_run
//! # async fn demo(node: &radiata::NodeHandle) -> radiata::Result<()> {
//! # use radiata::ResourceName;
//! // A resource another member wrote arrives through the plane: from
//! // the business side it is a plain read once converged. Convergence
//! // needs no verb — `node.sync()` exists to drive one round now (for
//! // deterministic tests), not because the plane waits for it; a
//! // bounded poll like this is the integration's own deadline.
//! let name = ResourceName::parse("example.woooo.tech/config/edge")?;
//! let mut waited = 0;
//! let view = loop {
//!   if let Some(view) = node.resources().get(name.clone()).await? {
//!     break view;
//!   }
//!   waited += 1;
//!   if waited == 120 {
//!     return Err(radiata::Error::caller("the edge never converged"));
//!   }
//!   tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//! };
//! # let _ = view;
//! # Ok(())
//! # }
//! ```
//!
//! # 4. Routing packets: `RouteNextHop`
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
//! # 5. Receiving packets: `PacketConsumer`
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
//! # 6. Holding identity keys: the built-in custody and `KeyProvider`
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
//! # 7. Leaving the cluster: `node.leave`
//!
//! An active leave is three effects behind one verb: the node's
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
//! [`node.leave`](crate::NodeHandle::leave) as the point of no return for
//! that node slot: the returned
//! [`LeaveOutcome`](crate::LeaveOutcome) names the exact former and
//! replacement identities, and the same storage restarted afterwards
//! boots the replacement.
//!
//! ```no_run
//! # async fn demo(node: &radiata::NodeHandle) -> radiata::Result<()> {
//! let task = node
//!     .leave(radiata::ReplaceIdentityAndDeleteOldCoreMetadata::new())
//!     .await?;
//! // The task's `wait` resolves with the outcome before the
//! // active-leave teardown begins: durable from here, the node shuts
//! // itself down and restarts as the replacement identity.
//! let outcome = task.wait().await?;
//! # let _ = (outcome.former_identity(), outcome.replacement_identity());
//! # Ok(())
//! # }
//! ```
//!
//! # 8. Operations are tasks
//!
//! Every mutating verb — `join`, `leave`, `connect`, `disconnect`,
//! `revoke`, `cleanup`, the resource writes, `patch_metadata`, the
//! listener and credential verbs — has the same two-step shape:
//! **admission** is fast and does no IO, and the **effect** runs as an
//! admitted task on the node's task manager.
//!
//! ```no_run
//! # async fn demo(node: &radiata::NodeHandle) -> radiata::Result<()> {
//! // Admission: pure validation plus hooks, no dial, no store commit.
//! // An `Err` here is a bad request (a stopped node, a malformed write,
//! // a rejected hook) and means nothing was enqueued.
//! let task = node
//!     .listeners()
//!     .create(radiata::Endpoint::parse("tls://0.0.0.0:9443")?)
//!     .await?;
//! // The effect: `wait` resolves with the verb's historical return type
//! // (here a `ListenerView`) and its typed errors.
//! let listener = task.wait().await?;
//! # let _ = listener;
//! # Ok(())
//! # }
//! ```
//!
//! `wait` is value-based: an already-terminal task resolves immediately,
//! so a caller that admitted a task and only later reads its outcome
//! never misses the transition. It is the only per-operation await —
//! nothing polls and nothing sleeps. A task the node's shutdown cancels
//! before it settles fails with
//! [`ErrorKind::ShuttingDown`](crate::ErrorKind::ShuttingDown); the two
//! journaled/store-atomic kinds (`leave`, `resolve_frozen_journal`)
//! still resolve with their real outcome, because the shutdown drain
//! awaits them.
//!
//! ## Three ways to observe the same operation
//!
//! Pick by *who needs the outcome*, not by the verb:
//!
//! - **`task.wait()`** — this caller wants this one operation's result before
//!   moving on. It hands back the verb's historical success type, so a
//!   read-modify-write (a conditional resource write, a descriptor revision
//!   CAS) checks its typed [`ErrorKind::Conflict`](crate::ErrorKind::Conflict)
//!   right here and retries. This is the primary pattern: admit, then wait.
//! - **`node.tasks().get` / `node.tasks().list`** — this caller wants a status
//!   snapshot without blocking: the phase, the attempt count, the time bounds,
//!   the typed terminal error, and the payload of a succeeded task. Both read
//!   the node-local table directly (no supervisor round trip) over the bounded
//!   live-plus-terminal history; an unknown or evicted id reads as `None`. Use
//!   them for a dashboard, an operator surface, or the "did it finish while I
//!   was away" question.
//! - **`node.watch::<TaskChanged>(...)`** — this caller wants to react to
//!   *every* task transition of the node, streaming. It is a transient event
//!   like the rest of the hub: a lagging subscriber observes
//!   [`EventReceive::Lagged`](crate::EventReceive::Lagged) and re-reads through
//!   `tasks().get/list` instead of assuming the missed transitions.
//!
//! ```no_run
//! # async fn demo(node: &radiata::NodeHandle) -> radiata::Result<()> {
//! use radiata::{EventOptions, EventReceive, TaskChanged};
//!
//! let mut changes = node.watch::<TaskChanged>(EventOptions::new())?;
//! while let EventReceive::Item(changed) = changes.recv().await? {
//!     if changed.phase().is_terminal() {
//!         // Re-read the table for the payload or the typed error: the
//!         // event is a pointer, never the record.
//!         let _ = node.tasks().get(changed.task().clone()).await?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The three compose: a caller may wait on the tasks it admitted while a
//! node-local observer watches `TaskChanged` for the operator surface,
//! and a caller that restarted can re-read `tasks().get` for any task
//! still inside the bounded terminal history.
//!
//! Custom kinds extend the same surface: register a
//! [`TaskReconciler`](crate::TaskReconciler) under a caller-owned
//! qualified tag, then submit it through `node.tasks().submit`; the
//! returned `Task<()>` waits exactly like a core kind. The reserved
//! builtin domain is refused, so custom kinds never shadow core ones.
//!
//! # 9. Deploying on low-performance devices
//!
//! **There is nothing to configure.** Build the node, form the
//! cluster, send data — the defaults are the deployment. The library
//! ships exactly one timing profile and it is calibrated for the
//! slowest supported device (slow flash, one or two cores, duty-cycled
//! peers): a mixed cluster of fast and slow nodes runs on the same
//! defaults with no per-device profiles, because every timing constant
//! is peer-visible and timing divergence is what breaks mixed
//! clusters.
//!
//! Two sizes are worth knowing, and the defaults already answer both:
//!
//! - **Memory** is roughly `queue bytes × live neighbors` plus local
//!   diagnostics and storage. The degree contract gives "live neighbors" a
//!   practical ceiling: every node maintains about `k(n)` sessions (seven at 64
//!   members, growing with the logarithm of the cluster), so a 64-node member
//!   holds roughly `8 MiB × 7 ≈ 56 MiB` of queue capacity at the defaults.
//!   [`with_session_queue_limits`](crate::NodeConfig::with_session_queue_limits)
//!   and the degree override are the two knobs that change it materially.
//! - **Background load** is the reconciliation plane ([chapter
//!   3](#3-how-state-converges-the-reconciliation-contract)) riding the sync
//!   tick (one second by default,
//!   [`with_anti_entropy_interval`](crate::NodeConfig::with_anti_entropy_interval)):
//!   the tick's store scan is incremental — only lanes whose key spaces were
//!   written since the last pass rescan, so a quiet node scans nothing — and a
//!   change costs one coalesced summary hint per live session plus the changed
//!   rows themselves, which cross an edge only under the receiver-evidenced
//!   rule or as the bounded eager piggyback, never as a whole-catalog re-send
//!   or a per-edge duplicate. The quiet steady state is one tens-of-bytes
//!   whole-lane summary per peer per 32 ticks, dispatched through a bounded
//!   rotation window (two peers per tick), so the per-tick cost is independent
//!   of the connection degree: a denser node spreads its cadence exchanges
//!   across consecutive ticks. The tick settles delivery verdicts off the tick
//!   path, so a hub's per-tick hold-down stays at the dispatch cost rather than
//!   the slowest peer's ack bound. The degree-maintenance tick adds bounded
//!   work only while a node is below its target: nothing while healthy, one
//!   deficit-sized dial batch per 30 seconds while healing.
//!
//! Delivery across restarts stays the application's job (the data
//! plane is at-most-once): a `Failed` or interrupted stream is a
//! typed, bounded observation, not a silent loss. The chat example
//! ships the reference pattern — queue locally, re-drive on the typed
//! outcome, and let the bounded budgets turn congestion into fast
//! failures instead of queueing.
//!
//! The setters on [`NodeConfig`](crate::NodeConfig) are operator
//! escape hatches for *measured* problems, not integration steps: the
//! timing ones are cluster-wide contracts and must move together; the
//! resource ones (queues, diagnostics budget, dial deadline) are safe
//! to scale per device. Their contracts live on the type.
//!
//! # Storage
//!
//! Storage selection is explicit: `adapters::json_store` (test-only,
//! built with the `json` feature), `adapters::redb_store` (production,
//! built with the `redb` feature), or your own
//! [`StorageFactory`](crate::extension::StorageFactory) for other
//! backends. Custom adapters that scan the store directly bridge
//! through [`store_scan_stream`](crate::store_scan_stream).
