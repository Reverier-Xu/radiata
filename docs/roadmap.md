# radiata Development Roadmap

## Reason for Existence

This document turns the accepted product boundary into an ordered, verifiable development program.
ADRs govern design choices: [ADR-0007](adr/0007-core-responsibility-and-metadata.md) governs the core
boundary, [ADR-0009](adr/0009-peer-trust-cluster-composition.md) governs cluster composition semantics.

`radiata` is a Rust library for authenticated cluster connectivity, opaque packet streams, and
convergent core metadata. It does not model, persist, schedule, or deploy an application.

## Product Contract

The library provides:

- Stable node, trace, transaction, and operation identities. A `NodeId` is immutably bound to one
  Ed25519 public key; addresses and certificates are mutable attributes.
- Cluster composition under a peer-trust deployment model: every node is born holding a singleton
  cluster, `cluster_merge` unions binding sets, `cluster_leave` rotates identity behind an
  owner-signed leave record, and user-invoked cleanup with checkpoint GC collects dead-node
  tombstones. One credential authorizes one pairwise merge under the complete fixed policy: 32-byte
  single-use, ten-minute lifetime, one committed merge per generation, 4/64 pending attempts, 16/256
  attempts per minute, 1,024 bounded source buckets retained for ten idle minutes, ten-second deadline.
- Authenticated full-duplex transports, endpoint discovery, trust propagation, sparse topology,
  multi-hop routing, and continuous recovery while known members remain mutually unreachable.
- Opaque directed packet streams. Core assigns a `TraceId` before body delivery, targets an exact node
  or a node selected from matching node labels, applies caller-selected load balancing and routing, preserves order, and ends
  interrupted streams with an explicit error.
- Synchronous packet delivery that waits for current-process incoming-stream admission or a route
  error, and asynchronous delivery with a queryable route handle and selected destination.
- Node-owned revision-marked records and a generic named resource catalog with reserved type and URI
  labels, custom namespaced labels, and deterministic multiwriter timestamp-maximum convergence.
- Internal metadata storage through provider-owned immutable snapshots, exact lookup, unsigned-byte
  ordered streaming scans, conditional transactions, reconciliation, capabilities, migrations, a JSON
  test backend, a feature-gated redb production backend, and an open provider SPI.
- Portable behavior across Windows, macOS, and Linux.

There is no hard node-count ceiling. The 1,024-node profile is mandatory functional and trend evidence,
not merge policy or a larger-scale latency promise. Population-sized membership, trust, resource,
topology, and policy-input views are streamed, paged, or incrementally observed.

The exact 16-node latency profile remains a release evidence workload after being rewritten around
merges, packet delivery, owner-revision node metadata, and generic resource metadata.

## Packet Boundary

Core transports bytes and metadata without assigning application meaning. It has no built-in
conversation pattern. An incoming packet exposes authenticated source and destination, `TraceId`,
metadata, and an ordered body stream. A caller may derive another packet by swapping endpoints and
reusing the `TraceId`; correlation and interpretation remain caller-owned.

A delivery acknowledgement proves only that the destination authenticated and admitted the packet to
its current-process bounded incoming stream. It does not prove durable retention, caller observation,
processing, or success. Core stores bounded trace metadata only and never stores body bytes. Disconnect
or restart terminates an in-flight stream; core does not transparently replay or continue it.

## Metadata Boundary

Node records carry an owner identity marking and persistent strictly increasing revisions:
same-revision updates are rejected; a strictly higher revision replaces the record so anti-entropy
heals skipped ones. Entries ride authenticated sessions and carry no per-entry signatures (ADR-0008).

Generic resources are stable names plus labels. Reserved labels identify resource type and resource
URI; the URI references an upper-layer object or service and is never followed by core. Each
multiwriter resource value is ordered by the lexicographic maximum of host system-wall-clock timestamp,
canonical writer `NodeId`, removal rank, and canonical record digest. This is deterministic but is not
causal, fresh, or real-time last-writer behavior. Clock rollback may make a later local write lose and a
future-dated write may dominate until a greater tuple appears.

All ordering, expiration, retry, deadline, and retention decisions use host `SystemTime`. Rollback,
freeze, and forward jumps can delay work indefinitely or make it immediately due. Executor timers may
wake work to re-read wall time but are not protocol ordering authorities.

## Non-Goals

- General application records, business schemas, replicated application data, CRDTs, or business conflict resolution.
- Persistent packet bodies, durable caller handoff, automatic stream continuation, or built-in
  conversation semantics.
- Peer clock coordination, causal timestamps, clock-health voting, or future-write holding areas.
- Consensus, linearizability, or exactly-once application side effects.
- Core-defined storage capacity, key/value/transaction size policy, or whole-store materialization.
- Workload scheduling, deployment orchestration, application rollout, persistent volumes, or business data migration.
- NAT hole punching, STUN, public rendezvous, external relays, or address provisioning.

## Architecture Rules

1. Treat identity, endpoint reachability, active sessions, topology, routing, and resources as distinct
   domains. Never infer identity from an address or graph.
2. Keep identity, merge authorization, wire canonicalization, authenticated negotiation, route
   safety, metadata convergence, and transaction semantics closed and auditable.
3. Keep transports, discovery, protocol definitions, packet consumers, load balancing, routing,
   neighbors, key custody, and storage implementations open behind tagged traits.
4. Bound frames, queues, parser allocation, subscriptions, fan-out, concurrent work, and tasks with
   caller-selected nonzero validated capacities and typed backpressure.
5. Never impose a product population ceiling or return a whole-population allocation.
6. Store only core metadata. Private-key bytes and packet body bytes never enter metadata storage.
7. Use host `SystemTime` for protocol-visible time and document discontinuity risk at every deadline or
   ordering boundary.
8. Tag network and persisted formats from their first release. Unknown or conflicting definitions fail
   clearly; exact authenticated feature intersection never invents a fallback.
9. Forbid `unsafe`, production `unwrap()`, and production `expect()`. Diagnostics exclude credentials,
   private keys, provider handles, body bytes, and unredacted paths or addresses.

## Planned Module Boundaries

| Area | Responsibility | Primary extension boundary |
| --- | --- | --- |
| `identity` | IDs, immutable key binding, merge authorization, trust, revoke, rotation | Key provider |
| `protocol` | Prelude, deterministic CBOR, feature and protocol definition intersection | Protocol registry |
| `transport` | Discovery, candidates, authenticated full-duplex sessions | Transport and discovery |
| `membership` | Owner-revision-marked entries and streamed membership observations | None |
| `topology` | Reachability, neighbor selection, recovery, streamed topology | Neighbor policy |
| `routing` | Packet targets, load balancing, routes, stream forwarding, trace status | Load-balancing and routing policies |
| `resource` | Named resource metadata, reserved/custom labels, selectors, convergence | Resource metadata API |
| `storage` | Internal metadata transactions, snapshots, scans, migration, adapters | Storage factory/backend |
| `node` | Builder, lifecycle, typed bus, events, task ownership | Injectable providers |

`src/lib.rs` remains a deliberate facade. Wire, backend, and task internals do not become public merely
because they share the crate.

## Milestones

### M0: Responsibility and Contract Rebaseline

Reopen G0 using the existing IDs. Reconcile every active planning artifact with ADR-0007 and ADR-0009,
freeze the
packet, metadata, time, storage, and population-query contracts, update threat/evidence ownership, and
make the validator reject reintroduced superseded active semantics. Earlier evidence cannot close the
new predicates.

Exit gate:

- All 69 task/verification IDs, 226 scenario IDs, ten E2E IDs, and 29 threat IDs remain stable.
- Active artifacts consistently state the connectivity-and-metadata boundary.
- API inventory and content digests match the rebaselined manifest.
- Planning validation and negative fixtures pass.

### M1: Deterministic Foundation

Deliver canonical IDs and tags, checked limits, errors, the Tokio supervisor and typed bus, seeded
entropy, injected wall-clock observations for tests, deterministic simulation, and secret-safe failure
artifacts. Time simulation models `SystemTime` discontinuities explicitly.

Exit gate:

- Canonical identity and transaction text round trips and deterministic encodings pass properties.
- Lifecycle and failure replay are bounded, reproducible, panic-free, and secret-safe.
- The minimal public facade contains no superseded surface.

### M2: Internal Metadata Persistence

Implement provider-owned immutable snapshots, exact lookup, ordered streaming scans, conditional
cross-family transactions, receipts, reconciliation, capabilities, key intents, canonical identity
records, and the JSON test backend. Providers own layout, durability configuration, and capacity.

Exit gate:

- Transaction IDs round-trip through canonical validated text.
- JSON and external-provider contract tests prove ordered streaming, conflicts, crash outcomes,
  reconciliation, corruption refusal, and typed resource exhaustion without truncation.
- Referenced private keys are never deleted and private bytes never enter storage.

### M3: Secure Two-Node Packet Slice

Implement the credential-authorized merge handshake, authenticated TLS 1.3 WebSocket sessions,
exporter binding, feature intersection, incoming packet streams, and direct exact-node packet delivery
in both directions.

Exit gate:

- Real loopback merge and authenticated packet streaming pass through the public facade.
- The `TraceId` exists before body delivery, bytes remain ordered, and disconnect is explicit.
- Delivery acknowledgement proves only current-process incoming-stream admission.

### M4: Session and Trust Generalization

Add transport/discovery registries, node-owned endpoint candidate revisions, crossed-dial replacement,
bounded queues, trust snapshots, paged trust observations, readdressing, and clean shutdown.

Exit gate:

- Reciprocal exact public-key trust propagates and catches up through ordinary metadata sync.
- Alternate-peer reconnect is credential-free after merge.
- Slow peers and replacement races release all bounded resources.

Reserved config: `NodeConfig::session_queue_bytes` is the session byte budget that M4 wires
(see `TODO(G4)` in `src/config.rs`).

### M5: Membership, Topology, and Recovery

Add monotonic owner-marked node metadata, paged membership/topology observations, incremental policy inputs,
sparse neighbor maintenance, reachability, and continuous configurable recovery until known online
members have an authenticated path.

Exit gate:

- Recovery reactivates on later membership/connectivity changes and stops at connected reachability,
  not a full mesh.
- 16-node functional/SLO readiness and 1,024-node functional/trend evidence pass without a ceiling claim.
- No membership, trust, topology, or policy API requires one whole-population allocation.

`NodeConfig::anti_entropy_interval` drives the session-carried membership sync
driver and `RecoveryConfig` drives the recovery controller (wired in M5). The
session sync protocol carries bounded membership pages and the issuer trust snapshot; the recovery controller heals edge loss among ever-connected
members and never dials intentionally disconnected peers until a deliberate
reconnect.

### M6: Multi-Hop Packet Streams

Add exact-node and matching-node-label targets, caller-selected load balancing/routing, ordered constant-memory
forwarding, synchronous terminal delivery, asynchronous route handles, selected-destination status,
bounded trace metadata retention, and explicit route/session interruption.

Exit gate:

- Packets cross at least three hops with constant memory and backpressure.
- Sync delivery returns current-process admission acknowledgement or a typed route error.
- Async status reports selection, progress, and terminal state; restart stores no body and continues no
  stream.

Reserved config: `NodeConfig::parser_limits` (the public twin of the enforced `CborLimits`) and
`TraceMetadataLimits::terminal`/`retention` are consumed by the packet parser and route-status
retention that M6 wires (see `TODO(G6)` in `src/config.rs`). The routing-domain code currently
parked in `session/stream.rs` moves to its own module here (see `TODO(M6)`).

### M7: Core Metadata Convergence

Implement node-owner revision registers and multiwriter resource registers ordered by the
`SystemTime` timestamp/writer/removal/digest tuple. Add reserved resource type and URI labels,
namespaced custom labels, selectors, paged scans, and normal-tick repair.

Exit gate:

- Same-revision node conflicts reject; generic resource permutations converge deterministically.
- Tests demonstrate rollback, equal timestamp, future dominance, and absence of causal/freshness claims.
- Partitioned resource metadata converges through the ordinary sync path.

### M8: redb and Metadata Migration

Implement the feature-gated redb production backend, migration graphs, capability refusal, crash
reconciliation, and logical parity with JSON and external providers.

Exit gate:

- JSON/redb metadata contracts and mixed-backend restart tests pass unchanged.
- Migration interruption is old-or-new and older readers refuse unsupported schemas.
- No storage API becomes an application persistence service.

### M9: Resource Operations and Facade Closure

Complete named resource mutation/removal, labels and selectors, convergent revocation,
leave-via-rotation, dead-node cleanup, immediate recovery, streamed observations, route status/events,
and the sealed public facade.

Exit gate:

- Resource URIs are never followed or deleted by core cleanup/leave.
- Explicit operations affect only core metadata and key intents.
- Public integration tests contain no platform or application model.

### M10: Compatibility and Release Evidence

Add golden vectors, mixed binaries, fuzzing, soak, native CI, public OCI evidence, and release guards.
Rewrite the fixed 16-node workload around merges, packets, node-owner revisions, and resources; retain
the 1,024-node functional/trend profile.

Exit gate:

- Native feature matrices and mixed binaries pass with zero warnings.
- Packet, metadata, storage, and wall-clock discontinuity fuzz/soak targets complete.
- All 125 exact-candidate samples use the revised workload and retain complete attempt lineage.
- Functional `0.1.0` API, wire, and metadata compatibility receive explicit review.

### M11: Rebaseline Fix and Cleanup

Execute the ADR-0009 cluster-composition rebaseline and the stream-terminology rename, regenerate
the affected wire/metadata evidence, rewrite the threat model and SLO workload, and complete the
deferred native-CI, SLO-harness, SLO-ledger, and publish work.

Exit gate:

- The public facade exposes only the merge/leave/cleanup and stream surface; no genesis or cluster
  identity remains in API, wire, or storage.
- Golden vectors, mixed binaries, fuzz, soak, and the 125-sample merge-workload ledger pass on the
  rebaselined formats.
- The README documents the peer-trust deployment model and its operational contract.

## Requirement Traceability

| Requirement | Owning milestones |
| --- | --- |
| Identity, merge authorization, key custody | M1, M2, M3 |
| Full-duplex authenticated transports and recovery | M3, M4, M5 |
| Exact-node and node-label-selected packet streaming | M3, M6, M9 |
| Revision-marked node and resource metadata convergence | M5, M7, M9 |
| Internal JSON/redb/provider metadata storage | M2, M8 |
| No node ceiling and streamed population views | M0, M5, M9 |
| System-wall-clock semantics and discontinuity evidence | M1, M6, M7, M10 |
| Portability, compatibility, and release evidence | M8, M10 |

## Delivery Order

Execution follows the gate order `G0 -> G1 -> G2 -> G3 -> G4 -> G5 -> G6 -> G7 -> G8 -> G9 -> G10`;
already-landed code is re-evaluated against the revised predicates.

## Definition of Done

Every milestone passes the repository quality suite plus its owned scenario, threat, compatibility,
crash, scale, and platform evidence. Evidence created for a superseded predicate cannot satisfy the
replacement predicate. Review final diffs for accidental production, dependency, CI, or test changes.

Verify this roadmap with:

```bash
test -f docs/roadmap.md
test "$(wc -l < docs/roadmap.md)" -le 320
grep -q '^## Requirement Traceability$' docs/roadmap.md
grep -q '^### M10: Compatibility and Release Evidence$' docs/roadmap.md
```
