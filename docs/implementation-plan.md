# radiata Implementation Task Plan

## Responsibility Rebaseline

This is the executable backlog for the radiata implementation. Already-landed code is re-evaluated
against the revised rows and scenario text.

A task changes no public/wire/persisted contract beyond this plan and the API manifest.
Population-sized outputs are always streamed, paged, or incremental. Packet bodies and application
objects never enter core storage.

Rebaseline (2026-09-05): ADR-0009 replaces the create/join admission lifecycle with the peer-trust
merge model and deletes `ClusterId`, genesis records, and creator privilege; rows and scenarios
referencing them are re-scoped at execution per
`docs/reviews/2026-09-05-plan-rebaseline-audit.md`. The rebaseline work and the incomplete G10
tasks (T-G10-07, T-G10-10, T-G10-11, T-G10-12) are orchestrated as gate G11.

Rollback codes: `R0` independent before compatibility; `R1` before dependents; `R2` retain shipped
readers/tags/migrations; `R3` irreversible security action requiring forward recovery.

## Package Decisions

Existing package decisions remain unchanged by this planning-only rebaseline: Tokio owns the runtime;
minicbor owns deterministic CBOR; Rustls/Tungstenite provide TLS 1.3 WebSockets; JSON is test-only; redb
is feature-gated production storage; test/evidence tools remain development-only. New dependencies
require a plan amendment.

Amendment (T-G03-02 observability baseline): `tracing` is an approved production diagnostics facade
(zero-cost no-op without a subscriber; host applications own their subscriber) and
`tracing-subscriber` remains development-only for test diagnostics. ADR-0004 records the rationale;
the dependency-graph baseline pins the exact resolution.

Amendment (post-G3 quality review, 2026-08): `domain` 0.11 is an approved production dependency
for DNS hostname grammar and label-length validation (endpoint and tag domains); IPv4/IPv6 literal
validation uses the standard library's `std::net` parsers. Both replace hand-written canonical
checks; DNS names are case-insensitive and are normalized to lowercase for storage and comparison.
This amendment also records the P2 cleanup batch that removed thin wrappers, duplicated helpers,
and hardcoded tables; see the project `.agents/skills/code-quality-review` findings for the full
inventory.

## Observability Discipline

From G3 onward every task instruments its owned paths with the approved `tracing` facade and keeps
diagnostics secret-safe (roadmap architecture rule 9): no credentials, private keys, provider
handles, body bytes, or unredacted paths and addresses in any emitted event, span, or error context.
Tests remain the primary evidence; tracing events support debugging and operational observability and
never replace assertions. T-G10-05 still owns the bounded public observability API surface.

## Critical Path

`G0 -> G1 -> G2 -> G3 -> G4 -> G5 -> G6 -> G7 -> G8 -> G9 -> G10 -> G11`

## G0: Responsibility and Contract Rebaseline

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G00-01 Identity/bootstrap/channel ADR | P0/H | Roadmap | Retain immutable IDs/key binding, complete fixed admission, TLS 1.3 exporter binding, and key-loss rules | ADR-0001 plus ADR-0007 authority | SC-G00-P0-01..02; fixed admission/identity review | R0 |
| T-G00-02 Wire/features/packet ADR | P0/H | 00-01 | Reinterpret wire around opaque ordered packet streams, immediate trace identity, exact feature intersection, current-process ACK, and no body storage | ADR-0002 plus ADR-0007 authority | SC-G00-P0-03..05; packet boundary review | R0 |
| T-G00-03 Metadata/storage/time ADR | P0/M | 00-01,02 | Reinterpret persistence as internal metadata storage, owner revisions, resource tuple order, provider snapshots/scans, and `SystemTime` risk | ADR-0003 plus ADR-0007 authority | SC-G00-P0-06..07; metadata/storage review | R0 |
| T-G00-04 Toolchain/features/evidence ADR | P1/L | 00-02,03 | Retain toolchain, additive features, budgets, corpus ownership, and secret-safe replay for revised domains | ADR-0004 and package metadata | SC-G00-P1-01..02; accepted policy checks | R0 |
| T-G00-05 Sixteen-node OCI SLO ADR | P1/N | 00-02,03,04 | Rewrite workload around admission, packets, node revisions, and resources while retaining 125 samples | ADR-0005 plus ADR-0007 authority | SC-G00-P1-03..04; revised profile checks | R0 |
| T-G00-06 Planning responsibility reconciliation | P0/H | 00-01..05 | Reopen G0; align active roadmap/gates/tasks/API/scenarios/threats/constants/evidence; reject superseded semantics | ADR-0006/0007, planning manifests, validator | SC-G00-P0-08..09; `scripts/verify-task.sh T-G00-06` | R0 |

## G1: Deterministic Foundation

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G01-01 Core values/envelopes | P0/M | 00-06 | Canonical IDs/tags/errors/finite limits, `TransactionId` text roundtrip, prelude and CBOR; no population ceiling | core values/protocol | SC-G01-P0-01, SC-G01-P1-01..02; canonical/bound properties | R1 |
| T-G01-02 Tokio lifecycle/typed bus | P0/L | 01-01 | Sealed command/query/event facade, supervisor, injected entropy, no wall-clock read before an owned deadline exists, start/shutdown | runtime/facade | SC-G01-P0-02, SC-G01-P1-03; lifecycle/time boundary | R1 |
| T-G01-03 Deterministic network/time simulator | P0/L | 01-01,02 | Directed links, finite work, loss/reorder/partition/restart/readdress and wall-clock rollback/freeze/jump | simulation | SC-G01-P0-03, SC-G01-P1-04; deterministic replay | R0 |
| T-G01-04 Failure artifact/replay | P0/M | 01-03 | Bounded allowlisted artifacts and closed argv excluding secrets, packet bytes, paths, and addresses | test-support/simulation fixtures | SC-G01-P0-04..05; redaction/provenance/replay tests | R0 |
| T-G01-05 G1 facade/MSRV/lint closure | P0/M | 01-01..04 | Freeze the complete externally implementable Key/Storage SPI shape, validation, canonical transaction/operation digest helper, constructors/accessors, and revised minimal facade; prove MSRV/stable/locked dependency and panic-free production gates | facade/quality scripts | SC-G01-P0-06..07; public facade and quality closure | R0 |

## G2: Internal Metadata Persistence

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G02-01 Metadata storage contract | P0/M | 01-05 | Implement the backend-neutral reusable storage semantic contract, capability probe, commit/freeze/reconcile engine, and generic receipt reference/host-wall-clock retention protocol using the G1-frozen SPI; exclude JSON (02-03), crash/key-intent evidence (02-04), and migrations/redb/backend parity (02-05/G8) | storage contract | SC-G02-P0-01, SC-G02-P1-01; order/conflict/outcome/retention contract | R1 |
| T-G02-02 Identity/genesis/admission records | P0/H | 02-01,01-01 | Key SPI and canonical identity/admission metadata; provider capacity and private custody remain external | identity/key/storage records | SC-G02-P0-02..03; uniqueness/reconcile/redaction | R1 |
| T-G02-03 JSON test adapter | P0/M | 02-01,02 | Immutable checksummed JSON generations implementing stream scans and typed provider exhaustion; feature powerset | JSON modules/feature CI | SC-G02-P0-04, SC-G02-P1-02; adapter and feature contract | R1 |
| T-G02-04 JSON/provider crash matrix | P0/M | 02-03,01-04 | Fault metadata commits and key intents at every write/flush/rename/reopen/result boundary | JSON/key crash fixtures | SC-G02-P0-05..06; old/new/unknown and referenced-key safety | R0 |
| T-G02-05 JSON native robustness | P0/H | 02-04 | Alias-safe locks, corruption refusal, provider capability/resource-exhaustion behavior, no truncation | JSON/storage errors/native CI | SC-G02-P0-07, SC-G02-P1-03; native/provider suite | R0 |

## G3: Secure Two-Node Packet Slice

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G03-01 Authenticated handshake/vectors | P0/H | G2 PASS | Genesis receiver, protocol/feature definitions, exact intersection, canonical authentication vectors | identity/protocol fixtures | SC-G03-P0-01..04; registry/vector/state tests | R1 |
| T-G03-02 Real TLS WebSocket packet | P0/H | 03-01 | Listen/join and exact-node outgoing/incoming packet streams over real TLS 1.3 WebSocket; approved secret-safe tracing observability baseline for the data plane (plan amendment, ADR-0004) | transport/packet facade/E2E | SC-G03-P0-05..06; secure join/stream integration | R1 |
| T-G03-03 Atomic admission/reconciliation | P0/H | 03-02 | Commit binding/use/grant once and reconcile every indeterminate outcome without duplicate subject | identity/admission | SC-G03-P0-07..09; every commit/result boundary | R2 |
| T-G03-04 Feature selection/reconnect | P0/H | 03-03 | Exact signed intersection/effective limits, required-feature refusal, credential-free reconnect | negotiation/session | SC-G03-P0-10..14, E2E-01; downgrade/reconnect matrix | R2 |
| T-G03-05 Bidirectional packet streams | P0/H | 03-02,04 | Immediate core TraceId, ordered full-duplex streams, bounded incoming admission, explicit disconnect failure | packet/session | SC-G03-P0-15..17; order/backpressure/interruption suite | R2 |
| T-G03-06 Hostile/admission-input closure | P0/H | 03-01..05 | Enforce complete fixed admission and caller-selected parser/frame/task limits with typed overload | config/error/transport | SC-G03-P0-18..22; admission/malformed/saturation suite | R1 |

## G4: Session and Trust Generalization

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G04-01 Discovery/transport registries | P0/H | G3 PASS | Open registries keyed by canonical tags; core retains authentication and stream safety | transport/discovery | SC-G04-P0-01..04; registry/security contract | R1 |
| T-G04-02 Endpoint revisions/readdress | P0/H | 04-01 | Node-owned signed candidate generations, caller filtering/priorities, expiration by wall time | transport/discovery metadata | SC-G04-P0-05..08; ownership/readdress/discontinuity | R1 |
| T-G04-03 Crossed-dial/session replacement | P0/H | 04-01,02 | Deterministic one-session ownership, drain, stale-generation rejection, restart/readdress behavior | session | SC-G04-P0-09..11; race/replacement suite | R1 |
| T-G04-04 Queue/keepalive/shutdown bounds | P0/H | 04-03 | Caller-selected nonzero queue/task capacities, wall-clock deadlines, backpressure/cancel/shutdown | session lifecycle | SC-G04-P0-12..15; saturation/discontinuity/baseline | R1 |
| T-G04-05 Trust snapshot/dissemination/page | P0/H | 04-01,02,03-04 | Admission grants and issuer trust snapshots, reciprocal exact bindings, paged trust observations, offline catch-up | identity trust metadata | SC-G04-P0-16..19; trust/page/format contracts | R2 |
| T-G04-06 Reciprocal alternate-peer reconnect | P0/H | 04-02..05 | Issuer disconnect, alternate authenticated route, outbound-only and readdressed packet paths | facade E2E | SC-G04-P0-20..22, E2E-02/E2E-03; four public targets | R0 |

## G5: Membership, Topology, and Recovery

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G05-01 Node metadata/vectors | P0/H | G4 PASS | Persistent strictly increasing owner revisions marked by NodeId; reject same-revision conflict; tombstone removals | membership metadata | SC-G05-P0-01..05; revision/vector contract | R2 |
| T-G05-02 Streamed membership repair | P0/H | 05-01 | Normal-tick bounded page/stream anti-entropy with no node ceiling or whole-population allocation | membership sync | SC-G05-P0-06..09; paging/replay/1,024 trend | R2 |
| T-G05-03 Sparse neighbor policy | P0/H | 05-01,02,04-04 | Incremental policy input, caller-configured neighbor/fan-out, streamed topology/reachability | topology policy | SC-G05-P0-10..13; incremental/churn/slow-policy suite | R1 |
| T-G05-04 Continuous recovery state machine | P0/H | 05-03 | Retry unreachable components using caller backoff/fan-out; immediate command; stop at connected path; reactivate | topology recovery | SC-G05-P0-14..19; activate/stop/reactivate/restart bounds | R1 |
| T-G05-05 Sixteen-node recovery simulation/E2E | P0/H | 05-02..04 | Simulated and facade recovery with configured policies and no full-mesh requirement | recovery simulation/E2E | SC-G05-P0-20..22, E2E-04; connected-path assertions | R0 |
| T-G05-06 Readiness/scale closure | P0/H | 05-01..05 | Public paged trust/node/topology readiness, 16-node profile, 1,024-node functional/trend evidence | membership/topology tests | SC-G05-P0-23..29; no-ceiling/no-whole-Vec matrix | R0 |

## G6: Multi-Hop Packet Streams

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G06-01 Packet route authorization | P0/H | G5 PASS | Exact-node/matching-node-label target, signed trace route context, checked hop/loop policy, one selected next hop | routing envelope/policy | SC-G06-P0-01..04; selection/mutation/loop/amplification properties | R1 |
| T-G06-02 Trace metadata store | P0/H | 06-01,G2 PASS | Store only selected destination/attempt/progress/terminal metadata with caller retention/capacity; never body bytes | routing trace metadata | SC-G06-P0-05..08; no-body/reconcile/capacity/compatibility | R2 |
| T-G06-03 Ordered constant-memory forwarding | P0/H | 06-02,G4 PASS | Stream frames once along selected route with backpressure; disconnect returns explicit typed failure | routing forwarder | SC-G06-P0-09..11; order/memory/fault boundaries | R2 |
| T-G06-04 Destination stream admission | P0/H | 06-02,G4 PASS | Authenticate and admit bounded incoming stream; ACK current-process admission only; no caller outcome semantics | routing destination/packet consumer | SC-G06-P0-12..15; forged/overload/crash/no-durability cases | R2 |
| T-G06-05 Sync/async route completion | P0/H | 06-03,04 | Sync waits ACK or route error; async returns handle/status with selected node; wall-clock retention; no continuation | routing source/facade | SC-G06-P0-16..20, E2E-05; route/status/disconnect/restart cases | R2 |

## G7: Core Metadata Convergence

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G07-01 Host wall-clock semantics | P0/H | G6 PASS,G2 PASS | Use `SystemTime` for ordering/deadlines/retention; test rollback/freeze/jump; expose no peer-clock API | time integration | SC-G07-P0-01..02, SC-G07-P1-03; discontinuity matrix | R2 |
| T-G07-02 Signed resource tuple/vectors | P0/H | 07-01 | Named resources; reserved type/URI and custom labels; signed timestamp/writer/removal/digest maximum | resource record/version | SC-G07-P0-04..06; signature/comparator/permutation vectors | R2 |
| T-G07-03 Conditional resource mutation | P0/H | 07-02,G2 PASS | Put/remove metadata with conditional local transactions; accepted writes may lose tuple order | resource store/facade | SC-G07-P0-07..09; conflict/loser/crash atomicity | R2 |
| T-G07-04 Resource metadata sync | P0/H | 07-03,G6 PASS | Bounded pages/deltas and ordinary repair; validate before merge; no business codec or record | resource sync | SC-G07-P0-10..11, SC-G07-P1-12; partition/page convergence | R2 |
| T-G07-05 Signed removal retention | P0/H | 07-04 | Preserve resource/node removal evidence; exact conditional metadata cleanup never follows URI | resource cleanup | SC-G07-P0-13..15; race/crash/stale/URI safety | R3 |
| T-G07-06 Partition/scale/SLO closure | P0/H | 07-04,05 | 8+8 node/resource merge, 1,024-node functional trend, revised 16-node workload | metadata E2E/scale/SLO | SC-G07-P0-16..18, E2E-06; tuple/no-causality/no-ceiling assertions | R0 |

## G8: redb and Mixed Metadata Storage

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G08-01 Complete metadata storage contract | P0/H | G7 PASS,G6 PASS | Apply snapshot/scan/transaction/reconcile/capability contract to all core metadata families | storage/backend schema | SC-G08-P0-01..02, SC-G08-P1-03; all-family JSON/provider contract | R1 |
| T-G08-02 Optional redb adapter | P0/H | 08-01 | Feature-gated production factory, provider-owned snapshots/scan streams, no redb type leak | redb adapter/manifest | SC-G08-P0-04..05, SC-G08-P1-06; feature isolation/parity | R1 |
| T-G08-03 redb crash/conflict/integrity | P0/H | 08-02,02-04 | Crash classification, conflicts, key intents, receipts, typed exhaustion, integrity reopen | redb crash tests | SC-G08-P0-07..09; no-partial-family/no-truncation | R1 |
| T-G08-04 Transactional migration graph | P0/H | 08-03 | Explicit immutable metadata schema edges, ambiguity refusal, old-or-new interruption, older-reader refusal | storage migration/fixtures | SC-G08-P0-10..12; migration matrix | R2 |
| T-G08-05 Mixed backend/feature closure | P0/H | 08-04,G7 PASS | Restart mixed JSON/redb metadata cluster and compare logical stream output; powerset CI | mixed storage E2E | SC-G08-P0-13..14, SC-G08-P1-15, E2E-07; parity/restart/powerset | R0 |

## G9: Resources, Explicit Operations, and Facade

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G09-01 Resource names/labels/vectors | P0/H | G8 PASS,G7 PASS | Stable resource name, reserved type/URI labels, namespaced custom labels, tuple-version fixtures | resource labels/records | SC-G09-P0-01..04; namespace/reserved/tuple/vector tests | R2 |
| T-G09-02 Selectors/paged queries | P1/M | 09-01 | Bounded selector grammar and paged resource selection; no whole-population output | resource selector/facade | SC-G09-P1-05..08; parser/evaluator/page parity | R1 |
| T-G09-03 Resource mutations/events | P0/H | 09-01,02,G6 PASS | Conditional metadata label batch and post-commit event; ordinary maintenance preserves metadata | resource operations/events | SC-G09-P0-09..12; JSON/redb concurrency/event cases | R2 |
| T-G09-04 Authorization revoke | P0/H | 09-03,G8 PASS | Revoke connectivity/admission authority while valid stored metadata remains eligible | identity/trust facade | SC-G09-P0-13..14; crash/reconnect/delayed metadata | R3 |
| T-G09-05 Metadata removal operation | P0/H | 09-03,G7 PASS | Exact signed resource removal evidence/cleanup limited to core metadata; never follow URI | resource cleanup facade | SC-G09-P0-15..17; atomicity/stale/URI/no-auto | R3 |
| T-G09-06 Active leave/identity rotation | P0/H | 09-04,05,G2 PASS | New identity/key and removal of old local core metadata/key intents only | node lifecycle/key/storage | SC-G09-P0-18..21; JSON/redb crash/restart/URI preservation | R3 |
| T-G09-07 Facade/population closure | P0/H | 09-01..06,G3 PASS | Packet/resource/route/recovery APIs, paged trust/member/resource/topology views, events, no platform semantics | facade/public tests | SC-G09-P0-22..26, E2E-08; external core-only API proof | R2 |

## G10: Compatibility and `0.1.0` Evidence

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G10-01 Freeze wire/metadata formats | P0/H | G9 PASS | Packet, identity, node, resource, trace metadata, transaction, and migration vectors/readers | compatibility/fixtures | SC-G10-P0-01..05; golden/migration suites | R2 |
| T-G10-02 Mixed-binary feature intersection | P0/H | 10-01 | Prior/current packet and core-metadata interop with exact authenticated intersection | mixed-version tests | SC-G10-P0-06..09, E2E-09; both initiator roles/refusal | R2 |
| T-G10-03 Decoder/selector fuzzing | P0/H | 10-01 | Wire, persisted metadata, and selector targets with bounded reviewed corpora | fuzz decoders | SC-G10-P0-10..11; corpus/live fuzz | R0 |
| T-G10-04 State-machine fuzzing | P0/H | 10-01 | Admission, feature, packet routing/stream, and resource tuple state targets | fuzz state machines | SC-G10-P0-12..14; invariant/corpus tests | R0 |
| T-G10-05 Secret-safe observability | P0/H | 10-02,G9 PASS | Bounded route/resource/reachability/queue/task/storage status; no body/secret/path/address leakage | observability | SC-G10-P0-15..16; baseline/redaction | R1 |
| T-G10-06 Churn/resource soak | P0/H | 10-05,G7 PASS | 8h/24h packet, metadata, session, wall-clock and provider churn with baseline return | soak | SC-G10-P0-17..19; duration/baseline evidence | R0 |
| T-G10-08 API/semver review | P0/H | 10-01,02,G9 PASS | Approve exact connectivity/packet/metadata facade and absence of superseded exports | API manifest/public tests | SC-G10-P0-25..26; public-api/semver/external test | R2 |
| T-G10-09 Evidence validator preflight | P0/H | 10-03..08 | Validate current threat/budget/attempt/profile semantics and reject stale/superseded evidence | evidence docs/validator | SC-G10-P0-27..29; negative ledgers | R0 |

## G11: Rebaseline Fix and Cleanup

G11 executes the ADR-0009 cluster-composition rebaseline and the stream-terminology rename recorded
in `docs/reviews/2026-09-05-plan-rebaseline-audit.md`, then completes the G10 work moved below.
Moved tasks keep their stable IDs; the gate closes on the publish task.

| Task | Risk | Depends | Deliverable / exact API impact | Owned paths | Evidence | RB |
| --- | --- | --- | --- | --- | --- | --- |
| T-G11-01 Stream rename/standard bodies | P0/H | G10 PASS | Rename the packet family to stream terminology and replace `PacketBody` with the standard `futures::Stream` (futures-core enters the public ABI); `open_stream` keeps the two-phase TraceId-before-body flow | packet/api/facade | SC-G11-P0-01..03; rename/public-api/stream-body suites | R2 |
| T-G11-02 Event/scan stream adapters | P1/M | 11-01 | `Stream` impl for `EventSubscription` and a `StoreScan` to `BoxStream` converter | node/provider | SC-G11-P1-04..05; adapter parity tests | R1 |
| T-G11-03 Public ABI rule amendment | P0/M | 11-01 | Manifest admits futures-core and Tokio traits/interfaces, keeps channel/task handles excluded; ADR rationale note | api-manifest/adr | SC-G11-P0-06; digest/freeze guard | R2 |
| T-G11-04 ChannelBody receiver cleanup | P2/L | 11-01 | Replace the hand-rolled incoming-body receiver loop with `ReceiverStream` plus an explicit end sentinel | packet internals | SC-G11-P1-07; interruption suites | R1 |
| T-G11-05 Born-with-cluster | P0/H | 11-01 | `start()` get-or-create local identity; delete `CreateCluster`, `JoinCluster`, `existing_cluster`, and the genesis/pointer storage families | identity/node/runtime | SC-G11-P0-08..10; reopen/idempotence/crash suites | R2 |
| T-G11-06 cluster_merge | P0/H | 11-05 | Credential-authorized pairwise merge; binding-set union over authenticated sessions and ordinary sync | identity/session/membership | SC-G11-P0-11..14; credential/expiry/single-use/union matrix | R2 |
| T-G11-07 cluster_leave | P0/H | 11-05 | Owner-signed leave record, bounded first-ACK wait, rotation pipeline with crash-safe journal | identity/leave/session | SC-G11-P0-15..18; ack/timeout/crash/replay suites | R3 |
| T-G11-08 Cleanup command family | P0/H | 11-06,07 | `cleanup_node` convergent tombstone, `purge_revocation` local explicit clear, detection views | membership/identity/facade | SC-G11-P0-19..22; terminality/convergence/view suites | R3 |
| T-G11-09 Checkpoint tombstone GC | P0/H | 11-08 | Unsigned max-wins checkpoint record, removal-only sync filtering, GC pass on the retention engine | membership/sync/storage | SC-G11-P0-23..26; checkpoint/filter/merge-after-checkpoint suites | R2 |
| T-G11-10 Convergent permanent revocation | P0/H | 11-08 | Revocation as a convergent permanent tombstone excluded from checkpoints; cluster-wide expulsion | identity/trust | SC-G11-P0-27..30; expulsion/permanence/backup-restore suites | R3 |
| T-G11-11 ClusterId excision/vector regen | P0/H | 11-05..10 | Handshake, hint, grant, and snapshot formats lose cluster fields; golden vectors and compatibility fixtures regenerated | protocol/identity/compatibility | SC-G11-P0-31..33; golden/migration re-run | R2 |
| T-G11-12 Threat/scenario/README rebaseline | P0/M | 11-05..11 | Threat model narrows to transport-path adversaries, scenario catalog re-keyed, README deployment-trust note | docs | SC-G11-P0-34..35; validator negative fixtures | R1 |
| T-G11-13 SLO merge-stratum workload | P0/H | 11-06,07 | The five admission samples become five merge samples with unchanged credential evidence rules | slo harness | SC-G11-P0-36..37; harness qualification | R0 |
| T-G11-14 API manifest/inventory amendment | P0/H | 11-01..13 | Merged ADR-0009 plus stream surface frozen into the manifest and api-inventory digests | api manifest/inventory | SC-G11-P0-38..39; digest/public-api proof re-run | R2 |
| T-G10-07 Native CI/evidence matrix (moved) | P0/H | 11-01..14 | MSRV/stable/native/features/fuzz/soak attestations for the rebaselined targets | workflows/evidence | SC-G10-P0-20..24; native/powerset/attestation | R0 |
| T-G10-10 OCI SLO harness qualification (moved) | P0/H | 11-13 and prior G11 | External publish-false 16-node harness using merges, packets, owner revisions, and resources only | SLO harness | SC-G10-P0-30..33; isolation/readiness/workload/cleanup | R0 |
| T-G10-11 Candidate and complete SLO ledger (moved) | P0/H | 11-13 and prior G11 | Immutable candidate, release matrices, 125 merge-workload samples, complete lineage | release/SLO evidence | SC-G10-P0-34..37, E2E-10; exact SHA/profile/results | R0 |
| T-G10-12 Manual publish contract (moved) | P1/L | 10-11 | No automated publication surface; the operator runs the launcher, reviews the outcomes, and tags the exact verified commit | release flow | SC-G10-P0-38..40; launcher sequencing and manual-publish contract | R0 |

## Gate Closure

Each gate closes on its final stable task (`00-06`, `01-05`, `02-05`, `03-06`, `04-06`, `05-06`,
`06-05`, `07-06`, `08-05`, `09-07`, `10-09`, `10-12`). T-G10-07, T-G10-10, T-G10-11, and T-G10-12
keep their stable IDs but execute inside G11. T-G10-12 closes as the manual publish contract
(`docs/reviews/2026-09-07-release-flow-closure.md`): no automated publication surface exists, and
the operator publishes by tagging the exact commit the launcher verified. Handoffs copy the current row, scenarios, threats, API
signatures, focused argv, `Q`, and rollback code. One writer owns the worktree; reviewers assess current
semantics and cannot cite evidence whose acceptance text predates this rebaseline.

```bash
test -f docs/implementation-plan.md
test "$(wc -l < docs/implementation-plan.md)" -le 300
test "$(rg -c '^\| T-G[0-9]{2}-[0-9]{2} ' docs/implementation-plan.md)" -eq 83
test "$(rg -c '^## G[0-9]+:' docs/implementation-plan.md)" -eq 12
```
