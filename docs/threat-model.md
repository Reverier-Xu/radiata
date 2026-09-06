# radiata Threat Model

## Authority

[threat-model.toml](threat-model.toml) is machine-readable authority for stable `THR-001` through
`THR-029`. ADR-0007 defines the active responsibility boundary. Scenario records marked
`rebaseline = "ADR-0007"` own current executable predicates; evidence for earlier predicates is stale.
Each threat row lists its minimum mandatory oracle scenarios, not every scenario that cites the threat.
Validation requires every listed oracle to cite that threat; additional scenario-to-threat links are
allowed for shared mitigations.

Rebaseline note (2026-09-05, ADR-0009): the peer-trust deployment model narrows the adversary model
to transport-path adversaries plus operational misuse. The authorized-malicious-member family
(`THR-012`, mandatory key `malicious-members`) moves out of architectural scope: under the merge
composition model, a hostile properly-admitted member is indistinguishable from a path adversary,
and its containment is a deployment responsibility documented in the repository README. The threat
row and its stable ID remain for evidence continuity; its predicates own no architectural
enforcement beyond the existing revoke/leave/cleanup boundaries.

## Protected Assets

- Canonical identity bindings, admission credentials, key-provider authority, and session-trusted
  membership metadata (ADR-0008).
- Authenticated TLS sessions, exact feature selection, packet route context, byte order, and
  current-process incoming-stream admission acknowledgement.
- Node-owner revisions, generic resource metadata, trace metadata, transaction receipts, and metadata
  schema/migration records.
- Availability bounded by caller-selected frames, queues, pages, streams, tasks, fan-out, recovery, and
  fixed admission policy.
- Failure artifacts, corpora, CI attestations, release candidates, eligibility tokens, and packages.

Packet body bytes and upper-layer objects are not durable core assets because core never stores them.
Their confidentiality while present in caller/process/transport memory is still protected from generic
core diagnostics and evidence artifacts.

## Adversaries

- An unauthenticated client with malformed input and many transport source addresses.
- A peer holding a stolen unexpired credential but no admitted identity key.
- A peer replaying, delaying, duplicating, reordering, dropping, or reflecting protocol traffic.
- A corrupt, unavailable, capacity-limited, or dishonest storage/key/network provider.
- A hostile host wall clock that rolls back, freezes, or jumps forward.
- An evidence producer attempting injection, secret/body retention, budget reduction, stale-predicate
  reuse, sample replacement, rerun masking, or release substitution.

A malicious or colluding admitted member with valid signing authority is out of architectural scope
under the peer-trust deployment model (ADR-0009): containing such a member is a deployment
responsibility (see the repository README). The revoke/leave/cleanup boundaries below remain as the
mechanisms a deployment uses to expel one.

## Trust Boundaries

TLS protects a channel, but exporter-bound authentication establishes NodeId/public-key trust.
Addresses and certificates are not identity. Transport, discovery, storage, key, packet-consumer,
neighbor, load-balancing, routing, entropy, and test wall-clock implementations are trusted in-process
extensions, not sandboxes.

The OS, hypervisor, process reader, debugger, caller holding a credential, key-provider operator, storage
capacity policy, and host-time accuracy are outside core control. Core still validates provider
capabilities and redacts its own errors, events, and artifacts.

## Admission Abuse Boundary

Every listener enforces the complete fixed policy: a 32-byte single-use credential valid for ten
minutes; 4 pending attempts per source and 64 globally; 16 attempts per source and 256 globally per
fixed minute; 1,024 source buckets retained for ten idle minutes; one verified committer per credential
generation; and a ten-second authentication deadline. These security controls are not a node limit.

Any admitted non-revoked member can issue credentials. A malicious member can create unbounded Sybil
growth over time, constrained only by fixed admission rate and caller/provider resources. Roles and
population approval belong above the crate.

## Packet Boundary

Core authenticates target and route context, selects one destination from matching node labels through
caller policy, preserves ordered constant-memory streaming, and bounds all queues/tasks. A delivery
acknowledgement means only that the destination process authenticated and admitted the incoming stream.
It says nothing about durable body retention, caller observation, processing, a return packet, or
success.

Disconnect and restart terminate an active stream. Core never persists body bytes and never recreates,
replays, or continues them. Trace retention can remove status and duplicate evidence but cannot make
body delivery durable.

## Metadata and Time Boundary

Node metadata carries strictly increasing owner revisions and rejects same-revision conflicts;
entries are trusted through the authenticated session that delivered them (ADR-0008). Generic
resource metadata uses the deterministic maximum of host `SystemTime`, writer `NodeId`, removal
rank, and digest. The tuple is not causal, fresh, or real-time last-writer behavior.

Rollback can make later local work lose; freeze can delay deadlines indefinitely; forward jumps can
make work immediately due; future-dated signed tuples can dominate. Core has no peer-clock authority or
future-write holding service. Executor timers only wake work to re-read wall time.

Revocation is prospective connectivity and admission authority. It does not invalidate otherwise
valid stored metadata. Cleanup and leave affect only core metadata and key intents and never dereference a
resource URI or delete an upper-layer object.

## Scale Storage and Availability

There is no product node-count ceiling. Membership, trust, resource, topology, and policy observations
are paged or incremental. The 1,024-node profile is mandatory functional/trend evidence only; the exact
revised 16-node workload has the release latency claim.

Storage is internal metadata infrastructure. Providers own immutable snapshot implementations, layout,
capacity, quotas, flush policy, and physical durability. Core owns exact lookup, unsigned-byte ordered
stream scans, conditional transactions, receipts, reconciliation, capabilities, corruption refusal,
and migrations. Resource exhaustion is typed and never silently truncates.

## Evidence and Release Boundary

Failure replay uses closed executable IDs and literal argv. Artifacts exclude secrets, packet bodies,
provider handles, paths, and addresses. Every SC and E2E carries the current ADR marker; validator
negative fixtures prove superseded active terms and stale evidence markers fail.

The immutable candidate exists before final evidence. The external eligibility token binds exact
candidate SHA, lock, complete attempt ledger, version, and artifact digests. Every attempt remains in
lineage; product failure cannot be hidden by a successful rerun.

## Release Rule

Release fails on an open threat, missing owner/scenario/current marker, unknown ID, ambiguous evidence
rule, incomplete attempt, stale responsibility predicate, or token/candidate mismatch. Every accepted
P0/P1 threat has a concrete mitigation and named residual where risk remains.
