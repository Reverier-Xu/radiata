---
id: ADR-0009
title: Compose clusters by merge under a peer-trust deployment model
status: accepted
date: 2026-09-05
deciders: radiata maintainers
---

# Compose Clusters by Merge Under a Peer-Trust Deployment Model

## Context

The cluster lifecycle was built around `CreateCluster`/`JoinCluster`: one genesis creator held a
privileged admission authority, every record family was marked with a `ClusterId`, and leave was an
active protocol. A design review (2026-09-05) established a different intended deployment model:

- Connections are unidirectional dials, but node interconnection semantics are undirected; `join`
  encodes a false asymmetry.
- All nodes are equal and mutually trusted. The deployment guarantees that only trusted nodes are
  ever admitted; a malicious member is indistinguishable from a man-in-the-middle on the path and is
  therefore out of scope for this crate's architecture. Defending against one is a deployment
  responsibility, documented in the README, not a design constraint here.
- Transport-path security (TLS 1.3, exporter binding, handshake transcripts, credentials) is
  unaffected: it defends the wire, not the members.

Under that model the genesis/creator machinery, the `ClusterId` marking, and the local-only
revocation boundary were re-examined. This ADR records the confirmed replacement semantics. Where it
conflicts with ADR-0001, ADR-0002, ADR-0007, or ADR-0008, this ADR governs; those documents receive
amendment notes when the implementation lands.

## Decision

1. **Born-with-cluster.** `NodeBuilder::start()` performs a get-or-create of the local identity
   through the existing journaled pipeline (key-creation intent, reconcile, pending cleanup). There
   is no genesis ceremony, no `ClusterGenesisV1`, no `LocalClusterPointerV1`, and no `ClusterId`
   anywhere in the API, wire formats, or record schemas. `CreateCluster`, `JoinCluster`,
   `ClusterView`, and `existing_cluster` with its two storage families are deleted. Every node is
   born holding a singleton cluster: a binding set of one. No node holds creator privileges; trust
   anchors are the merge credential handshake first and session-carried bindings thereafter
   (ADR-0008).

2. **`cluster_merge`.** The only composition primitive. One merge credential authorizes one
   authenticated session between two nodes; after authentication both sides adopt the union of
   their binding sets and ordinary sync converges the rest. The credential mechanism is reused
   unchanged: 32-byte bearer secret in canonical text form, ten-minute wall-clock lifetime, single
   successful use per generation (failed attempts never consume), one active generation per issuer
   (rotation invalidates the previous value), plus the fixed rate and pending guardrails. Merging
   K clusters takes K−1 credentials. There is no winner election and no record re-anchoring:
   bindings are immutable, `NodeId`s are unique by construction, and the union converges through
   the existing anti-entropy plane.

3. **`cluster_leave`.** The leaving node signs a leave record with its current key and injects it
   into its connected session(s), waits a bounded time for the first current-process admission
   acknowledgement, then rotates its identity regardless of the outcome (journaled leave-intent
   pipeline, crash-safe at every step). The leave record is an owner-signed removal tombstone that
   converges through sync; verification relies only on the permanently retained binding, never on
   the leaver staying online. Because the old key is destroyed by the rotation, the record is
   terminal and carries no replay or time-lag attack surface. A lost announcement degrades to a
   silent leave, which the cleanup path covers. Left nodes are excluded from session establishment
   and from recovery dialing; their historical signed records remain valid evidence.

4. **Dead-node cleanup.** A user-invoked command family: `cleanup_node(id)` issues a convergent
   peer-signed removal tombstone; `issue_cleanup_checkpoint()` starts a GC epoch (decision 5);
   `purge_revocation(id)` explicitly clears one local revocation record. Cleanup tombstones are
   terminal: there is no resurrection path, and the user is responsible for never cleaning a node
   that is merely offline. A mistakenly cleaned node recovers only by rotating its identity and
   re-merging as a new `NodeId`. Detection is assembled from the existing connectivity, session,
   and topology views; it is not a new protocol.

5. **Checkpoint tombstone GC.** A checkpoint is an unsigned, max-wins record that rides the sync
   plane and declares one wall-clock watermark. Sync filtering applies to **removal records only**;
   live entries always sync (a merge legitimately introduces entries older than any watermark).
   A pre-checkpoint removal is applied when its subject entry exists locally and ignored otherwise;
   post-checkpoint removals sync normally. After a sync round, each node may delete all removal
   data older than its latest checkpoint, reusing the conditional exact-digest delete engine of the
   resource retention pass. Operational contract: checkpoints are issued only against a fully
   converged cluster, cleaned subjects never return, and a later merge must not carry data about
   already-collected subjects. Violations degrade to metadata hygiene issues for key-dead subjects,
   never to security failures.

6. **Permanence classes.** Identity bindings, admission grants, and resource records are permanent
   verification anchors and are never garbage-collected. Leave, cleanup, and resource-removal
   tombstones are GC-eligible under decision 5. Revocation becomes a **convergent, permanent**
   removal tombstone: any member may expel a compromised binding cluster-wide, the record is never
   covered by checkpoints, and it is cleared only by an explicit local `purge_revocation`. The
   permanence asymmetry is deliberate: leave/cleanup subjects have dead keys, so post-GC
   resurrection is harmless; revocation subjects have live, hostile keys, and bindings resurface by
   design (sync, stragglers, storage backup restore), so the gate must live as long as the binding
   it constrains. Fat-fingered expulsion is recovered by identity rotation and re-merge.

7. **Cluster naming.** Cluster identity is the convergent binding set, nothing else. Users manage
   and name their clusters at the deployment layer; the crate exposes no machine cluster identity.

## Consequences

- **Planning artifacts.** Roadmap product contract, implementation plan, threat model, scenario
  catalog, API inventory/manifest, and the SLO workload are rebaselined in one batch with the
  stream-terminology rename (`docs/reviews/2026-09-05-stream-abstraction-audit.md` R1–R4). The SLO
  admission stratum becomes a merge stratum with unchanged credential evidence rules.
- **Wire and storage.** Handshake hello loses the cluster field; the join hint becomes a bare
  generation; grant payloads lose the genesis digest pin; trust snapshots lose the cluster marking
  and the creator-only refresh privilege. Golden vectors, compatibility fixtures, and mixed-version
  evidence are regenerated before the `0.1.0` publish; nothing is published yet, so no migration
  path is owed.
- **Security surface.** The threat model narrows to transport-path adversaries plus operational
  misuse; member-originated attacks are documented as out of scope in the README. Revocation's
  change from local-only to convergent-permanent strengthens the compromised-key response from a
  local boundary to a cluster-wide expulsion.
- **Operational contract.** Deployments owe three guarantees: only trusted nodes are merged,
  cleanup/checkpoints are issued only against a fully converged cluster, and cleaned subjects stay
  decommissioned. These are documented as deployment responsibilities.
