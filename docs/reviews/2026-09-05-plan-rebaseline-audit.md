---
title: Plan Rebaseline Audit — old G0–G10 plan vs the ADR-0009 model
status: review-record
date: 2026-09-05
scope: read-only audit plus overview adjustments; task-level re-scoping deferred to execution
---

# Plan Rebaseline Audit

## Purpose and Trigger

G10 is incomplete, which means the release-evidence plan is still being executed. Before the
remaining G10 work continues, the design review of 2026-09-05 produced two decision batches that
invalidate parts of the active plan:

- [ADR-0009](../adr/0009-peer-trust-cluster-composition.md) — cluster composition by merge under a
  peer-trust deployment model (born-with-cluster, `ClusterId` removal, owner-signed leave, dead-node
  cleanup with checkpoint GC, permanence classes);
- [Stream abstraction audit](2026-09-05-stream-abstraction-audit.md) R1–R4 — packet family renamed
  to stream terminology, standard `futures::Stream` bodies, Tokio admitted as the sole async
  ecosystem in the public ABI.

This document records how the old plan relates to the new model, what was adjusted now, what is
deferred to execution, and the key decision rationale.

## Old–New Relationship

The old plan is **not discarded**; it is rebaselined in place. Its gate structure (G0–G10), quality
gates, scenario/evidence discipline, and the majority of landed implementation survive. The
replacement is concentrated in the cluster-lifecycle semantics.

**Survives unchanged (landed code and evidence remain valid):**

- G1 deterministic foundation (canonical IDs, typed bus, simulation, failure artifacts);
- G2/G8 storage contract and adapters (snapshots, scans, conditional transactions, receipts,
  reconciliation, migrations) — nothing in the storage SPI changes;
- G3 session cryptography (TLS 1.3, exporter binding, six-position handshake) — the wire loses only
  the cluster field;
- G4/G5 membership sync and recovery (ADR-0008 session-carried trust becomes *more* central, not
  less: it is the convergence plane merge relies on);
- G6 routing and the packet data plane (renamed to stream terminology by R1, semantics intact);
- G7/G9 resource convergence, selectors, and signed removal retention — the checkpoint GC reuses
  this exact machinery;
- The fixed credential mechanism — same 32-byte/ten-minute/single-success/serial-per-issuer
  mechanism and the same rate/pending guardrails, reassigned from admission to merge authorization.

**Replaced (superseded by ADR-0009):**

- `CreateCluster`/`JoinCluster` and the genesis/creator privilege structure — every node is born
  holding a singleton cluster; trust anchors are the merge handshake and session-carried bindings;
- `ClusterId` in API, wire, and record schemas, plus the `ClusterGenesisV1` and
  `LocalClusterPointerV1` storage families and `existing_cluster`;
- Active leave (T-G09-06 as designed) — replaced by owner-signed leave record + identity rotation;
- Local-only revocation — becomes a convergent, permanent removal tombstone (cluster-wide
  expulsion of compromised keys).

**Re-scoped (survives in altered form):**

- Trust snapshots: lose the cluster marking and the creator-only refresh privilege;
- SLO workload: the five admission samples become five merge samples with unchanged credential
  evidence rules (ADR-0005 amendment required);
- Threat model: credential/replay/impersonation threats survive with merge terminology; the
  malicious-member threat family (e.g. `malicious-members` and related residuals) moves out of
  architectural scope to a README deployment-trust note;
- Scenario catalog: admission/join/cluster scenarios re-keyed to merge semantics at execution.

**G10 tasks specifically affected:**

- T-G10-01 freezes the **new** wire/metadata formats instead of the current ones;
- T-G10-02 mixed-binary evidence is regenerated post-rebaseline (nothing is published, no
  migration path is owed);
- T-G10-08 API review now covers the merged surface: ADR-0009 commands plus stream rename (R1);
- T-G10-09 evidence validator must reject pre-rebaseline acceptance text for re-scoped predicates.

## G11 Orchestration

The incomplete G10 work and this audit's work items are orchestrated as a new dedicated fix-and
cleanup gate **G11** in `docs/implementation-plan.md`:

- **G10 is reduced to its completed tasks** (T-G10-01/02/03/04/05/06/08/09, each with landed
  evidence and a verify script) and closes on T-G10-09;
- **Moved with stable IDs**: T-G10-07 (native CI/evidence matrix), T-G10-10 (OCI SLO harness
  qualification — the harness exists but qualification has not closed), T-G10-11 (candidate SLO
  ledger, now the merge workload), T-G10-12 (token/tag/publish);
- **New tasks T-G11-01..14**: stream rename + standard bodies (R1), event/scan stream adapters
  (R2), ABI rule amendment (R3), ChannelBody cleanup (R4), born-with-cluster, `cluster_merge`,
  `cluster_leave`, cleanup command family, checkpoint GC, convergent permanent revocation,
  ClusterId excision + vector regeneration, threat/scenario/README rebaseline, SLO merge-stratum
  workload, and the API manifest/inventory amendment;
- Critical path becomes `G0 → … → G10 → G11`; the plan's embedded self-check now expects 83 task
  rows and 12 gate headings.

## Adjusted in This Batch

Overview-level text only; task rows, scenario catalogs, threat entries, and harness code are
deferred to execution (listed above):

- `docs/roadmap.md` — Reason for Existence (ADR-0009 authority), Product Contract (cluster
  identities removed; merge/credential/cleanup contract added), Architecture Rule 2, module
  boundary table, M0/M3/M4/M9/M10 descriptions, requirement traceability row, self-check line
  budget raised 300 → 320 to admit the added contract text;
- `docs/implementation-plan.md` — Responsibility Rebaseline preamble now carries the ADR-0009
  rebaseline note pointing here;
- `docs/adr/0009-peer-trust-cluster-composition.md` — the decision record itself (seven decisions
  with consequences).

## Decision Rationale — Key Points

1. **Peer-trust scoping.** The deployment guarantees only trusted nodes are merged. A malicious
   member is indistinguishable from a path MITM and therefore out of architectural scope; transport
   security (TLS, exporter binding, credentials) is unaffected because it defends the wire, not the
   members. This single scoping decision is what makes the rest of the simplification sound.
2. **Merge algebra.** Singleton clusters are the identity element, `cluster_merge` the only
   composition primitive. Because bindings are immutable and `NodeId`s unique, cluster union is a
   set union over the existing anti-entropy plane — no winner election, no record re-anchoring. The
   `ClusterId` necessity analysis showed its three duties (handshake precheck, pollution guard,
   machine name) are redundant with the binding-introduction choke point or delegable to users.
3. **Key-dead vs key-alive permanence.** Leave/cleanup subjects have dead keys, so their tombstones
   are GC-eligible; revocation subjects have live hostile keys, and bindings resurface by design
   (sync, stragglers, backup restore), so revocation must be permanent. This asymmetry — not the
   tombstone mechanism — is what separates hygiene from security.
4. **Checkpoint GC makes deletion convergent.** Deleting tombstones directly causes sync storms;
   the checkpoint turns "these removals are gone" into convergent knowledge. The sync filter is
   removal-only because merges legitimately introduce live entries older than any watermark.
5. **Leave as terminal evidence, not a protocol.** An owner-signed leave record is verifiable
   forever from the retained binding; rotation destroys the key, so the record is final with no
   replay or time-lag surface. A bounded first-ACK wait maximizes graceful-leaf success; timeout
   degrades to silent leave, which cleanup already covers.
6. **One amendment batch.** The stream rename (R1) and the ADR-0009 surface changes share one API
   manifest amendment, one api-inventory digest update, and one evidence regeneration cycle —
   cheaper and more coherent than two separate rebaselines.

## Invariants Preserved Through the Rebaseline

- Packet/stream boundary: `TraceId` before body, no body persistence, explicit interruption,
  current-process admission acknowledgement semantics;
- Storage red lines: only core metadata, no private-key bytes, no packet bodies;
- Convergence semantics: owner revisions, tuple-max ordering, tombstone-defeats-replay;
- Boundedness: every capacity caller-selected and nonzero; population views paged or streamed;
- `SystemTime` honesty: discontinuity risk documented at every ordering/deadline boundary;
- Evidence discipline: superseded acceptance text closes no predicate.
