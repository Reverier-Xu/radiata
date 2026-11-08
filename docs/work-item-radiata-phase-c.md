# Work Item: Phase C — Cleanup as Controllers (cleanup-as-policy)

Status: approved direction (audit §3 decision 2; roadmap "Phase C").
Dispatch: single worker lane, worktree `wt-phase-c`, branch
`phase-c/cleanup-controllers`, checkpoint commits, extended budget.
Preconditions: Phase A (envelope + FamilyPolicy declarations) and
Phase B (admission enforcement, resource convergence) merged. Every unit
passes the five gates.

## Goal

A generic sweep engine consumes declared cleanup policies; cleanup
policy rides rows as **core-verb-writable reserved labels** whose values
come from the typed vocabulary — so policy changes converge through the
reconcile plane without fleet-wide binary upgrades. The old hand-written
sweep scaffolding is deleted. **The headline acceptance: tombstone
scenario tests — revoked-subject binding retention is preserved as
policy behavior, not as hardcoded cross-family rules.**

## Why

Cleanup semantics are currently smeared across hand-written sites: the
family-agnostic sweep hardcodes revocation's permanent-exclusion rule
(`identity/records.rs` `revoked_key_ctx`), leave and cleanup carry
identical checkpoint-sweep bodies (audit §5.1), and policy changes would
require synchronized binaries across a decentralized cluster —
impossible by design. Policy-as-data converges through the machinery
that already exists (LWW reconcile, core-verb-writable reserved labels,
W2-2 predicates for observers).

## Current-state anchors (verified 2026-11-08, post-Phase-B main)

- `src/storage/families.rs` `FamilyPolicy` cleanup vocabulary (Phase A):
  `LeaveWipe` / `CheckpointCollected` / `StoreHygiene` /
  `ProviderDeletionFlow` / `StorageInternal` — the declared classes the
  engine consumes.
- `src/identity/records.rs` — the family-agnostic sweep scaffolding
  (incl. the hardcoded `revoked_key_ctx` permanent-exclusion rule) —
  the primary deletion target.
- `src/identity/cleanup.rs` / `src/identity/leave.rs` — twin
  checkpoint-sweep bodies; `issue_cleanup_checkpoint` stamps the local
  wall clock (operator assertion, not autonomous policy — preserve that
  stance in wording).
- `src/runtime/retention.rs` / `src/storage/receipt.rs`
  (`scan_retention_candidates`) — the runtime retention loop the
  controllers replace/wrap.
- `src/keys/metadata.rs` — the provider deletion flow (KEY_SEED family,
  `ProviderDeletionFlow`): stays its own flow, now *declared*.
- Envelope labels (Phase A/B): reserved vocabulary
  (`RESERVED_RESOURCE_LABEL_KEYS`), core-verb-writable — the carrier for
  policy labels.

## Design commitments

1. **Typed policy vocabulary.** The cleanup label value is one of the
   declared classes (plus per-class parameters where the class carries
   them, e.g. checkpoint watermark scope), validated at seal/registration
   time — fail-closed on unknown vocabulary, matching the crate's decode
   discipline. Registration = the FamilyPolicy declaration; rows carry
   which policy applies.
2. **Policy labels are core-verb-writable.** Under Phase B's admission
   gate, external writers cannot set or alter them; core verbs mutate
   them through encapsulated semantic operations. Users never write
   these labels directly.
3. **One generic sweep engine.** Consumes the declared policy per row:
   `permanent` (never swept; revocation's rule becomes a policy
   behavior), `checkpoint-watermark` (swept after the adopted GC
   watermark passes, with pinned-binding retirement semantics where the
   family declares them), `provider-only` (KEY_SEED: swept only by the
   provider's own deletion flow), `storage-internal` (receipt hygiene).
   The engine is the single sweep path; identity leave/cleanup/revocation
   call it with their families' declarations.
4. **Delete the scaffolding.** `revoked_key_ctx`'s hardcoded cross-family
   rule, the twin checkpoint-sweep bodies, and the parallel sweep loops
   go away. Cross-family rules (revoked subject ⇒ binding retention)
   become policy-behavior tests over the declared combination.
5. **No fleet-upgrade coordination.** A policy label change commits as a
   normal core-verb row mutation and converges via reconcile; nodes with
   older binaries that do not know a vocabulary value fail closed for
   that row (never sweep it) — bounded-degrading, documented.

## Open micro-decisions (worker resolves, documents the reason)

- Label key names for the policy carrier (reserved namespace, one key or
  per-aspect keys) — must not collide with W2-2 selector semantics.
- Whether the engine lives in `runtime/` (controller tasks) already in
  C or the controller-task form waits for Phase D — the roadmap puts
  controller-task machinery in D; C may keep the engine invoked from the
  existing runtime loop. Prefer the smallest step that deletes the
  duplication.
- How pinned-binding retirement expresses per-family (declaration
  parameter vs separate class).

## Acceptance criteria

1. Five gates green.
2. Tombstone scenario tests: revoked-subject binding retention holds as
   declared-policy behavior; checkpoint watermark GC reclaims collected
   leaves; provider seed rows are swept only by the provider flow.
3. Policy-label mutation through core verbs converges across a
   multi-node scenario test; unknown vocabulary values never sweep.
4. The audit §5.1 duplicates (leave≈cleanup sweep bodies,
   revoked_key_ctx hardcode) are gone — reviewer greps for them.
5. Fresh tester + fresh reviewer reports; reviewer walks each family's
   sweep outcome old-vs-new for exact equivalence.
