# Work Item: Phase B — Resource Machinery Convergence (+ F4 storage rails)

Status: approved direction (audit roadmap "Phase B"). Dispatch: single
worker lane, worktree `wt-phase-b`, branch `phase-b/resource-machine`,
checkpoint commits, extended budget. Precondition satisfied: Phase A
merged (RowEnvelope, FamilyPolicy declarations, identity families on the
envelope). No new core verbs (A/B freeze continues). Every unit passes
the five gates.

## Goal

The resource module rides the same unified envelope the identity
families now use; reserved-domain write gating becomes enforced policy
(core domains refuse external writes, read stays open); the reconcile
lanes collapse to one row model. After B lands, the F4 storage rails
open the same machinery to external backend authors. **Event parity is
the acceptance headline: ResourceChanged emissions, watch replay, and
version ordering must be byte-identical.**

## Why

Phase A left resource/membership lanes as raw pass-throughs beside the
envelope — the last parallel machinery. Converging them removes the
second hand-written persist/scan path (the drift surface), and the
public write gate turns `FamilyAdmission` from a declared-but-unconsumed
record into enforced policy. F4 (audit §4.2, P1) then stops
third-party Storage authors from facing a dead end: they can reuse the
commit-semantics derivation and validate against the reference oracle.

## Current-state anchors (verified 2026-11-08, post-Phase-A main)

- `src/storage/row.rs` `RowEnvelope` (+ golden, fail-closed decode,
  CborLimits) — the envelope to adopt.
- `src/storage/families.rs` `FamilyPolicy` — `admission`
  (`CoreVerbGated`/`Multiwriter`/`NodeLocalOnly`) and `visibility`
  (`CoreOnly`/`PublicRead`) are declared but unconsumed (narrowly
  `#[allow(dead_code)]`); this phase consumes them.
- `src/resource/{store,lane,mod}.rs` — resource persist/scan path
  (`ResourceRecordV1`, `ResourcesLane`); membership descriptors lane
  (`membership/lane.rs` `DescriptorsLane`) and tombstones lane
  (`membership/tombstone.rs` `TombstonesLane`) are the other raw
  pass-throughs.
- `src/reconcile/lane.rs` `Lane` trait + `LaneEntry` — the row-model
  seam to unify.
- `src/membership.rs` / `src/membership/sync.rs` /
  `src/runtime/task_effects.rs` — `ensure_local_descriptor` call sites
  (restructures here per the roadmap).
- `src/storage/provider.rs` — `commit_precheck`/`condition_matches` are
  `pub(crate)`; the contract runner is `#[cfg(test)] pub(crate)`
  (`src/storage/contract/mod.rs`). F4 opens both.
- Event surfaces (from W2-2): `ResourceChanged` carries labels; emit
  sites `runtime/resources.rs` + `resource/lane.rs`; replay push-down in
  `resource/feed.rs`. These must not drift.

## Design commitments

1. **Resource families onto the envelope.** Resource records persist as
   `RowEnvelope` values (payload = the typed record bytes, unchanged
   encoding); labels ride the envelope's `labels` (already
   reserved-vocabulary-compatible). Persist/read sites seal/open like
   the identity families do. Zero wire-format change to the resource
   record codec itself.
2. **Enforced admission + visibility.** The storage write path consults
   `FamilyPolicy.admission`: `CoreVerbGated` families refuse writes that
   do not originate from a core verb context; `PublicRead` vs `CoreOnly`
   gates the read helpers. The gate must be fail-closed and pinned by
   tests (external write attempt on a core family → typed error;
   core-verb path unchanged; public read of core families stays open
   where it is open today — match Phase A behavior exactly).
3. **One reconcile row model.** Descriptors/Resources/Tombstones lanes
   adopt the same envelope projection the identity lanes use (scan →
   envelope projection → lane semantics). Lane content bytes and engine
   digests stay byte-identical (same discipline as Phase A: the
   envelope's payload element is the lane content; wire/digest/apply
   untouched).
4. **`ensure_local_descriptor` restructure.** Fold the hand-rolled
   ensure path into the unified envelope persist path — the drift-prone
   duplicate disappears; outcomes identical (pinned by existing
   membership tests).
5. **F4 storage rails (after B's core lands).** Public API for backend
   authors: expose the commit-semantics derivation
   (`commit_precheck`/`condition_matches` go public with documented
   contracts), an opt-in storage contract runner (public, feature of the
   crate — runs a backend through the reference oracle), and
   `adapters::memory_store()` (in-memory demo/reference factory).
   Regenerate the ABI baseline and add the API to CHANGELOG (Added).
   Docs: storage-author rails wording belongs to the deferred docs
   track — keep doc comments self-sufficient, do not write a guide
   chapter here.

## Open micro-decisions (worker resolves, documents the reason)

- How "core verb context" is threaded to the write gate without new
  public API surface (capability marker vs namespace-set check at the
  store seam) — prefer the smallest thread that cannot be forged by a
  caller who today cannot bypass the gate.
- Whether TombstonesLane's decode-time validation fits the envelope
  projection or stays lane-side (decode is the lane's contract).
- The public shape of the contract runner (free fn vs builder) and where
  `memory_store` lives (`storage/adapters.rs`?).

## Acceptance criteria

1. Five gates green; event parity suites pass unmodified (watch, feed,
   version ordering); soak + mixed-versions tests pass.
2. Membership/resource integration tests pass unmodified except stated
   golden changes.
3. F4: public rails usable from an external-crate-shaped test (the
   contract suite must run a non-redb, non-json backend — the memory
   store — to green).
4. ABI baseline regenerated (new public API) + CHANGELOG entries.
5. Fresh tester + fresh reviewer reports; reviewer verifies parity and
   the gate's unforgeability hunk-by-hunk.
