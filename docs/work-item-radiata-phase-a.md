# Work Item: Phase A — Row Envelope Unification

Status: approved direction (audit §3 decision 1; roadmap "Phase A").
Dispatch: single worker lane, worktree `wt-phase-a`, branch
`phase-a/row-envelope`, checkpoint commits, extended budget. Sequencing:
after Wave 2 merges; Phases B-E follow this doc's successors. Every unit
must pass the five gates; no new core verbs during Phases A/B.

## Goal

Persisted rows unify to one envelope: **`name + labels + version +
payload`**. Identity families migrate onto the envelope (typed payloads,
golden vectors regenerated); `storage/families.rs` gains per-family
policy records declaring the four aspects the later phases consume.
**Purely structural — zero behavior change.**

## Why

Core identity records and the resource register are two parallel private
persist/reconcile machines. That duplication is the root of the audit's
drift-risk findings (§5.1: hand-copied revoke effect sequence, twin
checkpoint sweeps, re-admitted validation, copied evidence probes). The
unification makes core the hardest user of its own resource machinery:
when the envelope gains a capability, identity gets it by construction,
not by a second hand-written implementation.

## Current-state anchors (verified 2026-11-08, main `76126d7`)

- `src/storage/families.rs`: the backend-neutral catalog — 19 families,
  8 domains (`MetadataDomain`), per-family `replicated` flag, consumed by
  the all-family contract lane. This is where the policy records go.
- `src/identity/*` records: `canonical_record!` triples (typed struct +
  wire codec + golden vector) persisted as opaque values under
  per-family namespaces. No labels; versioning lives in record-specific
  fields and storage revisions.
- `src/resource/mod.rs` `ResourceRecordV1`: already close to the envelope
  (name/labels/version/payload); the public types (`ResourceName`,
  `ResourceLabels`, `ResourceVersion`) are the vocabulary to generalize.
- `src/reconcile/wire.rs` `Row { key, content }`: the reconcile plane
  carries lane-canonical bytes; the envelope defines the shared meaning
  of `content` (and the key discipline) across lanes.

## Design commitments

1. **Envelope shape.** One crate type (placement: beside the storage
   layer, visible to identity/resource/reconcile) with:
   - `name`: the namespace-qualified row key (existing key discipline
     per family, unchanged);
   - `labels`: the reserved label vocabulary (`RESERVED_RESOURCE_LABEL_KEYS`
     extends naturally); identity families start with empty labels —
     **policy-as-row-data arrives in Phase C, not here**;
   - `version`: the family's existing monotonic ordering element (CAS
     revision / writer-timestamp tuple / counter), typed once;
   - `payload`: opaque bytes at the envelope level — user-domain payloads
     stay opaque, core-domain payloads stay typed (decoded through the
     existing `canonical_record!` codecs at the domain boundary).
2. **Per-family policy records in `families.rs`.** Extend
   `MetadataFamily` (or a sidecar record it carries) with declared
   aspects, replacing implicit behavior with explicit declarations:
   - `contest`: generalize the existing `decides: fn` precedent;
   - `admission`: who may write the family (core-verb-gated /
     multiwriter / node-local-only);
   - `visibility`: read scope (public read / core-only);
   - `cleanup vocabulary`: the typed enum placeholder mirroring today's
     hardcoded sweep classes (Phase C consumes it; no behavior change
     now).
   Derive the existing consumers (domain classification, leave wipe
   scope, node-local exclusion) from the declarations so a new family is
   correct by declaration, not by N consumer edits.
3. **Identity migration.** Each identity family's persisted body becomes
   the envelope; the typed record remains the payload codec. Persisted
   byte format changes are wire amendments — follow the CHANGELOG
   pre-release amendment precedent, regenerate golden vectors, and state
   each amendment in the commit message.
4. **Zero behavior.** Commit/contest/reconcile outcomes are equivalent
   at the API level; existing integration tests pass unmodified except
   golden vectors and regenerated ABI baseline.

## Open micro-decisions (worker resolves, documents the reason)

- Envelope struct placement and visibility (storage vs a new row module).
- Whether reconcile `Row.content` adopts the envelope encoding directly
  or the envelope wraps it — prefer the smallest change that makes the
  unified shape the single source of truth.
- How the identity families' CAS semantics map onto the envelope's
  `version` element without changing conflict outcomes.

## Acceptance criteria

1. Five gates green (`taplo fmt --check`, nightly `cargo fmt --all
   -- --check`, `cargo check --workspace --all-targets --all-features
   --locked`, `clippy --workspace --all-targets --all-features --locked
   -- -D warnings`, `cargo test --workspace --all-features --locked`).
2. All-family storage contract suite passes over the envelope.
3. Decoder/state fuzz targets pass (no panics, fail-closed on invalid).
4. ABI baseline regenerated and its diff reviewed in the final report.
5. Fresh tester + fresh reviewer reports attached (reviewer verifies
   behavior-equivalence hunk-by-hunk).
6. Golden-vector diffs are the only test modifications attributable to
   byte-format changes; every other test change must have a stated
   reason.
