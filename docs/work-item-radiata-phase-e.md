# Work Item: Phase E — Channel Selection Seam (EndpointSelectionPolicy)

Status: approved direction (audit roadmap "Phase E"). Dispatch: single
worker lane, worktree `wt-phase-e`, branch `phase-e/endpoint-selection`,
checkpoint commits, extended budget. Preconditions: Phase D merged.
Every unit passes the five gates. This is the final unification phase.

## Goal

A `EndpointSelectionPolicy` seam (candidates validated against
authoritative descriptors, fail-closed) with three official built-ins
registered through `register_default`: `published-order` (the default —
today's rotation, zero behavior change), `preference-order` (a
NodeConfig scheme preference list), and `outcome-weighted` (dial-outcome
EWMA). The three duplicated dial-endpoint resolution loops collapse into
the selector's callers. Default-policy resolution stays in the
registration channel (the Track 0 item 8 / W2-1 discipline).

## Why

0.1.0's design position is explicit endpoint choice; the preference seam
was deferred to the roadmap. The EWMA data (`LinkProfile` admission-ack
latency in `reconcile/plane.rs`) is already collected with no consumer.
The dial-endpoint rotation logic is hand-copied across three dial planes
(runtime/recovery.rs, runtime/degree.rs, reconcile/plane.rs) — a drift
surface: a fix to rotation semantics must be applied three times.

## Current-state anchors (verified 2026-11-08, post-Phase-D main)

- `src/runtime/recovery.rs` — the recovery dial plane's per-member
  endpoint rotation (candidate map built from member table, rotating
  cursor, fan-out caps).
- `src/runtime/degree.rs` — per-member endpoint rotation for density
  dials ("every dial of a member advances that member's cursor").
- `src/reconcile/plane.rs` — the sync plane's dial loop;
  `LinkProfile` (per-session, observes admission-ack latency, EWMA).
- `src/extension_registry.rs` — the registration channel
  (`register_default`, `effective_route_policy` precedent for
  default-at-registration).
- `src/config.rs` — `NodeConfig` (scheme preference list lands here;
  plain `Option` accessor discipline).
- Authoritative descriptors: member-table entries carry published
  endpoints (the validation source).

## Design commitments

1. **The seam.** One `EndpointSelectionPolicy` trait (or the crate's
   equivalent idiom): given a member's validated candidate set, produce
   the next endpoint (and optionally a ranking). Candidates are
   validated against authoritative descriptors — a candidate not in the
   descriptor is never returned, fail-closed. The trait is public for
   custom policies via the extension registry's caller domain.
2. **Three built-ins via `register_default`:**
   - `published-order` — exactly today's rotation (the shared algorithm
     the three loops currently hand-copy); registered as the default;
     zero behavior change when unconfigured.
   - `preference-order` — NodeConfig-declared scheme preference list
     (e.g. wss before tcp); unknown/no-preference falls back to
     published-order per candidate.
   - `outcome-weighted` — orders candidates by each scheme's recent dial
     outcomes (EWMA over admission-ack latency / failure marks from
     `LinkProfile`-style observations); cold-start ordering =
     published-order. Strictly observant, never creative: it reorders
     the validated set.
3. **Caller collapse.** The three loops resolve through the selector;
   their per-plane state (rotation cursors) moves behind the selector's
   per-member handle. Wire/dial outcomes identical under
   `published-order` (existing recovery/degree/sync tests unmodified).
4. **Registration-channel defaults.** The effective policy resolves once
   after `register_default` (mirroring `effective_route_policy`);
   config accessor is a plain `Option` read; fail-closed if the default
   is missing.
5. **Fleet visibility:** the policy is node-local configuration (like
   route_policy); no reconcile implications.

## Open micro-decisions (worker resolves, documents the reason)

- Trait shape: pull (next_endpoint per dial) vs push (ranked list per
  member refresh) — prefer the shape the three call sites share most
  naturally.
- Where `outcome-weighted` reads its observations: reuse `LinkProfile`
  vs a selector-owned stats table (avoid coupling the sync plane's
  session struct to the selector if the seam wants node-wide stats).
- Config surface: `NodeConfig::with_endpoint_preference([...])` shape
  and validation (unknown schemes rejected at builder? fail-closed at
  selection?).

## Acceptance criteria

1. Five gates green; recovery/degree/sync suites pass unmodified under
   the default policy.
2. A scenario test per built-in: preference-order reorders per config;
   outcome-weighted reorders after observed outcomes and falls back
   cold; invalid candidates never selected (fail-closed test).
3. The three loops share one implementation (reviewer greps for the
   collapsed duplicates).
4. ABI baseline regenerated (new public seam) + CHANGELOG.
5. Fresh tester + fresh reviewer reports.
