# Remediation Roadmap — post-audit decision record

Status: **Track 0 dispatched and fully merged (2026-11-08)** — all eleven
items plus the quick-fix pool landed via the merge queue (main at
`1895bf8`; 1159 tests, 0 failures, clippy clean). `radiata-cadence`
delivered as a workspace crate. Remaining: Phase A-E below (direction
approved, dispatch pending), Wave 2 leftovers (route_policy consumer-side
completion, redaction-stance doc sweep in error.rs/guide.rs/audit.rs),
and the deferred specialist tracks. Companion documents:
`docs/code-quality-audit.md` (findings), `docs/work-item-radiata-cadence.md`
(syntax-library work item). Delivery has no deadline.

## Decided scope stances (binding)

- Payload persistence/retry/reliable-delivery semantics are **application
  responsibilities**. The data plane stays fail-fast with typed outcomes;
  no core outbox, no official recipe. Guide wording to be updated in the
  docs track.
- Wall-clock reliability, cleanup all-node-online, and no-node-offline-
  past-retention-window are **operator obligations**. No clock-skew or
  retention-risk diagnostics.
- Error contexts carry **full dynamic detail** — the `&'static str`
  redaction discipline is dropped (redaction is the upper layer's job;
  tracing owns partitioning/delivery). Cryptographic secret hygiene
  (zeroize, Debug masking) is unrelated and stays.
- Reachability/NAT is out of scope (directed transports, undirected
  sessions; mobile nodes dial out; VPN solutions are the user's choice).

## Track 0 — approved items (dispatch first)

1. Seed-file permissions: redb/json creation/open tighten to 0600/0700
   when the store hosts the Custody domain, mirroring `keys/file.rs`.
2. One-line cleanups: stale doc `session/driver.rs:570`; dead statement
   `fuzz_adapters.rs:136`.
3. `tracing::warn!` on `tcp://` listener bind.
4. Task-kind policy five-table consolidation into `TaskReconcilePolicy`
   (retry_class, coalescing; derive check_shape/coalesce_key/retry_policy
   from the registration channel).
5. `SessionPacketContext`: extract `RoutingPlaneContext` (7 routing fields,
   17-arg ctor → session data + one struct; 5 test scaffolds collapse).
6. `receipt.rs` same-family convergence: `self_reference_op_shapes`
   shared by recover/build; `bounded_scan` skeleton for the two eligibility
   scans.
7. `on_session_ack` extraction: `attribute_ack` / `handle_discovering_
   failure` / `flip_terminal_route` (routing plane; not touched by
   unification phases).
8. `NodeConfig::route_policy` dependency direction: default resolution
   moves to the builder/registration channel; accessor becomes a plain
   `Option` read.
9. Event subscription predicates: `watch::<ResourceChanged>` options gain
   `domains` + label `selector` (emit-side evaluation; commit site holds
   the record's labels — no extra I/O). One predicate type designed for
   three consumers: live watch, durable `watch_resources` push-down,
   Phase D triggers.
10. Error-context dynamization: drop the `&'static str` discipline; errors
    carry offending names/values; first sites = transport scheme / protocol
    tag / task-kind resolution seams; incremental migration of old sites;
    secret hygiene untouched.
10b. Log-redaction teardown (owner decision: the redaction requirement in
    tests/observability.rs was invented, never a real one): delete the
    contextual-value non-leakage assertions (storage paths, labels,
    selectors, packet bodies, non-secret ids); KEEP the secret-material
    hygiene assertions (seed/key bytes never in output, zeroize, Debug
    masking); restore the storage-path field in the seed-permission warns
    (done in the storage lane); sweep error.rs/guide.rs/audit.rs for
    redaction-stance doc claims and update them.
11. Quick-fix pool (~24 mechanical items from the audit P3 list, categories
    A/B/C in the audit discussion): same-family micro-convergences, test-
    helper collapses, renames/moves (e.g. `inbound.rs` test modules out of
    the 3294-line file). Dispatched opportunistically between items.

Explicitly not doing (decided): `send_simple`/`direct()` ergonomics;
clock-skew/retention diagnostics; budget-mirror harness; commit critical
sections; ZeroCheck fan-out; the three backoff schedules; the remaining
report-only notes.

## Unification phases (direction approved; dispatch in order)

- **Phase A — row envelope unification.** Unified row = name + labels +
  version + payload (core-domain payloads stay typed; user-domain opaque).
  `families.rs` gains per-family policy records (contest / admission /
  visibility / cleanup vocabulary). Identity records migrate onto the
  envelope; golden vectors follow. No behavior change.
- **Phase B — resource machinery convergence.** Resource module onto the
  unified envelope; core-domain write gating; reconcile lanes collapse to
  one row model; event parity preserved. `ensure_local_descriptor`
  restructures here. F4 storage rails land after B (public
  `commit_precheck`/`condition_matches`, opt-in contract runner,
  `adapters::memory_store`).
- **Phase C — cleanup controllers.** Sweep engine generic over declared
  family policies (permanent / checkpoint-watermark + pinned-binding
  retirement / provider-only); policy vocabulary typed; cleanup-policy
  data rides rows as core-verb-writable reserved labels (policy-as-data
  converges via reconcile — no fleet-wide binary upgrades for policy
  changes). Old sweep scaffolding deleted; cross-family rules become
  policy-behavior tests.
- **Phase D — triggers and task unification.** Trigger declarations as
  node-local rows (durable, not replicated); `radiata-cadence` patterns
  drive time triggers; resource-change predicates (from Track 0 item 9)
  drive event triggers; core sweeps/checkpoints become core-owned
  controller tasks (bounded retention of completed controller runs;
  separate dial budget); operation events generated from the unified
  change stream.
- **Phase E — channel selection.** `EndpointSelectionPolicy` seam
  (candidates validated against authoritative descriptors, fail-closed),
  official built-ins via `register_default`: `published-order` (default
  fallback = today's rotation, zero behavior change), `preference-order`
  (NodeConfig scheme preference list), `outcome-weighted` (dial-outcome
  EWMA). The three duplicated dial-endpoint resolution loops collapse
  into the selector's callers. Default-policy resolution stays in the
  registration channel (same discipline as Track 0 item 8).

## Parallel work items

- `radiata-cadence` syntax crate (`docs/work-item-radiata-cadence.md`) —
  independent of all phases; dispatch anytime.
- Deferred specialist tracks (owner-approved deferral): SLO strata
  (isolated redial, bridge-probe, frozen-journal recovery), docs/
  extensibility track (guide blind spots: custom transports, hooks,
  `watch_resources`, dial-only members; storage-author rails docs;
  routed-`source` trust stance; join-credential blast radius; data-plane
  responsibility wording).

## Sequencing rules

- One large surface at a time: Track 0 → Phase A → B → C → D → E;
  quick-fix pool and cadence crate fill gaps between phases.
- Every unit must pass the five gates; wire amendments follow the
  pre-release amendment precedent; ABI baseline regenerated at each phase
  boundary; no new core verbs during Phases A/B.
