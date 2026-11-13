# Work Item: Phase D — Triggers and Task Unification

Status: approved direction (audit roadmap "Phase D"). Dispatch: single
worker lane, worktree `wt-phase-d`, branch `phase-d/triggers-tasks`,
checkpoint commits, extended budget. Preconditions: Phase C merged. The
controller machinery already exists (`CustomTaskSpec`/`TaskReconciler`,
`TaskReconcilePolicy` with slot/retry/coalescing aspects from Track 0)
— this phase consumes it, it does not invent a second one. Every unit
passes the five gates.

## Goal

Time and event triggers become declarative, durable, node-local rows;
`sched` schedule expressions drive time triggers and the W2-2
`SubscriptionPredicate` drives event triggers; core sweeps/checkpoints
run as core-owned controller tasks on the same machinery; operation
events are generated from the unified change stream. Also: re-examine
the Phase C deferral (per-row cleanup-policy labels on the reconcile
wire) with a real consumer in hand.

## Why

Trigger semantics are currently implicit (hardcoded runtime loops);
the schedule grammar has no consumer; the task machinery runs user
tasks but not the core's own periodic work, so core sweeps sit outside
the observability, coalescing, and shutdown-drain discipline everything
else gets.
Node-local rows give triggers durability and introspection without
replication (triggers are node policy, not cluster state).

## Current-state anchors (verified 2026-11-08, post-Phase-C main)

- `src/task/mod.rs` — `CustomTaskSpec`, `TaskReconciler`,
  `TaskReconcilePolicy` (four-aspect declaration: slot/retry/coalescing/
  drain); `core_task_policies()` registration.
- `src/runtime/retention.rs` — the runtime loop that currently invokes
  the Phase C sweep engine (`collected_tombstone_sweep`) and the
  checkpoint gate.
- `src/identity/sweep.rs` — the Phase C engine (to be wrapped by a
  controller task).
- `src/node/predicate.rs` — `SubscriptionPredicate` (domains + label
  selector; documented Phase D trigger seam).
- `sched` — the schedule-pattern crate: `Schedule::parse`/`bind` and
  `BoundSchedule::next_after`, plus the runtime-agnostic `Trigger` task
  table the dispatch engine drives. The crate carries the timezone
  database (jiff) and the stale-tick/overlap policies.
- Phase C deferral: policy labels are declaration-driven (auto-stamp at
  seal); per-row label carriage on the reconcile wire was deferred here.

## Design commitments

1. **Trigger declarations as node-local rows.** A trigger row carries:
   its `TriggerSource` (`sched` schedule text | event predicate) and the
   target (a core-owned operation or a registered task spec reference).
   The runtime policy is the `sched` engine's: overlap = skip, missed
   tick = skip (never replay) — spec/policy separation. Node-local
   family in the catalog (`node_local`), never replicated. Durable
   across restarts; the `sched` table is rebuilt from the rows on every
   incarnation.
2. **Time triggers.** The dispatch engine drives the shared `sched`
   table against the wall clock: `next` → sleep → `fire_due` → spawn
   the callback run. A row's next window is computed from the current
   clock when the table registers it, so a window missed while the node
   was down is skipped, not replayed. Expressions are forwarded to
   `sched` as written (`Z`, a fixed offset, an IANA zone, or the
   device-local frame).
3. **Event triggers.** Predicate-driven: the unified change stream
   feeds the predicate; a match enqueues the target per the overlap
   policy (skip). Reuses the W2-2 emit-side evaluation — no second
   matching path.
4. **Core sweeps/checkpoints become controller tasks.** The retention
   loop's sweep/checkpoint work moves onto `CustomTaskSpec` machinery as
   core-owned reconcilers: bounded retention of completed controller
   runs, separate dial budget (controllers never consume the user dial
   budget), drain-on-shutdown honored via the policy declaration.
   Outcome equivalence: the same engine, same gate, invoked through the
   task machine — swept/retained sets identical to Phase C. The
   recovery/sweep, degree-maintenance, and anti-entropy cadences are
   `sched` expressions too (the recovery tick is the ten-second enum
   `{0,10,20,30,40,50}`; trigger evaluation keeps its own one-second
   worker so the coarser recovery tick does not delay it).
5. **Operation events from the unified change stream.** Operation/task
   lifecycle events derive from the change stream rather than ad-hoc
   emission sites where the stream already carries the fact. Event
   parity with today's emissions for unchanged facts; new facts (trigger
   fires, controller runs) are additive event kinds.
6. **Per-row policy labels on the wire — decide with the consumer in
   hand.** If the trigger/controller work makes per-row relabeling real
   (a declared consumer), extend the tombstones lane wire to carry
   envelope labels (wire amendment, CHANGELOG, cross-version
   fail-closed: old rows decode label-less → declaration fallback); if
   not, record the deferral as final for 0.1.0.

## Open micro-decisions (worker resolves, documents the reason)

- Trigger row schema (one family vs per-source families) and the
  registration API shape (core verbs only?).
- Which clock drives catchup coalescing (wall clock via time.rs —
  operator obligation stance unchanged).
- The dial-budget separation mechanism (slot class vs dedicated budget).

## Acceptance criteria

1. Five gates green.
2. A time trigger fires per its `sched` schedule in a runtime scenario
   test; a stale tick is skipped; an event trigger fires on a predicate
   match and skips overlaps per policy.
3. Sweep/checkpoint outcomes identical to Phase C (existing suites
   unmodified); controller runs appear as bounded, observable task
   records; shutdown drains them.
4. No replication of trigger rows (node-local pin test).
5. Fresh tester + fresh reviewer reports; reviewer walks outcome
   equivalence and the wire-decision execution.
