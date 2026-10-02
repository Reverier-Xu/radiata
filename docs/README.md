# docs — working plans

This folder holds **time-scoped working documents**: refactoring plans,
hardening roadmaps, and post-incident analyses that drive upcoming work
cycles. It is deliberately not a reference-documentation home — the
canonical documentation stays anchored in the code (`radiata::guide`,
rustdoc, and module-level docs) so it cannot drift from behavior.

Lifecycle rules:

- A plan lands here when a work cycle is scoped, and is **deleted or
  moved into its commit history** once the work completes and its
  acceptance criteria are verified. Stale plans are drift.
- Every plan must trace its motivation to concrete evidence: incident
  reports, failing lanes, or measured behavior — never to speculation.
- Every work item in a plan names its acceptance criteria and the gate
  that will catch its regression in the future.

## Current documents

- [`backlog.md`](backlog.md) — the open-work ledger: decisions already
  made, the scoped items with their evidence, acceptance criteria and
  guarding gates, and the recorded environmental limits that audits
  must budget for.
- [`research/`](research/) — the sync-redundancy research cycle's evidence
  library and architecture decision record (the cycle landed 2026-10 and
  closed per the lifecycle rules): a source-grounded baseline of the
  watermark anti-entropy's structural redundancy, survey notes (gossip
  theory, set reconciliation, delta CRDTs), a candidate comparison, and
  the target architecture proposal. Retained as decision evidence —
  the shipped truth lives in `src/reconcile/` and `radiata::guide`, and
  the cycle's summary lives in the backlog's landed section.

Completed cycles do not keep their documents here. The
`starvation-hardening-plan` cycle (configurable admission and
authentication bounds, smooth token-bucket merge admission split by
pool, recovery defaults and jitter, per-hop relay budgets, the single
recalibrated timing profile, the one-core starvation CI gate, and the
pipelined sync planes that followed) deleted its plan per the lifecycle
rules, and its acceptance evidence lives in the commit history of the
`starvation-hardening-plan` and `trust-pass-repair` branches. The
connection-degree` cycle (degree maintenance, the typed member-dial
contract, the chat acceptance CI lane, the leave-persist log, and the
mode-1 hub-loss chaos phase) did the same: the degree formula and its
rationale live in `src/membership/degree.rs` and the guide, and the
cycle's summary lives in the backlog's landed section. The
`reconciliation plane` cycle (the fingerprint index, the engine and
wire v1, the four-lane migration off the watermark walks, the trigger
and adaptation layer, and the sync-budget lane) followed: its evidence
library stays as the decision record, and its summary lives in the
backlog's landed section.
