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
- [`node-handle-api-plan.md`](node-handle-api-plan.md) — the scoped
  cycle replacing the public command/query struct dispatch with the
  client-go-shaped verb surface (resource accessors, operation verbs,
  `watch`, `send`).

Completed cycles do not keep their documents here. The
`starvation-hardening-plan` cycle (configurable admission and
authentication bounds, smooth token-bucket merge admission split by
pool, recovery defaults and jitter, per-hop relay budgets, the single
recalibrated timing profile, the one-core starvation CI gate, and the
pipelined sync planes that followed) deleted its plan per the lifecycle
rules, and its acceptance evidence lives in the commit history of the
`starvation-hardening-plan` and `trust-pass-repair` branches. The
`connection-degree` cycle (degree maintenance, the typed member-dial
contract, the chat acceptance CI lane, the leave-persist log, and the
mode-1 hub-loss chaos phase) did the same: the degree formula and its
rationale live in `src/membership/degree.rs` and the guide, and the
cycle's summary lives in the backlog's landed section.
