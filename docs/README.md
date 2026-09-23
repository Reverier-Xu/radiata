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

None. The `starvation-hardening-plan` cycle (configurable admission
and authentication bounds, smooth token-bucket merge admission split
by pool, recovery defaults and jitter, per-hop relay budgets, the
single recalibrated timing profile, and the one-core starvation CI
gate) is complete: the plan document was deleted per the lifecycle
rules and its acceptance evidence lives in the commit history of the
`starvation-hardening-plan` branch.
