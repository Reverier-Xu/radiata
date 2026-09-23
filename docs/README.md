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

- [`starvation-hardening-plan.md`](./starvation-hardening-plan.md) —
  the low-power-device starvation-hardening refactor: configurable
  admission and authentication bounds, recovery defaults and jitter,
  per-hop relay budgets, a low-power device profile, and a
  starvation CI gate. Motivated by the transport-chaos incidents
  surfaced on the `pluggable-transports` cycle.
