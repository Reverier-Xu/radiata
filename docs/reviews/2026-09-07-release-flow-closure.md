---
id: 2026-09-07-release-flow-closure
status: review-record
scope: release-flow decision record; plan, scenario, and threat rows re-scoped to the operator-run verification form
date: 2026-09-07
---

# Release Flow Closure: Operator-Run Verification and Manual Publish

## Decision

The maintainer closes the remaining release-flow work with one simplifying decision:
publication is manual. The automated candidate-freeze, complete-ledger digest, external
signed release token, guarded publication workflow, and the associated guard-test
surface are retired instead of built. What replaces them is one operator-run command
and one operator judgment:

- `scripts/verify-release.sh` runs the full pre-publication suite in order and fails
  fast: quality gates, wire compatibility, mixed binaries, the sealed evidence
  validator, fuzz corpus replay, the churn soak, and the SLO harness with the
  125-sample measure pinned to the current commit.
- The SLO ledger records the exact tested commit and the samples are bound to it, so
  the operator publishes by tagging the same commit the launcher verified.

## Why the replaced controls are unnecessary here

The retired controls (external signed token, guarded publication workflow, complete
ledger digest) defend against evidence substitution by parties with write access to
the repository and CI. This project is a single-maintainer crate: the operator who
runs the verification is the same party who publishes, so the substituted-evidence
threat collapses into self-deception, which the retained controls already address —
the launcher refuses to run partial or stale evidence, the sealed validator rejects
under-budget or masked lineages, and the ledger binds every sample to the tested
commit and lock digest.

## Re-scoped rows

- **T-G10-11**: the deliverable is the release verification launcher and the exact
  sixteen-node per-run measurement. The candidate commit, workflow digest, SBOM, and
  image-digest freeze rows shrink to the launcher's commit-and-lock binding. The
  release-grade soak (24h) remains an operator decision and is documented in the
  launcher header.
- **T-G10-12**: closed as retired. No token, guard-test, or publication-workflow
  surface exists; the scenarios re-scope to the launcher's fail-fast sequencing and
  the manual publish contract.
- **THR-027**: mitigation reworded to the retained controls (launcher fail-fast,
  sealed validator, commit-and-lock-bound ledger, manual tag-on-verified-commit);
  the residual notes that publication correctness now rests on the operator running
  the launcher on the exact commit they tag.
- **E2E-10 / SC-G10-P0-36**: satisfied by the local qualification run (five runs,
  125 samples, all green) and repeatable through the launcher.

## Non-goals

No new automation is introduced for publication. The launcher is verification only;
it never tags, publishes, or contacts a registry.
