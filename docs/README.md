# docs directory index

This directory keeps exactly two kinds of content: **authoritative engineering
documents** and **archived point-in-time reports**. The code and its comments
are the single source of truth for implementation facts; the rustdoc
(`cargo doc`) is the authoritative API reference.

## Authoritative documents

| Document | Content | Maintenance convention |
| --- | --- | --- |
| [architecture.md](architecture.md) | Layered architecture and module responsibilities (rewritten against the `plan-0.1.0-baseline` 0.1.0 code freeze, 2026-09-15) | Update alongside code changes that touch architectural semantics |
| [plan-0.1.0.md](plan-0.1.0.md) | **The pre-0.1.0 improvement plan (single task ledger)**: every P0/P1/P2 item with root cause, design sketch, acceptance criteria, and batch order | Update each item's status in place as it completes; file newly discovered problems before starting work |
| [archive/README.md](archive/README.md) | Archive conventions | — |

## archive/ (point-in-time reports; for traceability only, unmaintained)

| Document | Point in time | Archive reason |
| --- | --- | --- |
| audit-findings.md | main @ `faf7833` | Full-codebase audit report; P1×3, P2×22, P3×14 all fixed (§9 ledger), items folded into plan-0.1.0.md |
| example-findings.md | cluster example campaign | Customer-integration friction list; #3/#4/#9/#10/#11/#12 fixed, remaining items folded into plan-0.1.0.md (P1-4, P2-5, P2-6) |
| snapshot-analysis.md | fix-audit-findings @ `fbfaa14` | Snapshot deep-dive; open recommendations (snapshot-refresh decoupling, trust comments, >16-node protocol rework) folded into plan-0.1.0.md (P0-4, P1-7, P2-1) |
| benchmark-loopback.md | 2026-09-10 | Loopback benchmark point-in-time data; the ack-delivery semantics changed performance characteristics, superseded by P0-2's soak |
