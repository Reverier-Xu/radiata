# Audit Documentation Index

This directory records audit conclusions and open work items. It describes **current facts and confirmed decisions**, not a development plan.

| File | Contents |
|---|---|
| [audit/00-overview.md](audit/00-overview.md) | Audit scope, method, summary |
| [audit/01-completed.md](audit/01-completed.md) | Work packages already merged (a9bc717..44f29ec, 22 commits) |
| [audit/02-findings.md](audit/02-findings.md) | All valid findings from every review round, grouped by theme |
| [audit/03-decisions.md](audit/03-decisions.md) | Confirmed dispositions (fix / no-fix / doc-only) |
| [audit/04-pending.md](audit/04-pending.md) | Open items and undecided questions |
| [audit/05-principles.md](audit/05-principles.md) | Design principles established during this audit |

## Reading order

Start with `05-principles.md` (the criteria), then `02-findings.md` (the problems), then `03-decisions.md` + `04-pending.md` (the dispositions).

## Status vocabulary

- **DECIDED** — disposition confirmed by the project owner; awaiting implementation.
- **PENDING** — identified, disposition not yet decided.
- **NO-FIX** — decided to keep as-is; rationale recorded.
- **MERGED** — code already on the `audit-followups` branch.

## Baseline

- Audit start point: `a9bc717`
- Current HEAD: `44f29ec` (branch `audit-followups`)
- Gate status: `taplo fmt --check` / `cargo check --all-targets --all-features` / `cargo clippy -D warnings` / `cargo test --all-features` (1123 passed / 0 failed / 26 ignored) / `cargo doc` / ABI freeze — all green.
