---
name: code-quality-review
description: >-
  Multi-agent architecture and code quality review for Rust crates. Runs a
  read-only review across 7 dimensions — thin wrappers, cross-module
  responsibility coupling, duplicated helper logic, poor helper factoring,
  over-abstraction, hardcoded if-else special-casing, and hardcoded strings
  where extensibility is needed — plus gate-closure evidence verification
  against the repo's planning documents. Use before gate closure, before
  major refactors, when a codebase grows past a few thousand lines, or when
  the user asks to review code quality, find duplicated helpers, audit module
  boundaries, or verify a development milestone is actually complete.
---

# Code Quality Review

A structured, read-only review methodology for Rust libraries. It combines:

1. **Gate-closure verification** — proving a milestone's claims against the
   repo's own planning evidence (scenarios → tests → verify scripts).
2. **Multi-agent code quality review** — parallel reviewer subagents over
   module partitions, each covering 7 quality dimensions.
3. **Skill output** — findings triaged into a fixable report.

Do this when: a development gate is about to close, the user suspects quality
debt (duplicated helpers, coupling, hardcoded strings), or the codebase has
grown past roughly 5k lines and module boundaries need an audit.

## 0. Setup: Read the Planning Documents First

Before any code review, read (in order):

- `docs/roadmap.md` — product contract, architecture rules, **planned module
  boundaries** (the authority for judging responsibility coupling).
- `docs/development-gates.md` — each gate's Build/Verify/Pass criteria and the
  E2E catalog.
- `docs/implementation-plan.md` — the 69 task rows; each task names its owned
  paths, evidence, and rollback code.
- `docs/task-verification.toml` — maps each task to a `scripts/verify-*.sh`.
- `docs/scenario-catalog.toml` — the SC-* acceptance text per scenario.
- `docs/threat-model.toml`, `docs/api-inventory.toml` — threat and API shape.

Record the target gate (e.g. G3) and its tasks (e.g. T-G03-01..06), scenarios
(SC-G03-P0-01..22), and E2E IDs.

## 1. Gate-Closure Verification (Is the Milestone Actually Done?)

Do not trust commit messages. Prove closure from evidence:

1. Run every `scripts/verify-*.sh` verification script. Each must exit 0.
   Capture the exact `cargo test` lanes each script runs (they encode which
   scenarios the gate considers covered).
2. Map every SC-* acceptance item to a concrete test:
   - grep the test name from the verify script lane;
   - confirm the test body asserts the acceptance's key claims (e.g. "body
     bytes never enter storage", "interruption is explicit", "no downgrade");
   - note any acceptance phrase with no visible test (gap).
3. Map E2E IDs to `tests/*.rs` `#[tokio::test]` functions.
4. Run the repository quality suite `Q`:
   - `taplo fmt --check`
   - `cargo +nightly fmt --all -- --check`
   - `cargo check --workspace --all-targets --all-features --locked`
   - `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
   - `cargo test --workspace --all-features --locked`
5. Check the gate's **pass predicate** verbatim (e.g. "Either endpoint streams
   opaque packets; interruption is explicit and no conversation semantics
   exist in core") and state a verdict: PASS / PASS-WITH-GAPS / NOT-PASS.
   List gaps explicitly — a gate can be PASS while leaving P2/P3 findings.

Output: a table `SC / acceptance claim / test / status` plus the verdict.

## 2. Multi-Agent Code Quality Review

### 2.1 Partition by Module Boundary

Split `src/` by the roadmap's planned module boundaries, grouping related
areas so each child gets a coherent responsibility slice:

| Partition | Typical files |
| --- | --- |
| protocol + identity | `src/protocol/*`, `src/identity/*` |
| transport + session + packet + node | `src/transport/*`, `src/session/*`, `src/packet/*`, `src/node/*` |
| storage + provider + runtime + simulation | `src/storage/*`, `src/provider.rs`, `src/runtime/*`, `src/simulation/*` |
| facade + cross-cutting | `src/lib.rs`, `src/api.rs`, `src/config.rs`, `src/error.rs`, `src/operation.rs`, `src/view.rs`, registry files + a **cross-module duplication scan** over all of `src/` |

One child must own the cross-cutting scan; without it, duplication findings
stay invisible because each child only sees its own slice.

### 2.2 The Shared Prompt (7 Dimensions)

Give every reviewer the same rubric (in the common prompt) plus lane-specific
files and focus hints. The 7 dimensions, with concrete signals:

1. **Thin wrappers** — functions that only delegate; error-remapping wrappers
   that discard information; traits with exactly one impl; `pub` fn that
   forwards to a private twin.
2. **Cross-module responsibility coupling** — module A reaching into B's
   internals; work in the wrong module per roadmap boundaries (identity logic
   inside protocol, storage logic inside session, transport leaking into
   packet); knowing another mod's private types.
3. **Duplicated helper logic** — same logic in 2+ files: canonical text
   encoding, hex/base64, time conversion, error construction, hash/credential
   derivation, limit validation, sorted inserts. Require exact file:line pairs.
4. **Poor helper factoring** — god-functions; piles of one-off private
   helpers; helpers in the wrong module that force duplication elsewhere;
   misleading helper names.
5. **Over-abstraction** — generics that never vary; single-impl traits; macros
   that could be functions; speculative extensibility with no callers;
   enum+match over plain data; dyn dispatch where concrete suffices.
6. **Hardcoded if-else special-casing** — if/match chains keyed on string
   literals deciding behavior; per-kind branches duplicating data that already
   lives in a registry; cascading boolean flags.
7. **Hardcoded strings where extensibility needed** — magic string
   identifiers/keys/labels/feature names that should be typed constants or
   registry entries; stringly-typed APIs; string-built keys.

Common prompt template (see `references/subagent-prompt.md` for the full text).
Require each child to: read files fully (chunk reads past 2000 lines), report
`severity (P0/P1/P2/P3), file:line, description, suggested fix`, and state
explicitly when a dimension has no findings. Read-only — no edits.

### 2.3 Orchestration

Launch the reviewers as one async `workflowScript` with `runs.all([...])` —
items are `{ key, agent, task }` objects (**not** run promises; `runs.all`
rejects promises as invalid keys). Use the `reviewer` agent. One child per
partition. Await all, then concatenate outputs.

## 3. Triage and Report

Aggregate findings across children:

- Deduplicate (the facade child often re-finds what others found).
- Re-verify high-severity findings against the real code before reporting —
  subagents hallucinate line numbers; spot-check every P0/P1.
- Classify by the gate's own risk language (P0/H vs P1/L) where useful.
- Produce a report: per-dimension findings table + a short "what is healthy"
  section (findings alone overstate debt) + prioritized remediation list.

## 4. Persist the Experience as a Skill

After each review, update this skill's `references/project-findings.md` with
the concrete hotspots found (module, pattern, fix), so the next review starts
from known territory. Keep the 7 dimensions stable; only the evidence mapping
and hotspot list evolve.

## Check Yourself

- [ ] Ran every verify script for the gate; recorded PASS/FAIL.
- [ ] Every SC acceptance phrase has a mapped test or an explicit gap.
- [ ] Every child reported per-dimension; cross-cutting child did the scan.
- [ ] P0/P1 findings spot-checked against real code.
- [ ] Verdict stated against the gate's verbatim pass predicate.
