---
name: code-quality-review
description: >-
  Multi-agent architecture and code quality review for Rust crates. Runs a
  read-only review across 7 dimensions — thin wrappers, cross-module
  responsibility coupling, duplicated helper logic, poor helper factoring,
  over-abstraction, hardcoded if-else special-casing, and hardcoded strings
  where extensibility is needed — plus evidence verification that milestone
  claims are backed by real tests and verify scripts. Use before closing a
  milestone, before major refactors, when a codebase grows past a few
  thousand lines, or when the user asks to review code quality, find
  duplicated helpers, audit module boundaries, or verify a development
  milestone is actually complete.
---

# Code Quality Review

A structured, read-only review methodology for Rust libraries. It combines:

1. **Milestone verification** — proving a milestone's claims against the
   repo's own evidence (tests → verify scripts → quality gates). The code,
   its comments, and its rustdoc are the single source of truth; there are
   no separate planning documents to consult.
2. **Multi-agent code quality review** — parallel reviewer subagents over
   module partitions, each covering 7 quality dimensions.
3. **Skill output** — findings triaged into a fixable report.

Do this when: a milestone is about to close, the user suspects quality debt
(duplicated helpers, coupling, hardcoded strings), or the codebase has grown
past roughly 5k lines and module boundaries need an audit.

## 0. Setup: Map the Code First

Before any review, build the module map from the code itself (in order):

- `src/lib.rs` — the facade: what is public, how modules re-export.
- Module-level rustdoc (`//!` headers) of each top-level module — ownership
  boundaries and invariants live here.
- `tests/` — the integration surface and the public-API baseline
  (`tests/public_api.rs`, `tests/fixtures/public-api/`).
- `scripts/verify-*.sh` — the per-family verification lanes and the exact
  `cargo test` filters each runs.

Record the milestone claims under review (from the user or commit history)
and the module partitions for section 2.

## 1. Milestone Verification (Is It Actually Done?)

Do not trust commit messages. Prove closure from evidence:

1. Run every `scripts/verify-*.sh` verification script relevant to the
   claim. Each must exit 0. Capture the exact `cargo test` lanes each
   script runs (they encode which behavior the repo considers covered).
2. Map every claim to a concrete test:
   - grep the test name from the verify script lane or `tests/*.rs`;
   - confirm the test body asserts the claim's key statements (e.g. "body
     bytes never enter storage", "interruption is explicit", "no downgrade");
   - note any claim with no visible test (gap).
3. Run the repository quality suite `Q`:
   - `taplo fmt --check`
   - `cargo +nightly fmt --all -- --check`
   - `cargo check --workspace --all-targets --all-features --locked`
   - `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
   - `cargo test --workspace --all-features --locked`
4. State a verdict: PASS / PASS-WITH-GAPS / NOT-PASS. List gaps explicitly —
   a milestone can pass while leaving P2/P3 findings.

Output: a table `claim / key assertions / test / status` plus the verdict.

## 2. Multi-Agent Code Quality Review

### 2.1 Partition by Module Boundary

Split `src/` into coherent responsibility slices (typically 5 lanes), each
child getting files whose ownership is contiguous. Derive the slices from
the module map built in section 0 — never from a stale document.

| Partition | Typical files |
| --- | --- |
| protocol + identity + keys | `src/protocol/*`, `src/identity/*`, `src/keys/*` |
| transport + session + packet + node | `src/transport/*`, `src/session/*`, `src/packet/*`, `src/node/*` |
| membership + resource + routing | `src/membership/*`, `src/resource/*`, `src/routing/*`, `src/sync_common.rs` |
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
   internals; work in the wrong module per the ownership boundaries the
   module rustdoc states (identity logic inside protocol, storage logic
   inside session, transport leaking into packet); knowing another mod's
   private types.
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
- Produce a report: per-dimension findings table + a short "what is healthy"
  section (findings alone overstate debt) + prioritized remediation list.

## Check Yourself

- [ ] Ran every relevant verify script; recorded PASS/FAIL.
- [ ] Every milestone claim has a mapped test or an explicit gap.
- [ ] Every child reported per-dimension; cross-cutting child did the scan.
- [ ] P0/P1 findings spot-checked against real code.
- [ ] Verdict stated against the milestone's claims.
