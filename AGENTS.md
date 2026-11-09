# AGENTS.md

## Project Scope

`radiata` is a Rust 2024 library crate. Keep changes minimal, maintain the public API deliberately, and do not add application, deployment, or platform-specific structure without a concrete requirement.

## Repository Structure

- `crates/radiata/`: the library crate (`src/lib.rs` entry point and
  public API, `tests/` integration suites).
- `crates/cadence/`: the schedule-pattern grammar crate
  (`radiata-cadence`).
- `crates/test-support/`: shared test-support crate.
- `Cargo.toml`: virtual workspace manifest (all packages under
  `crates/`).
- `rustfmt.toml`: nightly Rust formatting rules.
- `taplo.toml`: TOML formatting rules.
- `.github/workflows/quality_check.yml`: required CI quality gates.

Keep unit tests next to the code they validate in `#[cfg(test)]` modules. Add integration tests under `tests/` only when behavior must be exercised through the public API.

## Implementation Principles

- Prefer long-term correctness over short-lived workarounds.
- Choose the simplest design that preserves clear ownership and future changeability.
- Reuse existing modules and helpers before introducing abstractions.
- Keep each change atomic and avoid unrelated refactors.
- Do not add dependencies unless they remove meaningful complexity or provide required domain behavior.
- Forbid `unsafe` code unless the user explicitly approves it and all safety invariants are documented.
- Do not use `unwrap()` or `expect()` in production code. Return or propagate meaningful errors instead.
- All logging and diagnostics must go through the `tracing` crate (`tracing::trace!`, `tracing::debug!`, `tracing::info!`, …). Never add `println!`, `eprintln!`, `print!`, or `dbg!` — including during debugging. Temporary debug prints left in code are release blockers.
- Use the standard tools for standard code operations: read files with the read tool, locate with grep/rg, and edit with the edit tool. Do not edit, generate, or patch code through python/shell one-off scripts — script-driven edits hide what changed and defeat review. Reserve python (or ad-hoc scripts) for complex behavior testing, numerical computation, and data analysis where they are genuinely the right tool.

## Formatting

Rust formatting uses the nightly toolchain because `rustfmt.toml` enables unstable options:

```bash
cargo +nightly fmt --all
cargo +nightly fmt --all -- --check
```

TOML formatting uses Taplo:

```bash
taplo fmt
taplo fmt --check
```

Do not hand-format around these tools. Run both checks after changing Rust or TOML files.

## Quality Gates

Every change must pass with zero warnings:

```bash
taplo fmt --check
cargo +nightly fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

When `.github/workflows/` changes, validate the workflow with `act` when Docker is available. If local workflow execution is unavailable, run every CI command locally and verify the pushed GitHub Actions run before declaring completion.

## Git Conventions

- Use one logical change per commit.
- Use a short, lowercase, imperative summary prefixed by a valid gitmoji shortcode.
- Use a bulleted commit body when details are needed.
- Use short kebab-case branch names; the default branch is `main`.

Example:

```text
:wrench: initialize project quality gates

- add taplo and nightly rustfmt configuration
- enforce formatting, linting, and tests in ci
```

## Completion Checklist

Before committing or handing work back:

1. Run all formatting and quality gates listed above.
2. Fix every warning, error, and formatting diff.
3. Confirm workflow changes are syntactically valid and locally exercised where possible.
4. Remove temporary artifacts and leave only intentional changes.
5. Review the final diff for accidental API, dependency, or metadata changes.
