# Audit Overview

## What was audited

The `radiata` Rust crate at `/Users/bytedance/.local/share/orca/radiata` — a decentralized, Kubernetes-like cluster base for sparse clusters of unreliable personal edge devices.

## Method

Four review rounds, each using fresh read-only reviewer agents (no editing, no committing):

| Round | Reviewers | Focus |
|---|---|---|
| 1 | 7 parallel | Full-crate architecture and code quality across 7 dimensions |
| 2 | 4 parallel | (a) code added by this work, (b) whole architecture blind to the work, (c) promised user experience proven from tests, (d) 7 dimensions + cross-module duplication |
| 3 | 1 | Retention / capacity / eviction mechanisms against the "disk belongs to the user" principle |
| 4 | 1 | Closed-enum centralisation against the "adding an item must not touch other modules" principle |

Every P0/P1 finding was spot-checked against real source before being accepted. Reviewer claims that contradicted the source were corrected and recorded (see `02-findings.md` § Corrections).

## Headline conclusions

1. **No P0 findings.** Every round returned "OK with notes".
2. **The data plane holds up.** Per-hop authentication, loop-freedom within the hop budget, strict wire decoding, terminal-state monotonicity, backpressure-free write path, typed watch recovery — all verified correct with tests that would fail on regression.
3. **The extension surface was the weak spot, and it is now characterised precisely:**
   - TLS trust class was reachable only through the built-in enum (a caller's own TLS transport could not even dial).
   - The event seam is sealed in both directions (users cannot publish a typed event).
   - Core-ness selected task policy (slot class, shutdown drain).
   - `LaneId`, `TransportScheme`, and `TombstoneKind` are centralised such that adding one item edits other modules' files.
   - Four of eight registration seams skipped the reserved-domain rule.
4. **Verification facilities were largely self-referential.** `src/compatibility.rs` (930 lines, 23 vectors, 2516 bytes of hex) is mostly a gentleman's agreement; six of seven `tests/static_invariants.rs` tests are source greps. Only the "old wire shape still decodes" case and the "duplicated literal detected" case earn their keep.
5. **Retention was mostly already caller-owned.** Seven of eight disk-deleting mechanisms are caller-configured or operator-issued; only the resource feed window was a pure library imposition.

## Gate status at audit end

```
taplo fmt --check                                    PASS
cargo check --workspace --all-targets --all-features PASS
cargo clippy ... -- -D warnings                      PASS
cargo test --workspace --all-features                1123 passed / 0 failed / 26 ignored
cargo doc --no-deps --all-features                   PASS
ABI freeze (cargo-public-api 0.52.0 + nightly)       PASS
```

`cargo +nightly fmt` cannot be verified locally: the `cargo` on PATH is the stable toolchain binary, so `rustfmt.toml`'s unstable options are ignored and stable rustfmt is used instead. All touched files were verified with the nightly `rustfmt` binary directly. CI's nightly is authoritative.

## Scope of this document set

This records **facts and decisions**. It deliberately contains no implementation plan, no task breakdown, and no scheduling.
