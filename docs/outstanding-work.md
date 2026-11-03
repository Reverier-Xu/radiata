# Outstanding work

Scope: what is still open in `radiata` as of the 2026-11-03 sweep. Closed items
(the `start_recovery` forcing bug, the four 2026-11-03 residuals, and the test
suite pruning) are not repeated here — they are in the git history.

Ordered by risk, not by size.

---

## P1 — will eventually turn CI red

### 1. Two library tests flake when the suite runs concurrently, and CI runs it concurrently

- `src/storage/redb/store.rs:1239` —
  `backfill_scan_failure_fails_the_open_and_commits_nothing` drives a
  process-wide fault hook, so a sibling test in the same binary can observe the
  injected failure.
- `src/storage/redb/crash.rs:88` —
  `redb_crash_boundaries_recover_exact_old_or_new_state` reopens a redb file
  repeatedly and can collide with another test opening the same path class.

Both live in the single `radiata` lib test binary, so `cargo test --workspace`
runs them as concurrent threads. Neither takes the `cluster_gate` that the
redb reopen lane was given for exactly this reason (`src/storage/redb/` has no
gate use at all). The 2026-11-03 gate was green only because it ran with no
concurrent test process — that is a flake window, not a fix.

Fix: take the machine-level gate in both tests, or serialize the two.

---

## P2 — known behavioural residuals

### 2. A corrupt descriptor row can resurrect a removed node

`decode_or_absent` (`src/storage/incumbent.rs`) treats an undecodable stored row
as absent. For the descriptor lane that loses the removal protection in
`descriptor_skip_reason` (`src/membership.rs:400`): a corrupt *removal*
descriptor can be overwritten by an older *live* row, so a departed node can
re-enter the roster.

Not fixed because the honest fix needs a tombstone written over the corrupt row,
and the corrupt row's revision is unknowable — the tombstone would be fabricated
evidence. Any fix has to answer "what revision does a repair claim?" first.

### 3. A corrupt resource row is only half self-healing

A plain put now installs over an undecodable incumbent
(`commit_expected_record_ctx`, `src/resource/store.rs`), so the register heals
locally. But the corrupt row itself still cannot be read (`read_record_ctx`
reports the decode fault rather than fabricating an absence) and cannot be
removed (a removal record is built *from* the stored record's type, URI, labels
and rank). The operator remedy is the plain put that repairs it.

### 4. No CI upper bound on recovery convergence

`start_recovery()` now really forces a cycle and restarts the backoff cadence,
but nothing in CI asserts "for any configuration, the node converges within a
bound". The recovery lane checks convergence in specific scenarios only.

### 5. Deferred refactors (decided: after 0.1.0)

| Location | Size |
| --- | --- |
| `src/reconcile/plane.rs::tick` | 479 lines |
| `src/runtime/supervisor.rs::supervise` | 346 lines |
| `src/membership/sync.rs::apply_tombstone_rows` | 193 lines |
| `EventHub` / tombstone GC | module migration |

---

## P2 — gaps found during the 2026-11-03 sweep, not yet recorded anywhere else

### 6. CI has no rustdoc gate

Every job sets `RUSTDOCFLAGS: -Dwarnings`, but no step runs `cargo doc`. Doctest
compilation does not check intra-doc links, so a broken link in the (large)
`guide` chapter set would land silently. `cargo doc --no-deps --all-features
--locked` is clean today; nothing keeps it that way.

Fix: one step in the `format` or `stable` job.

### 7. Six operator-run lanes are never exercised by CI

`scripts/verify-decoder-fuzz.sh`, `verify-state-fuzz.sh`, `verify-soak.sh`,
`verify-release.sh`, `verify-evidence-validator.sh`,
`verify-simulation-artifacts.sh`.

This is a deliberate decision (a green CI run is functional evidence, not SLO
evidence), and the cost is drift: these lanes are the only fuzz and soak
evidence in the repository, and nothing notices when they rot. Concretely,
`fuzz/` is a separate crate whose targets only compile with `--cfg fuzzing`
(cargo-fuzz supplies it), so a plain `cargo check` in `fuzz/` fails by design —
a real breakage there would look identical to the expected failure.

Fix: at minimum a scheduled job that runs `cargo +nightly fuzz build` (compile
only) so the targets cannot silently stop building.

---

## P3 — hygiene and release

### 8. Test-suite pruning, remaining candidates

The 2026-11-03 sweep removed 63 duplicated or shape-only tests (1121 → 1058) on
one criterion: a test goes if a `tests/` lane already asserts the same contract
end to end, and stays if it covers an internal contract the public surface
cannot reach. These regions still need a per-test pass:

| Location | Tests | Note |
| --- | --- | --- |
| `src/session/inbound.rs` | 26 | mostly window backpressure and hop ownership (keep); a few digest/refusal cases may duplicate `tests/routed_packets.rs` |
| `src/routing/trace.rs` | 22 | retention and sweep accounting (keep); `failure_codes_round_trip` style may duplicate `tests/observability.rs` |
| `src/identity/records.rs` | 20 | golden vectors and canonical rejection (keep); accessor tests can go |
| `src/transport/registry.rs` | 19 | override/provider surface is covered by `tests/transport_override.rs` and `tests/transport_provider.rs` |
| `src/storage/migration.rs` | 13 | `*_json` / `*_redb` pairs can collapse into one parameterized test |

### 9. One `#[allow(dead_code)]` added by the sweep

`src/protocol/tag.rs` — the `category_tag!` macro generates `as_str`/`domain` for
every category tag; `DiscoveryTag` has no production reader, so both are marked
dead-code tolerant. Cleaner would be to generate them only where used, which is
a macro refactor rather than a test change.

### 10. Release loose ends

- No `LICENSE` file at the repository root, although `Cargo.toml` declares
  `GPL-2.0-only` (the licence text must accompany distribution).
- No `CHANGELOG`.
- `Cargo.toml` says `0.0.2` while the ABI fixture is
  `tests/fixtures/public-api/baseline-0.1.txt` and the docs speak of the "0.1
  baseline". Align the version, the fixture name and the baseline rendering in
  the same change.

### 11. The pre-0.1.0 wire break is frozen forward only

Removing the feature-limit negotiation was a deliberate pre-release wire break:
a pre-`0.1.0` binary cannot handshake with the current one. The compatibility
manifest now freezes the `0.1.0` initiator feature offer
(`feature-offer-initiator-v1`), so a *future* release can assert it still
accepts those bytes. Nothing can retroactively prove interoperability with
`0.1.0`'s predecessors, and `tests/mixed_versions.rs` is explicitly not that
evidence — it drives two nodes of the current build with different feature
surfaces.
