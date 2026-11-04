# Outstanding work

Scope: what is still open in `radiata` as of the 2026-11-04 sweep. Everything
closed in that sweep is listed first with its commit, so a reader can tell a
deliberate decision from an oversight.

Ordered by risk, not by size.

---

## Closed in the 2026-11-04 sweep

| Was | Outcome | Commit |
| --- | --- | --- |
| Two library tests flake when the suite runs concurrently | The backfill scan fault is now owned by one `RedbStoreFactory` instance instead of a process-global static, so a sibling test's open can no longer consume it. The documented `crash.rs` "path collision" was disproven: every matrix uses its own `TempDir` and children are separate processes, so nothing crossed a test boundary. | `355157d` |
| Crash matrices could pass on a child that died for the wrong reason | Both `std::process::abort()` hooks now go through one record-then-abort helper; `run_crash_child` asserts the record names the exact requested point and reports the captured child stdout/stderr when it does not. Proven by injecting a panic before the crash point and watching the parent go red. | `c9213d7` |
| The two descriptor write paths disagreed about a corrupt row | Both resolve their incumbent through one helper: an undecodable row is non-evidence and the verified incoming descriptor installs over it. The shared warning now carries the decode context, so an unreadable newer record version is distinguishable from file damage. Reads stay fail-closed. | `b52ab0e` |
| No CI upper bound on recovery convergence | Five property tests over any valid `RecoveryPolicy`: backoff ceiling, no starvation, the `ceil(n / fan_out)` sweep bound, quiescence in the observing call, and base-backoff monotonicity. The controller is a pure state machine over `now: u64`, so the tests drive wall time directly instead of pausing a clock. | `fbaa59a` |
| No rustdoc gate | One `cargo doc` step in the `stable` job, folded into that job's attestation without changing its schema. It sits in `stable` because a cold `--all-features` doc build would blow the `format` job's three-minute budget. | `489e84a` |
| Deferred refactors | `reconcile::plane::tick` 482 → 74 lines, `runtime::supervisor::supervise` 346 → 101, `membership::sync::apply_tombstone_rows` 193 → 53, and the tombstone lifecycle moved into its own `membership::tombstone` module (`sync.rs` 2135 → 1185). The row's other half — an `EventHub` module migration — was audited and needs nothing: `node::event` is 433 lines with one responsibility (bounded typed transient delivery), no membership, storage, or transport concern leaks in, and its tests are its own. | `54e7826`, `7536854`, `f8ad561`, `d0f71cd`, `44341ff` |
| Test-suite pruning candidates | Audited per test against one criterion — a test goes only if a `tests/` lane asserts the same contract end to end. `session/inbound.rs` (26), `routing/trace.rs` (22), and `identity/records.rs` (20) had **zero** qualifying deletions: the records are `pub(crate)`, the trace contracts are internal wire and sweep accounting, and `tests/routed_packets.rs` has five multi-hop lanes and no digest or refusal case. `storage/migration.rs` collapsed three json/redb pairs into one backend table. | `9c63ff6` |
| `category_tag!` dead-code allows | The macro now has a shared `@type` arm plus an accessor arm, and the test-only `DiscoveryTag` uses `@without_accessors`. Both `#[allow(dead_code)]` are gone. The accessors ride into the same `impl` block as `parse`, so the rendered public API stays byte-identical to the approved baseline — a second `impl` block would have added three `impl radiata::…Tag` header lines to the freeze. | `5f19a7c` |
| No `LICENSE`, no `CHANGELOG` | The verbatim GPL-2 text and a Keep a Changelog file populated from the git history. The version was deliberately left at `0.0.2` — see below. | `da1d4c7` |
| A `--cfg fuzzing` build carried a dead-code warning | `RouteContext::trace_id` is gated on `test` alone; no fuzz target reads it. | `7d38ca5` |
| The soak lane's ignore reason claimed a CI schedule | There is no `schedule:` trigger; the reason now names the one lane that runs it. | `e08eace` |

---

## P2 — open behavioural residuals

### 1. A corrupt local descriptor row blocks the node's own publication

`read_descriptor_ctx` stays fail-closed: an undecodable stored descriptor is
an error, never an absent descriptor, because the register's content is
genuinely unknown there. That is the right answer for a peer's row, but
`membership::sync::ensure_local_descriptor` reads the **local** node's
descriptor first and propagates the error, so one corrupt local row stops the
node from publishing its own descriptor at all.

The write paths already heal (see the closed item above); the read path is the
remaining half. Fixing it means deciding what a read should return for a row
this binary cannot decode — absent (heals, but a peer's row would then look
removable) or a typed "unknown" the caller must branch on. That decision has
not been made.

### 2. `maximum_backoff` is not a hard cap

`RecoveryPolicy::base_seconds` caps the deterministic base at
`maximum_backoff`, and `sample_jitter` then adds up to a quarter of that base,
so the longest wait a recovering node can schedule is
`maximum_backoff + maximum_backoff / 4`. The property test asserts that exact
ceiling, and `jitter_stays_bounded_and_decorrelates_identical_sequences`
witnesses it tightly (base 8, max 8, extreme entropy word → 10).

Two readings are defensible: the configured maximum is a cap on the *base*
with jitter allowed to overshoot, or it is a hard ceiling on the wait. The
current code and docs say the former. Changing to the latter moves recovery
timing, so it needs a deliberate decision rather than a drive-by edit.

### 3. A corrupt resource row is only half self-healing

A plain put installs over an undecodable incumbent, so the register heals
locally. But the corrupt row itself still cannot be read (`read_record_ctx`
reports the decode fault rather than fabricating an absence) and cannot be
removed (a removal record is built *from* the stored record's type, URI,
labels and rank). The operator remedy is the plain put that repairs it.

Decided: keep this, and say so in the rustdoc. A real fix needs an explicit
purge action that deletes the row by key under an exact CAS, which is new
public surface, not a bug fix.

---

## P3 — release

### 4. The version bump is the owner's

`Cargo.toml` still says `0.0.2` while the ABI fixture is
`tests/fixtures/public-api/baseline-0.1.txt` and the docs speak of the "0.1
baseline". The bump, the fixture name and the baseline rendering move
together, and the owner performs it at final acceptance. `Cargo.lock` must be
updated in the same change.

---

## Decided, no action

- **A corrupt descriptor removal row can resurrect a departed node.** The
  removal guard needs the row to decode, so a removal marker written by a
  newer record version protects nothing in an older binary. Accepted: the
  alternative is a tombstone whose revision is unknowable, which would be
  fabricated evidence. Documented in the `membership` module docs.
- **Six operator-run lanes are never exercised by CI**
  (`verify-decoder-fuzz.sh`, `verify-state-fuzz.sh`, `verify-soak.sh`,
  `verify-release.sh`, `verify-evidence-validator.sh`,
  `verify-simulation-artifacts.sh`). Deliberate: a green CI run is functional
  evidence, not SLO evidence. They stay local. The cost is drift, and the
  soak lane's own reason no longer pretends a CI schedule covers it.
- **The pre-0.1.0 wire break is frozen forward only.** Removing the
  feature-limit negotiation was a deliberate pre-release wire break. The
  compatibility manifest freezes the `0.1.0` initiator feature offer
  (`feature-offer-initiator-v1`), so a future release can assert it still
  accepts those bytes. Nothing can retroactively prove interoperability with
  `0.1.0`'s predecessors, and `tests/mixed_versions.rs` is explicitly not that
  evidence — it drives two nodes of the current build with different feature
  surfaces.
