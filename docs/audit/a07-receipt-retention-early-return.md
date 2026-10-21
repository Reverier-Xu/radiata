# A07: Receipt retention early-return skips the cleanup pass once the 4096 sweep bound is reached

- Verdict: CONFIRMED (core mechanism confirmed; the audit's "mobile profile" framing has no counterpart in the repo — the trigger is purely anchor-population size)

- Evidence:
  - `src/storage/receipt.rs:29` — `pub(crate) const RETENTION_SWEEP_BOUND: usize = 4096;`, documented at `:25-28` as "The upper bound on receipts one retention sweep **drives through the cleanup state machine** … the report says whether the scan stopped at the bound."
  - `src/storage/receipt.rs:461-468` — the guard sits at the top of the scan loop and returns out of the whole function:
    ```rust
    while let Some(entry) = scan.next().await? {
      if targets.len() >= RETENTION_SWEEP_BOUND {
        return Ok(ReceiptRetentionReport { forgotten: 0, remaining: true });
      }
    ```
  - `src/storage/receipt.rs:477-488` — the due filter (`if self.clock.now() < deadline { continue; }`) precedes `targets.push(...)`; only due entries are collected.
  - `src/storage/receipt.rs:493-502` — the cleanup loop (`for target in &targets { … self.cleanup_receipt(target, …) … }`) sits after the scan; the early `return` at `:463-467` exits before it ever runs. (The skipped `drop(scan)`/`drop(snapshot)` at `:491-492` is harmless — RAII drops on return; the loss is the cleanup loop.)
  - `src/storage/receipt.rs:501-504` — the intended design is visible in the natural-exit path: `remaining: targets.len() >= RETENTION_SWEEP_BOUND`, i.e. process the bound, then signal more work. The early `return` bypasses this and contradicts the contract in `src/node/handle.rs:441-444` ("The pass is idempotent and latency bounded; issue it again while `remaining` reports true") and `src/storage/receipt.rs:449-452` ("one explicit host-triggered pass advances the whole anchored population one idempotent step").
  - Drivers/population: `src/runtime/retention.rs:73-78` + `src/runtime/recovery.rs:52` run `apply_receipt_retention` automatically on every recovery tick; retention window defaults to 30 days (`src/config.rs:377`) but is host-settable (`src/config.rs:182`). No test covers the bound path — `src/storage/contract/engine.rs:246-292` and `src/runtime/supervisor.rs:1425-1520` exercise only single-digit receipt counts.
  - "mobile" appears nowhere in the repository (repo-wide grep), so the profile attribution is ungrounded; the finding stands without it.

- Root cause: `targets` can only reach `RETENTION_SWEEP_BOUND` via due pushes at `receipt.rs:488`, and the guard at `:462` is evaluated before the due filter, so the trigger is: ≥4096 due anchored receipts **and** at least one further anchored entry (due or not) in scan order. On that 4097th entry the loop `return`s with `forgotten: 0, remaining: true` instead of `break`ing. The explicit drops and the entire cleanup loop over the 4096 already-collected due targets are skipped, so the pass forgets nothing. Because the sweep is deterministic and the only mass remover of anchors (the forget arm at `receipt.rs:413-421`; the only other anchor deletion is the incidental reference-gain path at `receipt.rs:776-781`), every subsequent tick/command re-scans the same ordered anchor set and hits the identical early return — a deterministic livelock, not a transient condition.

- Impact: Any node whose anchored receipt population crosses 4096 due anchors + 1 extra entry loses receipt retention entirely: `forgotten` stays 0 forever while `remaining` perpetually reports true, so both the explicit command (`node/handle.rs:454`) and the automatic recovery-tick sweep (`runtime/receipt_retention_sweep`) spin without progress and the anchor population grows unboundedly. Severity: P1 — not memory-unsafe, but a permanent, self-sustaining stall of a lifecycle subsystem on busy/long-lived nodes with a short `receipt_retention` window.

- Suggested fix direction: Replace the `return Ok(…)` at `src/storage/receipt.rs:463-467` with `break` (optionally preceded by `tracing::debug!(target_count = targets.len(), "receipt retention scan stopped at sweep bound")`), letting the collected ≤4096 due targets flow into the existing cleanup loop; the final `remaining: targets.len() >= RETENTION_SWEEP_BOUND` at `:503` then reports "more work remains" exactly per the documented contract. Minimal one-word-class change; no unsafe, no unwrap, diagnostics via `tracing`.

- Validation ideas:
  1. Contract test (style of `storage/contract/engine.rs:246` with `ManualClock` + `retention_testing::anchor_receipt`): anchor 4097 receipts, advance the clock past all deadlines, assert `apply_receipt_retention` returns `forgotten == 4096, remaining == true`; repeat passes until the report is `forgotten > 0` then `remaining == false`, proving forward progress and full drain.
  2. The precise currently-broken interleaving: exactly 4096 due anchors plus 1 not-yet-due anchor — assert the pass still forgets the 4096 and `remaining == false`.
  3. Supervisor-level test in `runtime/supervisor.rs` `receipt_retention_sweep_tests`: drive repeated `receipt_retention_sweep()` ticks over a backlog ≥ bound+1 and assert the anchor count strictly decreases each tick (would fail on current code).
