# Starvation hardening — refactoring plan

Status: **scheduled — next work cycle**.
Motivating evidence: the three incidents the transport-chaos lane
(`tests/transport_chaos.rs`) surfaced on 2-vCPU CI runners during the
`pluggable-transports` cycle (§1). Line references align to main
`763b871`.

---

## 1. Background and motivation

The next deployment target for radiata-driven applications is
**very low-performance devices**: 1–2 slow cores, limited memory, slow
flash storage, possibly deep-sleep scheduling, possibly no RTC. The
stack's *correctness* design already targets constrained environments
(bounded frames, bounded queues, typed failures, exponential backoff,
the any-one-route contract, at-most-once data plane + application
retry). But the **time constants and defaults are calibrated for
server-class hardware**.

The chaos lane exposed three incidents on CI, all facets of one fault
chain — *fixed time constants meeting a slow environment*:

| # | Incident | Root cause | Evidence |
|---|---|---|---|
| A | Every Raw-class session (tls/tcp/unix) self-destructed exactly 1s after establishment | `framing::read_frame` answered a keepalive ping and returned `Ok(None)` — the same value that signals a clean peer EOF — and every caller maps `Ok(None)` to an orderly close | Fixed: `93b95ce` (regression tests in `src/transport/framing.rs` tests) |
| B | Recovery storm self-starvation: an isolated member could never heal; the CI job was cancelled | `fan_out=64` burst 63 concurrent handshakes → the tail of the burst starved past the 10s authentication deadline → the whole step failed → retry hit the merge limiter's aliased per-IP bucket (16/60s) and global window (256/60s) → refusal loop | Mitigated: chaos lane fan-out lowered to 16 + bounded awaits (`70889ee`) — but the library default and the limiter semantics are unchanged |
| C | Data-plane starvation: every 17-hop relay attempt failed with `StreamInterrupted` | 250 ms anti-entropy interval × 64 nodes saturated a 2-vCPU runner; the relay's transitive ack bound expired | Mitigated: interval raised to 1 s + relay gate shortened to 7 hops (`529a4cc`, `ca1a059`) — but "long relays fail under starvation" as a behavior is unchanged |

The mechanisms behind incidents B and C are **not fixed** — the tests
route around them. This plan removes them along the long-term roadmap while
there is no delivery deadline and no installed base.

## 2. Design principles (the constitution of this refactor)

1. **Bounded failure over unbounded waiting.** Every cross-task
   `await` is either itself bounded or provably terminated by another
   bounded mechanism. Unbounded awaits in tests hide library defects —
   before `70889ee` the chaos lane hung silently for 15+ minutes.
2. **Defaults must be safe on the slowest supported device.** Tuning
   direction is "faster", not "works at all". The version is
   unreleased with no installed base: defaults can change boldly.
3. **Eliminate all-or-nothing behavior.** Fixed-window rate limiting is
   binary at window edges (the head of a burst consumes the window,
   the tail is refused, refused attempts consume no budget, and the
   window never recovers for them). Replace with a smooth semantics.
4. **Starvation is a first-class CI scenario.** Defects invisible on
   fast runners need a slow-environment gate to catch them before
   merge.

## 3. Work items

### WP1 — Configurable authentication deadline 【P0 · small】

**Today**: `AUTHENTICATION_DEADLINE` is a fixed 10 s
(`src/session/driver.rs:59`), covering handshake positions 1–6,
**including the join-mode admission commit and grant adoption** — i.e.
including an fsync. On slow flash a single commit costs hundreds of
milliseconds; a few concurrent joins push the tail of the burst past
the deadline, and joins fail **persistently** (every attempt times
out) — the same shape as incident B.

**Change**:
- `NodeConfig::with_authentication_deadline(Duration)`, default
  recalibrated 10 s → 30 s (WP5's single timing profile: the default is
  the cluster-wide contract and must be safe on slow flash; fast
  deployments tighten it back — tuning direction is "faster"); the
  supervisor passes it into the runtime dependencies and
  `SessionDriver` reads it from there.
- The three call sites (`driver.rs:201`, `:403`, `:467`) converge to
  that single source for both the join and member paths.
- `guide` documents the knob under the mixed-cluster uniformity rule
  (WP5): keep it cluster-wide, do not tune per device.

**Acceptance**: the simulation matrix gains a "commit latency
injection" scenario (see WP6) where joins fail under a tightened
deadline and succeed under the recalibrated default; neither path
regresses.

### WP2 — Merge admission limiter redesign 【P0 · largest item】

**Today** (`src/identity/merge_rate.rs`, all hardcoded consts):
1. Fixed windows (16/source/60 s, 256/global/60 s) have window-edge
   behavior: refused attempts consume no budget, consumed budget never
   returns within the window — the head of a burst wins, the tail
   starves, and the starved party makes no progress for the whole
   window.
2. `MergeSource::normalize` aliases by IP (`:44`, the port is
   deliberately dropped): N devices behind one subnet/NAT share one
   16/60 s bucket. The per-source anti-abuse semantics scale into
   "the whole site's cluster starves itself" — the direct amplifier
   of incident B.
3. Recovery dials (member-mode, already-trusted identities
   reconnecting) share the budget with joins (strangers carrying
   credentials). The former is the self-healing path and must never be
   the one starved.

**Change**:
- Semantics: fixed windows → **token bucket / GCRA** (continuous,
  smooth, no window edges; a refused party advances at the refill
  rate).
- Split pools: joins (untrusted, carry credentials — stay strict) are
  metered separately from member reconnects (hold a trusted binding —
  the self-healing path, significantly more generous).
- Keep the by-IP source aliasing (per-source anti-abuse still holds),
  but parameterize the member pool's bucket budget by the actual
  member scale: a new admission block in `NodeConfig` with derived
  defaults (`member_rate ∝ max(16, 4 × expected_members)`).
- Every constant becomes configuration; `NodeConfig` defaults remain
  safe with no configuration.

**Acceptance**:
- Fault injection: N same-source nodes isolated simultaneously all
  reconnect within `O(N)` time (today: some never reconnect).
- Malformed-join flood simulation: a single source's join flood stays
  inside budget (the security semantics do not regress).
- All existing `merge_rate` unit tests migrate + new-semantics cases.

### WP3 — Recovery defaults + jitter 【P0 · small】

**Change**:
- `RecoveryConfig::default()` (`src/config.rs:350`): `fan_out 64 → 16`,
  `initial_backoff 1 s → 2 s`. Sixteen is proven sufficient by the
  chaos lane (the any-one-route contract needs exactly one route);
  sixty-four is proven harmful on 2 vCPUs (incident B).
- Backoff gains **±25% uniform jitter**: with identical backoff
  sequences, many devices recovering from one power/network event
  thundering-herd in lockstep and repeatedly slam WP2's global budget.
  The jitter seed comes from injected entropy, keeping tests
  reproducible.
- The chaos lane's `RECOVERY_FAN_OUT` override updates with the
  default (if the default is 16 the override is deleted, returning to
  the "defaults are safe" principle).

**Acceptance**: a multi-node simultaneous-isolation simulation shows
de-correlated reconnect times under jitter (no synchronized impact
spike); the 64-node chaos lane passes the 1-core gate (WP6).

### WP4 — Explicit per-hop relay budget 【P1 · medium】

**Today**: a forwarded stream's pending ack has no deadline of its
own — it is "transitively bounded by the liveness policies of the
sessions on both ends" (`src/session/liveness.rs:53`). A k-hop
attempt's latency is Σ(per-hop), and one hiccup at any hop fails the
whole attempt (the structural cause of incident C).

**Change**:
- `PendingAck::Relay` gains an explicit per-hop deadline (default 5 s,
  in `NodeConfig`); on expiry the hop fails locally and upstream
  receives `Failed` immediately — a bounded, fast failure instead of
  hanging to the transitive bound.
- Upstream handling of `Failed` is unchanged (ack propagation +
  `RouteState::Failed` observation); failure propagation becomes O(1)
  instead of O(remaining hops × bound).
- `guide` documents: long-path attempt latency is bounded by
  hops × per-hop budget; application retry remains part of the
  delivery contract.

**Acceptance**: relay attempt p99 is measurable and bounded by
hops × budget; a simulation injecting delay at hop ⌈k/2⌉ shows the
attempt failing within a deterministic bound and succeeding on retry.

### WP5 — One timing profile: recalibrated defaults, no device profiles 【P1 · medium】

**Adjustment (design review)**: a second, named low-power profile is
architecturally wrong for this stack. Every protocol-timing constant is
peer-visible — keepalive and idle deadlines, authentication deadlines,
anti-entropy cadence — so two coexisting profile classes produce mixed
clusters where the fast profile's observers close sessions the slow
profile still considers alive, and each side's recovery plane then
triggers the other's admission limits. Timing constants are a
cluster-wide contract, not a per-device choice.

**Change**:
- No `DeviceProfile`, no `NodeBuilder::low_power()`. `NodeConfig`
  stays the single knob surface, and the library ships exactly one
  profile — the defaults — recalibrated to be safe on the slowest
  supported device (principle 2): authentication deadline 30 s (WP1),
  anti-entropy 1 s (incident C), liveness idle 90 s / ping 20 s /
  timeout 60 s, recovery fan_out 16 / initial backoff 2 s (WP3), relay
  per-hop budget 5 s (WP4). Tuning direction is "faster"; nothing
  needs tuning to work.
- Device-*local* knobs stay generous by default (session queues,
  parser limits, trace metadata): they never cross the wire, so tuning
  them per device is safe; the guide documents that distinction
  instead of encoding it as a second profile.
- `guide` gains a "deploying on low-performance devices" chapter: the
  memory/neighbor budget formula (per-session queue × neighbors +
  trace metadata + storage), the cluster-uniformity rule for timing
  knobs, the per-device-safe resource knobs, and the application
  retry-queue pattern under the at-most-once contract (referencing the
  chat example).

**Acceptance**: a defaults test asserts every recalibrated value with
its incident rationale; the mixed-cluster simulation runs the same
defaults on fast and slow (injected-delay) nodes without divergence;
documentation walkthrough.

### WP6 — Starvation CI gate 【P0 · small, lands first】

**Change**:
- `quality_check.yml` gains a `starvation` job (ubuntu, pinned to one
  core via `taskset -c 0` or docker `--cpus=1`) running the full
  `transport_chaos` lane and the sixteen-node `membership_sync` lane.
  Budget 15 min (measured 3–5 min per lane on 2 vCPUs, scaled up).
- `simulation::network` fault matrix gains three injection dimensions:
  **slow CPU** (fixed inter-task delay injection), **slow storage**
  (commit delay injection — directly serves WP1 acceptance), and
  **slow clock** (ManualClock forward-jump/backward sequences),
  reusing the existing sealed-gate/replay machinery
  (`simulation_network_fault_matrix_gate`, already run in CI).

**Acceptance**: WP1–WP5 are all protected by this gate. Scenarios are
written red before their fix and green after — the gate lands first so
behavior changes cannot outrun the tests.

### WP7 — Anti-entropy load: recalibrated interval + documented formula 【P2 · documentation】

A fixed interval at N nodes costs O(N × interval) per-node load per
round (O(N²) aggregate). No adaptive machinery: stepped intervals
would reintroduce per-node divergence of a timing constant — the exact
mixed-cluster failure WP5 removes. WP5's single profile recalibrates
the default 250 ms → 1 s (incident C), and the `guide` documents the
N × interval load formula with sizing recommendations. Depends on the
WP6 gate to prove no regression.

## 4. Sequencing and dependencies

```
WP6 (gate first) ──► WP1 (deadline configurable) ──┐
                 └─► WP3 (defaults + jitter) ──────┼─► WP5 (recalibrated defaults close it out)
WP2 (limiter redesign, separate branch) ───────────┤
WP4 (per-hop budgets) ─────────────────────────────┘
WP7 (documentation) rides with WP5
```

- **WP6 lands first**: everything after it needs its regression
  protection.
- WP1 / WP3 are small and can proceed in parallel once the gate is in.
- **WP2 is the only large item**: separate branch, separate cycle;
  nothing else mixes with it.
- WP4 and WP5 close out after WP1/WP2 merge.

## 5. Explicitly out of scope

- No wire-protocol changes, no version/compatibility burden.
- No async-runtime replacement, no executor tuning.
- No dynamic QoS / congestion control — the data-plane
  at-most-once + application-retry contract is unchanged.
- No distributed coordination for rate limiting — admission stays a
  purely node-local semantic.

## 6. Risks and mitigations

| Risk | Mitigation |
|---|---|
| A looser member pool is read as weaker join anti-abuse | The join pool stays strict (strangers keep the tightest budget); the member pool only admits holders of a trusted binding — a flooder has none |
| Default changes break existing test expectations | Version unreleased, no installed base; the chaos/membership lanes update in the same commits and serve as the change evidence |
| The 1-core gate slows CI | Independent job, runs in parallel, 15 min budget (measured 3–5 min × 2 lanes); it does not duplicate other required lanes |
| Jitter makes tests flaky | The jitter seed comes from injected entropy; the simulation matrix pins seeds for reproducibility |

## 7. Definition of done

- The WP6 gate is green, and each historical incident (A/B/C) has a
  red-to-green case reproducing the old defect.
- WP1–WP5 merged; the single recalibrated profile (the defaults)
  satisfies the "safe on the slowest supported device" principle with
  no second profile in the codebase.
- The `guide` low-power chapter is live; per the lifecycle rules in
  `README.md`, this file is archived/deleted.
