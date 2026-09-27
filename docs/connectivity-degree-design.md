# Connection degree: node count → target peer degree

Design input for work item 1 of [`backlog.md`](backlog.md). Status:
reviewed, decisions incorporated. The conclusion is executable: the
formula translates directly into a Rust `const fn`, and the target
degree accepts an operator override.

## TL;DR (directly usable)

**One Poisson formula for every size** (no small-cluster special case):

```
k(n) = smallest k with n·(1 − k/(n−1))^(n−1) ≤ −ln(0.9) ≈ 0.1054, clamped to [1, n−1]
```

Asymptotic equivalent for large `n`: `k ≈ ⌈ln n + 2.25⌉`, clamped to
`[1, n−1]`.

| n | 2 | 3 | 4 | 5 | 6 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 2048 | 4096 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| exact k | 1 | 2 | 3 | 2 | 3 | 4 | 5 | 7 | 8 | 8 | 10 | 9 | 11 | 10 | 12 |

The exact finite-`n` form naturally converges to small values at small
`n` — at `n = 2`, `k = 1` gives `λ = 0`, i.e. certain connectivity. That
is the mathematical statement of "small clusters do not need spare
links".

**Operator override.** Target degree = configured value when set,
otherwise the derived `k(n)`. In the personal edge-computing shape (a
single public IP relaying the cluster) the operator may set the target
to 1: the library cannot know the topology, the operator can.

## 1. Model

`n` nodes, each maintaining links to `k` peers chosen approximately
uniformly at random. Uniform independent selection approximates the
classical random graph `G(n, p)` with `p = k/(n−1)` and expected degree
`k`. The real system forms a k-out graph; §4 discusses the difference
honestly.

## 2. Isolated vertices dominate the failure mode

The probability that a vertex has no inbound edge:

```
q_iso = (1 − p)^(n−1) = (1 − k/(n−1))^(n−1) ≈ e^(−k)
```

Expected isolated vertices: `λ = n · q_iso`. Near the threshold,
disconnection is dominated by isolated vertices: our construction
without isolated vertices but disconnected (two components of size ≥ 2)
is an order of magnitude less likely (Erdős–Rényi 1959: the
connectivity threshold coincides with the no-isolated-vertex threshold).
Engineering approximation:

```
P(connected) ≈ exp(−λ)
```

## 3. The 90% threshold and the single formula

Requiring `P(connected) ≥ 0.9`, i.e. `λ ≤ −ln 0.9 ≈ 0.1054`:

- Asymptotic form: `λ ≈ n·e^(−k)` ⟹ `k ≥ ln n + 2.25`.
- Exact form: `n·(1 − k/(n−1))^(n−1) ≤ 0.1054`. For finite `n` the exact
  form is slightly smaller than the asymptotic one, so computing with it
  **does not over-provision** at small `n` (the asymptotic form gives 5
  at `n = 6` where the exact form gives 3).

Per review, the whole range uses the **exact form** (the smallest
satisfying `k`, solvable by the simple iteration a `const fn` can run),
with no full-mesh special case: fewer devices, easier maintenance, lower
single-point reliability requirements — the formula already says so.

99% tier (for cost comparison): `λ ≤ 0.0101`, asymptotic
`k ≥ ln n + 4.60` — a constant +2 over the 90% tier.

## 4. Honest model notes (k-out ≠ G(n,p))

The real system is a k-out graph (exactly `k` out-edges per node, then
undirected), not `G(n,p)`. Known result (Fenner & Frieze 1982 and
follow-ups): a random k-out graph is connected whp for `k ≥ 2`. That is
better than the logarithmic `G(n,p)` threshold; engineering does not
lower the formula accordingly because:

1. whp is a limit statement, and concentration is poor at small `n`;
2. real peer selection is non-uniform (topology bias, NAT/subnet
   clustering), breaking the independence assumption;
3. the single-public-IP relay topology is highly non-uniform — which is
   exactly why the operator override exists: the topology knowledge is
   with the operator, not in the library.

## 5. Deterministic reference (not the recommendation)

Minimum degree `δ ≥ ⌈n/2⌉` implies connectivity (suppose disconnected;
take the smallest component `C` with `|C| ≤ n/2`; a vertex in `C` has
degree at least `⌈n/2⌉` but at most `|C| − 1 ≤ n/2 − 1` neighbours inside
`C`, so a cross-component edge must exist — contradiction). Tightness:
two disjoint cliques `K_{n/2}` have minimum degree `n/2 − 1` and are
disconnected. This bound grows linearly, so it stays a theoretical
reference outside the recommended table.

## 6. Implementation notes

1. **Target degree**: `target = config_override.unwrap_or_else(||
   derived(n))`; `derived(n)` is the exact-formula `const fn`
   (iterating `k`), and `n` is the member-page row count — the derived
   value tracks cluster size while an override is fixed.
2. **Healthy predicate**: `active sessions ≥ target`.
3. **Maintenance cadence**: nothing while healthy; while below target, a
   **30 s tick** dials uniformly random members from the member page,
   excluding peers that are already connected or terminal.
4. **Degraded but usable**: below target with at least one session,
   everything keeps working (data and sync planes unrestricted) — the
   degree gates status and maintenance cadence only, never functionality.
5. **Fully offline**: zero sessions with cluster size > 1 uses the
   existing high-frequency recovery backoff.
6. **Status visibility**: the status query exposes `connection state:
   unhealthy` with the current session count and the target, so an
   operator can perceive and fix network problems.
7. **Override knob**: a connection-degree setter on `NodeConfig` whose
   semantics are "maintenance target", not a hard limit; unset or zero
   means the derived value.
