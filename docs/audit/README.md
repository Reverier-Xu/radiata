# Audit Verification — Round 2 (branch `fix/audit-terminal-and-lifecycle`)

Each report verifies one finding from the previous audit round against the
current source, with file:line evidence, root cause, impact, a suggested fix
direction, and validation ideas.

| ID | Report | Verdict | Severity |
|----|--------|---------|----------|
| A01 | [a01-revocation-binding-merge.md](a01-revocation-binding-merge.md) | PARTIALLY CONFIRMED — permanent divergence for revocation records; transient for cleanup/leave; no enforcement gap | P1 |
| A03 | [a03-bridge-probing-topology.md](a03-bridge-probing-topology.md) | PARTIALLY CONFIRMED — the `target+1` bound exists; the low-frequency reconnect duty is already implemented; cluster-wide liveness gossip is not advisable | P2 |
| A04 | [a04-endpoint-rotation-coupling.md](a04-endpoint-rotation-coupling.md) | CONFIRMED — shared schedule serial pins each multi-homed member to one endpoint | P1 |
| A05 | [a05-revoke-expect-key-merge.md](a05-revoke-expect-key-merge.md) | CONFIRMED — coalesced revoke drops the second caller's expect-key precondition | P2 |
| A06 | [a06-reservation-commit-leak.md](a06-reservation-commit-leak.md) | CONFIRMED — `mem::forget` leaks one `Arc<QueueState>` per session queue | P1 |
| A07 | [a07-receipt-retention-early-return.md](a07-receipt-retention-early-return.md) | CONFIRMED — early `return` at the 4096 sweep bound skips the cleanup loop; deterministic livelock | P1 |
| A08 | [a08-lazy-publication-detached-spawn.md](a08-lazy-publication-detached-spawn.md) | CONFIRMED — detached lazy publication escapes the shutdown drain | P1 |
| A09 | [a09-opening-digest-ambiguous-encoding.md](a09-opening-digest-ambiguous-encoding.md) | PARTIALLY CONFIRMED — ambiguous preimage is real; consequence bounded to mis-acknowledged conflicting opens | P2 |
| A10 | [a10-wire-map-consumer-leak.md](a10-wire-map-consumer-leak.md) | REFUTED as a defect — the consumer future is always owned and drained; doc clarification only | — |
