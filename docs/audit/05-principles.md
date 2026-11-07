# Design Principles

These are the criteria every finding in this audit is judged against. They were established by the project owner during the audit and supersede any reviewer opinion that contradicts them.

## P1 — Threat model

After merge admission, every node runs unmodified `radiata`. **Do not design against a malicious admitted member.**

Consequences:
- "Evidence for evidence" recursion is rejected. A design that demands proof that a peer's proof is trustworthy has no bottom.
- `source` forgery, checkpoint validation on the receive side, duplicate-`Open` handling, and route-policy-before-validation are **not** security findings.
- The one invariant that *is* real: no peer can hand a frame to this node while claiming to be someone else. That is the authenticated-predecessor check.

## P2 — Library scope

`radiata` does not own business-level concerns:

- **Retry.** Business retry belongs to the user's logic. The library backs off and retries *cluster communication*; it must not stall user logic, and it must not decide that a user's operation should be retried.
- **Encryption at rest.** The user's responsibility. The library does not encrypt stored metadata.
- **Negotiation.** The user's responsibility.
- **Network availability.** The user's responsibility. The library only guarantees: a local write never blocks, and on reconnect every committed piece of metadata is reachable and recoverable.

The stated guarantee is **eventual consistency in the normal cluster state** — not availability under partition, not durability under arbitrary failure.

## P3 — Disk data belongs to the user

Anything on disk must be the upper layer's decision: whether to clean it up, and when. **A base library must not impose its own retention limits on persisted data.**

`radiata` already provides a `cleanup` facility (an operator-issued checkpoint GC). Retention should go through that, not through autonomous library-side eviction.

Corollary: a caller-configurable window is acceptable only when the window is a *cluster convergence contract* rather than a storage knob — and then it must be documented as such, not presented as GC.

## P4 — Extensibility must not be a closed enum

Interfaces that need to be extensible use **domain-qualified tags** (like resource tags), never closed enums.

- The built-in domain (`radiata.woooo.tech`) is reserved and hard-refused for user registrations.
- There is **no privileged "builtin"**: official and user-defined definitions must have **no functional difference**.
- Official definitions are installed through an explicit `register_default()`. A registry is born empty.

## P5 — No cross-file coupling when adding an item

Adding one item to a registry must not require editing code that does not belong to that item.

A central match table or an `ALL` constant that forces edits across several files is a design defect **even when the set is legitimately closed and no user extension is promised**. Centralising the table (shrinking five sites to two) reduces the cost but does not remove the defect: the remaining sites are still in other modules' files.

The only acceptable central registration is a single **registry entry point** that lists objects — not a per-variant match, not a per-variant wire code, not a per-variant policy arm.

## P6 — Comments describe current behavior

Comments and rustdoc describe **what the code does today**. No audit IDs, no dates, no incident names, no development history ("phase 1", "migrated", "replaced the old X", "used to").

`docs/` is scratch. Real documentation comes from `cargo doc`.

## P7 — Verification facilities must earn their keep

A frozen golden vector is worth its bytes only when it pins something git cannot give you: **an old wire shape that must still decode**. Everything else is a gentleman's agreement — whoever can change the encoder can change the vector in the same commit, and git already provides history and hashing.

Source-grep "invariant tests" are the same category, with two exceptions worth keeping:
- a test that detects **duplicated data** (a literal that should have referenced a single source of truth) — this catches real regressions;
- a test that asserts a **behavioral refusal** (unknown version fails closed), which does not depend on frozen bytes.

## P8 — Honest error classification

Errors must describe what actually happened. A transient network error reported as `AuthenticationFailed` misleads the caller's retry logic, even though the library itself does not retry.

## P9 — No panics in library code

`unwrap`, `expect`, `print`, `dbg`, and `unsafe` are forbidden in production code. Diagnostics go through `tracing`. Startup code reports the error and exits non-zero; user code that panics is not caught.

## P10 — No shared helpers across unrelated domains

Do not extract a helper that spans unrelated business domains with no protocol coupling; that creates avalanche coupling. Simple duplication of pure computation is acceptable when the domains are genuinely independent.

## P11 — Scope of the product

`radiata` is a decentralized, Kubernetes-like **cluster base** for sparse clusters of unreliable personal edge devices:

- join a handful of nodes into a sparse cluster;
- keep metadata eventually consistent; manage resource-object metadata like k8s;
- fault recovery as reliable as reasonable;
- **headline feature**: user-facing data-transport routing — built-in TLS / WSS / raw TCP, plus caller-registered channels; the user names a destination in very little code;
- beyond transport and sync, users attach their own logic to metadata state-change events.

Target scenario: one person's phone + laptop + server. The phone changes network constantly; the laptop goes offline and keeps producing local work; a local write must never block.
