# Recon: transport identity, builtin-tag duplication, registry locking

Branch `fix/connectivity-liveness-integrity`. Read-only. Line numbers verified against the working tree at recon time.

---

## Claim 3 — Temporary listener certificate pinning blocks legitimate channel changes

### Verdict: **partially-confirmed**

The SPKI cache is indeed keyed per node id only, so a rotated leaf or a second TLS/WSS listener of the same peer always fails the pin — but a documented merge-trust fallback (`src/runtime/supervisor.rs:962-1000`) prevents the "fails forever" outcome for the *rotation* case. The **dual-endpoint (tls:// + wss://) case is degraded, not blocked**: every alternating dial pays one failed TLS handshake + fallback retry, and the anchor flip-flops between the two listeners' leaves.

### Evidence: where the pin is keyed, written, and read

**Key: `NodeId → Vec<u8>` only** — `src/session/driver.rs:117`:
```rust
struct MemberSpkiTable(std::sync::Mutex<std::collections::BTreeMap<NodeId, Vec<u8>>>);
```

**Writes** (latest wins, overwriting across endpoints):
- `src/session/driver.rs:166-170` `record_peer_spki` inserts under `peer.clone()`.
- After a successful join: `src/runtime/task_effects.rs:315-318` records `hint.leaf_spki()` for the merged peer.
- After a member dial whose TLS pin mismatched and fell back: `src/runtime/supervisor.rs:1027-1034` — `if pinned.is_some() && let Some(spki) = observed_spki { driver.record_peer_spki(peer, spki) }`.

**Read (dial time)** — `src/runtime/supervisor.rs:967-974`:
```rust
let pinned = driver.peer_spki(peer);
let trust = TransportTrust::for_dial(&receiver.selector(),
    pinned.clone().map(SubjectPublicKeyInfoDer::from));
```
`TransportTrust::for_dial` (`src/transport/registry.rs:117-141`) maps any TLS-class selector (both `Tls` and `Wss`) to `Member { expected_spki }` when a pin exists — the endpoint/transport identity is *not* part of the key.

**Pin enforcement**: `src/transport/verify.rs:63-70` — `verify_server_cert` compares `parsed.subject_public_key_info() != *expected_spki` and rejects with `ApplicationVerificationFailure`. Reached via `src/transport/tls.rs:70-77,88-97` (`member_client_config`, `client_config_for_trust`); any TLS failure maps to `ErrorKind::AuthenticationFailed` in `tls_transport.rs:125-129` / `wss.rs` connect path.

**Leaf origin is per-listener ephemeral**: `src/transport/tls.rs:129-156` `listener_tls` generates a fresh `EphemeralCertificate` per `bind`; each listener stores its own `leaf: Option<Vec<u8>>` (`tls_transport.rs:142-153`, `wss.rs:111-121`) and stamps it into the join hint at accept (`tls_transport.rs:175-183`, `wss.rs:136-146`).

**The mitigation** — `src/runtime/supervisor.rs:979-999`: on `AuthenticationFailed` with `pinned.is_some()`, one retry with `TransportTrust::for_dial(..., None)` (merge trust). Identity is then proven by `driver.initiate_member(&mut connection, peer)` (`supervisor.rs:1001`) — the member handshake proves the durable Ed25519 identity over the RFC 9266 exporter channel binding (`exporter_channel_binding`, `connection.rs`).

### Root cause

The reconnect anchor conflates "peer identity" with "one listener's ephemeral TLS leaf": the table key is `NodeId` while the value is per-bind, per-transport ephemeral material. Two TLS-class endpoints of the same node have different leaves, so a single anchor cannot be correct for both.

### What identity verification already exists (redundancy question)

- The member-mode session handshake authenticates the peer's durable Ed25519 identity key via proofs over the exporter channel binding (`driver.initiate_member`, `supervisor.rs:1001`; verifier docs `verify.rs:20-30`). The SPKI pin is explicitly documented as "best-effort hardening, never the identity authority" (`registry.rs:126-131`, `verify.rs:24-31`). The pin is therefore redundant *for authentication*; it only adds same-listener MITM resistance between the TCP dial and the application proof.

### Minimal fix direction

Smallest correct change in existing patterns: key the table by `(NodeId, TransportScheme)` — or by the dial endpoint's transport class — instead of `NodeId` alone. `MemberSpkiTable` becomes `BTreeMap<(NodeId, TransportScheme), Vec<u8>>` (or two maps); `record_peer_spki`/`peer_spki` gain the scheme from the endpoint being dialed (`receiver.selector()`); `task_effects.rs` passes the scheme of the joined endpoint. No public API change; all call sites are crate-private.

### Coupling / risks

- `src/session/driver.rs:117,134,153,166-177` (table + accessors), `src/runtime/supervisor.rs:967-974,1027-1034`, `src/runtime/task_effects.rs:315-318`. That is the complete write/read set; nothing else touches `member_spkis`.
- The rollover fallback (`supervisor.rs:979-999`) must keep working when the peer rebinds on the *same* scheme — a `(Node, scheme)` key preserves that exactly.
- Shutdown/ownership impact: none; the table is process-local and never persisted.
- Alternative (smaller diff, weaker): keep per-node key but treat the fallback as the resolution — i.e., accept the extra failed handshake per alternating dial. Not recommended; it leaves permanent per-dial TLS failure noise and audit `dial_settled` churn.

### Test surface

- Existing: `tests/secure_join.rs:2197` `secure_join_certificate_rollover_reconnects_through_merge_fallback` covers rotation-on-restart only (single endpoint, new port).
- New regression test: in `tests/secure_join.rs`, join a peer via `wss://`, then `connect()` to the same peer's second listener (`tls://` endpoint, same durable identity/storage) and assert the member dial succeeds; add the alternating sequence (dial tls, then wss again, then tls) asserting each connect succeeds. A sharper version counts connect attempts via a `CountingTransport`-style wrapper (pattern in `registry.rs:987-1030`) to assert no TLS-failure/retry happens on the second dial to a previously-seen endpoint — proving the anchor is per (node, channel).

---

## Claim 13 — Duplicated builtin-tag parsing

### Verdict: **confirmed**

Four independent `OnceLock<Result<TransportTag, ()>>` caches parse the same three canonical literals through `TransportTag::parse`; two of them can in principle diverge if one literal is ever edited without the other.

### Duplicate sites and tag sets

| # | Site | Tags parsed | Mechanism |
|---|------|-------------|-----------|
| 1 | `src/transport/registry.rs:47-66` `builtin_transport_tag(scheme)` | all three: `.../transports/tls`, `/wss`, `/tcp` (from `BUILTIN_TRANSPORT_TLS` `tls_transport.rs:38`, `BUILTIN_TRANSPORT_WSS` `wss.rs:36`, `BUILTIN_TRANSPORT_TCP` `plain.rs`) | three `static OnceLock`s, match on `TransportScheme` |
| 2 | `src/transport/tls_transport.rs:57-71` `TlsTransport::tag()` | TLS only | own `OnceLock` |
| 3 | `src/transport/wss.rs:57-70` `WssTransport::tag()` | WSS only | own `OnceLock` |
| 4 | `src/transport/plain.rs:57` `PlainTransport::tag()` | TCP only | own `OnceLock` (same pattern) |

Consumers are split between the two families: `src/extension_registry.rs:181` and registry tests use `builtin_transport_tag`, while `src/node/builder.rs:71-81` and `src/runtime/supervisor.rs:1386-1396` call `TlsTransport::tag()`/`WssTransport::tag()`/`PlainTransport::tag()` — same tags via different caches. Grammar itself is single-source in `src/protocol/tag.rs:102-155` (`category_tag!` macro, `TransportTag` at line 154); the duplication is only the parse-and-cache of the literals, not the grammar.

### Root cause

Each transport module grew its own "parse once" accessor before the registry-level `builtin_transport_tag(scheme)` was introduced; both call sites were kept.

### Minimal fix direction

Delete the per-transport `tag()` accessors (and their `BUILTIN_TRANSPORT_*` visibility stays as-is) and route `builder.rs:71-81` and `supervisor.rs:1386-1396` through `builtin_transport_tag(TransportScheme::…)` — one cache, three literals. Keep the string constants as the single source; `builtin_transport_tag` already references them.

### Coupling / risks

- Files: `src/transport/tls_transport.rs`, `wss.rs`, `plain.rs` (remove `tag()`), `src/node/builder.rs:71-81`, `src/runtime/supervisor.rs:1386-1396` (call-site swap). Check for test references before deleting (`grep TlsTransport::tag`).
- No public API impact: everything is `pub(crate)`.
- Risk: near zero; parse semantics identical.

### Test surface

- Existing: `src/transport/registry.rs:502-514` `builtin_transport_tags_resolve_from_schemes` already asserts scheme→tag equality.
- New regression test: in the `registry.rs` test module, assert `TlsTransport`/`WssTransport`/`PlainTransport` resolve (post-fix: that the builder path uses the same tag), or simply that the duplicated accessors are gone — compile-time. A meaningful behavioral test: builder-seeded registry resolves identical `Arc<dyn Transport>` for `TransportSelector::Builtin(scheme)` and for `builtin_transport_tag(scheme)` lookups.

---

## Claim 14 — Frozen read-only registry takes a mutable lock on read

### Verdict: **partially-confirmed** (wrong file in the claim; real for the extension maps, not for transports)

`src/transport/registry.rs` contains no production lock at all (only test `tokio::sync::Mutex` for the test wire bus, line 837). The actual pattern lives in `src/extension_registry.rs`, and it applies to features/protocols/hooks/policies — **not** to transports.

### Evidence

`src/extension_registry.rs:61-84`: `transports` and `schemes` are plain `BTreeMap`s (read via `.get` with no lock — `transport()` lines 223-226, `resolve_transport` lines 174-192). But:

```rust
// src/extension_registry.rs:64-84
protocols: std::sync::Mutex<BTreeMap<ProtocolTag, Arc<ProtocolRegistration>>>,
...
load_balancers: std::sync::Mutex<BTreeMap<...>>,
next_hops: std::sync::Mutex<BTreeMap<...>>,
```

Read paths take the exclusive `std::sync::Mutex` guard just to clone values out, e.g. `protocol()` (lines 484-490), `has_protocol()` (lines 492-499), `feature_digest()` (lines 124-138), `load_balancer()`, `next_hop_policy()`. Hot-path callers: `src/session/inbound.rs:414` (`context.registry.protocol(&open.protocol)` — once per inbound stream open) and `src/packet/mod.rs:402` (`self.reply.registry.has_protocol(&protocol)` — per reply send).

### Root cause — why "frozen" state still needs a lock

The registry is shared behind `Arc<ExtensionRegistry>` from node start (`src/node/builder.rs`, `src/runtime/supervisor.rs:97`), but registration does **not** stop at freeze time: `register_core_protocol(&self, ...)` (lines 404-412, called at `src/protocol/feature.rs:563` after identity provisioning) mutates `protocols` through `&self`. Since `&self` cannot mutate a plain `BTreeMap`, every late-mutable map is wrapped in a `std::sync::Mutex`, whose guard is exclusive even for reads — serializing all readers on every read for the node's lifetime.

### Minimal fix direction

Two options, smallest first:

1. **Freeze like transports do** (matches the in-file pattern): move core-protocol registration into `NodeBuilder`/runtime startup *before* the registry is wrapped in `Arc`, make `register_protocol` take `&mut self` only, and drop the mutex from `protocols` (plain `BTreeMap`, `.get` reads like `transport()`). Requires confirming nothing registers core protocols after the node runs.
2. **Narrower, if late registration is required**: switch the affected maps to `std::sync::RwLock` and use `.read()` in the getters; registration keeps `.write()`. No ownership/public-API change (the maps are private; getters are `pub(crate)`), but it keeps the shared-mutable design.

### Coupling / risks

- `src/extension_registry.rs` (struct fields + all getters/setters + `Debug` impl lines 505-551), callers of `register_core_protocol` (`src/protocol/feature.rs:563` and the runtime startup path), `src/node/builder.rs`. Option 1 also touches whatever currently calls `register_core_protocol` post-start.
- Public API: `register_feature`/`register_protocol`/hooks already take `&mut self` (builder-phase only); `register_core_protocol` is `pub(crate)` — no public-surface change either way.
- Poisoning note: current getters silently degrade on poison (`unwrap_or_default()`, `record_peer_spki` `if let Ok` in `driver.rs:167`); a freeze removes that class entirely.

### Test surface

- Existing: `src/extension_registry.rs` tests (`tls_transport_extension_registry_registers_and_rejects_duplicates`, `hook_registrations_are_insertion_once`, etc.) cover registration semantics, not locking.
- New regression test: in the `extension_registry.rs` test module, a concurrency test — pre-register a protocol, then hammer `has_protocol`/`protocol` from many threads while a writer (option 2 only) registers distinct tags; assert no deadlock and reads stay correct. For option 1, the regression is structural: assert core protocols are present immediately after build and that `register_protocol` requires `&mut` (compile-checked).

---

## Adjacent bugs noticed (not fixed)

1. **Rollover fallback doubles the dial bound** — `src/runtime/supervisor.rs:976, 999`: both `connect_with_deadline` calls receive the full `dial_deadline` duration; a pinned dial that first times out can consume up to 2× the intended bound. Should pass the remaining time to the retry.
2. **Poisoned `MemberSpkiTable` lock silently drops anchors** — `src/session/driver.rs:167` `if let Ok(...)` discards the write on poison; a panic while holding the lock permanently disables pinning for that peer with no log line (contrasts with the crate's "must never degrade silently" comment style in `tls.rs:140`).
3. **`TrustMode::Member` carries `#[allow(dead_code)]` with a stale reason** — `src/transport/verify.rs:30-38`: the comment says "wired through member-mode dialing", which is true, yet the attribute remains; likely removable, otherwise misleading.
4. **Same-scheme second listener**: two `wss://` (or two `tls://`) listeners on one node also carry distinct leaves, so the per-node anchor claim-3 failure applies *within* one scheme too, not only across TLS vs WSS. The fix must key by endpoint or listener identity, not merely by scheme, to fully close it (or accept fallback churn).
