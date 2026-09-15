# radiata

A Rust library crate providing authenticated peer-to-peer connectivity, opaque packet streams, and
convergent core metadata for group applications: identity bindings, credential-authorized cluster
composition, membership and resource convergence, and a routed data plane — all over TLS 1.3.

radiata is a deterministic relay-node runtime, not an application. It owns the wire: transport
security, session admission, anti-entropy, storage durability, and route authorization. Your
application owns the semantics that ride on top — the crate never interprets payload bytes.

> **Status:** pre-release (`0.0.x`), unpublished on crates.io. The public surface is being
> finalized for `0.1.0`; the authoritative API reference is the crate's rustdoc (`cargo doc`).

## Features

- **Authenticated membership** — merge into a cluster through any single live member with join
  credentials; identity bindings converge to every peer and anchor all further authentication.
- **Any-one-route connectivity** — a node is connected when at least one authenticated path
  exists. While fully isolated, the recovery plane dials the member table with bounded fan-out and
  backoff; while connected, it never expands the topology (and prunes redundant recovery edges).
- **Convergent metadata** — signed resources (last-writer-wins versioned registers with CAS
  conditional writes) and owner-marked member descriptors, both delivered by bounded-page
  anti-entropy with admission-ack delivery truth and per-key watermarks.
- **Routed data plane** — opaque packet streams to an exact node or a label-selector-matched set:
  direct delivery when connected, relay through a replaceable next-hop policy otherwise; constant
  memory, bounded queues, no persistence, no replay.
- **Crash-safe storage** — journaled conditional transactions over a pluggable provider SPI with a
  production [redb](https://github.com/cberner/redb) adapter, a test-only JSON adapter, and a
  backend-neutral contract suite both adapters must satisfy byte-for-byte.
- **Extension points** — `KeyProvider` (your keystore), `StorageFactory` (your backend),
  `PacketConsumer` (your wire protocol), `RouteNextHop` / `LoadBalancingPolicy` (your routing).

## Installation

radiata is not yet published to crates.io; depend on the repository directly:

```toml
[dependencies]
radiata = { git = "https://github.com/Reverier-Xu/radiata" }
tokio = { version = "1.53", features = ["rt-multi-thread", "macros"] }
```

The default feature set enables the production `redb` storage adapter. `json` (a test-only
immutable-generation adapter) and `audit` (structured semantic-path events used by the scenario
fuzz harness) are opt-in. Rust 1.98 or newer is required.

## Quick start

A node needs three things: a storage factory, a keystore-backed `KeyProvider`, and a configuration.
The crate deliberately ships no production key provider — identity is only as durable as your
keystore — so you implement `radiata::extension::KeyProvider` (see the [`radiata::guide`
chapter](#documentation) and `examples/chat/src/keys.rs` for a reference implementation).

```rust
use std::sync::Arc;

use radiata::{adapters::redb_store, Endpoint, Listen, NodeBuilder, NodeConfig, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let storage = redb_store("node-data/store.redb".into());
    let keys: Arc<dyn radiata::extension::KeyProvider> = my_keystore_provider();

    // Bootstrap a new cluster by listening; join an existing one by
    // additionally running `MergeCluster` through any live member.
    let node = NodeBuilder::new(storage, keys)
        .config(NodeConfig::new())
        .start()
        .await?;
    node
        .command(Listen::new(Endpoint::parse("wss://node1.example.net:9443")?))
        .await?;
    Ok(())
}
```

The deployment-facing surface is deliberately small: **join** (one credential-authorized merge),
**send** (packets over the routed data plane), and **leave** (terminal departure with identity
replacement). Routing, recovery, and convergence are the library's responsibility; your code
registers extensions before the node starts and drives commands and queries through the
`NodeHandle` afterward.

## Security and trust model

radiata defends the **wire**, not the members. Transport-path security is unconditional: TLS 1.3
with exporter binding, handshake transcripts, merge credentials, and signature verification against
retained identity bindings. What the crate deliberately does not defend against is a member that is
hostile despite being properly admitted. The peer-trust model asks the deployment for three
guarantees:

1. **Only trusted nodes are merged.** A malicious full member is indistinguishable from a
   man-in-the-middle on the path; Sybil growth, collusion, and hostile metadata are the
   deployment's responsibility.
2. **Cleanup checkpoints are issued only against a fully converged cluster.** Deviating degrades
   to metadata hygiene for key-dead subjects, never to security failures.
3. **Cleaned subjects stay decommissioned.** A `cleanup_node` tombstone is terminal; there is no
   resurrection path — a mistakenly cleaned node re-merges as a new `NodeId`.

## Documentation

- **Integration guide** — `radiata::guide` in the rustdoc: resource-version round trips across
  process boundaries, the any-one-route contract, and step-by-step wiring for the three extension
  points, each with compiling examples.
- **Architecture** — [docs/architecture.md](docs/architecture.md): the layered module map, key
  data flows, and the design constraints visible in the code.
- **API reference** — `cargo doc --open`.

## Examples

Two end-to-end examples live under [`examples/`](examples/), written from an external consumer's
perspective and exercised by container-level suites (podman; not part of the CI gates):

- **[chat](examples/chat/)** — a decentralized chat room: roster, groups, announcements, and DMs
  over one cluster, including offline queueing and a model-driven scenario fuzz harness.
- **[cluster](examples/cluster/)** — a governance-flavored grid: credential joins, two independent
  clusters healing into a federation, leave/revoke/cleanup, and crash scenarios.

```bash
cd examples/chat
./up.sh && python3 test_chat.py && ./down.sh
```

## Development

The workspace gates every change on zero warnings:

```bash
taplo fmt --check
cargo +nightly fmt --all -- --check   # rustfmt.toml uses unstable options
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Per-family verification lanes live in `scripts/verify-*.sh` (storage contract, membership,
handshake, fuzz corpora, and more). The `unsafe` keyword is forbidden crate-wide, and production
code denies `unwrap()`/`expect()`.

## License

Licensed under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
