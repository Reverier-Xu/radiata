# radiata cluster example

A governance-flavored cluster built on the radiata library: nodes merge
through join credentials, page their member descriptors and trust
bindings to every peer, and expose the cluster's health over HTTP. The
example is written from an external consumer's perspective — it touches
only the public facade — and its container-level e2e suites
(`test_cluster.py`, `test_governance.py`, `test_lifecycle.py`) are the
delivery evidence the library relies on.

## What it demonstrates

- **Join**: one HTTP call merges through any live member
  (`IssueMergeCredential` at the operator side; credential-authorized
  admission at the receiving side).
- **Send**: routed packets over the data channel; direct delivery to a
  connected destination, relayed through a registered next-hop policy
  otherwise.
- **Leave**: `LeaveCluster` with identity replacement and core-metadata
  deletion; the leave record propagates as terminal evidence.

## How to integrate with the library

The task-oriented integration guide lives in the crate root docs:
`radiata::guide` (run `cargo doc --open` on the library crate). It
covers the resource-version round trip, the any-one-route connectivity
contract, and the `RouteNextHop` / `PacketConsumer` / `KeyProvider`
extension points — the same ones wired in `src/http.rs` and
`src/keys.rs` here.

## Run

```bash
./up.sh && python3 test_cluster.py       # baseline cluster scenarios
./up.sh && python3 test_governance.py    # credential governance matrix
./up.sh && python3 test_lifecycle.py     # leave / revoke / cleanup
./down.sh
```

## SLO evaluation

`test_slo.py` measures the library's service deadlines through this
example's public HTTP facade: five strata (admission, direct-packet,
routed-packet, node-metadata, resource-metadata) x five runs x five
samples, every sample bounded by the 10-second decision deadline, raw
wall-clock windows recorded with no post-start exclusions. With
`SLO=1 ./up.sh` the image builds with the library's `audit` feature and
each container is tailed into `.run/logs/n<i>.log`; the harness then
asserts the semantic path events (descriptor installed, resource pass
settled, journal resolved) appear in the node logs — state and path
evidence together. The report lands in `slo-report.json`.

```bash
SLO=1 ./up.sh && python3 test_slo.py && ./down.sh
```
