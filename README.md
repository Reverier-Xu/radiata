# radiata

A Rust library crate providing authenticated peer-to-peer connectivity, opaque streams, and core
metadata for group applications: identity bindings, credential-authorized cluster composition,
membership and resource convergence, and a routed stream data plane — all over TLS 1.3.

Status: pre-release (`0.0.x`); the public surface is being finalized for `0.1.0` under the gate plan
in [docs/implementation-plan.md](docs/implementation-plan.md). Architecture authority lives in
[docs/adr/](docs/adr/) and [docs/roadmap.md](docs/roadmap.md); the frozen facade contract is
[docs/api-manifest.md](docs/api-manifest.md).

## Deployment trust model (ADR-0009)

radiata's architecture defends the **wire**, not the members. Transport-path security — TLS 1.3 with
exporter binding, handshake transcripts, merge credentials, and signature verification against
retained identity bindings — is unconditional. What the crate deliberately does **not** defend
against is a member that is hostile despite being properly admitted.

Under the peer-trust deployment model, the deployment owes three guarantees:

1. **Only trusted nodes are merged.** A malicious full member is indistinguishable from a
   man-in-the-middle on the path and is therefore out of architectural scope. Membership-related
   defenses against authorized-but-hostile members (Sybil growth, collusion, hostile metadata) are
   the deployment's responsibility, not crate behavior.
2. **Cleanup checkpoints are issued only against a fully converged cluster.** The checkpoint GC
   deletes collected removal tombstones; issuing an epoch against a non-converged cluster degrades
   to metadata hygiene issues for key-dead subjects, never to security failures.
3. **Cleaned subjects stay decommissioned.** A `cleanup_node` tombstone is terminal; there is no
   resurrection path. A mistakenly cleaned node recovers only by rotating its identity and
   re-merging as a new `NodeId`.

Threat authority: [docs/threat-model.md](docs/threat-model.md).
