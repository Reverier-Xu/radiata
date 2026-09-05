---
id: ADR-0004
title: Fix the toolchain feature policy and evidence budgets
  - date: 2026-09-04
    summary: >-
      Remove the evidence-impact manifest and the dependency-graph digest baseline.
      The build provenance (git commit, lockfile digest, dirty flag) is removed from
      build.rs and failure artifacts; change identity is the git commit revision.
status: accepted
date: 2026-08-02
amended:
  - date: 2026-08-10
    summary: >-
      Promote rcgen 0.14.8 from dev-only to a production dependency for in-memory
      ephemeral self-signed listener certificates (defaults off, ring provider).
      The durable identity key remains separate; certificates are generated per
      listener, never persisted, and never derived from identity keys.
  - date: 2026-08-22
    summary: >-
      Approve tracing 0.1 as the production diagnostics facade and tracing-subscriber 0.3
      as a development-only subscriber for test diagnostics (T-G03-02 observability
      baseline). The facade is a zero-cost no-op without a subscriber, so host
      applications keep full subscriber choice; it is not feature-gated, keeps MSRV
      1.98.0, and its exact resolution is pinned by the dependency-graph baseline.
      From G3 onward every task instruments its owned paths through this facade with
      secret-safe events (roadmap architecture rule 9).
  - date: 2026-08-22
    summary: >-
      Raise the fixed MSRV from 1.97.1 to 1.98.0 (T-G03-03 toolchain alignment).
      The workspace builds, clippy -D warnings, and tests all pass on 1.98.0, and the
      stable CI job already runs the same compiler, so the floor and the forward
      detection lane coincide until the next stable release.
  - date: 2026-09-05
    summary: >-
      Admit futures-core 0.3 as a production dependency entering the public ABI and
      amend the manifest ABI rule (T-G11-03, stream abstraction audit R3): Tokio is the
      crate's sole supported async ecosystem, so futures-core and Tokio
      traits/interfaces (Stream, BoxStream, tokio-stream adapters, tokio::io traits
      where they fit) may appear in public signatures. Tokio channel and task handles
      (mpsc/broadcast senders and receivers, JoinHandle) stay excluded as runtime
      internals. Rationale: the hand-rolled PacketBody trait was isomorphic to the
      textbook Stream shape with real ergonomics cost, chunk boundaries carry no wire
      semantics, and the previous std-only ABI rule was the only blocker; futures-util
      was already a pinned production dependency, so futures-core adds no new supply
      chain.
  - date: 2026-09-05
    summary: >-
      Admit tokio-stream 0.1 (sync feature only) as an internal production dependency
      (T-G11-04, stream abstraction audit R4): the incoming-body receiver adopts the
      standard ReceiverStream adapter with an explicit end sentinel instead of a
      hand-rolled poll loop. tokio-stream types stay out of public signatures; only
      futures-core interfaces cross the ABI.
deciders: radiata maintainers
---

# Fix the Toolchain Feature Policy and Evidence Budgets

> **Amended by ADR-0007.** The toolchain, feature, replay, and evidence discipline remains active.
> Targets that exist only for superseded request/reply, HLC, or application-state APIs must be replaced
> by packet-routing and metadata-resource evidence before their owning gates activate.

## Context

`radiata` is a Rust 2024 library with security, crash-recovery, convergence, and cross-platform
claims. Those claims need one fixed compiler baseline, additive Cargo features, reviewed dependency
choices, bounded test cadences, owned regression corpora, secret-safe failure evidence, and a release
barrier that cannot confuse the placeholder package version with the functional `0.1.0` milestone.

The current development compiler is Rust 1.98.0. The package already says `0.1.0`, but no functional
release is eligible until G10 passes on the exact commit to be tagged and published.

Scenarios `SC-G00-P1-01` and `SC-G00-P1-02` are ratified by
`docs/scenario-catalog.toml`.

## Decision Drivers

- Give downstream users one explicit, reproducible Rust support floor.
- Prevent optional features from changing core security or wire semantics.
- Avoid duplicate TLS/crypto stacks, prerelease dependencies, and unreviewed feature leakage.
- Keep the backend-neutral core buildable without bundled storage adapters.
- Bound merge latency without reducing required evidence or hiding flakes through reruns.
- Make property, simulation, fuzz, crash, E2E, soak, and release evidence independently reproducible.
- Keep credentials, keys, opaque data, addresses, and hostile strings out of artifacts and commands.
- Assign one accountable owner to every fuzz target and retained corpus.
- Make tagging and publication impossible before final attestation for the exact immutable commit.

## Decision

### Fixed MSRV

The functional `0.1.0` MSRV is exactly Rust 1.98.0. `Cargo.toml` declares:

```toml
rust-version = "1.98.0"
```

Production code, build scripts, examples, tests required by an MSRV job, and all enabled dependencies
must compile with Rust 1.98.0. Stable CI also runs the current stable compiler to detect forward
regressions. Nightly is used only for repository rustfmt and fuzzing; it is never a production compile
requirement.

Dependency updates must pass the fixed-MSRV job before merge. After functional `0.1.0`, an MSRV
increase requires an ADR amendment, changelog entry, compatibility review, full feature matrix, and a
minor release at minimum. A patch release never raises MSRV. Rust 1.98.0 remains fixed until that
explicit change; this is not a rolling `stable-N` policy.

### Cargo Feature Policy

Initial package features are:

```toml
[features]
default = ["json"]
json = [
  "dep:atomic-write-file",
  "dep:fs4",
  "dep:rustix",
  "dep:serde",
  "dep:serde_json",
]
redb = ["dep:redb"]
```

The policy is:

- features are additive and may coexist;
- `--no-default-features` builds the backend-neutral core and extension contracts;
- default builds include the strictly test-only JSON adapter but do not select it at runtime without
  an explicit builder choice;
- `redb` adds the first production adapter and never leaks redb types into unconditional signatures;
- `json,redb` compiles and tests both adapters in one process;
- TLS 1.3, identity authentication, deterministic CBOR, signature verification, bounds, and redaction
  are unconditional and cannot be disabled by a feature;
- Cargo features never become feature-label negotiation authority; runtime registries produce the
  ADR-0002 offers;
- no mutually exclusive feature, negative feature, implicit default backend, or feature-controlled
  semantic weakening is permitted; and
- a new feature requires an impact review, powerset entry, documentation, and contract owner.

The required feature matrix is:

```text
default                    # json
--no-default-features      # backend-neutral core
--no-default-features --features redb
--all-features             # json + redb
cargo hack check --feature-powerset --depth 1 --locked
cargo hack test --feature-powerset --depth 1 --locked
```

Examples and doctests must state which feature they require. Tests do not infer a backend from feature
presence; they instantiate each backend explicitly.

### Approved Dependency Baseline

The initial baseline records reviewed crate families and minimum versions. Normal Cargo caret
requirements permit compatible releases; the committed `Cargo.lock` is the exact CI and release
resolution. Every update is a deliberate lockfile PR and repeats MSRV, feature, license, advisory,
duplicate-tree, and contract checks.

| Crate | Minimum | Feature/use policy |
| --- | ---: | --- |
| `tokio` | 1.53.1 | No `full`; only `rt-multi-thread`, `macros`, `net`, `sync`, `time`, `fs`, `io-util` |
| `rustls` | 0.23.37 | Defaults off; `std`, `ring`; TLS 1.2 and alternate providers disabled |
| `tokio-rustls` | 0.26.4 | Defaults off; `ring`; no TLS 1.2 or early data |
| `tokio-tungstenite` | 0.30.0 | Defaults off; connect/handshake only; TLS stream supplied by tokio-rustls |
| `futures-util` | 0.3.33 | Defaults off; `std`, `async-await`, `sink` only |
| `minicbor` | 2.3.0 | `std`, `derive`; explicit numeric IDs and ADR-0002 canonical validation |
| `ed25519-dalek` | 3.0.0 | Strict verification, `rand_core`, zeroization; no serde for private material |
| `hkdf` | 0.13.0 | HKDF-SHA-256 bootstrap derivation |
| `hmac` | 0.13.0 | Full HMAC-SHA-256 tags and constant-time verification |
| `sha2` | 0.11.0 | SHA-256 digests fixed by ADRs |
| `base64` | 0.23.0 | Defaults off, `std`; no SIMD-unsafe feature |
| `getrandom` | 0.4.3 | OS entropy implementation behind injected entropy trait |
| `secrecy` | 0.10.3 | Secret wrappers; serde feature disabled |
| `zeroize` | 1.9.0 | Secret-memory cleanup where ownership permits |
| `thiserror` | 2.0.19 | Contextual typed errors without secret fields |
| `atomic-write-file` | 0.3.0 | Safe same-directory file flush/rename; observable operation errors |
| `fs4` | 1.1.0 | Safe cross-platform lifetime file locking for `json` |
| `rustix` | 1.1.4 | Unix-only safe directory-fd `fsync`; `fs` feature |
| `rcgen` | 0.14.8 | Defaults off; ring provider; in-memory ephemeral self-signed listener certificates |
| `serde` | 1.0.229 | Optional `json` persisted format only, with derive |
| `serde_json` | 1.0.151 | Optional `json`; no unbounded-depth or preserve-order features |
| `redb` | 4.1.0 | Optional production adapter only |

Initial dev/build tools are:

| Crate/tool | Version | Policy |
| --- | ---: | --- |
| `proptest` | 1.11.0 | Retained failures, fork/timeout enabled |
| `tempfile` | 3.27.0 | Unique filesystem fixtures |
| `cargo-hack` | 0.6.45 | Pinned feature powerset CI |
| `cargo-fuzz` | 0.13.2 | Pinned nightly libFuzzer driver |
| `cargo-semver-checks` | 0.50.0 | Public API baseline at G10 |
| `cargo-deny` | 0.20.2 | Advisories, licenses, sources, and duplicate policy |

`atomic-write-file` plus target-specific `rustix` avoids local unsafe code. On Unix, JSON duplicates
the safe directory fd before unique-name commit and calls `rustix::fs::fsync` after rename; failure is
observable. On Windows, atomic-write-file 0.3 uses ordinary rename and does not expose a durable
write-through directory barrier, so JSON reports only ADR-0003 `ProcessCrashAtomic` and remains
strictly test-only. Production consumers require `OsCrashDurable` and reject it; redb closes that path.
Native fault tests, not dependency claims, remain the capability oracle.

The crate does not use `prefix_id`: its parser does not provide the full canonical validation required
by ADR-0001. It does not use a generic HLC crate unless a later impact review proves exact ADR-0003
transition, persistence, health, and quarantine semantics. Git dependencies, wildcard requirements,
prerelease crates, duplicate TLS providers, native-tls, OpenSSL, and an additional crypto provider are
forbidden without a new ADR.

The approved graph intentionally uses ring only as rustls/tokio-rustls's TLS 1.3 provider, while
ed25519-dalek and RustCrypto HKDF/HMAC/SHA-2 implement ADR-0001/0002 application authentication and
record signatures. This protocol-role overlap is reviewed and allowed. Duplicate crate families or
providers within one role remain blockers; application code must not call ring's Ed25519/HKDF/HMAC,
and rustls must not use the application crypto crates as a second TLS provider.

`cargo tree -d` is reviewed on dependency changes. Duplicate versions require an owner and written
reason; duplicate rustls or TLS providers, duplicate application identity implementations, or duplicate
CBOR implementations within the same protocol role are release blockers.

### Functional `0.1.0` Boundary

`Cargo.toml` keeps `publish = false` on development commits until T-G10-11 creates the explicit
publication-ready candidate. The existing `version = "0.1.0"` is development metadata, not release
eligibility. No crate publication, release tag, release archive, or
functional-release announcement may occur before final attestation.

Functional `0.1.0` requires, on one exact immutable commit:

- G0 through G10 closure and `Q`;
- all public API, error, wire schema/kind/tag, feature-definition, persisted-schema, and migration
  manifests frozen;
- MSRV, stable, native OS, and Cargo feature matrices passing;
- previous-reader/golden vectors and mixed-binary feature-intersection evidence;
- all required property, simulation, crash, fuzz, and soak budgets completed without reruns;
- threat matrix with no unresolved P0/P1 finding;
- published controlled SLO evidence; and
- `cargo-semver-checks` baseline plus final API review.

T-G10-11 creates one immutable release-candidate commit containing the intended package version,
publication transition, final workflow, and then runs the complete release/SLO evidence on that exact
SHA. T-G10-12 obtains the complete provider ledger, validates it, and issues a signed
release-eligibility token outside Git. The token contains the candidate commit digest, Cargo.lock
digest, attestation-manifest digest, package version, and `eligible = true`.

The release workflow may tag and publish only when that external token verifies and the checked-out
candidate SHA matches exactly. The token is never committed into the SHA it attests. Any candidate
change invalidates it and returns `publish = false` on the development branch until a new candidate and
full final validation exist.

After functional `0.1.0`, patch releases preserve public API and every published schema/tag behavior.
Additive API and feature work uses a minor release. A breaking public API change requires at least a
minor-version boundary, explicit ADR, migration/deprecation plan, and compatibility evidence; wire and
persisted readers remain governed by their immutable IDs rather than crate version arithmetic.

### Evidence Impact Manifest

> Superseded 2026-09-04: the evidence-impact manifest and the dependency-graph
> digest baseline were removed. Change identity is the git commit revision;
> verification is the repository quality suite (format, check, clippy, tests,
> cargo deny) plus the functional unit, integration, simulation, and E2E tests.
`docs/evidence-impact.toml` is the machine-readable ownership map. It maps every evidence-affecting
repository path, including production/source files, Cargo manifests/lockfiles, build configuration,
tests, fuzz adapters/corpora, fixtures, scripts, workflows, and evidence schemas, to property suites,
simulation matrices, fuzz targets, crash points, E2E tests, platform jobs, and owners. An unmapped
relevant path fails planning validation.

"Affected" means the transitive target set from this manifest, not agent judgment. "Changed fuzz
target" means a target activated by the manifest, including changes in shared dependencies. T-G00-06
creates and validates the initial map; every owning task updates it with its new files before RED.

The merge critical path remains at most ten minutes through a declared shard DAG. Every activated
target appears exactly once; shard dependencies, setup/cache allowance, target p95, and the longest p95
path are machine validated. If required evidence exceeds ten minutes, the change must split, optimize,
or add parallel capacity. Counts, durations, scenarios, and failures are never reduced, deferred,
sampled away, or rerun to make the merge green.

### Evidence Budgets

Counts are per property and seeds are per complete scenario matrix.

| Cadence | Required evidence |
| --- | --- |
| Every merge | `Q`; affected units/contracts/E2E/crash points; P0 properties 10,000 cases, P1 1,000; 100 simulation seeds; all retained corpus inputs; 30 s live fuzz per affected target in parallel |
| Gate closure | Merge evidence; P0/P1 properties 10,000 cases; 1,000 simulation seeds; every gate crash/security/E2E scenario; 5 min live fuzz for every manifest-activated canonical target |
| Nightly | P0/P1 properties 100,000 cases; 10,000 simulation seeds; every fuzz target 5 min; native OS/feature matrix; performance/resource trend checks |
| Weekly | Eight-hour churn/partition/slow-peer/clock/resource soak; return to baseline after quiescence |
| Release | P0/P1 properties 1,000,000 cases; 100,000 simulation seeds; every fuzz target 60 min; twenty-four-hour uninterrupted soak; full mixed-binary/backend, storage, threat, and SLO matrices |

Live fuzz duration is wall-clock evidence and is not byte-deterministic across hosts. Regression-input
replay, property cases, and virtual-time simulation provide deterministic merge evidence. A failing,
timed-out, crashed, OOM, leak, sanitizer, or invariant result fails immediately. CI retries are disabled;
a known infrastructure outage is re-run only as a new recorded workflow attempt and never reclassifies
a product failure as success.

Fuzz defaults include one process per target, a ten-second per-input timeout, a 4 GiB RSS limit, and the
platform's supported AddressSanitizer/libFuzzer configuration. Release evidence records the exact
sanitizer and flags. Input adapters apply ADR hard bounds before allocation.

### Fuzz Targets and Owners

Canonical targets are:

| Target | Implementation/corpus owner | Scope |
| --- | --- | --- |
| `wire_decode` | T-G10-03 / protocol | Prelude, deterministic CBOR, kinds, tags, limits |
| `persisted_decode` | T-G10-03 / storage | JSON generations, records, schema/migration manifests |
| `selector` | T-G10-03 / resource | Label and selector parser/evaluator |
| `admission` | T-G10-04 / identity | Join/member authentication state machine |
| `feature_selection` | T-G10-04 / protocol | Definition digests, dependencies, conflicts, limits, no fallback |
| `routing` | T-G10-04 / routing | Request/attempt/receipt journals, ordinals, hops, state transitions |

Each owner implements the target, curates and reviews its corpus, maintains regressions, fixes findings,
and supplies release evidence. CI cadence is owned by T-G10-07 and release evidence validation by
T-G10-09. Shared artifact support is owned by T-G01-04 and must serve property, simulation, fuzz,
crash, E2E, and soak producers through one schema.

### Corpus Policy

Retained corpora live at `fuzz/corpus/<target>/`. Each target has at most 4,096 entries and 64 MiB of
retained input.

A candidate is handled in this order:

1. classify its origin with a closed allowlist such as synthetic generator, golden fixture, or local
   minimized failure; arbitrary production capture is forbidden;
2. run the pinned privacy-screen tool and manual owner review before minimization, digesting, naming,
   copying to a retained path, or uploading;
3. delete rejected bytes without computing or retaining a content hash;
4. replace any sensitive structure with synthetic structure-preserving input;
5. minimize approved bytes, then repeat screening and review; and
6. only then compute lowercase SHA-256, name `<digest>.bin`, and deduplicate.

`fuzz/corpus/<target>/manifest.toml` records per entry: target, relevant schema/kind/tag IDs,
`byte_count`, allowlisted origin class and lineage, minimizer/tool version, owner/reviewer, privacy-screen
tool/version/result, review status, and approved content digest. It also records aggregate entry count
and bytes, and contains no input bytes or hostile free text.

Every merge enumerates approved retained files in filename order and replays each exactly once outside
libFuzzer scheduling. Corpus additions are committed in one logical change with the fix only after the
ordered promotion pipeline succeeds. Golden vectors seed corpora but remain separately owned fixtures.

Live-fuzz working corpora and crash artifacts are temporary and never become merge evidence
automatically. Inputs containing credentials, private keys, key-provider handles, exporter/proof
material, TLS tickets, unredacted transcripts, addresses, paths, user payloads, or other secret/PII are
deleted before hashing and replaced with synthetic data. Arbitrary input is never hashed into an
artifact as a substitute for redaction.

### Failure Artifact Schema

Failure artifacts use deterministic bounded JSON tagged
`radiata.woooo.tech/schemas/failure-replay`. The producer-neutral serializer and closed replay model live
in the workspace's `radiata-test-support` library. That package is `publish = false`, is consumed
only through development/test dependencies, and does not enter the `radiata` facade or production
dependency graph. Property, simulation, fuzz, crash, E2E, and soak producers use the same recorder;
producer-owned private adapters convert source events into its sealed evidence model.

The serializer accepts only an allowlisted evidence model; production record types and secret-bearing
types cannot be generically serialized into it.

Allowed fields include:

- scenario/test ID, seed, event digest, failure class, and invariant ID;
- commit and lockfile digest, package/compiler/tool versions, target OS/architecture, and Cargo features;
- selected feature labels and definition digests;
- scenario-local node, endpoint, path, and fault aliases such as `node-1`, `endpoint-2`, and `store-1`;
- virtual timestamps, normalized event kinds, configured bounds, fault point, and state-machine names;
- payload lengths and schema tags, never payload bytes or stable payload hashes;
- deterministic truncation flags plus first/last bounded event windows; and
- one structured replay specification.

Credential text, private material, provider handles, proof/HMAC/exporter bytes, TLS tickets, raw
transcripts, opaque values, resource labels/values, selectors, real addresses/ports, host paths,
environment values, and arbitrary error input are forbidden. They never reach the serializer and are
not replaced by stable hashes. Secret wrappers do not implement evidence serialization or `Display`;
`Debug` emits only a constant redaction marker. Redaction happens when events are created, not during
final file rendering.

Artifacts are at most 1 MiB and contain at most 10,000 normalized events before deterministic
first/last-window truncation. The full canonical normalized event stream produces the event digest;
secret-bearing events are rejected before digesting. Simulation/property artifacts are byte-stable for
one seed and manifest. Real socket/filesystem/fuzz/soak artifacts normalize ephemeral values and promise
reproducible assertions, not identical ports, paths, scheduling, coverage, or durations across hosts.

Replay is structured data:

```text
ReplaySpec { executable_id, argv: [validated literal argument, ...] }
```

`executable_id` is a closed enum such as `cargo-test`, `simulation`, or `fuzz-corpus`; it is not a path.
Arguments have fixed count, length, character, and value rules per executable. Replay never invokes a
shell, concatenates a command string, derives a path from hostile data, or honors environment variables
from the artifact. Test-support APIs are internal package APIs rather than `radiata` public API;
changes to their sealed evidence or replay models still require T-G01-04 ownership and regression review.

Local failure artifacts go under ignored `target/radiata-failures/`. CI uploads the same secret-safe
artifact for seven days. Only minimized, reviewed regression fixtures enter the repository.

### Release Attestation Schema

Every test, fuzz, soak, and SLO attempt, successful or failed, emits canonical JSON tagged
`radiata.woooo.tech/schemas/test-attestation`. It uses the same allowlisted serializer and closed
`ReplaySpec` as failure artifacts. Each attempt records:

- exact commit and Cargo.lock digests;
- CI provider run ID, attempt number, job/shard ID, predecessor attempt digest, and a closed retry
  reason/classification;
- Rust, Cargo, cargo-fuzz/libFuzzer, sanitizer, and relevant tool versions;
- target name, closed `ReplaySpec`, enabled Cargo features, platform/architecture, and CPU class;
- start/end monotonic duration, configured limits/budgets, and uninterrupted-run status;
- exit status and normalized failure count;
- approved corpus manifest and before/after digests without input bytes;
- failure-artifact digest when present; and
- task/thread/queue/storage resource baselines before, peak, quiescent, and after.

Environment values, real paths/addresses, arbitrary argv, hostile free text, and every forbidden
failure-artifact field are also forbidden here.

T-G10-09 implements and preflights the validator against complete synthetic ledgers. T-G10-12 obtains
the real provider attempt ledger and verifies every manifest, predecessor link, retry classification,
cadence, and threat requirement. A failed product attempt can never be superseded by a later successful
attempt; only an independently classified provider outage permits a new lineage, and both attempts
remain evidence. T-G10-12 hashes the complete validated ledger into the external release token. Missing, interrupted, mismatched-commit, rerun-masked, under-budget, or
secret-bearing evidence fails release eligibility.

## Required Verification

T-G00-04 is documentation and metadata policy. Later tasks own executable evidence:

- G1: set `rust-version`, add first-use dependencies only, verify no-default/default/all-feature builds,
  ensure secret types cannot serialize to evidence, and implement canonical bounded artifact/replay tests.
- G1/G2/G8: MSRV/stable CI, Cargo.lock enforcement, dependency duplicate/license/advisory/source
  checks, powerset checks from the first storage feature, and JSON/redb coexistence.
- G1: artifact tests inject every forbidden field class, hostile argv/path/tag strings, event overflow,
  truncation, real endpoint/path normalization, and deterministic simulation replay.
- G10: all six fuzz targets, target/schema corpus manifests, count/byte/provenance/minimization checks,
  deterministic corpus replay, dependency-map activation, and live-fuzz cadence evidence.
- G10: merge-shard p95 remains within ten minutes without reducing required work; every failure blocks
  without automatic retry.
- G10: weekly/release soak and fuzz attestations bind exact commit, lockfile, tools, flags, platform,
  duration, corpus, result, and resource baselines.
- G10: release workflow cannot tag or publish without an external T-G10-12 token for the exact
  release-candidate commit and complete attempt ledger; development branches retain `publish = false`.

## Rejected Alternatives

### Rust 1.85.0 or Rolling MSRV

Rejected by explicit maintainer decision. Rust 1.98.0 is the fixed functional-release floor. Rolling
stable policies make downstream requirements change without an intentional compatibility decision.

### TLS or Security Cargo Features

Rejected because disabling authentication, bounds, canonical decoding, or redaction would make feature
combinations semantically unsafe and impossible to attest.

### Native TLS or Multiple Crypto Providers

Rejected to keep one auditable TLS 1.3/ring path and avoid platform-dependent negotiation behavior.

### `fs4` Alone or Unobservable Durability Claims

Rejected because locking does not supply ADR-0003's barrier and a wrapper may not suppress sync
failure. The approved Unix composition propagates directory fsync. Windows JSON explicitly reports the
weaker process-crash capability instead of claiming unavailable OS-crash durability.

### Stable Hashes of Sensitive Values

Rejected because low-entropy payloads and addresses are enumerable and hashes create cross-run tracking
identifiers. Sensitive data never enters the evidence model.

### Shell Replay Commands

Rejected because hostile scenario/tag/path values can become command injection. Replay uses a closed
executable enum and validated literal argument array.

### Automatic Corpus Promotion or CI Reruns

Rejected because unreviewed corpora can retain secrets and reruns hide nondeterminism. Promotion and
infrastructure retries are explicit new evidence events.

### Package Version as Release Eligibility

Rejected because the placeholder already says `0.1.0`. Only the exact-commit eligibility token unlocks
publication and tagging.

## Consequences

- The project intentionally requires a very recent fixed Rust compiler.
- Default builds include JSON code, but production use still requires explicit backend selection.
- The dependency graph is larger because JSON durability uses reviewed safe locking and filesystem
  abstractions instead of local unsafe platform calls.
- Merge evidence is substantial and depends on parallel CI capacity to stay within ten minutes.
- Failure artifacts sacrifice raw diagnostic values in favor of confidentiality and safe replay.
- Fuzz wall-clock coverage varies by host; retained-input replay remains deterministic.
- Functional release requires an exact immutable evidence set and cannot be inferred from Cargo version.

## Residual Risks

- Dependencies can contain unsafe code or platform defects outside this crate's local `unsafe` ban.
- Filesystems and hardware may violate documented durability despite a reported capability.
- A seven-day CI artifact can expose allowed metadata such as commit, platform, scenario, and feature set.
- Sanitizer and fuzz coverage differ across CPUs and toolchain implementations.
- Fixed Rust 1.98.0 may reduce downstream adoption and require older compatible dependency pins later.
- Manual corpus and dependency review can miss novel secret formats or supply-chain compromise.
- CI parallelism and hosted-runner variance can threaten the ten-minute merge target without changing
  correctness budgets.

## References

- Cargo Reference: `rust-version`, features, package publication, and lockfiles.
- Rust 1.98.0 release toolchain.
- cargo-hack, cargo-fuzz, cargo-semver-checks, and cargo-deny documentation.
- ADR-0001, Bind Node Identity and Admission to a TLS 1.3 Channel.
- ADR-0002, Negotiate Feature Labels and Provide Bounded Durable Delivery.
- ADR-0003, Reconcile Durable Transactions and Order Replicated State with HLC.
