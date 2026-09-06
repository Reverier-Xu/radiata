---
id: ADR-0005
title: Measure the sixteen-node connectivity and metadata profile
status: accepted
date: 2026-08-02
amended: 2026-08-04
amended-notes:
  - date: 2026-09-05
    summary: >-
      The admission stratum becomes the merge stratum (T-G11-13, ADR-0009
      rebaseline): the five fixed-admission samples execute credential-
      authorized cluster merges with unchanged credential evidence rules;
      the method, pass rule, lineage, and sample totals are unchanged.
deciders: radiata maintainers
---

# Measure the Sixteen-Node Connectivity and Metadata Profile

## Context

A functional `0.1.0` release needs one reproducible latency profile for the responsibilities retained by
ADR-0007. The profile is release evidence, not a universal deployment promise, product population limit,
or substitute for correctness and scale tests.

The superseded profile measured application state, HLC readiness, and tombstones. Those operations are no
longer part of `radiata`. This ADR replaces that workload completely while retaining the controlled
OCI method, exact per-sample pass rule, five-run lineage, and 125-sample total.

## Decision Drivers

- Measure only public connectivity, packet, node-metadata, and resource-metadata operations.
- Include fixed admission, direct delivery, routed delivery, owner revisions, and multiwriter resources.
- Make every sample and exclusion decision reviewable against one immutable candidate.
- Avoid averages or percentiles that can hide one failed operation.
- Keep the workload finite and reproducible without turning its topology or capacity into runtime policy.

## Scope of the Claim

The quantified claim applies only to the exact 16-node final population and unimpaired single-host OCI
bridge profile defined here. Every measured sample must complete in at most 10,000 milliseconds.

The claim excludes impaired links, overload, provider resource exhaustion, wall-clock discontinuity,
concurrent writes to one metadata key, host-to-host networking, and populations other than the exact
profile. These exclusions select a workload; they never authorize deleting a failed in-profile sample.

The separate 1,024-node suite is mandatory functional and trend evidence. It defines neither a hard node
ceiling nor a latency promise. Larger finite deployments remain valid subject to caller/provider
resources.

## Candidate and Attempts

The controller first creates one immutable candidate commit. Every preflight, run, artifact, container,
backend, and result binds that exact commit and lockfile digest.

The release attempt consists of five fresh independent runs. Each run creates fresh identities, keys,
metadata stores, credentials, ports, network namespace, and wall-clock observations. A run contains
exactly 25 measured samples, producing exactly 125 samples across the attempt. A failed, timed-out,
missing, retried, or excluded sample fails the attempt.

## Host and Container Profile

The reference profile uses:

- Linux x86_64 with kernel 6.6 or newer;
- at least 12 logical CPUs and 16 GiB RAM;
- an OCI runtime with cgroup v2 and an isolated bridge;
- 16 node containers plus one controller;
- Rust, crate features, JSON/redb selection, and image digests frozen by the candidate ledger;
- no external network dependency after required images and toolchains are present.

Each node receives 0.5 CPU, 512 MiB memory, 128 PIDs, and 4,096 file descriptors. The controller receives
2 CPUs, 1 GiB memory, and 256 PIDs. These are harness settings, not crate-enforced limits.

A 60-second preflight requires no swap activity, no kernel or storage errors, at least 12 GiB available
memory, and no sustained external CPU or disk pressure above ten percent. The controller records raw
preflight observations. A failed preflight aborts before measurement and cannot be reclassified after a
sample starts.

## Network and Clock Profile

All nodes use one isolated OCI bridge with MTU 1,500 and no injected loss, delay, duplicate, reorder, or
bandwidth shaping. Preflight proves every directed path needed by the configured topology and records
latency and throughput without using those observations to discard later samples.

The host system wall clock is the protocol time authority. Preflight records synchronization status and
the wall-clock value before each run. Any observed rollback, freeze, or forward discontinuity during a
run fails this unimpaired profile; discontinuity behavior is covered separately by deterministic tests.
The harness does not substitute HLC, peer clock voting, or application timestamps.

## Population and Topology

Each run starts with one cluster creator and ten already admitted trusted nodes. The measured admission
stratum adds five fresh nodes, producing the final 16-node population. The final authenticated graph uses
a deterministic sparse connected topology with at least one exact three-hop path. The graph need not be
a full mesh.

Readiness requires public paged observations to prove:

- every admitted `NodeId` has the expected public key and trust state;
- every online member has at least one authenticated path to every other member;
- owner-revision node metadata is identical at every member;
- the resource catalog has converged to the expected signed tuple winners;
- no route, stream, queue, task, or provider operation from setup remains active.

Readiness polling is controller-owned and bounded. It uses only public facade pages, events, and status;
it cannot inspect private stores or tasks.

## Exact Workload

Each of the five runs records these 25 sequential samples in this order:

1. **Five fixed-admission samples.** For each fresh node, rotate one single-use credential, complete the
   authenticated join, durably converge the exact `NodeId` to public-key binding to all currently online
   members, and observe the new member through public pages.
2. **Five direct-packet samples.** Send one 4,096-byte finite stream to an exact `NodeId` and wait for the
   current-process incoming-stream delivery acknowledgement. The receiver verifies byte order and
   `TraceId`; application processing is not part of the sample.
3. **Five routed-packet samples.** Use node-label selection and the frozen load-balancing policy to select
   one eligible destination, route one 4,096-byte stream over the configured path, and wait for the same
   current-process acknowledgement. At least one sample uses the exact three-hop path.
4. **Five node-metadata samples.** Commit one owner-signed endpoint or capability-label revision and wait
   until all 16 members expose that exact revision and digest through paged public observations.
5. **Five resource-metadata samples.** Commit one named resource candidate with reserved type and URI
   labels plus a custom label, then wait until all 16 members expose the same deterministic
   timestamp/writer/removal/digest winner. The URI is never dereferenced.

The 4,096-byte stream is a benchmark payload, not an API maximum. Samples are sequential and make no
concurrent-throughput claim.

## Timing Boundaries

A sample starts immediately before the public operation that owns it:

- credential rotation for admission;
- packet send for packet strata;
- local metadata command for node and resource strata.

A sample ends only when its public acceptance predicate is observed. Setup, readiness, fixture creation,
and cleanup are not included in sample latency but have separate bounded harness deadlines. The
controller stores raw start/end wall timestamps and elapsed host observations for every sample.

## Statistics and Pass Rule

There is no percentile, mean, median, or warmup exclusion. All 125 samples are release evidence and each
must be at most 10,000 milliseconds. Any missing predicate, route failure, stream interruption,
provider error, wall-clock discontinuity, forced shutdown, or sample above the deadline fails the exact
candidate.

A new attempt uses a new immutable candidate or an explicitly recorded rerun reason. Rerunning until green
without retaining every attempt is forbidden.

## Cleanup and Artifact Rules

After measurement, the controller requests graceful shutdown, waits up to 30 seconds, then treats any
forced termination as failure. It removes only run-owned containers, networks, stores, credentials, and
artifacts. Resource URIs are never followed and upper-layer objects are never touched.

Artifacts contain candidate identity, image digests, host/preflight facts, topology, configuration,
public readiness observations, all 125 raw samples, failures, and cleanup outcomes. They contain no
credential, private key, provider handle, packet body, unredacted path, or unredacted address.

## Consequences

The profile gives an exact, reproducible release signal for the crate's approved responsibilities. It
does not claim payload durability, application response latency, arbitrary-population performance,
impaired-network latency, clock-discontinuity tolerance within the SLO, or business-data convergence.
