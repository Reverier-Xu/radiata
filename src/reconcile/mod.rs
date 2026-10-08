//! The reconciliation plane.
//!
//! Scope, evidence, and the phased plan live in
//! `docs/research/06-architecture-proposal.md` (the research cycle's
//! architecture decision record). The plane replaced the push watermark
//! anti-entropy with receiver-evidenced range reconciliation: lanes
//! exchange
//! `(count, xor)` range fingerprints over their item-digest space, and
//! row bytes only cross a session for ranges whose fingerprints prove
//! the receiving side lacks them.
//!
//! The module tree carries the landed phases of the plan:
//!
//! - [`fingerprint`] — the digest-ordered aggregate index (phase 1), the
//!   derived local view a lane negotiates over;
//! - [`digest`] — the frozen row-digest function every fingerprint aggregates
//!   (a wire-contract constant, pinned by golden vectors);
//! - [`wire`] — the reconcile v1 message contract: canonical CBOR encodings for
//!   ROOT/HINT/OFFER/NEED/ROWS/DONE, fail-closed decode, bounded shapes, golden
//!   vectors;
//! - [`engine`] — the per-session, per-lane negotiation state machine (phase
//!   2): pure deterministic drives from inputs (messages, local changes, root
//!   exchanges) to the exact outbound message set.

// The phase-3 lane migration is the first production consumer of the
// primitive, the wire contract, and the engine: the plane module wires
// them to the session and the tick.
pub(crate) mod digest;
pub(crate) mod engine;
// The fingerprint index is the plane's primitive: its full query
// surface (point lookups, removal, set algebra) lands ahead of its
// consumers — the engine exercises the aggregate paths today, and the
// R4 trigger layer and lane pruning pick up the rest.
#[allow(dead_code)]
pub(crate) mod fingerprint;
pub(crate) mod plane;
pub(crate) mod wire;

// The R4 acceptance lane: the deterministic engine-level budget matrix
// (payload redundancy, hint traffic, loss convergence) over the same
// engine the plane drives.
#[cfg(test)]
mod budget;
