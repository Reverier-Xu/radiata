//! The reconciliation plane.
//!
//! Scope, evidence, and the phased plan live in
//! `docs/research/06-architecture-proposal.md` (the research cycle's
//! architecture decision record). In target form the plane replaces the
//! push watermark anti-entropy (`sync_common`'s `WatermarkWalk`) with
//! receiver-evidenced range reconciliation: lanes exchange
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
//! - [`wire`] — the reconcile-v1 message contract: canonical CBOR encodings for
//!   ROOT/HINT/OFFER/NEED/ROWS/DONE, fail-closed decode, bounded shapes, golden
//!   vectors;
//! - [`engine`] — the per-session, per-lane negotiation state machine (phase
//!   2): pure deterministic drives from inputs (messages, local changes, root
//!   exchanges) to the exact outbound message set.

// Phases 1 and 2 land the primitive, the wire contract, and the engine
// before any production caller exists: the phase-3 lane migration
// (descriptors, trust, resources, tombstones riding the engine) is the
// first production consumer. Remove this allowance when the lanes ride
// the engine.
#[allow(dead_code)]
pub(crate) mod digest;
#[allow(dead_code)]
pub(crate) mod engine;
#[allow(dead_code)]
pub(crate) mod fingerprint;
#[allow(dead_code)]
pub(crate) mod wire;
