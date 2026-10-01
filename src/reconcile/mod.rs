//! The reconciliation plane.
//!
//! Scope, evidence, and the phased plan live in
//! `docs/research/06-architecture-proposal.md` (the research cycle's
//! architecture decision record). In target form the plane replaces the
//! push watermark anti-entropy (`sync_common`'s `WatermarkWalk`) with
//! receiver-evidenced range reconciliation: lanes exchange
//! `(count, xor)` range fingerprints over their item-digest space, and
//! row bytes only cross a session for ranges whose fingerprints prove
//! the receiving side lacks them. The module tree grows in the order
//! the plan's phases land; the first phase is the [`fingerprint`]
//! index primitive, which carries no wire surface of its own.

// Phase 1 lands the index primitive before its consumer: the phase-2
// reconciliation engine is the first production caller. Remove this
// allowance when the engine lands.
#[allow(dead_code)]
pub(crate) mod fingerprint;
