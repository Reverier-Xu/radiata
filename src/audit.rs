//! Semantic path events for the scenario fuzz harness and deep
//! diagnostics.
//!
//! Compiled only under the `audit` feature. Every function emits one
//! structured tracing event at the `audit` target, describing a
//! semantic decision the harness's state map verifies: which path a
//! sync step took, why a session changed, how a journal resolved.
//! Without the feature every body is empty — production builds carry
//! neither the events nor their field formatting.
//!
//! Event contract: one line per decision, stable field names, stable
//! message text. The harness parses these lines; renaming a field or
//! message is a breaking change to the fuzz suite.

#[cfg(feature = "audit")]
use tracing::debug;

/// One watermark-filtered sync step settled without a page: `continued`
/// records whether the walk advances from its budget boundary (`true`)
/// or the pass closed at the catalog end (`false`). Closing on a quiet
/// mid-catalog window instead of continuing is the stranded-tail defect
/// the fuzz suite watches for.
pub(crate) fn resource_pass_settled(peer: &str, continued: bool) {
  #[cfg(feature = "audit")]
  debug!(target: "audit", peer, continued, "resource pass settled");
  #[cfg(not(feature = "audit"))]
  let _ = (peer, continued);
}

/// A dispatched sync page failed its admission verdict and rewound to
/// its scan start: the records re-collect on the next tick. Verdict
/// failures during steady state mean the session cannot carry the page.
pub(crate) fn resource_page_rewound(peer: &str) {
  #[cfg(feature = "audit")]
  debug!(target: "audit", peer, "resource page rewound");
  #[cfg(not(feature = "audit"))]
  let _ = peer;
}

/// A peer's watermark table refreshed to empty: the next pass
/// re-delivers the whole catalog once, bounding any
/// admission-versus-application divergence.
pub(crate) fn resource_watermarks_refreshed(peer: &str) {
  #[cfg(feature = "audit")]
  debug!(target: "audit", peer, "resource watermarks refreshed");
  #[cfg(not(feature = "audit"))]
  let _ = peer;
}

/// A member dial toward `peer` was attempted; `recovery` records
/// whether the recovery plane (rather than an operator) initiated it.
pub(crate) fn dial_started(peer: &str, recovery: bool) {
  #[cfg(feature = "audit")]
  debug!(target: "audit", peer, recovery, "member dial started");
  #[cfg(not(feature = "audit"))]
  let _ = (peer, recovery);
}

/// A member dial toward `peer` settled: `recovery` records the
/// initiator as above, `connected` whether an authenticated session
/// registered.
pub(crate) fn dial_settled(peer: &str, recovery: bool, connected: bool) {
  #[cfg(feature = "audit")]
  debug!(target: "audit", peer, recovery, connected, "member dial settled");
  #[cfg(not(feature = "audit"))]
  let _ = (peer, recovery, connected);
}

/// One member descriptor was installed from an anti-entropy page:
/// the receiving peer adopted a new or higher-revision record. This is
/// the delivery-truth proof for member metadata propagation — labels,
/// revisions, and membership knowledge reach a peer only through this
/// path, so the harness asserts it after every descriptor-carrying
/// operation instead of trusting the sender's tick.
pub(crate) fn descriptor_installed(node: &str, revision: u64) {
  #[cfg(feature = "audit")]
  debug!(target: "audit", node, revision, "member descriptor installed");
  #[cfg(not(feature = "audit"))]
  let _ = (node, revision);
}

/// One purpose-scoped pending journal resolved against durable
/// evidence: `committed` records the classification.
pub(crate) fn journal_resolved(purpose: &str, committed: bool) {
  #[cfg(feature = "audit")]
  debug!(target: "audit", purpose, committed, "journal resolved");
  #[cfg(not(feature = "audit"))]
  let _ = (purpose, committed);
}
