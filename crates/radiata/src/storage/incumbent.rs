//! The shared corrupt-incumbent policy for the register write paths.
//!
//! A stored row that no longer decodes is non-evidence, not a poison
//! pill: the lane's emit scan skips undecodable rows, so refusing the
//! valid incoming row would leave the receiver's fingerprint without the
//! key the sender keeps re-offering — a permanent divergence loop. The
//! resource and descriptor page batches, the resource put, and the
//! descriptor single-record store therefore treat the corrupt value as
//! absent and let the verified incoming record install over it through
//! the normal exact-CAS Put (the expectation is the corrupt value's
//! digest, so a concurrent change conflicts and the retry re-decodes).
//! This helper only reports the fact; what an absent incumbent means for
//! a write (skip rules, preconditions) stays with the caller.

use crate::Result;

/// Decodes one stored incumbent, mapping an undecodable value to `None`
/// (absent) instead of a batch-fatal fault. The warning carries the
/// caller's identity context (the resource name or node id), the decode
/// error kind, and the decode error's own context, so the operator can
/// tell the two failure classes apart: the schema and version contexts
/// mean a record version this binary cannot read, the decode and
/// canonical contexts mean file damage.
pub(crate) fn decode_or_absent<T>(
  bytes: &[u8], decode: impl FnOnce(&[u8]) -> Result<T>, context: &str,
) -> Option<T> {
  match decode(bytes) {
    Ok(decoded) => Some(decoded),
    Err(error) => {
      tracing::warn!(
        incumbent = context,
        kind = ?error.kind(),
        context = error.context(),
        "stored incumbent is undecodable; treating it as absent"
      );
      None
    }
  }
}
