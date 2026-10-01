//! The frozen row-digest function of the reconciliation plane.
//!
//! Every reconciliation fingerprint aggregates *item digests*: one 64-bit
//! digest per stored row, computed as the first eight bytes (big-endian)
//! of SHA-256 over the canonical CBOR encoding of the two-element array
//! `[key, content]`. The key participates in the preimage because the
//! audit that motivated the plane measured same-content rows cancelling
//! under a pure content hash: two distinct rows that share content bytes
//! but not a key must never XOR-cancel each other out of a fingerprint
//! (the `item_hash` semantics of
//! `docs/research/06-architecture-proposal.md` §2).
//!
//! This function is a **frozen wire-contract constant**, pinned by the
//! golden vectors below: every peer's range fingerprints are only
//! comparable because they hash the same preimage shape with the same
//! truncation. Changing any byte of the contract — preimage shape,
//! hash, or truncation — desynchronizes every fingerprint in a cluster
//! and is a new wire version, not an edit. The digest width (64 bits) is
//! likewise a row-format constant: the proposal §10 risk table records
//! the 128-bit upgrade reservation, which would land as a new wire
//! version alongside the existing one, never as an in-place widening.

use minicbor::{Decode, Encode, bytes::ByteVec};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
  Result,
  protocol::{CborLimits, MAX_BODY_BYTES, encode_canonical},
};

/// The canonical preimage budget: the key and content together must fit
/// the control-plane body ceiling, because a row that cannot be hashed
/// cannot be carried in a ROWS message either (both live inside the
/// same 64 KiB wire envelope).
const PREIMAGE_LIMITS: CborLimits = CborLimits::new(4, 4, MAX_BODY_BYTES);

/// The digest preimage: exactly the canonical CBOR encoding of the
/// two-element array `[key, content]`. Canonical form makes the
/// key/content boundary unambiguous — plain concatenation would let
/// `(b"ab", b"c")` and `(b"a", b"bc")` share a digest.
#[derive(Encode, Decode)]
#[cbor(array)]
struct PreimageWire {
  #[n(0)]
  key: ByteVec,
  #[n(1)]
  content: ByteVec,
}

/// The item digest of one row: `u64::from_be_bytes(SHA-256(preimage)[0..8])`.
///
/// Equal rows digest equal; distinct rows collide with probability
/// 2⁻⁶⁴, which the fingerprint pair `(count, xor)` further guards (the
/// collision risk analysis lives in the proposal §10). Callers feed the
/// result to [`crate::reconcile::fingerprint::FingerprintIndex`] as the
/// row's sort key and aggregate input.
pub(crate) fn item_digest(key: &[u8], content: &[u8]) -> Result<u64> {
  let preimage = encode_canonical(
    &PreimageWire {
      key: ByteVec::from(key.to_vec()),
      content: ByteVec::from(content.to_vec()),
    },
    PREIMAGE_LIMITS,
  )?;
  let hash: [u8; 32] = Sha256::digest(preimage).into();
  let mut digest = [0u8; 8];
  digest.copy_from_slice(&hash[..8]);
  Ok(u64::from_be_bytes(digest))
}

#[cfg(test)]
mod tests {
  use sha2::Digest as _;

  use super::{PreimageWire, item_digest};
  use crate::protocol::{CborLimits, MAX_BODY_BYTES, encode_canonical};

  /// The frozen golden vectors: any change to the preimage shape, the
  /// hash, or the truncation fails here, by design.
  #[test]
  fn reconcile_digest_golden_vectors_are_frozen() {
    assert_eq!(
      item_digest(b"member-1", b"descriptor-row").unwrap(),
      0x37E6_6054_37D4_AE3A
    );
    assert_eq!(item_digest(b"", b"").unwrap(), 0xC515_4455_F73E_3716);
    assert_eq!(item_digest(b"a", b"a").unwrap(), 0x9E65_1BBD_964F_83C6);
    assert_eq!(item_digest(b"b", b"a").unwrap(), 0xF01F_64BF_9E50_705D);
  }

  /// The preimage shape is pinned independently of the helper: the exact
  /// canonical bytes `0x82 ‖ bstr(key) ‖ bstr(content)` hashed with an
  /// in-test SHA-256 must reproduce the function's output.
  #[test]
  fn reconcile_digest_preimage_is_the_canonical_pair_encoding() {
    let expected = {
      let preimage = [0x82, 0x41, 0x61, 0x41, 0x61];
      let hash = sha2::Sha256::digest(preimage);
      let mut digest = [0u8; 8];
      digest.copy_from_slice(&hash[..8]);
      u64::from_be_bytes(digest)
    };
    assert_eq!(item_digest(b"a", b"a").unwrap(), expected);
  }

  /// Same content under distinct keys digests distinctly, so two such
  /// rows can never XOR-cancel out of a fingerprint — the audit's
  /// `item_hash` pathology.
  #[test]
  fn reconcile_digest_separates_same_content_under_distinct_keys() {
    let left = item_digest(b"a", b"payload").unwrap();
    let right = item_digest(b"b", b"payload").unwrap();
    assert_ne!(left, right);
    assert_ne!(left ^ right, 0);

    let repeated = item_digest(b"key", b"payload").unwrap();
    assert_eq!(
      item_digest(b"key", b"payload").unwrap(),
      repeated,
      "the digest is a pure function of the row bytes"
    );
  }

  /// A row whose preimage cannot fit the wire body budget fails closed
  /// with a typed error instead of hashing a truncated view.
  #[test]
  fn reconcile_digest_rejects_preimages_over_the_body_budget() {
    let oversize = vec![0u8; MAX_BODY_BYTES];
    assert!(item_digest(&oversize, b"").is_err());
  }

  /// The preimage encoder shares the crate's one canonical encoder; a
  /// direct encode matches the hand-written golden bytes.
  #[test]
  fn reconcile_digest_preimage_encodes_canonically() {
    let bytes = encode_canonical(
      &PreimageWire {
        key: minicbor::bytes::ByteVec::from(b"a".to_vec()),
        content: minicbor::bytes::ByteVec::from(b"a".to_vec()),
      },
      CborLimits::new(4, 4, MAX_BODY_BYTES),
    )
    .unwrap();
    assert_eq!(bytes, vec![0x82, 0x41, 0x61, 0x41, 0x61]);
  }
}
