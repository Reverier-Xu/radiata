//! The merge-grant signature domain and the shared signature helpers.
//!
//! The helpers are domain-agnostic and live in
//! [`crate::protocol::signature`]; this module re-exports them for the
//! identity record callers and owns the one identity-specific piece: the
//! merge-grant domain label.

pub(crate) use crate::protocol::signature::{body_digest, signature_message, verify_strict};

pub(crate) const MERGE_GRANT_DOMAIN: &[u8] = b"radiata.woooo.tech/crypto/v1/merge-grant";

#[cfg(test)]
mod tests {
  use super::MERGE_GRANT_DOMAIN;

  #[test]
  fn identity_records_signature_domains_are_exact_ascii_labels() {
    assert_eq!(
      MERGE_GRANT_DOMAIN,
      b"radiata.woooo.tech/crypto/v1/merge-grant"
    );
    assert!(MERGE_GRANT_DOMAIN.is_ascii());
  }
}
