//! The canonical `reconcile_decode` fuzz target.
//!
//! Feeds every input through the reconcile v1 production decoder under
//! the frozen canonical CBOR contract: unknown message kinds and lanes,
//! over-bound lists, inverted ranges, non-canonical integers, padding,
//! and truncation must all return typed errors and never panic, while a
//! successfully decoded message must re-encode and re-decode to the
//! identical value (the canonical round-trip invariant the golden
//! vectors pin pointwise). Any finding belongs to the target owner.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  let _ = radiata::fuzz_adapters::reconcile_decode(input);
});
