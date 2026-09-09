//! The canonical `selector` fuzz target.
//!
//! Feeds every input through the bounded selector parser and asserts the
//! canonical round-trip invariant: parsed canonical text reparses to
//! itself and stays within the frozen input bound. A panic is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  let _ = radiata::fuzz_adapters::selector_parse(input);
});
