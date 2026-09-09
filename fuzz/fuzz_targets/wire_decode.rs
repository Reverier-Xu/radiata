//! The canonical `wire_decode` fuzz target.
//!
//! Feeds every input through the prelude splitter, the closed kind
//! registries, and each packet frame decoder with the frozen control-plane
//! limits. Malformed or over-bound input must return a typed error and
//! never panic; any finding belongs to the target owner.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  let _ = radiata::fuzz_adapters::wire_decode(input);
});
