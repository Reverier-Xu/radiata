//! The canonical `feature_selection` state-machine fuzz target.
//!
//! Derived offer pairs exercise digest equality, dependency closure,
//! conflict pairs, limit minima, and required-label rejection. An accepted
//! selection must satisfy every structural invariant again; any panic is
//! a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  let _ = radiata::fuzz_adapters::feature_selection(input);
});
