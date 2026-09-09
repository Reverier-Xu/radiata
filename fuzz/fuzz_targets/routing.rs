//! The canonical `routing` state-machine fuzz target.
//!
//! Derived transition sequences drive the route envelope state machine:
//! authenticated holder selection, one checked next hop, monotone budget
//! drain, duplicate-free visited chains, and explicit termination. Any
//! panic is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  let _ = radiata::fuzz_adapters::routing(input);
});
