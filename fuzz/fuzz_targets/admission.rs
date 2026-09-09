//! The canonical `admission` state-machine fuzz target.
//!
//! Derived operation sequences drive the admission commit/reconcile state
//! machine: propose, replay, double-book a generation, and replay with a
//! wrong key. Every outcome must be a typed error or the exact retained
//! grant; any panic is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  radiata::fuzz_adapters::admission(input);
});
