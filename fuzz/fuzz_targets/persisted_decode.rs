//! The canonical `persisted_decode` fuzz target.
//!
//! Feeds every input through each frozen persisted-metadata record
//! decoder: identity, node, resource, trace, transaction, and migration
//! schema records. Every outcome must be a clean value or a typed error;
//! any panic is a target finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  radiata::fuzz_adapters::persisted_decode(input);
});
