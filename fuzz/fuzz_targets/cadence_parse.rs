//! The `cadence_parse` fuzz target.
//!
//! Feeds every input through `radiata_cadence::Ticker::parse` and asserts
//! the crate's fail-closed contract plus the canonical round-trip
//! invariant: any accepted ticker's canonical form reparses to itself with
//! the same declared frame. A panic is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  let Ok(text) = core::str::from_utf8(input) else {
    return;
  };
  if let Ok(ticker) = radiata_cadence::Ticker::parse(text) {
    let canonical = ticker.to_string();
    let reparsed = radiata_cadence::Ticker::parse(&canonical)
      .unwrap_or_else(|error| panic!("canonical form {canonical:?} rejected: {error}"));
    assert_eq!(reparsed.to_string(), canonical, "canonical form is not a fixed point");
    assert_eq!(reparsed.offset(), ticker.offset(), "frame changed across round-trip");
  }
});
