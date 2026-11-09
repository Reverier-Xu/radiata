//! The civil interchange reading: one wall-clock second with any
//! reference frame stripped away.
//!
//! [`Civil`] is what a [`Ticker`](crate::Ticker) evaluates and what its
//! [`next_fire`](crate::Ticker::next_fire) search returns. It carries no
//! frame: every frame decision lives in [`Offset`](crate::Offset) and the
//! [`Cadence`](crate::Cadence) conversion, never in the reading itself.

use core::{fmt, str::FromStr};

use crate::{
  error::{ParseError, ParseErrorKind, Result},
  ticker::{Offset, parse_offset},
};

/// One civil wall-clock second: the six calendar fields of a reading
/// with any reference frame stripped away.
///
/// Civil values are produced by the crate —
/// [`Ticker::next_fire`](crate::Ticker::next_fire) returns them, and the civil
/// shape `YYYY-MM-DDThh:mm:ss` parses into them (see [`FromStr`]) — and read
/// back through the accessors or [`Display`]. There is deliberately no public
/// constructor: callers hand the crate their own reading through the
/// [`Cadence`](crate::Cadence) trait instead of assembling fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Civil {
  pub(crate) year: u16,
  pub(crate) month: u8,
  pub(crate) day: u8,
  pub(crate) hour: u8,
  pub(crate) minute: u8,
  pub(crate) second: u8,
}

impl Civil {
  /// Creates a civil second, rejecting out-of-domain components.
  ///
  /// Civil validity (e.g. February 30th) is deliberately not required:
  /// [`Ticker::next_fire`](crate::Ticker::next_fire) rolls such starts
  /// forward, and matching is pure set membership over the fields.
  pub(crate) fn new(
    year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8,
  ) -> Option<Self> {
    if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
      return None;
    }
    Some(Self {
      year,
      month,
      day,
      hour,
      minute,
      second,
    })
  }

  /// Year, 0000-9999.
  pub const fn year(&self) -> u16 {
    self.year
  }

  /// Month of year, 1-12.
  pub const fn month(&self) -> u8 {
    self.month
  }

  /// Day of month, 1-31.
  pub const fn day(&self) -> u8 {
    self.day
  }

  /// Hour of day, 0-23.
  pub const fn hour(&self) -> u8 {
    self.hour
  }

  /// Minute of hour, 0-59.
  pub const fn minute(&self) -> u8 {
    self.minute
  }

  /// Second of minute, 0-59.
  pub const fn second(&self) -> u8 {
    self.second
  }
}

impl fmt::Display for Civil {
  /// Renders the civil shape `YYYY-MM-DDThh:mm:ss`: zero-padded fields,
  /// no offset — the reading is frame-free.
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
      self.year, self.month, self.day, self.hour, self.minute, self.second
    )
  }
}

impl FromStr for Civil {
  type Err = ParseError;

  /// Parses the strict civil shape `YYYY-MM-DDThh:mm:ss`: zero-padded
  /// fixed widths, no whitespace, no trailing offset (an offset-carrying
  /// string denotes an instant — read it through
  /// [`Cadence::to_civil`](crate::Cadence::to_civil) with a frame in
  /// hand).
  ///
  /// ```
  /// use radiata_cadence::Civil;
  ///
  /// let civil: Civil = "2026-11-08T13:45:01".parse().unwrap();
  /// assert_eq!((civil.year(), civil.month(), civil.second()), (2026, 11, 1));
  /// assert_eq!(civil.to_string(), "2026-11-08T13:45:01");
  /// ```
  ///
  /// # Errors
  ///
  /// Returns a [`ParseError`] naming the offending text for every
  /// malformation: skeleton breaks, wrong digit counts, and
  /// out-of-domain field values.
  fn from_str(text: &str) -> Result<Self> {
    let (civil, rest) = parse_civil(text)?;
    if !rest.is_empty() {
      return Err(ParseError::new(
        ParseErrorKind::Skeleton,
        format!("expected end of input, found {rest:?}"),
      ));
    }
    Ok(civil)
  }
}

/// Parses the fixed-width civil prefix `YYYY-MM-DDThh:mm:ss`, returning
/// the reading and the unconsumed remainder.
pub(crate) fn parse_civil(text: &str) -> Result<(Civil, &str)> {
  let (year, rest) = parse_field(text, 4, "year")?;
  let rest = strip(rest, '-')?;
  let (month, rest) = parse_field(rest, 2, "month")?;
  let rest = strip(rest, '-')?;
  let (day, rest) = parse_field(rest, 2, "day")?;
  let rest = strip(rest, 'T')?;
  let (hour, rest) = parse_field(rest, 2, "hour")?;
  let rest = strip(rest, ':')?;
  let (minute, rest) = parse_field(rest, 2, "minute")?;
  let rest = strip(rest, ':')?;
  let (second, rest) = parse_field(rest, 2, "second")?;
  Civil::new(
    year as u16,
    month as u8,
    day as u8,
    hour as u8,
    minute as u8,
    second as u8,
  )
  .ok_or_else(|| {
    ParseError::new(
      ParseErrorKind::Domain,
      format!("field value outside its domain in {text:?}"),
    )
  })
  .map(|civil| (civil, rest))
}

/// Parses the civil shape plus an optional trailing offset — the string
/// reading shape of the [`Cadence`](crate::Cadence) trait.
pub(crate) fn parse_civil_with_offset(text: &str) -> Result<(Civil, Option<Offset>)> {
  let (civil, rest) = parse_civil(text)?;
  if rest.is_empty() {
    return Ok((civil, None));
  }
  let offset = parse_offset(rest)?;
  Ok((civil, Some(offset)))
}

/// Parses one fixed-width zero-padded numeric field.
fn parse_field<'a>(text: &'a str, digits: usize, name: &'static str) -> Result<(u32, &'a str)> {
  let bytes = text.as_bytes();
  if bytes.len() < digits || !bytes[..digits].iter().all(u8::is_ascii_digit) {
    return Err(ParseError::new(
      ParseErrorKind::DigitCount,
      format!("expected {digits} digits for the {name}, found {text:?}"),
    ));
  }
  let mut value = 0_u32;
  for &byte in &bytes[..digits] {
    value = value * 10 + u32::from(byte - b'0');
  }
  Ok((value, &text[digits..]))
}

/// Consumes exactly one expected separator character.
fn strip(text: &str, expected: char) -> Result<&str> {
  text.strip_prefix(expected).ok_or_else(|| {
    ParseError::new(
      ParseErrorKind::Skeleton,
      format!("expected {expected:?}, found {text:?}"),
    )
  })
}

#[cfg(test)]
mod tests {
  use super::Civil;
  use crate::error::ParseErrorKind;

  /// A value that must parse.
  fn civil(text: &str) -> Civil {
    text
      .parse()
      .unwrap_or_else(|error| panic!("{text:?} should parse: {error}"))
  }

  /// The frozen accept matrix: every well-formed civil shape parses with
  /// the exact fields and round-trips through Display.
  #[test]
  fn civil_strings_parse_and_round_trip() {
    let cases = [
      ("0000-01-01T00:00:00", (0, 1, 1, 0, 0, 0)),
      ("2026-11-08T13:45:01", (2026, 11, 8, 13, 45, 1)),
      ("9999-12-31T23:59:59", (9999, 12, 31, 23, 59, 59)),
    ];
    for (text, (year, month, day, hour, minute, second)) in cases {
      let civil = civil(text);
      assert_eq!(
        (
          civil.year(),
          civil.month(),
          civil.day(),
          civil.hour(),
          civil.minute(),
          civil.second()
        ),
        (year, month, day, hour, minute, second),
        "{text:?}"
      );
      assert_eq!(civil.to_string(), text, "{text:?}");
    }
  }

  /// The frozen reject matrix: skeleton breaks, digit counts, domains,
  /// and offset-carrying strings (an offset denotes an instant).
  #[test]
  fn civil_strings_reject_malformations() {
    let rejects = [
      ("", ParseErrorKind::DigitCount),
      ("2026-11-08", ParseErrorKind::Skeleton),
      ("2026-11-08T13:45", ParseErrorKind::Skeleton),
      ("2026/11/08T13:45:01", ParseErrorKind::Skeleton),
      ("2026-1-08T13:45:01", ParseErrorKind::DigitCount),
      ("2026-11-8T13:45:01", ParseErrorKind::DigitCount),
      ("2026-11-08T3:45:01", ParseErrorKind::DigitCount),
      ("2026-11-08T13:45:1", ParseErrorKind::DigitCount),
      ("2026-13-08T13:45:01", ParseErrorKind::Domain),
      ("2026-11-32T13:45:01", ParseErrorKind::Domain),
      ("2026-11-08T24:45:01", ParseErrorKind::Domain),
      ("2026-11-08T13:60:01", ParseErrorKind::Domain),
      ("2026-11-08T13:45:60", ParseErrorKind::Domain),
      (" 2026-11-08T13:45:01", ParseErrorKind::DigitCount),
      ("2026-11-08T13:45:01 ", ParseErrorKind::Skeleton),
      // Offset-carrying strings denote instants, not civil readings;
      // FromStr rejects the trailing text before any offset parsing.
      ("2026-11-08T13:45:01Z", ParseErrorKind::Skeleton),
      ("2026-11-08T13:45:01+09:00", ParseErrorKind::Skeleton),
    ];
    for (text, kind) in rejects {
      assert_eq!(
        text.parse::<Civil>().expect_err(text).kind(),
        kind,
        "{text:?}"
      );
    }
  }

  /// Civil ordering is field-lexicographic, so chronological within a
  /// frame; equality is field-wise.
  #[test]
  fn civil_orders_field_lexicographically() {
    assert!(civil("2026-11-08T13:45:01") > civil("2026-11-08T13:45:00"));
    assert!(civil("2026-11-08T13:45:00") > civil("2026-11-08T12:59:59"));
    assert!(civil("2026-11-08T00:00:00") > civil("2026-11-07T23:59:59"));
    assert_eq!(civil("2026-11-08T13:45:01"), civil("2026-11-08T13:45:01"));
  }
}
