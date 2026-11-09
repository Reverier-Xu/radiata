//! The cadence pattern: strict parsing, canonical form, set-membership
//! matching, and ordered next-fire search.
//!
//! Matching is one rule with no special cases: a wall-clock second fires iff
//! each field's value is a member of its compiled set. The crate is
//! clock-blind and timezone-blind — the caller resolves the reference frame
//! (device-local or fixed-offset) and supplies field values in it.

use core::fmt::{self, Write as _};

use crate::{
  calendar::days_in_month,
  error::{ParseError, ParseErrorKind, Result},
  field::{FieldDomain, FieldSet},
};

/// One wall-clock second in a chosen reference frame: the six field values
/// a pattern matches against.
///
/// Construct with [`FieldValues::new`] or struct literals; the fields are
/// public so callers can bridge their own civil-time representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldValues {
  /// Year, 0000-9999.
  pub year: u16,
  /// Month of year, 1-12.
  pub month: u8,
  /// Day of month, 1-31.
  pub day: u8,
  /// Hour of day, 0-23.
  pub hour: u8,
  /// Minute of hour, 0-59.
  pub minute: u8,
  /// Second of minute, 0-59.
  pub second: u8,
}

impl FieldValues {
  /// Creates field values, rejecting out-of-domain components.
  ///
  /// Civil validity (e.g. February 30th) is deliberately not required:
  /// [`Pattern::next_fire`] rolls such starts forward, and matching is pure
  /// set membership over the supplied values.
  pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Self> {
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
}

/// The declared reference frame of a pattern.
///
/// `Utc` is the `Z` sugar; `Fixed` carries the declared `+hh:mm`/`-hh:mm`
/// offset in seconds east of UTC. The distinction is preserved so the
/// accessor reports the frame exactly as declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offset {
  /// No offset declared: evaluate in the device's local wall clock.
  Local,
  /// Declared with `Z`: evaluate in the UTC frame.
  Utc,
  /// Declared with an explicit offset: evaluate in that fixed civil frame.
  Fixed(i32),
}

impl fmt::Display for Offset {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match *self {
      Self::Local => Ok(()),
      Self::Utc => f.write_str("Z"),
      Self::Fixed(seconds) => {
        let magnitude = seconds.unsigned_abs();
        write!(
          f,
          "{}{:02}:{:02}",
          if seconds < 0 { '-' } else { '+' },
          magnitude / 3600,
          magnitude % 3600 / 60
        )
      }
    }
  }
}

/// A compiled schedule pattern: six per-field selection sets plus the
/// declared reference frame.
///
/// Build with [`Pattern::parse`]; the canonical form round-trips through
/// [`Display`](fmt::Display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
  year: FieldSet,
  month: FieldSet,
  day: FieldSet,
  hour: FieldSet,
  minute: FieldSet,
  second: FieldSet,
  offset: Offset,
}

impl Pattern {
  /// Parses and compiles a pattern string.
  ///
  /// The grammar is the fixed six-field skeleton `year-month-dayThh:mm:ss`
  /// with an optional trailing offset (`Z` or `[+/-]hh:mm`), no whitespace.
  /// Every field is either a braced set `{...}` (elements: `*`, a two-digit
  /// literal, or an inclusive two-digit range; four digits for the year) or
  /// a bare single numeric literal. Bare `*`, bare ranges, and bare
  /// enumerations are syntax errors. Duplicate set elements are rejected.
  ///
  /// ```
  /// use radiata_cadence::Pattern;
  ///
  /// let pattern = Pattern::parse("2026-{03,09-12}-01T00:00:00Z").unwrap();
  /// assert_eq!(pattern.to_string(), "2026-{03,09-12}-01T00:00:00Z");
  /// ```
  ///
  /// # Errors
  ///
  /// Returns a [`ParseError`] naming the offending text for every
  /// malformation: skeleton breaks, wrong digit counts, out-of-domain
  /// values, descending ranges, duplicate set elements, and bad offsets.
  pub fn parse(text: &str) -> Result<Pattern> {
    let (year, rest) = FieldSet::parse(text, FieldDomain::YEAR)?;
    let rest = expect(rest, '-', "'-'")?;
    let (month, rest) = FieldSet::parse(rest, FieldDomain::MONTH)?;
    let rest = expect(rest, '-', "'-'")?;
    let (day, rest) = FieldSet::parse(rest, FieldDomain::DAY)?;
    let rest = expect(rest, 'T', "'T'")?;
    let (hour, rest) = FieldSet::parse(rest, FieldDomain::HOUR)?;
    let rest = expect(rest, ':', "':'")?;
    let (minute, rest) = FieldSet::parse(rest, FieldDomain::MINUTE)?;
    let rest = expect(rest, ':', "':'")?;
    let (second, rest) = FieldSet::parse(rest, FieldDomain::SECOND)?;
    let offset = parse_offset(rest)?;
    Ok(Pattern {
      year,
      month,
      day,
      hour,
      minute,
      second,
      offset,
    })
  }

  /// Returns the declared reference frame.
  pub const fn offset(&self) -> Offset {
    self.offset
  }

  /// Returns `true` when the wall-clock second with these field values
  /// fires.
  ///
  /// Pure set membership: every field must be a member of its set. Callers
  /// supply values in the pattern's reference frame; nonexistent civil
  /// dates (February 30th) simply never occur in a real frame, and
  /// [`Pattern::next_fire`] never produces them.
  pub fn r#match(&self, year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> bool {
    self.matches(FieldValues {
      year,
      month,
      day,
      hour,
      minute,
      second,
    })
  }

  /// The [`FieldValues`]-taking form of [`Pattern::r#match`].
  pub fn matches(&self, values: FieldValues) -> bool {
    self.year.contains(values.year)
      && self.month.contains(u16::from(values.month))
      && self.day.contains(u16::from(values.day))
      && self.hour.contains(u16::from(values.hour))
      && self.minute.contains(u16::from(values.minute))
      && self.second.contains(u16::from(values.second))
  }

  /// Returns the first matching wall-clock second at or after `start`
  /// (inclusive), or `None` when no second can ever match.
  ///
  /// The search is an ordered walk over the compiled sets: each field is
  /// tested from the year down, and a failing field jumps to its next
  /// member while resetting all lower fields. Calendar arithmetic
  /// (month lengths, leap years) is implemented in-crate, so nonexistent
  /// dates — February 30th, non-leap February 29ths — are skipped, never
  /// produced. The search is bounded by the grammar's 0000-9999 year
  /// domain: when the pattern's last set year is exhausted, `None` is
  /// returned.
  ///
  /// ```
  /// use radiata_cadence::{FieldValues, Pattern};
  ///
  /// let daily = Pattern::parse("{*}-{*}-{*}T00:00:00Z").unwrap();
  /// let start = FieldValues::new(2026, 3, 15, 12, 30, 45).unwrap();
  /// let next = daily.next_fire(start).unwrap();
  /// assert_eq!(next, FieldValues::new(2026, 3, 16, 0, 0, 0).unwrap());
  /// ```
  pub fn next_fire(&self, start: FieldValues) -> Option<FieldValues> {
    let mut cursor = start;
    loop {
      if !self.year.contains(cursor.year) {
        cursor.year = self.year.next_at(cursor.year)?;
        reset_date(&mut cursor);
        continue;
      }
      if !self.month.contains(u16::from(cursor.month)) {
        advance_month(&mut cursor, &self.year)?;
        reset_time(&mut cursor);
        continue;
      }
      if !self.day.contains(u16::from(cursor.day))
        || cursor.day > days_in_month(cursor.year, cursor.month)
      {
        advance_day(&mut cursor, &self.year)?;
        reset_time(&mut cursor);
        continue;
      }
      if !self.hour.contains(u16::from(cursor.hour)) {
        advance_hour(&mut cursor, &self.year)?;
        cursor.minute = 0;
        cursor.second = 0;
        continue;
      }
      if !self.minute.contains(u16::from(cursor.minute)) {
        advance_minute(&mut cursor, &self.year)?;
        cursor.second = 0;
        continue;
      }
      if !self.second.contains(u16::from(cursor.second)) {
        advance_second(&mut cursor, &self.year)?;
        continue;
      }
      return Some(cursor);
    }
  }
}

impl fmt::Display for Pattern {
  /// Renders the canonical form: zero-padded fields, sets as sorted and
  /// coalesced runs (or `{*}`), the offset as declared (`Z` stays `Z`).
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut out = String::new();
    self.year.write_canonical(&mut out);
    out.push('-');
    self.month.write_canonical(&mut out);
    out.push('-');
    self.day.write_canonical(&mut out);
    out.push('T');
    self.hour.write_canonical(&mut out);
    out.push(':');
    self.minute.write_canonical(&mut out);
    out.push(':');
    self.second.write_canonical(&mut out);
    write!(out, "{}", self.offset)?;
    f.write_str(&out)
  }
}

/// Consumes exactly one expected separator character.
fn expect<'a>(text: &'a str, expected: char, description: &'static str) -> Result<&'a str> {
  text.strip_prefix(expected).ok_or_else(|| {
    ParseError::new(
      ParseErrorKind::Skeleton,
      format!("expected {description}, found {text:?}"),
    )
  })
}

/// Parses the optional trailing offset into the declared reference frame.
fn parse_offset(text: &str) -> Result<Offset> {
  if text.is_empty() {
    return Ok(Offset::Local);
  }
  if text == "Z" {
    return Ok(Offset::Utc);
  }
  let body = text.strip_prefix(['+', '-']).ok_or_else(|| {
    ParseError::new(
      ParseErrorKind::Offset,
      format!("expected 'Z' or '[+/-]hh:mm', found {text:?}"),
    )
  })?;
  let sign = if text.starts_with('-') { -1 } else { 1 };
  let (hours, minutes) = body.split_once(':').ok_or_else(|| {
    ParseError::new(
      ParseErrorKind::Offset,
      format!("expected 'hh:mm', found {text:?}"),
    )
  })?;
  let hours = parse_offset_component(hours, "hours", 23, text)?;
  let minutes = parse_offset_component(minutes, "minutes", 59, text)?;
  Ok(Offset::Fixed(
    sign * (i32::from(hours) * 3600 + i32::from(minutes) * 60),
  ))
}

/// Parses one two-digit offset component with an inclusive upper bound.
fn parse_offset_component(text: &str, name: &'static str, max: u8, whole: &str) -> Result<u8> {
  let digits = text
    .bytes()
    .take_while(|byte| byte.is_ascii_digit())
    .count();
  if digits != 2 || digits != text.len() {
    return Err(ParseError::new(
      ParseErrorKind::Offset,
      format!("{name} must be exactly two digits, found {text:?} in {whole:?}"),
    ));
  }
  let value = (text.as_bytes()[0] - b'0') * 10 + (text.as_bytes()[1] - b'0');
  if value > max {
    return Err(ParseError::new(
      ParseErrorKind::Offset,
      format!("{name} {value} exceeds {max} in {whole:?}"),
    ));
  }
  Ok(value)
}

/// Resets the time-of-day after a month or day jump; the advanced field is
/// left as the carry left it.
fn reset_time(cursor: &mut FieldValues) {
  cursor.hour = 0;
  cursor.minute = 0;
  cursor.second = 0;
}

/// Resets month, day, and time-of-day after a year jump.
fn reset_date(cursor: &mut FieldValues) {
  cursor.month = 1;
  cursor.day = 1;
  cursor.hour = 0;
  cursor.minute = 0;
  cursor.second = 0;
}

/// Advances to the next month, rolling into the next set year past December.
fn advance_month(cursor: &mut FieldValues, years: &FieldSet) -> Option<()> {
  if cursor.month >= 12 {
    cursor.year = years.next_at(cursor.year.checked_add(1)?)?;
    cursor.month = 1;
  } else {
    cursor.month += 1;
  }
  cursor.day = 1;
  Some(())
}

/// Advances to the next day, rolling the month and year as needed.
fn advance_day(cursor: &mut FieldValues, years: &FieldSet) -> Option<()> {
  cursor.day += 1;
  if cursor.day > days_in_month(cursor.year, cursor.month) {
    advance_month(cursor, years)?;
  }
  Some(())
}

/// Advances to the next hour, rolling the day past 23.
fn advance_hour(cursor: &mut FieldValues, years: &FieldSet) -> Option<()> {
  cursor.hour += 1;
  if cursor.hour > 23 {
    cursor.hour = 0;
    advance_day(cursor, years)?;
  }
  Some(())
}

/// Advances to the next minute, rolling the hour past 59.
fn advance_minute(cursor: &mut FieldValues, years: &FieldSet) -> Option<()> {
  cursor.minute += 1;
  if cursor.minute > 59 {
    cursor.minute = 0;
    advance_hour(cursor, years)?;
  }
  Some(())
}

/// Advances to the next second, rolling the minute past 59.
fn advance_second(cursor: &mut FieldValues, years: &FieldSet) -> Option<()> {
  cursor.second += 1;
  if cursor.second > 59 {
    cursor.second = 0;
    advance_minute(cursor, years)?;
  }
  Some(())
}

#[cfg(test)]
mod tests {
  use super::{FieldValues, Offset, ParseErrorKind, Pattern};

  /// Parses an input that must be accepted.
  fn parse_ok(text: &str) -> Pattern {
    Pattern::parse(text).unwrap_or_else(|error| panic!("{text:?} should parse: {error}"))
  }

  /// Asserts an input is rejected and returns the failure category.
  fn rejected(text: &str) -> ParseErrorKind {
    Pattern::parse(text).expect_err(text).kind()
  }

  /// Builds field values that must be in-domain.
  fn values(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> FieldValues {
    FieldValues::new(year, month, day, hour, minute, second).expect("in-domain values")
  }

  /// The frozen canonical-form golden corpus: input, canonical rendering.
  #[test]
  fn golden_canonical_forms() {
    let cases = [
      ("{*}-{*}-{*}T{*}:{*}:{*}", "{*}-{*}-{*}T{*}:{*}:{*}"),
      ("2026-03-15T00:00:00", "2026-03-15T00:00:00"),
      ("2026-03-15T00:00:00Z", "2026-03-15T00:00:00Z"),
      ("2026-03-15T00:00:00+00:00", "2026-03-15T00:00:00+00:00"),
      ("2026-03-15T09:00:00+09:00", "2026-03-15T09:00:00+09:00"),
      ("2026-03-15T09:00:00-05:30", "2026-03-15T09:00:00-05:30"),
      ("2026-{03,09-12}-01T00:00:00", "2026-{03,09-12}-01T00:00:00"),
      ("2026-{09-12,03}-01T00:00:00", "2026-{03,09-12}-01T00:00:00"),
      (
        "{2026,2030-2033}-{03,09-12}-01T00:00:00Z",
        "{2026,2030-2033}-{03,09-12}-01T00:00:00Z",
      ),
      ("2026-{01-03,03-05}-01T00:00:00", "2026-{01-05}-01T00:00:00"),
      ("2026-03-15T{*,07}:{00,30}:59", "2026-03-15T{*}:{00,30}:59"),
      (
        "{0059}-{03}-{03}T{03}:{03}:{03}",
        "{0059}-{03}-{03}T{03}:{03}:{03}",
      ),
      ("0000-01-01T00:00:00", "0000-01-01T00:00:00"),
      ("9999-12-31T23:59:59", "9999-12-31T23:59:59"),
    ];
    for (input, canonical) in cases {
      let pattern = parse_ok(input);
      assert_eq!(
        pattern.to_string(),
        canonical,
        "canonical form of {input:?}"
      );
      assert_eq!(
        parse_ok(&pattern.to_string()).to_string(),
        canonical,
        "reparse of {input:?}"
      );
    }
  }

  /// The frozen reject matrix: every malformation fails closed with the
  /// right category.
  #[test]
  fn reject_matrix() {
    let skeleton = [
      "",
      "*",
      "2026",
      "2026-03",
      "2026-03-15",
      "2026-03-15T",
      "2026-03-15T00",
      "2026-03-15T00:00",
      "2026-03-15t00:00:00",
      "2026/03/15T00:00:00",
      "2026-03-15V00:00:00",
      "2026-03-15T00-00:00",
      " 2026-03-15T00:00:00",
    ];
    for text in skeleton {
      assert_eq!(rejected(text), ParseErrorKind::Skeleton, "{text:?}");
    }
    // The brace rule: bare *, bare ranges, and bare enumerations fail.
    let bare = [
      "*-*-*T*:*:*",
      "2026-03-15T0-30:00:00",
      "00:00:00",
      "2026-03-15T*:00:00",
    ];
    for text in bare {
      let kind = rejected(text);
      assert!(
        matches!(kind, ParseErrorKind::Skeleton | ParseErrorKind::DigitCount),
        "{text:?}"
      );
    }
    let digit_counts = [
      "202-03-15T00:00:00",
      "20260-03-15T00:00:00",
      "2026-3-15T00:00:00",
      "2026-013-15T00:00:00",
      "2026-03-1T00:00:00",
      "2026-03-15T0:00:00",
      "2026-03-15T00:0:00",
      "2026-03-15T00:00:0",
      "2026-03-15T001:00:00",
      "{00}-{01}-01T00:00:00",
      "{32}-{01}-01T00:00:00",
      "{24}-{01}-01T00:00:00",
      "{60}-{01}-01T00:00:00",
      "2026-{03-03-03}-01T00:00:00",
    ];
    for text in digit_counts {
      assert_eq!(rejected(text), ParseErrorKind::DigitCount, "{text:?}");
    }
    let domains = [
      "2026-00-01T00:00:00",
      "2026-13-01T00:00:00",
      "2026-03-00T00:00:00",
      "2026-03-32T00:00:00",
      "2026-03-15T24:00:00",
      "2026-03-15T00:60:00",
      "2026-03-15T00:00:60",
      "{2026}-{13}-01T00:00:00",
      "{2026}-{01}-{32}T00:00:00",
      "2026-03-15T{24}:00:00",
      "2026-03-15T00:{60}:00",
      "2026-03-15T00:00:{60}",
    ];
    for text in domains {
      assert_eq!(rejected(text), ParseErrorKind::Domain, "{text:?}");
    }
    let ranges = ["2026-{05-02}-01T00:00:00", "2026-03-15T{23-00}:00:00"];
    for text in ranges {
      assert_eq!(rejected(text), ParseErrorKind::RangeOrder, "{text:?}");
    }
    let duplicates = [
      "2026-{03,03}-01T00:00:00",
      "2026-{03,03-03}-01T00:00:00",
      "2026-{01-05,03}-01T00:00:00",
      "2026-{01-05,01-05}-01T00:00:00",
      "{*,*}-{01}-01T00:00:00",
      "2026-03-15T{00,00}:{00}:00",
    ];
    for text in duplicates {
      assert_eq!(rejected(text), ParseErrorKind::DuplicateElement, "{text:?}");
    }
    let offsets = [
      "2026-03-15T00:00:00x",
      "2026-03-15T00:00:00Zx",
      "2026-03-15T00:00:00+",
      "2026-03-15T00:00:00-",
      "2026-03-15T00:00:00+24:00",
      "2026-03-15T00:00:00+00:60",
      "2026-03-15T00:00:00+1:00",
      "2026-03-15T00:00:00+0900",
      "2026-03-15T00:00:00+09:0",
      "2026-03-15T00:00:00 {*}",
      "2026-03-15T00:00:00 ",
      "2026-03-15T00:00:00+5:00",
      "2026-03-15T00:00:00+005:00",
    ];
    for text in offsets {
      assert_eq!(rejected(text), ParseErrorKind::Offset, "{text:?}");
    }
  }

  /// Round-trips: parse, render, reparse — the canonical form is a fixed
  /// point and the declared frame is preserved.
  #[test]
  fn parse_display_parse_round_trips() {
    let inputs = [
      "{*}-{*}-{*}T{*}:{*}:{*}",
      "2026-{03,09-12}-01T00:00:00+09:00",
      "{2026,2030-2033}-{03,09-12}-01T00:00:00Z",
      "2026-03-15T{06-18}:{00,30}:{15-45}",
      "0000-01-01T00:00:00",
      "9999-12-31T23:59:59-08:00",
    ];
    for input in inputs {
      let first = parse_ok(input);
      let canonical = first.to_string();
      let second = parse_ok(&canonical);
      assert_eq!(second.to_string(), canonical, "fixed point of {input:?}");
      assert_eq!(second.offset(), first.offset(), "frame of {input:?}");
    }
  }

  /// Membership agrees with the brute-force oracle over dense sample
  /// spaces, including out-of-domain field values (both are pure set
  /// membership, so they agree everywhere).
  #[test]
  fn membership_matches_oracle() {
    let patterns = [
      "2026-03-15T00:00:00",
      "2026-{03,07,09-12}-01T00:00:00Z",
      "2026-02-29T12:34:56+05:45",
      "{2025,2026}-{01-12}-{01,15,28-31}T{00,12,23}:{00,29,30,59}:{00,01,59}",
      "{*}-{*}-{30,31}T{23}:59:59",
    ];
    let oracles: Vec<(Pattern, Oracle)> = patterns
      .iter()
      .map(|text| (parse_ok(text), Oracle::parse(text)))
      .collect();
    for year in 2025..=2026 {
      for month in 1..=12u8 {
        for day in 1..=31u8 {
          for hour in [0u8, 12, 23] {
            for minute in [0u8, 29, 30, 59] {
              for second in [0u8, 1, 59] {
                let candidate = values(year, month, day, hour, minute, second);
                for (pattern, oracle) in &oracles {
                  assert_eq!(
                    pattern.matches(candidate),
                    oracle.matches(candidate),
                    "{pattern:?} at {candidate:?}"
                  );
                }
              }
            }
          }
        }
      }
    }
    // Dense time-of-day sweep on one day.
    let (pattern, oracle) = (&oracles[3].0, &oracles[3].1);
    for hour in 0..=23u8 {
      for minute in 0..=59u8 {
        for second in 0..=59u8 {
          let candidate = values(2026, 6, 15, hour, minute, second);
          assert_eq!(
            pattern.matches(candidate),
            oracle.matches(candidate),
            "{pattern:?} at {candidate:?}"
          );
        }
      }
    }
  }

  /// Next-fire agrees with exhaustive second-stepping over dense sample
  /// spaces, including year, month, day, and leap-day boundaries.
  #[test]
  fn next_fire_matches_step_oracle() {
    let cases: &[(&str, FieldValues)] = &[
      ("{*}-{*}-{*}T00:00:00Z", values(2026, 3, 15, 12, 30, 45)),
      ("2026-01-{01,15}T00:00:00", values(2026, 1, 2, 0, 0, 0)),
      (
        "2026-{01-12}-{01,15}T00:00:00",
        values(2026, 1, 2, 6, 30, 0),
      ),
      ("2024-{02}-{29}T00:00:00Z", values(2024, 2, 1, 0, 0, 0)),
      ("2026-12-31T23:59:59", values(2026, 12, 31, 0, 0, 0)),
      ("2026-{02,04}-{30,31}T00:00:00", values(2026, 1, 1, 0, 0, 0)),
      (
        "2026-03-15T{*,07}:{00,30}:59",
        values(2026, 3, 15, 7, 30, 58),
      ),
    ];
    for (text, start) in cases {
      let pattern = parse_ok(text);
      let oracle = Oracle::parse(text);
      assert_eq!(
        pattern.next_fire(*start),
        oracle_next_fire(&oracle, *start, 12_000_000),
        "{text:?} from {start:?}"
      );
    }
  }

  /// The next-fire chain stays on the oracle's matched-second sequence.
  #[test]
  fn next_fire_chain_matches_oracle() {
    let text = "{*}-{*}-{*}T{06,18}:{00,30}:00Z";
    let pattern = parse_ok(text);
    let oracle = Oracle::parse(text);
    let mut cursor = values(2026, 2, 27, 12, 0, 0);
    for _ in 0..24 {
      let next = pattern
        .next_fire(cursor)
        .expect("daily-ish pattern always fires");
      let stepped = oracle_next_fire(&oracle, cursor, 1_000_000).expect("oracle fires too");
      assert_eq!(next, stepped);
      assert!(pattern.matches(next), "next_fire output matches");
      cursor = step(next).expect("chain stays in range");
    }
  }

  /// Calendar edges: inclusive start, leap days, never-matching patterns,
  /// and end-of-month rolls.
  #[test]
  fn next_fire_calendar_edges() {
    // Inclusive: a matching start fires itself.
    let daily = parse_ok("{*}-{*}-{*}T00:00:00");
    let midnight = values(2026, 3, 15, 0, 0, 0);
    assert_eq!(daily.next_fire(midnight), Some(midnight));

    // Leap day: fires in leap years only, never between them.
    let leap_day = parse_ok("{*}-{02}-{29}T00:00:00Z");
    assert_eq!(
      leap_day.next_fire(values(2024, 1, 1, 0, 0, 0)),
      Some(values(2024, 2, 29, 0, 0, 0))
    );
    assert_eq!(
      leap_day.next_fire(values(2024, 3, 1, 0, 0, 0)),
      Some(values(2028, 2, 29, 0, 0, 0))
    );
    assert_eq!(
      parse_ok("{2024}-{02}-{29}T00:00:00").next_fire(values(2024, 3, 1, 0, 0, 0)),
      None
    );

    // February 30th can never fire; the bounded search returns None.
    let feb_30 = parse_ok("{*}-{02}-{30}T00:00:00");
    assert_eq!(feb_30.next_fire(values(2026, 1, 1, 0, 0, 0)), None);

    // End-of-month rolls skip impossible set days.
    let month_ends = parse_ok("2026-{02,04}-{30,31}T00:00:00");
    assert_eq!(
      month_ends.next_fire(values(2026, 1, 1, 0, 0, 0)),
      Some(values(2026, 4, 30, 0, 0, 0))
    );

    // Year exhaustion bounds the search.
    let last = parse_ok("2026-12-31T23:59:59");
    assert_eq!(
      last.next_fire(values(2026, 12, 31, 23, 59, 59)),
      Some(values(2026, 12, 31, 23, 59, 59))
    );
    assert_eq!(
      last.next_fire(values(2026, 12, 31, 23, 59, 58)),
      Some(values(2026, 12, 31, 23, 59, 59))
    );
    assert_eq!(
      parse_ok("9999-12-31T00:00:00").next_fire(values(9999, 12, 31, 0, 0, 1)),
      None
    );
  }

  /// The offset accessor reports the declared frame, and Display renders
  /// the offset spellings round-trip-stably.
  #[test]
  fn offset_frames() {
    assert_eq!(parse_ok("2026-03-15T00:00:00").offset(), Offset::Local);
    assert_eq!(parse_ok("2026-03-15T00:00:00Z").offset(), Offset::Utc);
    assert_eq!(
      parse_ok("2026-03-15T00:00:00+00:00").offset(),
      Offset::Fixed(0)
    );
    assert_eq!(
      parse_ok("2026-03-15T00:00:00+05:45").offset(),
      Offset::Fixed(20_700)
    );
    assert_eq!(
      parse_ok("2026-03-15T00:00:00-08:30").offset(),
      Offset::Fixed(-30_600)
    );
    for (spelling, expected) in [("Z", "Z"), ("+00:00", "+00:00"), ("-08:30", "-08:30")] {
      let text = format!("2026-03-15T00:00:00{spelling}");
      assert_eq!(parse_ok(&text).offset().to_string(), expected);
    }
    assert_eq!(parse_ok("2026-03-15T00:00:00").offset().to_string(), "");
  }

  /// Randomly generated valid patterns round-trip through the canonical
  /// form with identical semantics. Hand-rolled xorshift with a fixed seed:
  /// no test dependencies.
  #[test]
  fn random_patterns_round_trip() {
    let mut rng = Rng::new(0x5EED_2026_1114_0808);
    for _ in 0..256 {
      let text = random_pattern(&mut rng);
      let first = parse_ok(&text);
      let canonical = first.to_string();
      let second = parse_ok(&canonical);
      assert_eq!(second.to_string(), canonical, "fixed point of {text:?}");
      assert_eq!(second.offset(), first.offset());
      // Semantics agree on a few probe seconds.
      for probe in [
        values(2026, 3, 15, 12, 0, 0),
        values(2024, 2, 29, 23, 59, 59),
      ] {
        assert_eq!(
          first.matches(probe),
          second.matches(probe),
          "{text:?} at {probe:?}"
        );
      }
    }
  }

  /// A deterministic xorshift* generator (fixed seed, no dependencies).
  struct Rng(u64);

  impl Rng {
    fn new(seed: u64) -> Self {
      Self(seed)
    }

    fn next(&mut self) -> u64 {
      let mut x = self.0;
      x ^= x << 13;
      x ^= x >> 7;
      x ^= x << 17;
      self.0 = x;
      x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
      self.next() % bound
    }
  }

  /// Builds one random valid field: a bare literal or a small braced set of
  /// disjoint literals and ranges (cut from the domain), zero-padded to the
  /// field width.
  fn random_field(rng: &mut Rng, min: u16, max: u16, digits: usize) -> String {
    let render = |value: u16| format!("{value:0digits$}");
    let span = u64::from(max - min + 1);
    if rng.below(4) == 0 {
      return render(min + rng.below(span) as u16);
    }
    let count = (1 + rng.below(3)) as usize;
    let mut cuts: Vec<u64> = Vec::new();
    while cuts.len() < count * 2 {
      let cut = rng.below(span);
      if !cuts.contains(&cut) {
        cuts.push(cut);
      }
    }
    cuts.sort_unstable();
    let elements: Vec<String> = cuts
      .chunks(2)
      .map(|pair| {
        let low = min + pair[0] as u16;
        let high = min + pair[1] as u16;
        if pair[0] == pair[1] {
          render(low)
        } else {
          format!("{}-{}", render(low), render(high))
        }
      })
      .collect();
    format!("{{{}}}", elements.join(","))
  }

  /// Builds one random valid pattern string.
  fn random_pattern(rng: &mut Rng) -> String {
    let year = random_field(rng, 0, 9999, 4);
    let month = random_field(rng, 1, 12, 2);
    let day = random_field(rng, 1, 31, 2);
    let hour = random_field(rng, 0, 23, 2);
    let minute = random_field(rng, 0, 59, 2);
    let second = random_field(rng, 0, 59, 2);
    let offset = ["", "Z", "+09:00"][rng.below(3) as usize];
    format!("{year}-{month}-{day}T{hour}:{minute}:{second}{offset}")
  }

  /// An independent brute-force oracle: inclusive ranges per field with
  /// linear scans and its own civil-calendar stepping. Deliberately shares
  /// no code with the production parser, masks, or search.
  struct Oracle {
    year: Vec<(u16, u16)>,
    month: Vec<(u16, u16)>,
    day: Vec<(u16, u16)>,
    hour: Vec<(u16, u16)>,
    minute: Vec<(u16, u16)>,
    second: Vec<(u16, u16)>,
  }

  impl Oracle {
    /// Parses a pattern with plain string splitting and `u16::from_str`.
    /// The oracle ignores the offset: frames do not affect matching.
    fn parse(text: &str) -> Oracle {
      let (date, rest) = text.split_once('T').expect("oracle: T separator");
      let time_end = rest.find(['+', '-']).unwrap_or(rest.len());
      let time = rest[..time_end].trim_end_matches('Z');
      // Range hyphens live inside braces, so split on '-' but re-merge
      // brace groups across the splits.
      let date = date
        .split('-')
        .fold(Vec::new(), |mut fields: Vec<String>, part| {
          match fields.last_mut() {
            Some(last) if last.starts_with('{') && !last.ends_with('}') => {
              last.push('-');
              last.push_str(part);
            }
            _ => fields.push(part.to_string()),
          }
          fields
        });
      let mut date_fields = date.iter();
      let mut time_fields = time.split(':');
      Oracle {
        year: Self::field(date_fields.next().expect("year"), 0, 9999),
        month: Self::field(date_fields.next().expect("month"), 1, 12),
        day: Self::field(date_fields.next().expect("day"), 1, 31),
        hour: Self::field(time_fields.next().expect("hour"), 0, 23),
        minute: Self::field(time_fields.next().expect("minute"), 0, 59),
        second: Self::field(time_fields.next().expect("second"), 0, 59),
      }
    }

    fn field(text: &str, min: u16, max: u16) -> Vec<(u16, u16)> {
      let inner = text
        .strip_prefix('{')
        .map(|rest| rest.strip_suffix('}').expect("oracle: closed set"))
        .unwrap_or(text);
      inner
        .split(',')
        .map(|element| {
          if element == "*" {
            (min, max)
          } else if let Some((low, high)) = element.split_once('-') {
            (Self::num(low), Self::num(high))
          } else {
            let value = Self::num(element);
            (value, value)
          }
        })
        .collect()
    }

    fn num(text: &str) -> u16 {
      text.parse().expect("oracle: numeric element")
    }

    fn covered(ranges: &[(u16, u16)], value: u16) -> bool {
      ranges
        .iter()
        .any(|&(low, high)| value >= low && value <= high)
    }

    fn matches(&self, values: FieldValues) -> bool {
      Self::covered(&self.year, values.year)
        && Self::covered(&self.month, u16::from(values.month))
        && Self::covered(&self.day, u16::from(values.day))
        && Self::covered(&self.hour, u16::from(values.hour))
        && Self::covered(&self.minute, u16::from(values.minute))
        && Self::covered(&self.second, u16::from(values.second))
    }
  }

  /// Independent civil-calendar day lengths for the stepping oracle.
  fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
      1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
      4 | 6 | 9 | 11 => 30,
      2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => 29,
      2 => 28,
      _ => 0,
    }
  }

  /// Advances one second with civil-calendar carries; `None` past
  /// 9999-12-31T23:59:59.
  fn step(values: FieldValues) -> Option<FieldValues> {
    let mut next = values;
    next.second += 1;
    if next.second == 60 {
      next.second = 0;
      next.minute += 1;
    }
    if next.minute == 60 {
      next.minute = 0;
      next.hour += 1;
    }
    if next.hour == 24 {
      next.hour = 0;
      next.day += 1;
    }
    if next.day > days_in_month(next.year, next.month) {
      next.day = 1;
      next.month += 1;
    }
    if next.month == 13 {
      next.month = 1;
      next.year += 1;
    }
    if next.year > 9999 {
      return None;
    }
    Some(next)
  }

  /// Exhaustive second-stepping next-fire oracle, bounded by `limit` steps.
  fn oracle_next_fire(oracle: &Oracle, start: FieldValues, limit: u64) -> Option<FieldValues> {
    let mut cursor = start;
    for _ in 0..=limit {
      if oracle.matches(cursor) {
        return Some(cursor);
      }
      cursor = step(cursor)?;
    }
    None
  }
}
