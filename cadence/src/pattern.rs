//! The cadence pattern: strict parsing, canonical form, set-membership
//! matching, and ordered next-fire search.
//!
//! Matching is one rule with no special cases: a wall-clock second fires iff
//! each field's value is a member of its compiled set. The crate is
//! clock-blind and timezone-blind — the caller resolves the reference frame
//! (device-local or fixed-offset) and supplies field values in it.

use core::fmt::{self, Write as _};

use crate::calendar::days_in_month;
use crate::error::{ParseError, ParseErrorKind, Result};
use crate::field::{FieldDomain, FieldSet};

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
    if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59
    {
      return None;
    }
    Some(Self { year, month, day, hour, minute, second })
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
        write!(f, "{}{:02}:{:02}", if seconds < 0 { '-' } else { '+' }, magnitude / 3600, magnitude % 3600 / 60)
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
    Ok(Pattern { year, month, day, hour, minute, second, offset })
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
  pub fn r#match(
    &self, year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8,
  ) -> bool {
    self.matches(FieldValues { year, month, day, hour, minute, second })
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
    ParseError::new(ParseErrorKind::Offset, format!("expected 'hh:mm', found {text:?}"))
  })?;
  let hours = parse_offset_component(hours, "hours", 23, text)?;
  let minutes = parse_offset_component(minutes, "minutes", 59, text)?;
  Ok(Offset::Fixed(sign * (i32::from(hours) * 3600 + i32::from(minutes) * 60)))
}

/// Parses one two-digit offset component with an inclusive upper bound.
fn parse_offset_component(text: &str, name: &'static str, max: u8, whole: &str) -> Result<u8> {
  let digits = text.bytes().take_while(|byte| byte.is_ascii_digit()).count();
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
