//! One pattern field: a braced selection set compiled to a membership mask.
//!
//! The grammar's brace rule gives every field exactly two spellings — a
//! braced set `{...}` or a bare single numeric literal — which keeps `-`
//! unambiguous between the date separator and range syntax. Bare `*`, bare
//! ranges, and bare enumerations are syntax errors.
//!
//! A set element whose full range is already covered by earlier elements is
//! rejected as a duplicate; partially overlapping elements are allowed and
//! coalesce in the canonical form.

use crate::error::{ParseError, ParseErrorKind, Result};

/// The inclusive value domain and element width of one pattern field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldDomain {
  name: &'static str,
  digits: usize,
  min: u16,
  max: u16,
}

impl FieldDomain {
  pub(crate) const YEAR: Self = Self { name: "year", digits: 4, min: 0, max: 9999 };
  pub(crate) const MONTH: Self = Self { name: "month", digits: 2, min: 1, max: 12 };
  pub(crate) const DAY: Self = Self { name: "day", digits: 2, min: 1, max: 31 };
  pub(crate) const HOUR: Self = Self { name: "hour", digits: 2, min: 0, max: 23 };
  pub(crate) const MINUTE: Self = Self { name: "minute", digits: 2, min: 0, max: 59 };
  pub(crate) const SECOND: Self = Self { name: "second", digits: 2, min: 0, max: 59 };
}

/// A compiled per-field selection set.
///
/// Membership is a plain bit test against a mask covering the field's whole
/// domain; [`FieldSet::next_at`] drives the ordered next-fire search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldSet {
  domain: FieldDomain,
  /// `true` when the set was declared with `*` (the full domain).
  wildcard: bool,
  /// Bit `v` of word `v / 64` is set iff value `v` is a member.
  mask: Vec<u64>,
}

impl FieldSet {
  /// Parses one field: a braced set or a bare single numeric literal.
  ///
  /// Returns the compiled set and the unconsumed remainder of the input.
  pub(crate) fn parse(text: &str, domain: FieldDomain) -> Result<(Self, &str)> {
    if let Some(rest) = text.strip_prefix('{') {
      let end = rest.find('}').ok_or_else(|| {
        ParseError::new(ParseErrorKind::Skeleton, format!("unterminated set in {} field", domain.name))
      })?;
      let set = Self::parse_set(&rest[..end], domain)?;
      Ok((set, &rest[end + 1..]))
    } else {
      let digits = text.bytes().take_while(|byte| byte.is_ascii_digit()).count();
      if digits == 0 {
        return Err(ParseError::new(
          ParseErrorKind::Skeleton,
          format!("expected {} field", domain.name),
        ));
      }
      if digits != domain.digits {
        return Err(ParseError::new(
          ParseErrorKind::DigitCount,
          format!(
            "{} field: {:?} must have exactly {} digits",
            domain.name, &text[..digits], domain.digits
          ),
        ));
      }
      let value = Self::parse_number(&text[..digits], domain)?;
      Ok((Self::single(domain, value), &text[digits..]))
    }
  }

  /// Parses the inside of a braced set: a non-empty comma-separated list of
  /// `*`, literal, and range elements with no duplicates.
  fn parse_set(text: &str, domain: FieldDomain) -> Result<Self> {
    if text.is_empty() {
      return Err(ParseError::new(
        ParseErrorKind::Skeleton,
        format!("{} field: empty set", domain.name),
      ));
    }
    let mut set = Self::empty(domain);
    for element in text.split(',') {
      if element == "*" {
        if set.wildcard {
          return Err(ParseError::new(
            ParseErrorKind::DuplicateElement,
            format!("{} field: duplicate `*`", domain.name),
          ));
        }
        set.wildcard = true;
        continue;
      }
      let (low, high) = Self::parse_element(element, domain)?;
      if (low..=high).all(|value| set.contains(value)) {
        return Err(ParseError::new(
          ParseErrorKind::DuplicateElement,
          format!("{} field: duplicate element {element:?}", domain.name),
        ));
      }
      for value in low..=high {
        set.set_bit(value);
      }
    }
    if set.wildcard {
      for value in 0..=domain.max {
        set.set_bit(value);
      }
    } else if set.mask.iter().all(|word| *word == 0) {
      return Err(ParseError::new(
        ParseErrorKind::Skeleton,
        format!("{} field: empty set", domain.name),
      ));
    }
    Ok(set)
  }

  /// Parses one set element: a literal or an inclusive `low-high` range.
  fn parse_element(element: &str, domain: FieldDomain) -> Result<(u16, u16)> {
    let (low, high) = match element.split_once('-') {
      Some((low, high)) => (Self::parse_number(low, domain)?, Self::parse_number(high, domain)?),
      None => {
        let value = Self::parse_number(element, domain)?;
        (value, value)
      }
    };
    if low > high {
      return Err(ParseError::new(
        ParseErrorKind::RangeOrder,
        format!("{} field: {element:?} descends", domain.name),
      ));
    }
    Ok((low, high))
  }

  /// Parses a zero-padded two- or four-digit numeric element.
  fn parse_number(text: &str, domain: FieldDomain) -> Result<u16> {
    if text.len() != domain.digits || !text.bytes().all(|byte| byte.is_ascii_digit()) {
      return Err(ParseError::new(
        ParseErrorKind::DigitCount,
        format!(
          "{} field: {text:?} must have exactly {} digits",
          domain.name, domain.digits
        ),
      ));
    }
    let value = text.bytes().fold(0u32, |acc, byte| acc * 10 + u32::from(byte - b'0'));
    if value < u32::from(domain.min) || value > u32::from(domain.max) {
      return Err(ParseError::new(
        ParseErrorKind::Domain,
        format!("{} field: {value} outside {}-{}", domain.name, domain.min, domain.max),
      ));
    }
    Ok(value as u16)
  }

  fn empty(domain: FieldDomain) -> Self {
    let words = usize::from(domain.max) / 64 + 1;
    Self { domain, wildcard: false, mask: vec![0; words] }
  }

  fn single(domain: FieldDomain, value: u16) -> Self {
    let mut set = Self::empty(domain);
    set.set_bit(value);
    set
  }

  fn set_bit(&mut self, value: u16) {
    let index = usize::from(value);
    self.mask[index / 64] |= 1 << (index % 64);
  }

  /// Returns `true` when `value` is a member of the set.
  pub(crate) fn contains(&self, value: u16) -> bool {
    if value > self.domain.max {
      return false;
    }
    let index = usize::from(value);
    self.mask[index / 64] & (1 << (index % 64)) != 0
  }

  /// Returns the smallest member greater than or equal to `value`.
  pub(crate) fn next_at(&self, value: u16) -> Option<u16> {
    if self.contains(value) {
      return Some(value);
    }
    let start = usize::from(value) + 1;
    if start > usize::from(self.domain.max) {
      return None;
    }
    let mut index = start;
    for word in &self.mask[index / 64..] {
      let significant = word >> (index % 64);
      if significant != 0 {
        return Some((index + significant.trailing_zeros() as usize) as u16);
      }
      index = (index / 64 + 1) * 64;
    }
    None
  }

  /// Appends the canonical form: `{*}` for a wildcard declaration, else the
  /// sorted, coalesced list of inclusive runs over the domain.
  pub(crate) fn write_canonical(&self, out: &mut String) {
    out.push('{');
    if self.wildcard {
      out.push('*');
    } else {
      let mut runs = Vec::new();
      let mut value = 0u16;
      while let Some(low) = self.next_at(value) {
        let mut high = low;
        while high < self.domain.max && self.contains(high + 1) {
          high += 1;
        }
        let mut run = format!("{low:0width$}", width = self.domain.digits);
        if high != low {
          run.push('-');
          run.push_str(&format!("{high:0width$}", width = self.domain.digits));
        }
        runs.push(run);
        if high == self.domain.max {
          break;
        }
        value = high + 1;
      }
      out.push_str(&runs.join(","));
    }
    out.push('}');
  }
}

#[cfg(test)]
mod tests {
  use super::{FieldDomain, FieldSet};
  use crate::error::ParseErrorKind;

  /// Renders a set's canonical form.
  fn canonical(text: &str, domain: FieldDomain) -> String {
    let (set, rest) = FieldSet::parse(text, domain).expect("valid field");
    assert_eq!(rest, "");
    let mut out = String::new();
    set.write_canonical(&mut out);
    out
  }

  #[test]
  fn bare_literals_parse_and_render_zero_padded() {
    assert_eq!(canonical("09", FieldDomain::HOUR), "{09}");
    assert_eq!(canonical("59", FieldDomain::SECOND), "{59}");
    assert_eq!(canonical("2026", FieldDomain::YEAR), "{2026}");
  }

  #[test]
  fn wildcard_renders_as_star() {
    assert_eq!(canonical("{*}", FieldDomain::MINUTE), "{*}");
    assert_eq!(canonical("{*,07}", FieldDomain::MINUTE), "{*}");
    assert_eq!(canonical("{00-59}", FieldDomain::MINUTE), "{00-59}");
  }

  #[test]
  fn sets_coalesce_into_sorted_runs() {
    assert_eq!(canonical("{09-12,03}", FieldDomain::MONTH), "{03,09-12}");
    assert_eq!(canonical("{01-03,03-05}", FieldDomain::MONTH), "{01-05}");
    assert_eq!(canonical("{30,00-05,20}", FieldDomain::SECOND), "{00-05,20,30}");
    assert_eq!(canonical("{03-03}", FieldDomain::DAY), "{03}");
    assert_eq!(canonical("{10,11,12}", FieldDomain::MONTH), "{10-12}");
  }

  #[test]
  fn rejects_malformed_fields() {
    let cases: &[(&str, FieldDomain, ParseErrorKind)] = &[
      ("*", FieldDomain::HOUR, ParseErrorKind::Skeleton),
      ("1-5", FieldDomain::HOUR, ParseErrorKind::DigitCount),
      ("1", FieldDomain::HOUR, ParseErrorKind::DigitCount),
      ("012", FieldDomain::HOUR, ParseErrorKind::DigitCount),
      ("1a", FieldDomain::HOUR, ParseErrorKind::DigitCount),
      ("60", FieldDomain::HOUR, ParseErrorKind::Domain),
      ("00", FieldDomain::DAY, ParseErrorKind::Domain),
      ("00", FieldDomain::MONTH, ParseErrorKind::Domain),
      ("{00}", FieldDomain::DAY, ParseErrorKind::Domain),
      ("{00-31}", FieldDomain::DAY, ParseErrorKind::Domain),
      ("32", FieldDomain::DAY, ParseErrorKind::Domain),
      ("13", FieldDomain::MONTH, ParseErrorKind::Domain),
      ("10000", FieldDomain::YEAR, ParseErrorKind::DigitCount),      ("{05-02}", FieldDomain::MONTH, ParseErrorKind::RangeOrder),
      ("{,}", FieldDomain::MONTH, ParseErrorKind::DigitCount),
      ("{05,}", FieldDomain::MONTH, ParseErrorKind::DigitCount),
      ("{05,05}", FieldDomain::MONTH, ParseErrorKind::DuplicateElement),
      ("{05,05-05}", FieldDomain::MONTH, ParseErrorKind::DuplicateElement),
      ("{01-05,03}", FieldDomain::MONTH, ParseErrorKind::DuplicateElement),
      ("{*,*}", FieldDomain::MONTH, ParseErrorKind::DuplicateElement),
      ("{05 05}", FieldDomain::MONTH, ParseErrorKind::DigitCount),
      ("{0x}", FieldDomain::MONTH, ParseErrorKind::DigitCount),
    ];
    for (text, domain, kind) in cases {
      let error = FieldSet::parse(text, *domain).expect_err(text);
      assert_eq!(error.kind(), *kind, "{text}: {}", error);
    }
  }

  #[test]
  fn empty_set_is_rejected() {
    let error = FieldSet::parse("{}", FieldDomain::MONTH).expect_err("empty set");
    assert_eq!(error.kind(), ParseErrorKind::Skeleton);
  }

  #[test]
  fn unterminated_set_is_rejected() {
    let error = FieldSet::parse("{05,06", FieldDomain::MONTH).expect_err("unterminated");
    assert_eq!(error.kind(), ParseErrorKind::Skeleton);
  }

  #[test]
  fn membership_matches_parsed_elements() {
    let (set, _) = FieldSet::parse("{09-12,03}", FieldDomain::MONTH).expect("valid");
    for value in 0..=13u16 {
      let expected = value == 3 || (9..=12).contains(&value);
      assert_eq!(set.contains(value), expected, "month {value}");
    }
    assert!(!set.contains(u16::MAX));
  }

  #[test]
  fn wildcard_membership_covers_the_domain() {
    let (set, _) = FieldSet::parse("{*}", FieldDomain::MONTH).expect("valid");
    assert!((0..=12).all(|value| set.contains(value)));
    assert!(!set.contains(13));
  }

  #[test]
  fn next_at_scans_past_word_boundaries() {
    let (set, _) = FieldSet::parse("{0063,0065,0127}", FieldDomain::YEAR).expect("valid");
    assert_eq!(set.next_at(0), Some(63));
    assert_eq!(set.next_at(63), Some(63));
    assert_eq!(set.next_at(64), Some(65));
    assert_eq!(set.next_at(127), Some(127));
    assert_eq!(set.next_at(128), None);
    assert_eq!(set.next_at(9999), None);
  }

  #[test]
  fn next_at_respects_domain_boundaries() {
    let (set, _) = FieldSet::parse("{00-23}", FieldDomain::HOUR).expect("valid");
    assert_eq!(set.next_at(5), Some(5));
    assert_eq!(set.next_at(23), Some(23));
    assert_eq!(set.next_at(24), None);
  }

  #[test]
  fn day_and_year_domains_stay_wide() {
    // The day field's domain stays 1-31 and the year's 0000-9999; calendar
    // validity is next-fire's concern, not membership's.
    let (day, _) = FieldSet::parse("{31}", FieldDomain::DAY).expect("valid");
    assert!(day.contains(31));
    let (year, _) = FieldSet::parse("{0000-9999}", FieldDomain::YEAR).expect("valid");
    assert!(year.contains(0) && year.contains(9999));
  }
}
