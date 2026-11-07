//! Parse-failure reporting for the cadence grammar.
//!
//! Every rejection is fail-closed and names the offending text: the parser
//! never guesses, never truncates, and never accepts a prefix of a pattern.

use core::fmt;

/// The reason a pattern string failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
  /// The pattern does not follow the fixed six-field skeleton
  /// `year-month-dayThh:mm:ss` with an optional trailing offset.
  Skeleton,
  /// A bare numeric field or set element does not have the required digit
  /// count (two digits, four for the year).
  DigitCount,
  /// A value is outside its field's domain (second/minute 0-59, hour 0-23,
  /// day 1-31, month 1-12, year 0000-9999).
  Domain,
  /// A range's lower bound exceeds its upper bound.
  RangeOrder,
  /// A set contains the same element twice.
  DuplicateElement,
  /// The trailing offset is malformed or out of range.
  Offset,
}

impl fmt::Display for ParseErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let message = match self {
      Self::Skeleton => "malformed pattern skeleton",
      Self::DigitCount => "wrong digit count",
      Self::Domain => "value outside the field domain",
      Self::RangeOrder => "range lower bound exceeds upper bound",
      Self::DuplicateElement => "duplicate set element",
      Self::Offset => "malformed or out-of-range offset",
    };
    f.write_str(message)
  }
}

/// The error returned when a pattern string fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
  kind: ParseErrorKind,
  detail: String,
}

impl ParseError {
  pub(crate) fn new(kind: ParseErrorKind, detail: impl Into<String>) -> Self {
    Self { kind, detail: detail.into() }
  }

  /// The failure category.
  pub fn kind(&self) -> ParseErrorKind {
    self.kind
  }

  /// The offending text or value, for diagnostics.
  pub fn detail(&self) -> &str {
    &self.detail
  }
}

impl fmt::Display for ParseError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "invalid cadence pattern ({}): {}", self.kind, self.detail)
  }
}

impl std::error::Error for ParseError {}

/// The result alias for pattern parsing.
pub type Result<T> = core::result::Result<T, ParseError>;
