//! Minimal proleptic-Gregorian civil calendar arithmetic.
//!
//! The crate is clock-blind and timezone-blind, but next-fire search needs
//! real month lengths and leap years so that nonexistent dates (February
//! 30th, non-leap February 29ths) are never produced.

/// Returns `true` when `year` is a leap year in the proleptic Gregorian
/// calendar.
pub(crate) fn is_leap(year: u16) -> bool {
  year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Returns the number of days in `month` (1-12) of `year`.
///
/// Returns `0` for out-of-domain months so that callers can never observe a
/// valid day count for an invalid month.
pub(crate) fn days_in_month(year: u16, month: u8) -> u8 {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
    4 | 6 | 9 | 11 => 30,
    2 if is_leap(year) => 29,
    2 => 28,
    _ => 0,
  }
}

#[cfg(test)]
mod tests {
  use super::{days_in_month, is_leap};

  #[test]
  fn leap_years_follow_the_gregorian_rule() {
    assert!(is_leap(2024));
    assert!(is_leap(2000));
    assert!(!is_leap(1900));
    assert!(!is_leap(2023));
    assert!(is_leap(0));
    assert!(!is_leap(100));
    assert!(is_leap(400));
  }

  #[test]
  fn month_lengths_match_the_civil_calendar() {
    let expected = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for month in 1..=12u8 {
      assert_eq!(days_in_month(2026, month), expected[usize::from(month)]);
    }
  }

  #[test]
  fn february_tracks_the_leap_year() {
    assert_eq!(days_in_month(2024, 2), 29);
    assert_eq!(days_in_month(2000, 2), 29);
    assert_eq!(days_in_month(1900, 2), 28);
    assert_eq!(days_in_month(2026, 2), 28);
  }

  #[test]
  fn out_of_domain_months_report_zero_days() {
    assert_eq!(days_in_month(2026, 0), 0);
    assert_eq!(days_in_month(2026, 13), 0);
  }
}
