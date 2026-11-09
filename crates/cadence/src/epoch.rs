//! Unix-epoch plumbing for instant-style readings: the civil-string
//! instant path and the `std-time`/`jiff` interop features.
//!
//! The civil calendar arithmetic (Hinnant's `days_from_civil` /
//! `civil_from_days`) lives here once so every conversion surface —
//! offset-carrying strings, `SystemTime`, `jiff::Timestamp` — cannot
//! drift on epoch semantics.

use crate::{civil::Civil, ticker::Offset};

const SECS_PER_DAY: i64 = 86_400;

/// The days from 1970-01-01 to the given proleptic-Gregorian civil date.
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
  let shifted_year = if month <= 2 { year - 1 } else { year };
  let era = if shifted_year >= 0 {
    shifted_year
  } else {
    shifted_year - 399
  } / 400;
  let year_of_era = shifted_year - era * 400;
  let month_pattern = (i64::from(month) + 9) % 12;
  let day_of_year = (153 * month_pattern + 2) / 5 + i64::from(day) - 1;
  let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  era * 146_097 + day_of_era - 719_468
}

/// The proleptic-Gregorian civil date `days` after 1970-01-01.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
  let shifted = days + 719_468;
  let era = if shifted >= 0 {
    shifted
  } else {
    shifted - 146_096
  } / 146_097;
  let day_of_era = shifted - era * 146_097;
  let year_of_era =
    (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
  let year = year_of_era + era * 400;
  let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  let month_pattern = (5 * day_of_year + 2) / 153;
  let day = day_of_year - (153 * month_pattern + 2) / 5 + 1;
  let month = if month_pattern < 10 {
    month_pattern + 3
  } else {
    month_pattern - 9
  };
  (
    if month <= 2 { year + 1 } else { year },
    month as u32,
    day as u32,
  )
}

/// The reference frame's offset in seconds east of UTC, `None` for the
/// device-local frame (unresolvable without a timezone-aware library).
pub(crate) fn frame_offset_seconds(frame: Offset) -> Option<i64> {
  match frame {
    Offset::Local => None,
    Offset::Utc => Some(0),
    Offset::Fixed(seconds) => Some(i64::from(seconds)),
  }
}

/// Converts a civil second in a resolvable frame into unix-epoch
/// seconds.
pub(crate) fn civil_to_unix_seconds(
  civil: Civil, frame: Offset,
) -> Result<i64, crate::TimeInteropError> {
  let offset = frame_offset_seconds(frame).ok_or(crate::TimeInteropError::LocalFrameUnsupported)?;
  if civil.year > 9999 {
    return Err(crate::TimeInteropError::OutOfRange);
  }
  let days = days_from_civil(
    i64::from(civil.year),
    u32::from(civil.month),
    u32::from(civil.day),
  );
  let time_of_day =
    i64::from(civil.hour) * 3600 + i64::from(civil.minute) * 60 + i64::from(civil.second);
  days
    .checked_mul(SECS_PER_DAY)
    .and_then(|day_secs| day_secs.checked_add(time_of_day))
    .and_then(|civil_secs| civil_secs.checked_sub(offset))
    .ok_or(crate::TimeInteropError::OutOfRange)
}

/// Converts unix-epoch seconds plus a frame offset into a civil second,
/// rejecting instants outside the crate's 0000-9999 civil year domain.
pub(crate) fn unix_seconds_to_civil(
  seconds: i64, frame: Offset,
) -> Result<Civil, crate::TimeInteropError> {
  let offset = frame_offset_seconds(frame).ok_or(crate::TimeInteropError::LocalFrameUnsupported)?;
  let shifted = seconds
    .checked_add(offset)
    .ok_or(crate::TimeInteropError::OutOfRange)?;
  let days = shifted.div_euclid(SECS_PER_DAY);
  let remainder = shifted.rem_euclid(SECS_PER_DAY);
  let (year, month, day) = civil_from_days(days);
  if !(0..=9999).contains(&year) {
    return Err(crate::TimeInteropError::OutOfRange);
  }
  Civil::new(
    year as u16,
    month as u8,
    day as u8,
    (remainder / 3600) as u8,
    (remainder % 3600 / 60) as u8,
    (remainder % 60) as u8,
  )
  .ok_or(crate::TimeInteropError::OutOfRange)
}

#[cfg(test)]
mod tests {
  use super::{civil_from_days, days_from_civil};

  #[test]
  fn epoch_round_trips_across_eras_and_boundaries() {
    for days in [-719_468, -719_162, -1, 0, 1, 19_000, 11_016, 293_2896] {
      let (year, month, day) = civil_from_days(days);
      assert_eq!(days_from_civil(year, month, day), days, "days={days}");
    }
  }

  #[test]
  fn known_dates_map_to_known_days() {
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(days_from_civil(1900, 3, 1), -25_508);
    assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(civil_from_days(11_017), (2000, 3, 1));
  }
}
