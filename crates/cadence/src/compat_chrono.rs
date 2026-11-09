//! `chrono` interop.
//!
//! Any `chrono::DateTime<Tz>` converts into field values via [`TryFrom`]
//! (its local civil reading; the frame stays known from the `Tz` you
//! hold). The reverse direction targets `DateTime<FixedOffset>` for the
//! `Utc` and fixed-offset frames; the device-local frame is rejected
//! because choosing among a DST fold's ambiguous readings is a policy
//! the caller must own.
//!
//! ```
//! use chrono::TimeZone;
//!
//! use radiata_cadence::{FieldValues, Pattern};
//!
//! let pattern = Pattern::parse("{*}-{*}-{*}T09:{00,30}:00Z").unwrap();
//! let moment = chrono::Utc.with_ymd_and_hms(2026, 11, 8, 9, 30, 0).unwrap();
//! let values = FieldValues::try_from(moment).unwrap();
//! assert!(pattern.matches(values));
//! ```

use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Timelike};

use crate::{
  TimeInteropError,
  pattern::{FieldValues, Offset},
};

impl<Tz: TimeZone> TryFrom<DateTime<Tz>> for FieldValues {
  type Error = TimeInteropError;

  /// Reads the civil fields of a `chrono` datetime in its local frame.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] when the year falls outside the
  /// crate's 0000-9999 domain.
  fn try_from(value: DateTime<Tz>) -> Result<Self, Self::Error> {
    let naive = value.naive_local();
    let (year, month, day) = (naive.year(), naive.month(), naive.day());
    let (hour, minute, second) = (naive.hour(), naive.minute(), naive.second());
    if !(0..=9999).contains(&year) {
      return Err(TimeInteropError::OutOfRange);
    }
    FieldValues::new(
      year as u16,
      month as u8,
      day as u8,
      hour as u8,
      minute as u8,
      second as u8,
    )
    .ok_or(TimeInteropError::OutOfRange)
  }
}

impl FieldValues {
  /// Converts field values into a `chrono::DateTime<FixedOffset>` in the
  /// given `Utc` or fixed-offset frame.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
  /// frame; [`TimeInteropError::OutOfRange`] when the field values are
  /// not a real civil datetime (e.g. February 30th).
  pub fn to_chrono_fixed(self, frame: Offset) -> Result<DateTime<FixedOffset>, TimeInteropError> {
    let offset_seconds = match frame {
      Offset::Local => return Err(TimeInteropError::LocalFrameUnsupported),
      Offset::Utc => 0,
      Offset::Fixed(seconds) => seconds,
    };
    let offset = FixedOffset::east_opt(offset_seconds).ok_or(TimeInteropError::OutOfRange)?;
    let date = chrono::NaiveDate::from_ymd_opt(
      i32::from(self.year),
      u32::from(self.month),
      u32::from(self.day),
    )
    .ok_or(TimeInteropError::OutOfRange)?;
    let time = chrono::NaiveTime::from_hms_opt(
      u32::from(self.hour),
      u32::from(self.minute),
      u32::from(self.second),
    )
    .ok_or(TimeInteropError::OutOfRange)?;
    let naive_local = date.and_time(time);
    let naive_utc = naive_local
      .checked_sub_signed(chrono::Duration::seconds(i64::from(offset_seconds)))
      .ok_or(TimeInteropError::OutOfRange)?;
    Ok(DateTime::from_naive_utc_and_offset(naive_utc, offset))
  }
}

#[cfg(test)]
mod tests {
  use chrono::{Datelike, TimeZone};

  use crate::pattern::{FieldValues, Offset};

  #[test]
  fn utc_and_fixed_datetimes_convert_into_field_values() {
    let moment = chrono::Utc.with_ymd_and_hms(2026, 11, 8, 9, 30, 0).unwrap();
    assert_eq!(
      FieldValues::try_from(moment).unwrap(),
      FieldValues::new(2026, 11, 8, 9, 30, 0).unwrap()
    );
    let offset = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
    let tokyo = offset.with_ymd_and_hms(2026, 11, 8, 18, 0, 5).unwrap();
    assert_eq!(
      FieldValues::try_from(tokyo).unwrap(),
      FieldValues::new(2026, 11, 8, 18, 0, 5).unwrap()
    );
  }

  #[test]
  fn field_values_convert_back_into_fixed_datetimes() {
    let values = FieldValues::new(2026, 11, 8, 18, 0, 5).unwrap();
    let tokyo = values.to_chrono_fixed(Offset::Fixed(9 * 3600)).unwrap();
    assert_eq!(tokyo.offset().local_minus_utc(), 9 * 3600);
    assert_eq!(
      tokyo.with_timezone(&chrono::Utc),
      chrono::Utc.with_ymd_and_hms(2026, 11, 8, 9, 0, 5).unwrap()
    );
    let utc = values.to_chrono_fixed(Offset::Utc).unwrap();
    assert_eq!(utc.offset().local_minus_utc(), 0);
  }

  #[test]
  fn local_frame_and_non_dates_are_rejected() {
    let values = FieldValues::new(2026, 11, 8, 0, 0, 0).unwrap();
    assert_eq!(
      values.to_chrono_fixed(Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    assert_eq!(
      FieldValues::new(2026, 2, 30, 0, 0, 0)
        .unwrap()
        .to_chrono_fixed(Offset::Utc),
      Err(crate::TimeInteropError::OutOfRange)
    );
  }

  #[test]
  fn year_domain_is_enforced_in_both_directions() {
    let future = chrono::Utc.with_ymd_and_hms(10_000, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
      FieldValues::try_from(future),
      Err(crate::TimeInteropError::OutOfRange)
    );
    let boundary = FieldValues::new(9999, 12, 31, 23, 59, 59).unwrap();
    assert_eq!(boundary.to_chrono_fixed(Offset::Utc).unwrap().year(), 9999);
  }
}
