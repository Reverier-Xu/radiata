//! `jiff` interop.
//!
//! [`jiff::Timestamp`] (a UTC instant) and [`jiff::Zoned`] (a local
//! reading in a named or system timezone) convert into field values via
//! [`TryFrom`]; the reverse direction targets [`jiff::Timestamp`] for the
//! `Utc` and fixed-offset frames and [`jiff::civil::DateTime`] for
//! frame-agnostic civil readings. The device-local frame is rejected on
//! the timestamp path: picking a reading for the device's current zone is
//! the caller's `TimeZone::system()` decision.
//!
//! ```
//! use radiata_cadence::{FieldValues, Pattern};
//!
//! let pattern = Pattern::parse("{*}-{*}-{*}T09:{00,30}:00Z").unwrap();
//! let moment: jiff::Timestamp = "2026-11-08T09:30:00Z".parse().unwrap();
//! let values = FieldValues::try_from(moment).unwrap();
//! assert!(pattern.matches(values));
//! ```

use crate::{
  TimeInteropError,
  epoch::{field_values_to_unix_seconds, unix_seconds_to_field_values},
  pattern::{FieldValues, Offset},
};

impl TryFrom<jiff::Timestamp> for FieldValues {
  type Error = TimeInteropError;

  /// Reads a `jiff` instant as field values in the `Utc` frame.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] when the instant falls outside the
  /// crate's 0000-9999 civil year domain.
  fn try_from(value: jiff::Timestamp) -> Result<Self, Self::Error> {
    unix_seconds_to_field_values(value.as_second(), Offset::Utc)
  }
}

impl TryFrom<&jiff::Zoned> for FieldValues {
  type Error = TimeInteropError;

  /// Reads the local civil fields of a zoned `jiff` datetime — the path
  /// for `Offset::Local` patterns: resolve the device zone once with
  /// `jiff::TimeZone::system()`, convert the reading, match or search.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] when the reading falls outside the
  /// crate's 0000-9999 civil year domain.
  fn try_from(value: &jiff::Zoned) -> Result<Self, Self::Error> {
    let civil = value.datetime();
    if civil.year() < 0 {
      return Err(TimeInteropError::OutOfRange);
    }
    FieldValues::new(
      civil.year() as u16,
      civil.month() as u8,
      civil.day() as u8,
      civil.hour() as u8,
      civil.minute() as u8,
      civil.second() as u8,
    )
    .ok_or(TimeInteropError::OutOfRange)
  }
}

impl TryFrom<jiff::civil::DateTime> for FieldValues {
  type Error = TimeInteropError;

  /// Reads a `jiff` civil datetime as field values.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] when the year falls outside the
  /// crate's 0000-9999 domain.
  fn try_from(value: jiff::civil::DateTime) -> Result<Self, Self::Error> {
    if value.year() < 0 {
      return Err(TimeInteropError::OutOfRange);
    }
    FieldValues::new(
      value.year() as u16,
      value.month() as u8,
      value.day() as u8,
      value.hour() as u8,
      value.minute() as u8,
      value.second() as u8,
    )
    .ok_or(TimeInteropError::OutOfRange)
  }
}

impl FieldValues {
  /// Converts field values into a `jiff::Timestamp` in the given `Utc`
  /// or fixed-offset frame.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
  /// frame; [`TimeInteropError::OutOfRange`] when the instant falls
  /// outside `jiff`'s representable range.
  pub fn to_jiff_timestamp(self, frame: Offset) -> Result<jiff::Timestamp, TimeInteropError> {
    let seconds = field_values_to_unix_seconds(self, frame)?;
    jiff::Timestamp::from_second(seconds).map_err(|_| TimeInteropError::OutOfRange)
  }

  /// Converts field values into a frame-agnostic
  /// [`jiff::civil::DateTime`].
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] when the field values are not a
  /// real civil datetime (e.g. February 30th) — `jiff` validates civil
  /// dates where this crate's matching semantics do not.
  pub fn to_jiff_civil(self) -> Result<jiff::civil::DateTime, TimeInteropError> {
    jiff::civil::DateTime::new(
      i16::try_from(self.year).map_err(|_| TimeInteropError::OutOfRange)?,
      i8::try_from(self.month).map_err(|_| TimeInteropError::OutOfRange)?,
      i8::try_from(self.day).map_err(|_| TimeInteropError::OutOfRange)?,
      i8::try_from(self.hour).map_err(|_| TimeInteropError::OutOfRange)?,
      i8::try_from(self.minute).map_err(|_| TimeInteropError::OutOfRange)?,
      i8::try_from(self.second).map_err(|_| TimeInteropError::OutOfRange)?,
      0,
    )
    .map_err(|_| TimeInteropError::OutOfRange)
  }
}

#[cfg(test)]
mod tests {
  use crate::pattern::{FieldValues, Offset};

  #[test]
  fn timestamps_round_trip_through_field_values() {
    let moment: jiff::Timestamp = "2026-11-08T09:30:05Z".parse().unwrap();
    let values = FieldValues::try_from(moment).unwrap();
    assert_eq!(values, FieldValues::new(2026, 11, 8, 9, 30, 5).unwrap());
    assert_eq!(values.to_jiff_timestamp(Offset::Utc).unwrap(), moment);
  }

  #[test]
  fn fixed_frames_shift_the_instant_not_the_fields() {
    let values = FieldValues::new(2026, 11, 8, 18, 0, 0).unwrap();
    let tokyo = values.to_jiff_timestamp(Offset::Fixed(9 * 3600)).unwrap();
    let utc = values.to_jiff_timestamp(Offset::Utc).unwrap();
    assert_eq!(tokyo.as_second(), utc.as_second() - 9 * 3600);
    assert_eq!(
      FieldValues::try_from(tokyo).unwrap(),
      FieldValues::new(2026, 11, 8, 9, 0, 0).unwrap()
    );
  }

  #[test]
  fn zoned_readings_convert_in_their_local_civil_form() {
    let zone = jiff::tz::TimeZone::fixed(jiff::tz::offset(9));
    let zoned = "2026-11-08T18:00:05[+09:00]"
      .parse::<jiff::Zoned>()
      .unwrap()
      .with_time_zone(zone);
    assert_eq!(
      FieldValues::try_from(&zoned).unwrap(),
      FieldValues::new(2026, 11, 8, 18, 0, 5).unwrap()
    );
  }

  #[test]
  fn civil_conversions_validate_real_dates() {
    let values = FieldValues::new(2026, 11, 8, 9, 30, 5).unwrap();
    let civil = values.to_jiff_civil().unwrap();
    assert_eq!(civil.year(), 2026);
    assert_eq!(
      FieldValues::try_from(civil)
        .expect("jiff civil years are i16")
        .year,
      2026
    );
    assert_eq!(
      FieldValues::new(2026, 2, 30, 0, 0, 0)
        .unwrap()
        .to_jiff_civil(),
      Err(crate::TimeInteropError::OutOfRange)
    );
  }

  #[test]
  fn local_frame_and_domain_bounds_are_enforced() {
    let values = FieldValues::new(2026, 11, 8, 0, 0, 0).unwrap();
    assert_eq!(
      values.to_jiff_timestamp(Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    let year_10_000 = FieldValues::new(10_000, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
      year_10_000.to_jiff_timestamp(Offset::Utc),
      Err(crate::TimeInteropError::OutOfRange)
    );
    assert_eq!(
      year_10_000.to_jiff_civil(),
      Err(crate::TimeInteropError::OutOfRange)
    );
  }
}
