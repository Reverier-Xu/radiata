//! `jiff` interop.
//!
//! [`jiff::Timestamp`] (a UTC instant), [`jiff::Zoned`] (a local reading
//! in a named or system timezone), and [`jiff::civil::DateTime`] (a
//! frame-free civil reading) are [`Cadence`] readings. The reverse
//! direction targets [`jiff::Timestamp`] for the `Utc` and fixed-offset
//! frames and [`jiff::civil::DateTime`] for frame-agnostic civil
//! readings.
//!
//! The device-local frame is rejected on the timestamp path: picking a
//! reading for the device's current zone is the caller's
//! `TimeZone::system()` decision — wrap the instant into a
//! [`jiff::Zoned`] and pass that.
//!
//! ```
//! use radiata_cadence::Ticker;
//!
//! let ticker = Ticker::parse("{*}-{*}-{*}T09:{00,30}:00Z").unwrap();
//! let moment: jiff::Timestamp = "2026-11-08T09:30:00Z".parse().unwrap();
//! assert!(ticker.fires_at(&moment));
//! ```

use crate::{
  Cadence, Civil, TimeInteropError,
  epoch::{civil_to_unix_seconds, unix_seconds_to_civil},
  ticker::Offset,
};

impl Cadence for jiff::Timestamp {
  /// Reads the instant as one civil second in `frame` (`Utc` or a fixed
  /// offset).
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
  /// frame (hold a `jiff::Zoned` instead);
  /// [`TimeInteropError::OutOfRange`] outside the crate's 0000-9999
  /// civil year domain.
  fn to_civil(&self, frame: Offset) -> Result<Civil, TimeInteropError> {
    match frame {
      Offset::Local => Err(TimeInteropError::LocalFrameUnsupported),
      frame => unix_seconds_to_civil(self.as_second(), frame),
    }
  }
}

impl Cadence for jiff::Zoned {
  /// Reads the zoned reading as one civil second in `frame`: the wall
  /// clock of the zone it carries for the device-local frame (build it
  /// with `TimeZone::system()` for the device's), its instant shifted
  /// into the frame otherwise.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] outside the crate's 0000-9999
  /// civil year domain.
  fn to_civil(&self, frame: Offset) -> Result<Civil, TimeInteropError> {
    match frame {
      Offset::Local => civil_from_jiff(self.datetime()),
      frame => unix_seconds_to_civil(self.timestamp().as_second(), frame),
    }
  }
}

impl Cadence for jiff::civil::DateTime {
  /// A civil datetime is frame-free: it passes through unchanged.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] outside the crate's 0000-9999
  /// civil year domain.
  fn to_civil(&self, _frame: Offset) -> Result<Civil, TimeInteropError> {
    civil_from_jiff(*self)
  }
}

/// Reads a `jiff` civil datetime as one civil second.
fn civil_from_jiff(civil: jiff::civil::DateTime) -> Result<Civil, TimeInteropError> {
  let year = civil.year();
  if !(0..=9999).contains(&year) {
    return Err(TimeInteropError::OutOfRange);
  }
  Civil::new(
    year as u16,
    civil.month() as u8,
    civil.day() as u8,
    civil.hour() as u8,
    civil.minute() as u8,
    civil.second() as u8,
  )
  .ok_or(TimeInteropError::OutOfRange)
}

impl Civil {
  /// Converts the civil second into a `jiff::Timestamp` in the given
  /// `Utc` or fixed-offset frame.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
  /// frame; [`TimeInteropError::OutOfRange`] when the instant falls
  /// outside `jiff`'s representable range.
  pub fn to_jiff_timestamp(self, frame: Offset) -> Result<jiff::Timestamp, TimeInteropError> {
    let seconds = civil_to_unix_seconds(self, frame)?;
    jiff::Timestamp::from_second(seconds).map_err(|_| TimeInteropError::OutOfRange)
  }

  /// Converts the civil second into a frame-agnostic
  /// [`jiff::civil::DateTime`].
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] when the civil second is not a
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
  use super::{Cadence as _, Civil, Offset};

  /// The civil shape of the readings under test, as a comparable value.
  fn civil(text: &str) -> Civil {
    text.parse().expect("in-domain reading")
  }

  #[test]
  fn timestamps_round_trip_through_civil_seconds() {
    let moment: jiff::Timestamp = "2026-11-08T09:30:05Z".parse().unwrap();
    let values = moment.to_civil(Offset::Utc).unwrap();
    assert_eq!(values, civil("2026-11-08T09:30:05"));
    assert_eq!(values.to_jiff_timestamp(Offset::Utc).unwrap(), moment);
  }

  #[test]
  fn fixed_frames_shift_the_instant_not_the_fields() {
    let values = civil("2026-11-08T18:00:00");
    let tokyo = values.to_jiff_timestamp(Offset::Fixed(9 * 3600)).unwrap();
    let utc = values.to_jiff_timestamp(Offset::Utc).unwrap();
    assert_eq!(tokyo.as_second(), utc.as_second() - 9 * 3600);
    assert_eq!(
      tokyo.to_civil(Offset::Fixed(9 * 3600)).unwrap(),
      civil("2026-11-08T18:00:00")
    );
  }

  #[test]
  fn zoned_readings_read_their_zone_for_the_local_frame() {
    let zone = jiff::tz::TimeZone::fixed(jiff::tz::offset(9));
    let zoned = "2026-11-08T18:00:05[+09:00]"
      .parse::<jiff::Zoned>()
      .unwrap()
      .with_time_zone(zone);
    assert_eq!(
      zoned.to_civil(Offset::Local).unwrap(),
      civil("2026-11-08T18:00:05")
    );
    // Declared frames convert the instant the zoned reading carries.
    assert_eq!(
      zoned.to_civil(Offset::Utc).unwrap(),
      civil("2026-11-08T09:00:05")
    );
  }

  #[test]
  fn civil_conversions_validate_real_dates() {
    let values = civil("2026-11-08T09:30:05");
    let jiff_civil = values.to_jiff_civil().unwrap();
    assert_eq!(jiff_civil.year(), 2026);
    assert_eq!(jiff_civil.to_civil(Offset::Utc).unwrap().year(), 2026);
    assert_eq!(
      crate::civil::Civil::new(2026, 2, 30, 0, 0, 0)
        .unwrap()
        .to_jiff_civil(),
      Err(crate::TimeInteropError::OutOfRange)
    );
  }

  #[test]
  fn local_frame_and_domain_bounds_are_enforced() {
    let values = civil("2026-11-08T00:00:00");
    assert_eq!(
      values.to_jiff_timestamp(Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    let timestamp: jiff::Timestamp = "2026-11-08T00:00:00Z".parse().unwrap();
    assert_eq!(
      timestamp.to_civil(Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    let year_10_000 = crate::civil::Civil::new(10_000, 1, 1, 0, 0, 0).unwrap();
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
