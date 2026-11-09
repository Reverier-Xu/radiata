//! `std::time::SystemTime` interop for `Utc` and fixed-offset frames.
//!
//! The device-local frame is deliberately unsupported here: `std` has no
//! timezone database, so resolving local wall-clock readings requires a
//! timezone-aware library (enable `chrono` or `jiff` for that).
//!
//! Sub-second readings truncate toward negative infinity, matching the
//! crate's ordering discipline: a reading maps to the schedule second it
//! falls in, never the one after.
//!
//! ```
//! use std::time::{Duration, UNIX_EPOCH};
//!
//! use radiata_cadence::Ticker;
//!
//! let ticker = Ticker::parse("{*}-{*}-{*}T00:00:00Z").unwrap();
//! assert!(ticker.fires_at(&UNIX_EPOCH));
//! let next = ticker.next_fire(&(UNIX_EPOCH + Duration::from_secs(1))).unwrap();
//! assert_eq!(next.to_string(), "1970-01-02T00:00:00");
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
  Cadence, Civil, TimeInteropError,
  epoch::{civil_to_unix_seconds, unix_seconds_to_civil},
  ticker::Offset,
};

impl Cadence for SystemTime {
  /// Reads the instant as one civil second in `frame` (`Utc` or a fixed
  /// offset; the device-local frame needs a timezone-aware library).
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
  /// frame; [`TimeInteropError::OutOfRange`] outside the crate's
  /// 0000-9999 civil year domain.
  fn to_civil(&self, frame: Offset) -> Result<Civil, TimeInteropError> {
    // Floor toward negative infinity: a pre-epoch reading with a
    // sub-second remainder belongs to the earlier schedule second.
    let seconds = match self.duration_since(UNIX_EPOCH) {
      Ok(past_epoch) => past_epoch.as_secs() as i64,
      Err(before_epoch) => {
        let whole = before_epoch.duration().as_secs() as i64;
        if before_epoch.duration().subsec_nanos() > 0 {
          -(whole + 1)
        } else {
          -whole
        }
      }
    };
    unix_seconds_to_civil(seconds, frame)
  }
}

impl Civil {
  /// Converts the civil second in a `Utc` or fixed-offset frame into a
  /// `SystemTime` instant.
  ///
  /// ```
  /// use std::time::{Duration, UNIX_EPOCH};
  ///
  /// use radiata_cadence::{Cadence, Civil, Offset};
  ///
  /// let civil: Civil = "2026-11-08T00:00:00".parse().unwrap();
  /// let time = civil.to_system_time(Offset::Utc).unwrap();
  /// assert_eq!(time, UNIX_EPOCH + Duration::from_secs(1_794_096_000));
  /// assert_eq!(time.to_civil(Offset::Utc).unwrap(), civil);
  /// ```
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
  /// frame; [`TimeInteropError::OutOfRange`] when the instant falls
  /// outside the representable range.
  pub fn to_system_time(self, frame: Offset) -> Result<SystemTime, TimeInteropError> {
    let seconds = civil_to_unix_seconds(self, frame)?;
    if seconds >= 0 {
      UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds as u64))
        .ok_or(TimeInteropError::OutOfRange)
    } else {
      UNIX_EPOCH
        .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
        .ok_or(TimeInteropError::OutOfRange)
    }
  }
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, SystemTime, UNIX_EPOCH};

  use super::{Cadence as _, Civil, Offset};

  #[test]
  fn epoch_second_maps_to_unix_zero() {
    let values: Civil = "1970-01-01T00:00:00".parse().unwrap();
    assert_eq!(values.to_system_time(Offset::Utc).unwrap(), UNIX_EPOCH);
    assert_eq!(UNIX_EPOCH.to_civil(Offset::Utc).unwrap(), values);
  }

  #[test]
  fn pre_epoch_readings_floor_toward_negative_infinity() {
    let half_before = UNIX_EPOCH
      .checked_sub(Duration::from_nanos(500_000_000))
      .unwrap();
    assert_eq!(
      half_before.to_civil(Offset::Utc).unwrap().to_string(),
      "1969-12-31T23:59:59"
    );
    let whole_before = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
    assert_eq!(
      whole_before.to_civil(Offset::Utc).unwrap().to_string(),
      "1969-12-31T23:59:59"
    );
  }

  #[test]
  fn fixed_offset_frames_shift_the_instant_not_the_fields() {
    let values: Civil = "2026-11-08T09:00:00".parse().unwrap();
    let utc_instant = values.to_system_time(Offset::Utc).unwrap();
    let tokyo_instant = values.to_system_time(Offset::Fixed(9 * 3600)).unwrap();
    assert_eq!(
      utc_instant.duration_since(tokyo_instant).unwrap(),
      Duration::from_secs(9 * 3600)
    );
    assert_eq!(
      tokyo_instant.to_civil(Offset::Fixed(9 * 3600)).unwrap(),
      values
    );
  }

  #[test]
  fn local_frame_is_unsupported_and_year_domain_is_bounded() {
    let values: Civil = "2026-11-08T00:00:00".parse().unwrap();
    assert_eq!(
      values.to_system_time(Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    assert_eq!(
      UNIX_EPOCH.to_civil(Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    let year_10_000 = crate::civil::Civil::new(10_000, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
      year_10_000.to_system_time(Offset::Utc),
      Err(crate::TimeInteropError::OutOfRange)
    );
  }

  #[test]
  fn samples_round_trip() {
    let samples = [
      "1889-06-14T00:00:01",
      "1969-12-31T23:59:59",
      "1972-02-29T12:30:30",
      "2026-11-08T13:45:01",
      "2100-03-01T00:00:00",
      "9999-12-31T23:59:59",
    ];
    for text in samples {
      let values: Civil = text.parse().unwrap();
      for frame in [Offset::Utc, Offset::Fixed(-18_000)] {
        let time = values.to_system_time(frame).unwrap();
        assert_eq!(time.to_civil(frame).unwrap().to_string(), text);
      }
    }
  }

  #[test]
  fn system_time_helpers_read_the_seam_consistently() {
    let now = SystemTime::now();
    let values = now.to_civil(Offset::Utc).unwrap();
    let round_tripped = values.to_system_time(Offset::Utc).unwrap();
    assert!(round_tripped <= now);
    assert!(now.duration_since(round_tripped).unwrap() < Duration::from_secs(1));
  }
}
