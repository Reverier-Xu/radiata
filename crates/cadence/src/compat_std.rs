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
//! use std::time::{Duration, SystemTime, UNIX_EPOCH};
//!
//! use radiata_cadence::{field_values_to_system_time, system_time_to_field_values, FieldValues, Offset};
//!
//! let values = FieldValues::new(2026, 11, 8, 0, 0, 0).unwrap();
//! let time = field_values_to_system_time(values, Offset::Utc).unwrap();
//! assert_eq!(time, UNIX_EPOCH + Duration::from_secs(1_794_096_000));
//! assert_eq!(system_time_to_field_values(time, Offset::Utc).unwrap(), values);
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
  TimeInteropError,
  epoch::{field_values_to_unix_seconds, unix_seconds_to_field_values},
  pattern::{FieldValues, Offset},
};

/// Converts field values in a `Utc` or fixed-offset frame into a
/// `SystemTime` instant.
///
/// # Errors
///
/// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
/// frame; [`TimeInteropError::OutOfRange`] when the instant falls outside
/// the representable range.
pub fn field_values_to_system_time(
  values: FieldValues, frame: Offset,
) -> Result<SystemTime, TimeInteropError> {
  let seconds = field_values_to_unix_seconds(values, frame)?;
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

/// Converts a `SystemTime` instant into field values in a `Utc` or
/// fixed-offset frame.
///
/// # Errors
///
/// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
/// frame; [`TimeInteropError::OutOfRange`] when the instant falls outside
/// the crate's 0000-9999 civil year domain.
pub fn system_time_to_field_values(
  time: SystemTime, frame: Offset,
) -> Result<FieldValues, TimeInteropError> {
  // Floor toward negative infinity: a pre-epoch reading with a
  // sub-second remainder belongs to the earlier schedule second.
  let seconds = match time.duration_since(UNIX_EPOCH) {
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
  unix_seconds_to_field_values(seconds, frame)
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, SystemTime, UNIX_EPOCH};

  use super::{field_values_to_system_time, system_time_to_field_values};
  use crate::pattern::{FieldValues, Offset};

  #[test]
  fn epoch_second_maps_to_unix_zero() {
    let values = FieldValues::new(1970, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
      field_values_to_system_time(values, Offset::Utc).unwrap(),
      UNIX_EPOCH
    );
    assert_eq!(
      system_time_to_field_values(UNIX_EPOCH, Offset::Utc).unwrap(),
      values
    );
  }

  #[test]
  fn pre_epoch_readings_floor_toward_negative_infinity() {
    let half_before = UNIX_EPOCH
      .checked_sub(Duration::from_nanos(500_000_000))
      .unwrap();
    assert_eq!(
      system_time_to_field_values(half_before, Offset::Utc).unwrap(),
      FieldValues::new(1969, 12, 31, 23, 59, 59).unwrap()
    );
    let whole_before = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
    assert_eq!(
      system_time_to_field_values(whole_before, Offset::Utc).unwrap(),
      FieldValues::new(1969, 12, 31, 23, 59, 59).unwrap()
    );
  }

  #[test]
  fn fixed_offset_frames_shift_the_instant_not_the_fields() {
    let values = FieldValues::new(2026, 11, 8, 9, 0, 0).unwrap();
    let utc_instant = field_values_to_system_time(values, Offset::Utc).unwrap();
    let tokyo_instant = field_values_to_system_time(values, Offset::Fixed(9 * 3600)).unwrap();
    assert_eq!(
      utc_instant.duration_since(tokyo_instant).unwrap(),
      Duration::from_secs(9 * 3600)
    );
    assert_eq!(
      system_time_to_field_values(tokyo_instant, Offset::Fixed(9 * 3600)).unwrap(),
      values
    );
  }

  #[test]
  fn local_frame_is_unsupported_and_year_domain_is_bounded() {
    let values = FieldValues::new(2026, 11, 8, 0, 0, 0).unwrap();
    assert_eq!(
      field_values_to_system_time(values, Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    assert_eq!(
      system_time_to_field_values(UNIX_EPOCH, Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    let year_10_000 = FieldValues::new(10_000, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
      field_values_to_system_time(year_10_000, Offset::Utc),
      Err(crate::TimeInteropError::OutOfRange)
    );
  }

  #[test]
  fn samples_round_trip() {
    let samples = [
      (1889, 6, 14, 0, 0, 1),
      (1969, 12, 31, 23, 59, 59),
      (1972, 2, 29, 12, 30, 30),
      (2026, 11, 8, 13, 45, 1),
      (2100, 3, 1, 0, 0, 0),
      (9999, 12, 31, 23, 59, 59),
    ];
    for (year, month, day, hour, minute, second) in samples {
      let values = FieldValues::new(year, month, day, hour, minute, second).unwrap();
      for frame in [Offset::Utc, Offset::Fixed(-18_000)] {
        let time = field_values_to_system_time(values, frame).unwrap();
        assert_eq!(system_time_to_field_values(time, frame).unwrap(), values);
      }
    }
  }

  #[test]
  fn system_time_helpers_read_the_seam_consistently() {
    let now = SystemTime::now();
    let values = system_time_to_field_values(now, Offset::Utc).unwrap();
    let round_tripped = field_values_to_system_time(values, Offset::Utc).unwrap();
    assert!(round_tripped <= now);
    assert!(now.duration_since(round_tripped).unwrap() < Duration::from_secs(1));
  }
}
