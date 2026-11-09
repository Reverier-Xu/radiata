//! `chrono` interop.
//!
//! Any `chrono::DateTime<Tz>` is a [`Cadence`] reading: its own wall
//! clock for the device-local frame (the zone it carries is the resolved
//! frame), its UTC reading for `Utc`, and its instant shifted into the
//! frame for a fixed offset. The reverse direction targets
//! `DateTime<FixedOffset>` for the `Utc` and fixed-offset frames; the
//! device-local frame is rejected because choosing among a DST fold's
//! ambiguous readings is a policy the caller must own.
//!
//! ```
//! use chrono::TimeZone;
//!
//! use radiata_cadence::Ticker;
//!
//! let ticker = Ticker::parse("{*}-{*}-{*}T09:{00,30}:00Z").unwrap();
//! let moment = chrono::Utc.with_ymd_and_hms(2026, 11, 8, 9, 30, 0).unwrap();
//! assert!(ticker.fires_at(&moment));
//! ```

use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Timelike};

use crate::{Cadence, Civil, TimeInteropError, ticker::Offset};

impl<Tz: TimeZone> Cadence for DateTime<Tz> {
  /// Reads the datetime as one civil second in `frame`.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::OutOfRange`] when the reading falls outside the
  /// crate's 0000-9999 civil year domain.
  fn to_civil(&self, frame: Offset) -> Result<Civil, TimeInteropError> {
    let naive = match frame {
      // The zone the datetime carries resolves the device-local frame.
      Offset::Local => self.naive_local(),
      Offset::Utc => self.naive_utc(),
      Offset::Fixed(seconds) => {
        let offset = FixedOffset::east_opt(seconds).ok_or(TimeInteropError::OutOfRange)?;
        self.with_timezone(&offset).naive_local()
      }
    };
    let (year, month, day) = (naive.year(), naive.month(), naive.day());
    let (hour, minute, second) = (naive.hour(), naive.minute(), naive.second());
    if !(0..=9999).contains(&year) {
      return Err(TimeInteropError::OutOfRange);
    }
    Civil::new(
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

impl Civil {
  /// Converts the civil second into a `chrono::DateTime<FixedOffset>` in
  /// the given `Utc` or fixed-offset frame.
  ///
  /// # Errors
  ///
  /// [`TimeInteropError::LocalFrameUnsupported`] for the device-local
  /// frame; [`TimeInteropError::OutOfRange`] when the civil second is
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

  use super::{Cadence as _, Civil, Offset};

  /// The civil shape of the readings under test, as a comparable value.
  fn civil(text: &str) -> Civil {
    text.parse().expect("in-domain reading")
  }

  #[test]
  fn utc_and_fixed_datetimes_read_their_frames() {
    let moment = chrono::Utc.with_ymd_and_hms(2026, 11, 8, 9, 30, 0).unwrap();
    assert_eq!(
      moment.to_civil(Offset::Utc).unwrap(),
      civil("2026-11-08T09:30:00")
    );
    // The instant 09:30Z reads as 18:30 at +09:00.
    assert_eq!(
      moment.to_civil(Offset::Fixed(9 * 3600)).unwrap(),
      civil("2026-11-08T18:30:00")
    );
    // The device-local frame reads the zone the datetime carries.
    let offset = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
    let tokyo = offset.with_ymd_and_hms(2026, 11, 8, 18, 0, 5).unwrap();
    assert_eq!(
      tokyo.to_civil(Offset::Local).unwrap(),
      civil("2026-11-08T18:00:05")
    );
  }

  #[test]
  fn civil_seconds_convert_back_into_fixed_datetimes() {
    let values = civil("2026-11-08T18:00:05");
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
    let values = civil("2026-11-08T00:00:00");
    assert_eq!(
      values.to_chrono_fixed(Offset::Local),
      Err(crate::TimeInteropError::LocalFrameUnsupported)
    );
    assert_eq!(
      crate::civil::Civil::new(2026, 2, 30, 0, 0, 0)
        .unwrap()
        .to_chrono_fixed(Offset::Utc),
      Err(crate::TimeInteropError::OutOfRange)
    );
  }

  #[test]
  fn year_domain_is_enforced_in_both_directions() {
    let future = chrono::Utc.with_ymd_and_hms(10_000, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
      future.to_civil(Offset::Utc),
      Err(crate::TimeInteropError::OutOfRange)
    );
    let boundary = civil("9999-12-31T23:59:59");
    assert_eq!(boundary.to_chrono_fixed(Offset::Utc).unwrap().year(), 9999);
  }
}
