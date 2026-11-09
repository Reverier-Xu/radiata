//! The [`Cadence`] trait: caller-side wall-clock readings a
//! [`Ticker`](crate::Ticker) evaluates in its declared frame.
//!
//! The crate stays clock-blind and timezone-blind — it reads no wall
//! clock and carries no timezone database — so the caller's time
//! representation bridges in through one conversion:
//! [`Cadence::to_civil`] reads a value as one civil wall-clock second in
//! a requested frame. The built-in `str` implementation covers the civil
//! shape `YYYY-MM-DDThh:mm:ss` (optionally carrying `Z` or
//! `[+/-]hh:mm`), and the optional features bridge `chrono`, `jiff`, and
//! `std::time` types the same way.

use crate::{
  TimeInteropError,
  civil::{Civil, parse_civil_with_offset},
  epoch::{civil_to_unix_seconds, unix_seconds_to_civil},
  ticker::Offset,
};

/// A wall-clock reading a [`Ticker`](crate::Ticker) evaluates.
///
/// One conversion, implemented for the caller's time representation:
/// read the value as one civil wall-clock second in the requested frame.
///
/// - Frame-free readings — a bare civil string, a `jiff::civil::DateTime`, a
///   [`Civil`] — pass through unchanged in any frame (the caller means "this
///   wall clock in the ticker's frame").
/// - Instants — `SystemTime`, `chrono::DateTime`, `jiff::Timestamp`, and
///   offset-carrying strings — convert into the requested frame.
/// - Zoned readings — `jiff::Zoned` — convert their instant for declared frames
///   and read their own wall clock for the device-local frame (the zone they
///   carry is the resolved frame).
pub trait Cadence {
  /// Reads this value as one civil wall-clock second in `frame`.
  ///
  /// # Errors
  ///
  /// - [`TimeInteropError::Malformed`] when the value is not a readable civil
  ///   moment (e.g. a malformed string).
  /// - [`TimeInteropError::LocalFrameUnsupported`] when the value is an instant
  ///   that carries no zone and the frame is the device-local one — resolving
  ///   it needs a timezone database, so hold a zoned reading instead.
  /// - [`TimeInteropError::OutOfRange`] outside the crate's 0000-9999 civil
  ///   year domain (or on arithmetic overflow).
  fn to_civil(&self, frame: Offset) -> Result<Civil, TimeInteropError>;
}

impl Cadence for Civil {
  /// A civil reading is frame-free: it passes through unchanged.
  fn to_civil(&self, _frame: Offset) -> Result<Civil, TimeInteropError> {
    Ok(*self)
  }
}

impl Cadence for str {
  /// Reads the civil shape `YYYY-MM-DDThh:mm:ss` in any frame. A bare
  /// string is a frame-free reading and passes through unchanged; a
  /// string carrying `Z` or `[+/-]hh:mm` is an instant and converts
  /// into the frame, exactly like a `SystemTime`.
  ///
  /// ```
  /// use radiata_cadence::{Cadence, Offset, Ticker};
  ///
  /// let ticker = Ticker::parse("2026-{03,09-12}-01T09:00:00+09:00").unwrap();
  /// assert!(ticker.fires_at("2026-09-01T09:00:00"));
  /// // The offset-carrying spelling denotes the same instant.
  /// assert!(ticker.fires_at("2026-09-01T00:00:00Z"));
  /// assert!(!ticker.fires_at("2026-09-01T09:00:01"));
  /// ```
  fn to_civil(&self, frame: Offset) -> Result<Civil, TimeInteropError> {
    let (civil, declared) =
      parse_civil_with_offset(self).map_err(|_| TimeInteropError::Malformed)?;
    match (declared, frame) {
      (None, _) => Ok(civil),
      (Some(_), Offset::Local) => Err(TimeInteropError::LocalFrameUnsupported),
      (Some(declared), frame) => {
        unix_seconds_to_civil(civil_to_unix_seconds(civil, declared)?, frame)
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::Cadence;
  use crate::{TimeInteropError, ticker::Offset};

  /// Bare civil strings pass through every frame unchanged.
  #[test]
  fn bare_civil_strings_pass_through_every_frame() {
    let expected = "2026-11-08T13:45:01".parse().unwrap();
    for frame in [Offset::Local, Offset::Utc, Offset::Fixed(20_700)] {
      assert_eq!("2026-11-08T13:45:01".to_civil(frame).unwrap(), expected);
    }
  }

  /// Offset-carrying strings are instants: they convert into the
  /// requested frame and refuse the device-local frame.
  #[test]
  fn offset_carrying_strings_convert_like_instants() {
    let utc = "2026-11-08T13:45:01Z".to_civil(Offset::Utc).unwrap();
    assert_eq!(utc.to_string(), "2026-11-08T13:45:01");
    // 13:45:01Z is 22:45:01 on the same day at +09:00.
    let tokyo = "2026-11-08T13:45:01Z"
      .to_civil(Offset::Fixed(9 * 3600))
      .unwrap();
    assert_eq!(tokyo.to_string(), "2026-11-08T22:45:01");
    // A fixed-offset spelling converts into other fixed frames.
    let shifted = "2026-11-08T13:45:01+01:00".to_civil(Offset::Utc).unwrap();
    assert_eq!(shifted.to_string(), "2026-11-08T12:45:01");
    assert_eq!(
      "2026-11-08T13:45:01Z".to_civil(Offset::Local),
      Err(TimeInteropError::LocalFrameUnsupported)
    );
  }

  /// Malformed strings and out-of-domain readings fail closed.
  #[test]
  fn malformed_strings_fail_closed() {
    for text in ["", "not a moment", "2026-11-08", "2026-13-08T00:00:00Z"] {
      assert_eq!(
        text.to_civil(Offset::Utc),
        Err(TimeInteropError::Malformed),
        "{text:?}"
      );
    }
  }
}
