#![cfg_attr(
  not(test),
  deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro
  )
)]

//! A cron-replacement schedule-pattern grammar: RFC 3339 shapes with
//! set-valued fields.
//!
//! A [`Pattern`] is the fixed six-field skeleton `year-month-dayThh:mm:ss`
//! with an optional trailing offset (`Z` or `[+/-]hh:mm`). Every field is
//! either a braced set `{...}` or a bare single numeric literal; the set
//! elements are `*` (full domain), a zero-padded literal, or an inclusive
//! range. Bare `*`, bare ranges, and bare enumerations are syntax errors,
//! which keeps `-` unambiguous between the date separator and range syntax.
//!
//! The whole semantics is one rule: a wall-clock second fires iff each
//! field's value is a member of its set. The crate is clock-blind and
//! timezone-blind — the caller resolves the reference frame ([`Offset`])
//! and supplies field values in it. Nonexistent local times do not fire and
//! duplicated local times fire twice, deliberately: predictability over
//! cleverness, same stance as Temporal and systemd.
//!
//! # Examples
//!
//! Every second of every day:
//!
//! ```
//! use radiata_cadence::{FieldValues, Pattern};
//!
//! let every_second = Pattern::parse("{*}-{*}-{*}T{*}:{*}:{*}").unwrap();
//! assert!(every_second.matches(FieldValues::new(2026, 11, 8, 13, 45, 1).unwrap()));
//! ```
//!
//! Daily at midnight in the device's local frame (no offset declared):
//!
//! ```
//! use radiata_cadence::{FieldValues, Pattern};
//!
//! let daily = Pattern::parse("{*}-{*}-{*}T00:00:00").unwrap();
//! assert_eq!(daily.offset().to_string(), "");
//! assert!(daily.r#match(2026, 11, 8, 0, 0, 0));
//! assert!(!daily.r#match(2026, 11, 8, 0, 0, 1));
//! ```
//!
//! Sets, ranges, and mixed forms, anchored to a fixed civil frame:
//!
//! ```
//! use radiata_cadence::Pattern;
//!
//! let quarterly = Pattern::parse("2026-{03,06,09,12}-01T09:00:00+09:00").unwrap();
//! assert_eq!(quarterly.offset().to_string(), "+09:00");
//!
//! let mixed = Pattern::parse("{2026,2030-2033}-{03,09-12}-01T00:00:00Z").unwrap();
//! assert_eq!(mixed.to_string(), "{2026,2030-2033}-{03,09-12}-01T00:00:00Z");
//! ```
//!
//! Calendar-natural consequences fall out of set semantics: February 29th
//! fires only in leap years, and February 30th never fires. Next-fire
//! search implements the civil calendar in-crate and skips nonexistent
//! dates:
//!
//! ```
//! use radiata_cadence::{FieldValues, Pattern};
//!
//! let leap_day = Pattern::parse("{*}-{02}-{29}T00:00:00Z").unwrap();
//! let next = leap_day.next_fire(FieldValues::new(2025, 3, 1, 0, 0, 0).unwrap()).unwrap();
//! assert_eq!(next, FieldValues::new(2028, 2, 29, 0, 0, 0).unwrap());
//!
//! let impossible = Pattern::parse("{*}-{02}-{30}T00:00:00Z").unwrap();
//! assert_eq!(impossible.next_fire(FieldValues::new(2026, 1, 1, 0, 0, 0).unwrap()), None);
//! ```
//!
//! # Time-library interop
//!
//! The core stays dependency-free and clock-blind. Optional features
//! bridge caller-side time libraries (all off by default):
//!
//! - `std-time`: `SystemTime` conversions for the `Utc` and fixed-offset frames
//!   (see `field_values_to_system_time` / `system_time_to_field_values`).
//! - `chrono`: [`TryFrom`] any `chrono::DateTime<Tz>` into [`FieldValues`],
//!   plus `to_chrono_fixed` back.
//! - `jiff`: [`TryFrom`] for `jiff::Timestamp` and `jiff::Zoned`, plus
//!   `to_jiff_timestamp` / `to_jiff_civil` back.
//!
//! The device-local frame needs a timezone database, so only `chrono`
//! and `jiff` can resolve it: read the local civil fields from their
//! types and match or search against an `Offset::Local` pattern. `std`
//! alone cannot, and the `std-time` conversions reject the local frame
//! explicitly.

mod calendar;
#[cfg(feature = "chrono")]
mod compat_chrono;
#[cfg(feature = "jiff")]
mod compat_jiff;
#[cfg(feature = "std-time")]
mod compat_std;
#[cfg(any(feature = "jiff", feature = "std-time"))]
mod epoch;
mod error;
mod field;
mod pattern;

#[cfg(feature = "std-time")]
pub use compat_std::{field_values_to_system_time, system_time_to_field_values};
pub use error::{ParseError, ParseErrorKind, Result};
pub use pattern::{FieldValues, Offset, Pattern};

/// Why a time-library conversion failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeInteropError {
  /// The pattern frame is [`Offset::Local`]: resolving the device's
  /// local wall clock needs a timezone database, which `std` alone does
  /// not have. Enable `chrono` or `jiff` and resolve local readings
  /// through their timezone types.
  LocalFrameUnsupported,
  /// The instant or civil values do not round-trip through the crate's
  /// 0000-9999 proleptic-Gregorian domain (or the arithmetic overflowed).
  OutOfRange,
}

impl core::fmt::Display for TimeInteropError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::LocalFrameUnsupported => f.write_str(
        "the local frame needs a timezone-aware library (enable the chrono or jiff feature)",
      ),
      Self::OutOfRange => f.write_str("outside the 0000-9999 civil calendar domain"),
    }
  }
}

impl std::error::Error for TimeInteropError {}
