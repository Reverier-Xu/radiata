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
//! A [`Ticker`] is the fixed six-field skeleton `year-month-dayThh:mm:ss`
//! with an optional trailing offset (`Z` or `[+/-]hh:mm`). Every field is
//! either a braced set `{...}` or a bare single numeric literal; the set
//! elements are `*` (full domain), a zero-padded literal, or an inclusive
//! range. Bare `*`, bare ranges, and bare enumerations are syntax errors,
//! which keeps `-` unambiguous between the date separator and range syntax.
//!
//! The whole semantics is one rule: a wall-clock second fires iff each
//! field's value is a member of its set. The crate is clock-blind and
//! timezone-blind — the caller resolves the reference frame ([`Offset`])
//! and supplies the reading in it through the [`Cadence`] trait.
//! Nonexistent local times do not fire and duplicated local times fire
//! twice, deliberately: predictability over cleverness, same stance as
//! Temporal and systemd.
//!
//! # Examples
//!
//! Every second of every day:
//!
//! ```
//! use radiata_cadence::Ticker;
//!
//! let every_second = Ticker::parse("{*}-{*}-{*}T{*}:{*}:{*}").unwrap();
//! assert!(every_second.fires_at("2026-11-08T13:45:01"));
//! ```
//!
//! Daily at midnight in the device's local frame (no offset declared):
//!
//! ```
//! use radiata_cadence::Ticker;
//!
//! let daily = Ticker::parse("{*}-{*}-{*}T00:00:00").unwrap();
//! assert_eq!(daily.offset().to_string(), "");
//! assert!(daily.fires_at("2026-11-08T00:00:00"));
//! assert!(!daily.fires_at("2026-11-08T00:00:01"));
//! ```
//!
//! Sets, ranges, and mixed forms, anchored to a fixed civil frame:
//!
//! ```
//! use radiata_cadence::Ticker;
//!
//! let quarterly = Ticker::parse("2026-{03,06,09,12}-01T09:00:00+09:00").unwrap();
//! assert_eq!(quarterly.offset().to_string(), "+09:00");
//!
//! let mixed = Ticker::parse("{2026,2030-2033}-{03,09-12}-01T00:00:00Z").unwrap();
//! assert_eq!(mixed.to_string(), "{2026,2030-2033}-{03,09-12}-01T00:00:00Z");
//! ```
//!
//! Calendar-natural consequences fall out of set semantics: February 29th
//! fires only in leap years, and February 30th never fires. Next-fire
//! search implements the civil calendar in-crate and skips nonexistent
//! dates, returning the frame-free [`Civil`] reading:
//!
//! ```
//! use radiata_cadence::Ticker;
//!
//! let leap_day = Ticker::parse("{*}-{02}-{29}T00:00:00Z").unwrap();
//! let next = leap_day.next_fire("2025-03-01T00:00:00").unwrap();
//! assert_eq!(next.to_string(), "2028-02-29T00:00:00");
//!
//! let impossible = Ticker::parse("{*}-{02}-{30}T00:00:00Z").unwrap();
//! assert_eq!(impossible.next_fire("2026-01-01T00:00:00"), None);
//! ```
//!
//! # Readings: the `Cadence` trait
//!
//! The crate never reads a clock and never consults a timezone database;
//! callers hand it their own wall-clock reading through [`Cadence`],
//! which converts the reading into one civil second in the ticker's
//! declared frame. The built-in `str` implementation reads the civil
//! shape `YYYY-MM-DDThh:mm:ss` — a bare string is a frame-free civil
//! reading, and a string carrying `Z` or `[+/-]hh:mm` is an instant that
//! converts into the frame:
//!
//! ```
//! use radiata_cadence::Ticker;
//!
//! let tokyo = Ticker::parse("{*}-{*}-{*}T09:00:00+09:00").unwrap();
//! assert!(tokyo.fires_at("2026-11-08T09:00:00"));
//! // 00:00:00Z is 09:00:00 at +09:00: the same fire.
//! assert!(tokyo.fires_at("2026-11-08T00:00:00Z"));
//! ```
//!
//! # Time-library interop
//!
//! Optional features bridge caller-side time libraries (all off by
//! default):
//!
//! - `std-time`: [`Cadence`] for `SystemTime` plus `Civil::to_system_time`
//!   back, for the `Utc` and fixed-offset frames.
//! - `chrono`: [`Cadence`] for any `chrono::DateTime<Tz>`, plus
//!   `Civil::to_chrono_fixed` back.
//! - `jiff`: [`Cadence`] for `jiff::Timestamp`, `jiff::Zoned`, and
//!   `jiff::civil::DateTime`, plus `Civil::to_jiff_timestamp` / `to_jiff_civil`
//!   back.
//!
//! The device-local frame needs a timezone database, so only `chrono`
//! and `jiff` can resolve it: read the local civil fields from their
//! zoned types and evaluate against an `Offset::Local` ticker. `std`
//! alone cannot, and the `std-time` conversions reject the local frame
//! explicitly.

mod cadence;
mod calendar;
mod civil;
#[cfg(feature = "chrono")]
mod compat_chrono;
#[cfg(feature = "jiff")]
mod compat_jiff;
#[cfg(feature = "std-time")]
mod compat_std;
mod epoch;
mod error;
mod field;
mod ticker;

pub use cadence::Cadence;
pub use civil::Civil;
pub use error::{ParseError, ParseErrorKind, Result};
pub use ticker::{Offset, Ticker};

/// Why a time-library conversion failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeInteropError {
  /// The value is not a readable civil moment (e.g. a malformed
  /// string reading).
  Malformed,
  /// The ticker frame is [`Offset::Local`]: resolving the device's
  /// local wall clock needs a timezone database, which the value at
  /// hand does not carry. Enable `chrono` or `jiff` and resolve local
  /// readings through their timezone types.
  LocalFrameUnsupported,
  /// The instant or civil values do not round-trip through the crate's
  /// 0000-9999 proleptic-Gregorian domain (or the arithmetic overflowed).
  OutOfRange,
}

impl core::fmt::Display for TimeInteropError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::Malformed => f.write_str("not a readable civil moment"),
      Self::LocalFrameUnsupported => f.write_str(
        "the local frame needs a timezone-aware library (enable the chrono or jiff feature)",
      ),
      Self::OutOfRange => f.write_str("outside the 0000-9999 civil calendar domain"),
    }
  }
}

impl std::error::Error for TimeInteropError {}
