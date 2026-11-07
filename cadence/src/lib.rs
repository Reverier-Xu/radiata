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

mod calendar;
mod error;
mod field;
mod pattern;

pub use error::{ParseError, ParseErrorKind, Result};
pub use pattern::{FieldValues, Offset, Pattern};
