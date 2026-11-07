//! Shared wall-clock source and conversion helpers.
//!
//! One home for the injectable [`WallClock`] source and the UNIX-epoch
//! second/millisecond conversions that every subsystem needs, so the
//! clock seam and the conversion semantics cannot drift between
//! modules. The `to_*`/`from_*` functions are pure conversions over a
//! [`SystemTime`] value. The reading functions — [`now_seconds`],
//! [`now_millis`], and [`now`] — are the only authority for a host wall
//! clock read in production code: protocol-visible liveness and expiry
//! boundaries take their readings through them, and production modules
//! never call `SystemTime::now` directly. They are deliberately not
//! pure, because production code calls them exactly where the host wall
//! clock is the required authority (injected boundaries instead take a
//! [`WallClock`], which wraps these conversions for tests).
//!
//! The two scales have different conversion contracts:
//!
//! - Milliseconds are the stored-and-ordered wall-time scale (resource stamps,
//!   identity stamps, trace records). `to_millis` is signed and lossless down
//!   to the millisecond: a pre-epoch reading reports a negative value instead
//!   of collapsing onto the epoch, so timestamp-tuple ordering survives a
//!   wall-clock rollback below the epoch. Sub-millisecond remainders truncate
//!   toward negative infinity, so `from_millis(to_millis(t))` never lands after
//!   `t`.
//! - Seconds feed liveness and deadline arithmetic only (session idle-timeout,
//!   recovery scheduling) and are never stored as absolute instants;
//!   `to_seconds` saturates at the epoch, which only makes a pre-epoch reading
//!   look maximally overdue.
//!
//! Not every wall-time encoding lives here: the receipt anchor's
//! fixed-width wall-time wire codec (`storage/receipt.rs`'s
//! `encode_wall_time`/`decode_wall_time`) is a wire-format concern and
//! stays beside the receipt transcript it is frozen into.

use std::{
  fmt,
  time::{SystemTime, UNIX_EPOCH},
};

/// The injected wall-clock seam: production wires
/// [`HostWallClock`], tests freeze or script readings. L0 by content —
/// every layer reads time through this trait, so it lives beside the
/// conversions instead of inside one consumer domain.
pub(crate) trait WallClock: fmt::Debug + Send + Sync + 'static {
  fn now(&self) -> SystemTime;
}

/// The production clock: an unadorned host `SystemTime::now` reader.
#[derive(Debug)]
pub(crate) struct HostWallClock;

impl WallClock for HostWallClock {
  fn now(&self) -> SystemTime {
    SystemTime::now()
  }
}

/// The current host wall-clock reading, for sites that need the instant
/// itself: `SystemTime`-typed stamps, tick arithmetic, and monotonic
/// elapsed comparisons. The one production home for a direct host read —
/// production modules never call `SystemTime::now` directly.
pub(crate) fn now() -> SystemTime {
  SystemTime::now()
}

/// UNIX seconds of `time`, saturating at the epoch (a pre-epoch reading
/// reports zero rather than failing bounded work).
pub(crate) fn to_seconds(time: SystemTime) -> u64 {
  time
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or(0)
}

/// Current host wall-clock seconds, used for protocol-visible liveness and
/// expiry boundaries. Host `SystemTime` is the only time authority;
/// injected clocks wrap these conversions for tests.
pub(crate) fn now_seconds() -> u64 {
  to_seconds(SystemTime::now())
}

/// UNIX milliseconds of `time`, signed and floor-truncated: a pre-epoch
/// reading reports a negative value instead of collapsing onto the epoch,
/// so timestamp-tuple ordering and stored stamps survive a wall-clock
/// rollback below the epoch. Readings beyond the `i64` millisecond range
/// (roughly ±292 million years) saturate at the nearest boundary.
pub(crate) fn to_millis(time: SystemTime) -> i64 {
  match time.duration_since(UNIX_EPOCH) {
    Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
    Err(before) => {
      let millis = before.duration().as_nanos().div_ceil(1_000_000);
      i64::try_from(millis).map_or(i64::MIN, |millis| -millis)
    }
  }
}

/// Current host wall-clock milliseconds; resource writes stamp their
/// signed tuple with this host reading.
pub(crate) fn now_millis() -> i64 {
  to_millis(SystemTime::now())
}

/// Rebuilds a [`SystemTime`] from stored UNIX milliseconds (signed; a
/// negative value is a pre-epoch instant).
pub(crate) fn from_millis(millis: i64) -> SystemTime {
  if millis >= 0 {
    UNIX_EPOCH + std::time::Duration::from_millis(millis as u64)
  } else {
    UNIX_EPOCH - std::time::Duration::from_millis(millis.unsigned_abs())
  }
}

/// Rebuilds a [`SystemTime`] from stored UNIX seconds.
pub(crate) fn from_seconds(seconds: u64) -> SystemTime {
  UNIX_EPOCH + std::time::Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, UNIX_EPOCH};

  use super::{from_millis, to_millis, to_seconds};

  // Host `SystemTime` is the only ordering authority. Milliseconds are
  // the stored-and-ordered scale: the conversion is signed, so a
  // wall-clock rollback below the epoch keeps its identity instead of
  // collapsing onto the epoch.
  #[test]
  fn millis_conversions_are_signed_across_the_epoch() {
    assert_eq!(to_millis(UNIX_EPOCH), 0);
    assert_eq!(to_millis(UNIX_EPOCH - Duration::from_secs(1)), -1_000);
    assert_eq!(to_millis(UNIX_EPOCH - Duration::from_millis(1)), -1);
    // One FILETIME tick below the epoch: the smallest pre-epoch reading
    // every supported host clock (100 ns resolution on Windows) can
    // represent floors to -1.
    assert_eq!(to_millis(UNIX_EPOCH - Duration::from_nanos(100)), -1);
    assert_eq!(to_millis(UNIX_EPOCH + Duration::from_millis(1_500)), 1_500);
    assert_eq!(
      from_millis(-1_500),
      UNIX_EPOCH - Duration::from_millis(1_500)
    );
    assert_eq!(from_millis(0), UNIX_EPOCH);
    assert_eq!(
      from_millis(1_500),
      UNIX_EPOCH + Duration::from_millis(1_500)
    );
  }

  // Distinct pre-epoch instants stay distinct and ordered after the
  // round trip, so a rollback cannot reorder stored stamps.
  #[test]
  fn pre_epoch_stamps_keep_their_order_across_the_round_trip() {
    let rolled_back = UNIX_EPOCH - Duration::from_millis(10_000);
    let deeper = UNIX_EPOCH - Duration::from_millis(20_000);
    assert!(to_millis(deeper) < to_millis(rolled_back));
    assert_eq!(from_millis(to_millis(rolled_back)), rolled_back);
    assert_eq!(from_millis(to_millis(deeper)), deeper);
    assert!(deeper < from_millis(to_millis(rolled_back)));
  }

  // The sub-millisecond remainder truncates toward negative infinity on
  // both sides of the epoch, so the rebuilt instant never lands after
  // the reading it came from.
  #[test]
  fn millis_truncation_is_floor_on_both_sides_of_the_epoch() {
    // The offsets stay on whole FILETIME ticks (multiples of 100 ns) so
    // the host clock represents them exactly on every platform.
    let after = UNIX_EPOCH + Duration::from_nanos(1_500_000_100);
    let before = UNIX_EPOCH - Duration::from_nanos(1_500_000_100);
    assert_eq!(to_millis(after), 1_500);
    assert_eq!(to_millis(before), -1_501);
    assert!(from_millis(to_millis(after)) <= after);
    assert!(from_millis(to_millis(before)) <= before);
  }

  // Stored millisecond timestamps round-trip exactly, so a
  // clock freeze re-reads the same instant.
  #[test]
  fn millis_round_trip_preserves_frozen_readings() {
    let frozen = UNIX_EPOCH + Duration::from_millis(123_456_789);
    assert_eq!(from_millis(to_millis(frozen)), frozen);
    let pre_epoch = UNIX_EPOCH - Duration::from_millis(123_456_789);
    assert_eq!(from_millis(to_millis(pre_epoch)), pre_epoch);
  }

  // Seconds feed deadline arithmetic only; a pre-epoch reading
  // saturates at zero, the maximally-overdue reading.
  #[test]
  fn seconds_saturate_at_the_epoch() {
    assert_eq!(to_seconds(UNIX_EPOCH), 0);
    assert_eq!(to_seconds(UNIX_EPOCH - Duration::from_secs(1)), 0);
    assert_eq!(to_seconds(UNIX_EPOCH + Duration::from_millis(1_500)), 1);
  }
}
