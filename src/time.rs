//! Shared wall-clock conversion helpers.
//!
//! One home for the UNIX-epoch second/millisecond conversions that every
//! subsystem needs, so saturation and epoch handling cannot drift between
//! modules. The `to_*`/`from_*` functions are pure conversions over a
//! [`SystemTime`] value. The `now_seconds`/`now_millis` functions are the
//! protocol-visible liveness readings taken directly from the host clock
//! (`SystemTime::now`) — deliberately not pure, because production code
//! calls them exactly where the host wall clock is the required
//! authority (storage receipt internals instead take the injected
//! [`WallClock`](crate::storage::receipt::WallClock), which wraps these
//! conversions for tests).

use std::time::{SystemTime, UNIX_EPOCH};

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

/// UNIX milliseconds of `time`, saturating at the epoch.
pub(crate) fn to_millis(time: SystemTime) -> u64 {
  time
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis() as u64)
    .unwrap_or(0)
}

/// Current host wall-clock milliseconds; resource writes stamp their
/// signed tuple with this host reading.
pub(crate) fn now_millis() -> u64 {
  to_millis(SystemTime::now())
}

/// Rebuilds a [`SystemTime`] from stored UNIX milliseconds.
pub(crate) fn from_millis(millis: u64) -> SystemTime {
  UNIX_EPOCH + std::time::Duration::from_millis(millis)
}

/// Rebuilds a [`SystemTime`] from stored UNIX seconds.
pub(crate) fn from_seconds(seconds: u64) -> SystemTime {
  UNIX_EPOCH + std::time::Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
  use std::time::{Duration, UNIX_EPOCH};

  use super::{from_millis, to_millis, to_seconds};

  // Host `SystemTime` is the only ordering authority and conversions are
  // total — a wall-clock rollback below the epoch saturates at zero
  // instead of failing bounded work.
  #[test]
  fn conversions_are_total_and_saturate_at_the_epoch() {
    assert_eq!(to_seconds(UNIX_EPOCH), 0);
    assert_eq!(to_seconds(UNIX_EPOCH - Duration::from_secs(1)), 0);
    assert_eq!(to_millis(UNIX_EPOCH - Duration::from_secs(1)), 0);
    assert_eq!(to_millis(UNIX_EPOCH - Duration::from_millis(1)), 0);
    let later = UNIX_EPOCH + Duration::from_millis(1_500);
    assert_eq!(to_seconds(later), 1);
    assert_eq!(to_millis(later), 1_500);
  }

  // Stored millisecond timestamps round-trip exactly, so a
  // clock freeze re-reads the same instant and a rollback restores an
  // earlier recorded value without drift.
  #[test]
  fn millis_round_trip_preserves_frozen_and_rolled_back_readings() {
    let frozen = UNIX_EPOCH + Duration::from_millis(123_456_789);
    assert_eq!(from_millis(to_millis(frozen)), frozen);
    let rolled_back = frozen - Duration::from_secs(10_000);
    assert_eq!(from_millis(to_millis(rolled_back)), rolled_back);
    assert!(rolled_back < from_millis(to_millis(frozen)));
  }
}
