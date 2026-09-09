//! Fixed credential-merge rate limiting.
//!
//! Before any handshake or signing work, each connection attempt is
//! admitted against the fixed policy: per-source and global pending
//! attempts, per-source and global 60-second fixed windows, a bounded
//! source-bucket table with idle eviction, and the ten-second
//! authentication deadline owned by the session driver. A rejected
//! attempt consumes no credential, performs no signing, and consumes no
//! rate-window budget: both windows record an attempt only after every
//! admission check has passed. An [`MergeSlot`] holds the pending count
//! for exactly one in-flight attempt and releases it on every outcome,
//! including cancellation.
//!
//! Rate windows use the monotonic clock, so host wall-clock rollback can
//! delay the authentication deadline and a forward jump can make it
//! immediately due, but neither ever widens or narrows the fixed rate
//! counts (host-wall-clock semantics).

use std::{
  collections::BTreeMap,
  net::{IpAddr, SocketAddr},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use crate::{Error, Result};

pub(crate) const PENDING_PER_SOURCE: usize = 4;
pub(crate) const PENDING_GLOBAL: usize = 64;
pub(crate) const RATE_PER_SOURCE: usize = 16;
pub(crate) const RATE_GLOBAL: usize = 256;
pub(crate) const WINDOW_SECONDS: Duration = Duration::from_secs(60);
pub(crate) const SOURCE_BUCKET_LIMIT: usize = 1024;
pub(crate) const SOURCE_IDLE_LIFETIME: Duration = Duration::from_secs(600);

/// The canonical merge source. The peer port is dropped (ephemeral
/// reconnects are aliases of one source), IPv4-mapped IPv6 collapses to its
/// IPv4 form, so every alias of one source shares one bucket
/// (normalized-source aliases).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum MergeSource {
  V4([u8; 4]),
  V6([u8; 16]),
}

impl MergeSource {
  pub(crate) fn normalize(address: SocketAddr) -> Self {
    match address.ip() {
      IpAddr::V4(v4) => Self::V4(v4.octets()),
      IpAddr::V6(v6) => {
        let octets = v6.octets();
        if octets[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] {
          let mut v4 = [0_u8; 4];
          v4.copy_from_slice(&octets[12..]);
          Self::V4(v4)
        } else {
          Self::V6(octets)
        }
      }
    }
  }
}

struct RateWindow {
  start: Instant,
  count: usize,
  limit: usize,
}

impl RateWindow {
  const fn new(now: Instant, limit: usize) -> Self {
    Self {
      start: now,
      count: 0,
      limit,
    }
  }

  /// Reports whether one attempt is admitted by the fixed 60-second
  /// window, rotating to a fresh window first. Rotation is deterministic
  /// on `now` and consumes nothing; only [`RateWindow::record`] does.
  fn admits(&mut self, now: Instant) -> bool {
    if now.duration_since(self.start) >= WINDOW_SECONDS {
      self.start = now;
      self.count = 0;
    }
    self.count < self.limit
  }

  /// Records one admitted attempt. Saturation was already refused by
  /// [`RateWindow::admits`]; callers must check before recording.
  fn record(&mut self) {
    self.count += 1;
  }
}

struct SourceBucket {
  pending: usize,
  window: RateWindow,
  last_seen: Instant,
}

struct Inner {
  sources: BTreeMap<MergeSource, SourceBucket>,
  global_pending: usize,
  global_window: RateWindow,
}

/// The fixed merge limiter shared by every accepted connection.
#[derive(Clone)]
pub(crate) struct MergeLimiter {
  inner: Arc<Mutex<Inner>>,
}

impl MergeLimiter {
  pub(crate) fn new() -> Self {
    let now = Instant::now();
    Self {
      inner: Arc::new(Mutex::new(Inner {
        sources: BTreeMap::new(),
        global_pending: 0,
        global_window: RateWindow::new(now, RATE_GLOBAL),
      })),
    }
  }

  /// Admits one connection attempt from `source`, holding its pending slot
  /// until the [`MergeSlot`] drops. Rejection is a typed overload and
  /// never consumes a credential; the per-source and global windows
  /// record the attempt only after every admission check has passed,
  /// immediately before the grant, so rejected attempts never consume
  /// the rate budget of any source.
  pub(crate) fn begin(&self, source: MergeSource) -> Result<MergeSlot> {
    let now = Instant::now();
    let mut inner = self
      .inner
      .lock()
      .map_err(|_| Error::internal("merge limiter"))?;
    if !inner.sources.contains_key(&source) && inner.sources.len() >= SOURCE_BUCKET_LIMIT {
      inner.evict_idle(now);
      if !inner.sources.contains_key(&source) && inner.sources.len() >= SOURCE_BUCKET_LIMIT {
        return Err(Error::overloaded("merge source buckets"));
      }
    }
    if inner.global_pending >= PENDING_GLOBAL {
      return Err(Error::overloaded("merge global pending"));
    }
    if !inner.global_window.admits(now) {
      return Err(Error::overloaded("merge rate window"));
    }
    let bucket = inner.sources.entry(source).or_insert_with(|| SourceBucket {
      pending: 0,
      window: RateWindow::new(now, RATE_PER_SOURCE),
      last_seen: now,
    });
    bucket.last_seen = now;
    if bucket.pending >= PENDING_PER_SOURCE {
      return Err(Error::overloaded("merge source pending"));
    }
    if !bucket.window.admits(now) {
      return Err(Error::overloaded("merge rate window"));
    }
    // Every admission check passed: record both windows as the final
    // grant step. Recording is infallible and the per-source bucket is
    // last used before the global window is touched, so a rejected
    // attempt can never consume either window's budget.
    bucket.window.record();
    bucket.pending += 1;
    inner.global_window.record();
    inner.global_pending += 1;
    Ok(MergeSlot {
      limiter: self.clone(),
      source,
    })
  }
}

impl Inner {
  /// Evicts buckets idle for the configured lifetime when the table is
  /// full, so one source can never pin the table against all others.
  fn evict_idle(&mut self, now: Instant) {
    let expired: Vec<MergeSource> = self
      .sources
      .iter()
      .filter(|(_, bucket)| {
        bucket.pending == 0 && now.duration_since(bucket.last_seen) >= SOURCE_IDLE_LIFETIME
      })
      .map(|(source, _)| *source)
      .collect();
    for source in expired {
      self.sources.remove(&source);
    }
  }
}

/// One in-flight admission attempt. Holds the per-source and global
/// pending counts until dropped, whatever the handshake outcome.
pub(crate) struct MergeSlot {
  limiter: MergeLimiter,
  source: MergeSource,
}

impl core::fmt::Debug for MergeSlot {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("MergeSlot(..)")
  }
}

impl Drop for MergeSlot {
  fn drop(&mut self) {
    if let Ok(mut inner) = self.limiter.inner.lock() {
      inner.global_pending = inner.global_pending.saturating_sub(1);
      if let Some(bucket) = inner.sources.get_mut(&self.source) {
        bucket.pending = bucket.pending.saturating_sub(1);
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
  };

  use super::{
    MergeLimiter, MergeSource, PENDING_GLOBAL, PENDING_PER_SOURCE, RATE_GLOBAL, RATE_PER_SOURCE,
    SOURCE_BUCKET_LIMIT,
  };
  use crate::ErrorKind;

  fn source(octet: u8) -> MergeSource {
    MergeSource::V4([10, 0, 0, octet])
  }

  fn source16(index: u16) -> MergeSource {
    MergeSource::V4([10, 0, (index >> 8) as u8, index as u8])
  }

  fn addr(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, 443)
  }

  #[test]
  fn merge_rate_normalizes_ipv4_mapped_aliases() {
    let v4 = MergeSource::normalize(addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7))));
    let mapped = MergeSource::normalize(addr(IpAddr::V6(Ipv6Addr::new(
      0, 0, 0, 0, 0, 0xFFFF, 0xC0A8, 0x0107,
    ))));
    assert_eq!(v4, mapped, "v4-mapped v6 must share the v4 bucket");
    let native = MergeSource::normalize(addr(IpAddr::V6(Ipv6Addr::new(
      0x2001, 0xDB8, 0, 0, 0, 0, 0, 1,
    ))));
    assert_ne!(v4, native);
  }

  #[test]
  fn merge_rate_per_source_window_and_pending_are_bounded() {
    let limiter = MergeLimiter::new();
    let origin = source(1);
    // The per-source fixed window saturates at the configured rate.
    for _ in 0..RATE_PER_SOURCE {
      drop(limiter.begin(origin).unwrap());
    }
    assert_eq!(
      limiter.begin(origin).unwrap_err().kind(),
      ErrorKind::Overloaded,
      "per-source rate window must saturate"
    );
    // A different source is unaffected.
    drop(limiter.begin(source(2)).unwrap());

    // Pending: hold the per-source limit, then one more is refused.
    let limiter = MergeLimiter::new();
    let held: Vec<_> = (0..PENDING_PER_SOURCE)
      .map(|_| limiter.begin(origin).unwrap())
      .collect();
    assert_eq!(
      limiter.begin(origin).unwrap_err().kind(),
      ErrorKind::Overloaded,
      "per-source pending must saturate"
    );
    drop(held);
    drop(limiter.begin(origin).unwrap());
  }

  /// Rejected attempts must not consume the global rate budget: one
  /// source hammering past its per-source window cannot exhaust the
  /// global 60-second window for every other source.
  #[test]
  fn merge_rate_rejected_attempts_do_not_consume_the_global_window() {
    let limiter = MergeLimiter::new();
    let hammer = source(1);
    let other = source(2);
    // The hammer saturates its per-source window with granted attempts.
    for _ in 0..RATE_PER_SOURCE {
      drop(limiter.begin(hammer).unwrap());
    }
    // Rapid-fire past the saturated window: every further attempt is
    // rejected (and, before the fix, each of these consumed a global
    // slot because the global window recorded before the per-source
    // check).
    for _ in 0..RATE_GLOBAL {
      assert_eq!(
        limiter.begin(hammer).unwrap_err().kind(),
        ErrorKind::Overloaded,
        "saturated source must be rejected"
      );
    }
    // A different source still passes global admission inside the same
    // window: none of the hammer's rejections consumed the global budget.
    drop(limiter.begin(other).unwrap());
  }

  #[test]
  fn merge_rate_global_window_and_pending_are_bounded() {
    let limiter = MergeLimiter::new();
    let mut held = Vec::new();
    // Hold the global pending limit from distinct sources.
    let mut octet = 1;
    while held.len() < PENDING_GLOBAL {
      held.push(limiter.begin(source(octet)).unwrap());
      octet = octet.wrapping_add(1);
    }
    assert_eq!(
      limiter.begin(source(octet)).unwrap_err().kind(),
      ErrorKind::Overloaded,
      "global pending must saturate"
    );
    drop(held);

    // Global rate window saturates across sources.
    let limiter = MergeLimiter::new();
    let mut octet = 1;
    for _ in 0..RATE_GLOBAL {
      drop(limiter.begin(source(octet)).unwrap());
      octet = octet.wrapping_add(1);
    }
    assert_eq!(
      limiter.begin(source(octet)).unwrap_err().kind(),
      ErrorKind::Overloaded,
      "global rate window must saturate"
    );
  }

  #[test]
  fn merge_rate_bucket_table_is_bounded_and_evicts_idle_sources() {
    let limiter = MergeLimiter::new();
    // Fill the table up to the limit with distinct sources. The global
    // rate window is reset per iteration so the test isolates the bucket
    // bound from the 256/60s global rate (which would legitimately cap a
    // 1,024-bucket fill in one window).
    for index in 0..SOURCE_BUCKET_LIMIT as u16 {
      {
        let mut inner = limiter.inner.lock().unwrap();
        inner.global_window.start = std::time::Instant::now();
        inner.global_window.count = 0;
      }
      drop(limiter.begin(source16(index)).unwrap());
    }
    // A brand-new source is refused while every bucket is live.
    let fresh = source16(SOURCE_BUCKET_LIMIT as u16);
    assert_eq!(
      limiter.begin(fresh).unwrap_err().kind(),
      ErrorKind::Overloaded,
      "full bucket table must refuse new sources"
    );
    // Idle eviction uses the monotonic clock: force the last-seen far back
    // by draining live buckets, then a new source is admitted again.
    let mut inner = limiter.inner.lock().unwrap();
    for bucket in inner.sources.values_mut() {
      bucket.last_seen = bucket
        .last_seen
        .checked_sub(super::SOURCE_IDLE_LIFETIME + Duration::from_secs(1))
        .unwrap();
    }
    drop(inner);
    limiter
      .inner
      .lock()
      .unwrap()
      .evict_idle(std::time::Instant::now());
    {
      let mut inner = limiter.inner.lock().unwrap();
      inner.global_window.start = std::time::Instant::now();
      inner.global_window.count = 0;
    }
    drop(limiter.begin(fresh).unwrap());
  }
}
