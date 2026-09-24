//! Credential-merge admission control.
//!
//! Admission classifies each accepted connection by its hello mode and
//! meters it against a smooth token-bucket policy in two separate
//! pools: **join** attempts (untrusted strangers carrying a credential —
//! the strictest budget) and **member reconnects** (holders of a trusted
//! binding — the self-healing path, budgeted by the cluster scale). Each
//! pool holds a per-source and a global bucket, per-pool
//! pending-attempt bounds, and one bounded source-bucket table with
//! idle eviction shared by both pools; the session driver owns the
//! configured authentication deadline. Tokens refill continuously at
//! `burst / window` per second, so a refused party advances at the
//! refill rate instead of waiting for a window edge, and the head of a
//! burst can no longer consume a whole window for the tail.
//!
//! A refused attempt consumes no budget, performs no signing, creates
//! no bucket, and refreshes no idle clock: buckets and idle clocks
//! record only on the grant path. A rejected attempt also neither
//! creates nor refreshes the source's bucket, so refused sources can
//! never pin the bounded table. A [`MergeSlot`] holds the pool's
//! pending count for exactly one in-flight attempt and releases it on
//! every outcome, including cancellation.
//!
//! Buckets run on the monotonic clock: host wall-clock rollback can
//! delay the authentication deadline and a forward jump can make it
//! immediately due, but neither widens or narrows the admission rates.

use std::{
  collections::BTreeMap,
  net::{IpAddr, SocketAddr},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use crate::{Error, Result, config::MergeAdmissionLimits};

/// The scaled token unit: one admission consumes `TOKEN_SCALE` fixed
/// points, so continuous refill keeps sub-token remainders.
const TOKEN_SCALE: u64 = 1 << 32;

/// The concurrent in-flight attempts one source may hold per pool.
const PENDING_PER_SOURCE: usize = 4;
/// The concurrent in-flight attempts the node may hold per pool.
const PENDING_GLOBAL: usize = 64;
/// The bounded number of tracked sources; idle eviction keeps one
/// source from pinning the table.
const SOURCE_BUCKET_LIMIT: usize = 1024;
/// How long a bucket stays evictable after its last grant.
const SOURCE_IDLE_LIFETIME: Duration = Duration::from_secs(600);

/// The canonical merge source. The peer port is dropped (ephemeral
/// reconnects are aliases of one source), IPv4-mapped IPv6 collapses to
/// its IPv4 form, so every alias of one source shares one bucket. A
/// medium without peer addresses (a caller-registered custom transport)
/// attributes its attempts to one shared per-medium bucket derived from
/// the transport class binding: the configured limits still bound it,
/// just at the coarsest attribution the medium supports.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum MergeSource {
  V4([u8; 4]),
  V6([u8; 16]),
  Medium([u8; 16]),
}

impl MergeSource {
  pub(crate) fn normalize(address: SocketAddr) -> Self {
    match address.ip() {
      IpAddr::V4(v4) => Self::V4(v4.octets()),
      IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
        Some(v4) => Self::V4(v4.octets()),
        None => Self::V6(v6.octets()),
      },
    }
  }

  /// The shared bucket of one addressless medium, derived from the
  /// transport class channel binding (per-transport-tag constant).
  pub(crate) fn medium(class_binding: &[u8; 32]) -> Self {
    let mut medium = [0_u8; 16];
    medium.copy_from_slice(&class_binding[..16]);
    Self::Medium(medium)
  }
}

/// The admission pool a handshake draws from, classified by the hello
/// mode before any credential or signing work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionPool {
  Join,
  Member,
}

impl AdmissionPool {
  const INDEX: usize = 2;

  fn index(self) -> usize {
    match self {
      Self::Join => 0,
      Self::Member => 1,
    }
  }
}

/// One continuously refilling token bucket: capacity `burst` tokens,
/// refilled at `burst / window` per second. `tokens` is fixed point at
/// `TOKEN_SCALE` per token.
struct TokenBucket {
  burst: u32,
  window: Duration,
  tokens: u64,
  last_refill: Instant,
}

impl TokenBucket {
  fn new(now: Instant, burst: u32, window: Duration) -> Self {
    Self {
      burst,
      window,
      tokens: u64::from(burst) * TOKEN_SCALE,
      last_refill: now,
    }
  }

  /// Empties the bucket (a freshly saturated budget); test-only state
  /// surgery alongside the same-module tests that pin refill behavior.
  #[cfg(test)]
  fn drain(&mut self) {
    self.tokens = 0;
  }

  /// Refills continuously up to capacity. A forward jump fills the
  /// bucket; the monotonic clock makes rollback a no-op.
  fn refill(&mut self, now: Instant) {
    let elapsed = now.saturating_duration_since(self.last_refill);
    if elapsed.is_zero() {
      return;
    }
    self.last_refill = now;
    if self.burst == 0 || self.window.is_zero() {
      return;
    }
    let gained = (elapsed.as_nanos() * u128::from(self.burst) * u128::from(TOKEN_SCALE))
      / self.window.as_nanos().max(1);
    self.tokens = (u128::from(self.tokens))
      .saturating_add(gained)
      .min(u128::from(self.capacity())) as u64;
  }

  fn capacity(&self) -> u64 {
    u64::from(self.burst) * TOKEN_SCALE
  }

  fn admits(&self) -> bool {
    self.tokens >= TOKEN_SCALE
  }

  fn consume(&mut self) {
    self.tokens -= TOKEN_SCALE;
  }
}

/// The per-pool limits the limiter reads out of the configured
/// [`MergeAdmissionLimits`] (source bucket, global bucket).
use crate::config::AdmissionPoolLimits;

/// One source's two pool buckets, its per-pool pending counts, and the
/// idle clock only grants refresh.
struct SourceBuckets {
  buckets: [TokenBucket; AdmissionPool::INDEX],
  pending: [usize; AdmissionPool::INDEX],
  last_seen: Instant,
}

impl SourceBuckets {
  fn new(now: Instant, join: AdmissionPoolLimits, member: AdmissionPoolLimits) -> Self {
    Self {
      buckets: [
        TokenBucket::new(now, join.source.0, join.source.1),
        TokenBucket::new(now, member.source.0, member.source.1),
      ],
      pending: [0; AdmissionPool::INDEX],
      last_seen: now,
    }
  }
}

struct Inner {
  sources: BTreeMap<MergeSource, SourceBuckets>,
  global: [TokenBucket; AdmissionPool::INDEX],
  global_pending: [usize; AdmissionPool::INDEX],
  limits: MergeAdmissionLimits,
}

/// The merge admission limiter shared by every accepted connection.
#[derive(Clone)]
pub(crate) struct MergeLimiter {
  inner: Arc<Mutex<Inner>>,
}

impl MergeLimiter {
  pub(crate) fn new(limits: MergeAdmissionLimits) -> Self {
    let now = Instant::now();
    let join = limits.join_pool();
    let member = limits.member_pool();
    Self {
      inner: Arc::new(Mutex::new(Inner {
        sources: BTreeMap::new(),
        global: [
          TokenBucket::new(now, join.global.0, join.global.1),
          TokenBucket::new(now, member.global.0, member.global.1),
        ],
        global_pending: [0; AdmissionPool::INDEX],
        limits,
      })),
    }
  }

  /// Admits one connection attempt from `source` against `pool`,
  /// holding its pending slot until the [`MergeSlot`] drops. Rejection
  /// is a typed overload and never consumes a credential or budget: the
  /// buckets, pending counts, and idle clocks record only after every
  /// admission check has passed. The per-source checks evaluate the
  /// looked-up bucket or the fresh defaults (full bucket, no pending)
  /// for a source with no bucket yet, so a rejection leaves no bucket
  /// behind and cannot pin the bounded table.
  pub(crate) fn begin(&self, source: MergeSource, pool: AdmissionPool) -> Result<MergeSlot> {
    let index = pool.index();
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
    if inner.global_pending[index] >= PENDING_GLOBAL {
      return Err(Error::overloaded("merge global pending"));
    }
    // The global bucket is checked and refilled before anything is
    // materialized; the consume happens on the grant path only.
    inner.global[index].refill(now);
    if !inner.global[index].admits() {
      return Err(Error::overloaded("merge rate budget"));
    }
    // Per-source checks evaluate the looked-up bucket, or the fresh
    // defaults (full bucket, zero pending) for a source with no bucket
    // yet. Nothing is materialized until every check has passed.
    let join_limits = inner.limits.join_pool();
    let member_limits = inner.limits.member_pool();
    let source_admitted = {
      let existing = inner.sources.get_mut(&source);
      let pending = existing.as_ref().map_or(0, |bucket| bucket.pending[index]);
      if pending >= PENDING_PER_SOURCE {
        return Err(Error::overloaded("merge source pending"));
      }
      match existing {
        Some(bucket) => {
          bucket.buckets[index].refill(now);
          bucket.buckets[index].admits()
        }
        // A brand-new source starts against a full bucket.
        None => true,
      }
    };
    if !source_admitted {
      return Err(Error::overloaded("merge rate budget"));
    }
    // Every admission check passed: materialize the bucket, refresh its
    // idle clock, and consume both buckets as the final grant step.
    let bucket = inner
      .sources
      .entry(source)
      .or_insert_with(|| SourceBuckets::new(now, join_limits, member_limits));
    bucket.last_seen = now;
    bucket.buckets[index].consume();
    bucket.pending[index] += 1;
    inner.global[index].consume();
    inner.global_pending[index] += 1;
    Ok(MergeSlot {
      limiter: self.clone(),
      source,
      pool,
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
        bucket.pending == [0; AdmissionPool::INDEX]
          && now.duration_since(bucket.last_seen) >= SOURCE_IDLE_LIFETIME
      })
      .map(|(source, _)| *source)
      .collect();
    for source in expired {
      self.sources.remove(&source);
    }
  }
}

/// One in-flight admission attempt. Holds the pool's per-source and
/// global pending counts until dropped, whatever the handshake outcome.
pub(crate) struct MergeSlot {
  limiter: MergeLimiter,
  source: MergeSource,
  pool: AdmissionPool,
}

impl core::fmt::Debug for MergeSlot {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("MergeSlot(..)")
  }
}

impl Drop for MergeSlot {
  fn drop(&mut self) {
    if let Ok(mut inner) = self.limiter.inner.lock() {
      let index = self.pool.index();
      inner.global_pending[index] = inner.global_pending[index].saturating_sub(1);
      if let Some(bucket) = inner.sources.get_mut(&self.source) {
        bucket.pending[index] = bucket.pending[index].saturating_sub(1);
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
    AdmissionPool, MergeLimiter, MergeSource, PENDING_GLOBAL, PENDING_PER_SOURCE,
    SOURCE_BUCKET_LIMIT, SOURCE_IDLE_LIFETIME, TOKEN_SCALE,
  };
  use crate::{ErrorKind, config::MergeAdmissionLimits};

  fn source(octet: u8) -> MergeSource {
    MergeSource::V4([10, 0, 0, octet])
  }

  fn source16(index: u16) -> MergeSource {
    MergeSource::V4([10, 0, (index >> 8) as u8, index as u8])
  }

  fn addr(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, 443)
  }

  fn limiter() -> MergeLimiter {
    MergeLimiter::new(MergeAdmissionLimits::default())
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

  /// The default limits derive from the reference cluster scale: the
  /// join pool keeps today's strict per-source budget, and the member
  /// pool admits a whole same-site cluster reconnecting at once (the
  /// incident-B shape) instead of starving it.
  #[test]
  fn merge_rate_defaults_derive_from_the_reference_cluster_scale() {
    let limits = MergeAdmissionLimits::default();
    let join = limits.join_pool();
    let member = limits.member_pool();
    assert_eq!(join.source, (16, Duration::from_secs(60)));
    assert_eq!(join.global, (256, Duration::from_secs(60)));
    assert_eq!(member.source, (256, Duration::from_secs(60)));
    assert_eq!(member.global, (256, Duration::from_secs(60)));

    let small = MergeAdmissionLimits::for_cluster(4).unwrap();
    assert_eq!(small.member_pool().source.0, 16, "the floor is 16");
    let large = MergeAdmissionLimits::for_cluster(1_000).unwrap();
    assert_eq!(large.member_pool().source.0, 4_000);
    assert!(MergeAdmissionLimits::for_cluster(0).is_err());
  }

  /// A same-site cluster reconnecting as members draws the generous
  /// pool: sixty-four same-source member reconnects are all admitted
  /// outright (the incident-B shape now converges in one step), and
  /// member volume consumes none of the same source's strict join
  /// budget: sixteen joins still pass, the seventeenth is refused.
  #[test]
  fn merge_rate_member_pool_admits_a_same_site_burst_and_joins_stay_strict() {
    let limiter = limiter();
    let origin = source(1);
    for _ in 0..64 {
      drop(limiter.begin(origin, AdmissionPool::Member).unwrap());
    }
    for _ in 0..16 {
      drop(limiter.begin(origin, AdmissionPool::Join).unwrap());
    }
    assert_eq!(
      limiter
        .begin(origin, AdmissionPool::Join)
        .unwrap_err()
        .kind(),
      ErrorKind::Overloaded,
      "the same site's joins stay strictly budgeted"
    );
  }

  #[test]
  fn merge_rate_join_pool_saturates_and_refills_smoothly() {
    let limiter = limiter();
    let origin = source(1);
    // The join pool saturates at its per-source burst.
    for _ in 0..16 {
      drop(limiter.begin(origin, AdmissionPool::Join).unwrap());
    }
    assert_eq!(
      limiter
        .begin(origin, AdmissionPool::Join)
        .unwrap_err()
        .kind(),
      ErrorKind::Overloaded,
      "the per-source join bucket must saturate"
    );
    // The member pool of the same source is untouched: the pools are
    // independent budgets.
    drop(limiter.begin(origin, AdmissionPool::Member).unwrap());
    // A different source's joins are unaffected.
    drop(limiter.begin(source(2), AdmissionPool::Join).unwrap());

    // Half a window later the bucket has refilled half its burst:
    // smooth refill, no window edge to wait for.
    {
      let mut inner = limiter.inner.lock().unwrap();
      let bucket = inner.sources.get_mut(&origin).unwrap();
      assert!(
        bucket.buckets[0].tokens < TOKEN_SCALE,
        "the join bucket must be saturated below one token"
      );
      bucket.buckets[0].last_refill -= Duration::from_secs(30);
    }
    for _ in 0..8 {
      drop(limiter.begin(origin, AdmissionPool::Join).unwrap());
    }
    assert_eq!(
      limiter
        .begin(origin, AdmissionPool::Join)
        .unwrap_err()
        .kind(),
      ErrorKind::Overloaded,
      "the refill grants exactly half a burst per half window"
    );
  }

  /// Rejected attempts must not consume any budget: one source hammering
  /// past its saturated join bucket cannot drain the global buckets or
  /// the member pool of any other source.
  #[test]
  fn merge_rate_rejected_attempts_do_not_consume_budget() {
    let limiter = limiter();
    let hammer = source(1);
    for _ in 0..16 {
      drop(limiter.begin(hammer, AdmissionPool::Join).unwrap());
    }
    for _ in 0..256 {
      assert_eq!(
        limiter
          .begin(hammer, AdmissionPool::Join)
          .unwrap_err()
          .kind(),
        ErrorKind::Overloaded,
        "the saturated join bucket must refuse the attempt"
      );
    }
    // None of the hammer's refusals touched the global join bucket:
    // a different source still passes, and the member pools are full.
    // (Whole-token counts tolerate the sub-token refill remainder that
    // accrued across the grants.)
    drop(limiter.begin(source(2), AdmissionPool::Join).unwrap());
    drop(limiter.begin(source(2), AdmissionPool::Member).unwrap());
    {
      let inner = limiter.inner.lock().unwrap();
      let join_tokens = inner.global[0].tokens / TOKEN_SCALE;
      let member_tokens = inner.global[1].tokens / TOKEN_SCALE;
      assert!(
        (239..=240).contains(&join_tokens),
        "the hammer's refusals must not drain the global join bucket"
      );
      assert!(
        (255..=256).contains(&member_tokens),
        "the hammer's refusals must not drain the global member bucket"
      );
    }
  }

  /// A rejected attempt must never create a bucket nor refresh the idle
  /// clock: a brand-new source refused at the global stage leaves the
  /// table empty, and a saturated source's refusals keep its bucket
  /// evictable.
  #[test]
  fn merge_rate_rejected_attempts_never_create_or_refresh_a_bucket() {
    let limiter = limiter();
    // Saturate the global join bucket without granting anything, so a
    // brand-new source is refused at the global stage.
    {
      let mut inner = limiter.inner.lock().unwrap();
      inner.global[0].drain();
    }
    let fresh = source(200);
    assert_eq!(
      limiter
        .begin(fresh, AdmissionPool::Join)
        .unwrap_err()
        .kind(),
      ErrorKind::Overloaded,
      "a drained global join bucket must refuse a brand-new source"
    );
    assert!(
      limiter.inner.lock().unwrap().sources.is_empty(),
      "a rejected attempt must not create a bucket for a brand-new source"
    );

    // A source refused by its own saturated per-source bucket: no new
    // bucket, no pending slot held, and no idle-clock refresh (only
    // grants may keep a bucket alive). The global bucket drained above
    // is refilled first: this half isolates the per-source budget.
    let origin = source(1);
    {
      let mut inner = limiter.inner.lock().unwrap();
      inner.global[0].tokens = inner.global[0].capacity();
    }
    for _ in 0..16 {
      drop(limiter.begin(origin, AdmissionPool::Join).unwrap());
    }
    let marked = std::time::Instant::now();
    for _ in 0..16 {
      assert_eq!(
        limiter
          .begin(origin, AdmissionPool::Join)
          .unwrap_err()
          .kind(),
        ErrorKind::Overloaded,
        "the saturated per-source join bucket must refuse the attempt"
      );
    }
    let inner = limiter.inner.lock().unwrap();
    assert_eq!(inner.sources.len(), 1, "rejections must not create buckets");
    let bucket = inner.sources.get(&origin).unwrap();
    assert_eq!(bucket.pending, [0, 0], "a rejection holds no pending slot");
    assert!(
      bucket.last_seen <= marked,
      "a rejected attempt must not refresh the bucket's idle clock"
    );
  }

  /// Refused sources must not keep their buckets alive: a table filled
  /// to its limit with drained (refusing) sources cannot lock out a
  /// brand-new source once the idle lifetime has passed.
  #[test]
  fn merge_rate_refused_sources_do_not_pin_the_bucket_table() {
    let limiter = limiter();
    // Fill the table to the limit with one member grant per source; the
    // global member bucket is refilled per iteration so the test
    // isolates the table bound from the global budget.
    for index in 0..SOURCE_BUCKET_LIMIT as u16 {
      {
        let mut inner = limiter.inner.lock().unwrap();
        inner.global[1].tokens = inner.global[1].capacity();
      }
      drop(
        limiter
          .begin(source16(index), AdmissionPool::Member)
          .unwrap(),
      );
    }
    // Drain every per-source member bucket: further member attempts are
    // refused by their own bucket and must not refresh the idle clock.
    {
      let mut inner = limiter.inner.lock().unwrap();
      for bucket in inner.sources.values_mut() {
        bucket.buckets[1].drain();
      }
    }
    let marked = std::time::Instant::now();
    for index in 0..SOURCE_BUCKET_LIMIT as u16 {
      assert_eq!(
        limiter
          .begin(source16(index), AdmissionPool::Member)
          .unwrap_err()
          .kind(),
        ErrorKind::Overloaded,
        "the drained per-source bucket must refuse the attempt"
      );
    }
    {
      let inner = limiter.inner.lock().unwrap();
      assert!(
        inner
          .sources
          .values()
          .all(|bucket| bucket.last_seen <= marked),
        "a refusal must not refresh the bucket's idle clock"
      );
    }
    // Simulate the idle lifetime passing: every refused bucket is now
    // evictable, so a brand-new source is admitted instead of refused
    // with "merge source buckets" forever.
    {
      let mut inner = limiter.inner.lock().unwrap();
      for bucket in inner.sources.values_mut() {
        bucket.last_seen = bucket
          .last_seen
          .checked_sub(super::SOURCE_IDLE_LIFETIME + Duration::from_secs(1))
          .unwrap();
      }
      inner.global[1].tokens = inner.global[1].capacity();
    }
    drop(
      limiter
        .begin(source16(SOURCE_BUCKET_LIMIT as u16), AdmissionPool::Member)
        .unwrap(),
    );
  }

  /// Pending bounds are per pool: a site's concurrent joins cannot take
  /// the concurrent reconnect slots its members need to heal (and vice
  /// versa), and both pools' global pending bounds hold.
  #[test]
  fn merge_rate_pending_bounds_are_per_pool() {
    let limiter = limiter();
    let origin = source(1);
    // Hold the per-source join pending limit; the same source's member
    // reconnect still passes.
    let held: Vec<_> = (0..PENDING_PER_SOURCE)
      .map(|_| limiter.begin(origin, AdmissionPool::Join).unwrap())
      .collect();
    assert_eq!(
      limiter
        .begin(origin, AdmissionPool::Join)
        .unwrap_err()
        .kind(),
      ErrorKind::Overloaded,
      "per-source join pending must saturate"
    );
    drop(limiter.begin(origin, AdmissionPool::Member).unwrap());
    drop(held);

    // Hold the global member pending limit from distinct sources; one
    // more is refused, and a join still passes (independent pool).
    let mut held_global = Vec::new();
    let mut octet = 1_u16;
    while held_global.len() < PENDING_GLOBAL {
      held_global.push(
        limiter
          .begin(source16(octet), AdmissionPool::Member)
          .unwrap(),
      );
      octet += 1;
    }
    assert_eq!(
      limiter
        .begin(source16(octet), AdmissionPool::Member)
        .unwrap_err()
        .kind(),
      ErrorKind::Overloaded,
      "global member pending must saturate"
    );
    drop(limiter.begin(source(9), AdmissionPool::Join).unwrap());
    drop(held_global);
    drop(limiter.begin(source(9), AdmissionPool::Member).unwrap());
  }

  /// The source bucket table is bounded and evicts idle sources.
  #[test]
  fn merge_rate_bucket_table_is_bounded_and_evicts_idle_sources() {
    let limiter = limiter();
    for index in 0..SOURCE_BUCKET_LIMIT as u16 {
      {
        let mut inner = limiter.inner.lock().unwrap();
        inner.global[1].tokens = inner.global[1].capacity();
      }
      drop(
        limiter
          .begin(source16(index), AdmissionPool::Member)
          .unwrap(),
      );
    }
    let fresh = source16(SOURCE_BUCKET_LIMIT as u16);
    assert_eq!(
      limiter
        .begin(fresh, AdmissionPool::Member)
        .unwrap_err()
        .kind(),
      ErrorKind::Overloaded,
      "full bucket table must refuse new sources"
    );
    // Idle eviction uses the monotonic clock: force the last-seen far
    // back, then a new source is admitted again.
    let mut inner = limiter.inner.lock().unwrap();
    for bucket in inner.sources.values_mut() {
      bucket.last_seen = bucket
        .last_seen
        .checked_sub(SOURCE_IDLE_LIFETIME + Duration::from_secs(1))
        .unwrap();
    }
    inner.evict_idle(std::time::Instant::now());
    inner.global[1].tokens = inner.global[1].capacity();
    drop(inner);
    drop(limiter.begin(fresh, AdmissionPool::Member).unwrap());
  }
}
