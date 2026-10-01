//! The fingerprint index: the range-aggregate primitive behind the
//! reconciliation plane.
//!
//! A lane's local state is an ordered set of item digests — one 64-bit
//! content digest per stored row. The index maintains the pair
//! `(count, xor of digests)` for every digest range: the
//! transitive-group fingerprint of range-based set reconciliation
//! (`docs/research/03-set-reconciliation.md`). Two peers that agree on
//! a range's fingerprint hold the same items in that range (the
//! remaining disagreement requires a digest collision *and* a matching
//! count, bounded far below any operational catalog size), so payload
//! bytes only ever cross a session for ranges whose fingerprints
//! differ.
//!
//! The structure is a derived view of storage: never persisted, never
//! expired, rebuilt from the store snapshot on start. It therefore
//! cannot drift from the rows it summarizes — the failure mode that
//! forced the watermark tables' periodic whole-catalog refresh
//! (`src/sync_common.rs`, `WATERMARK_REFRESH_PASSES`).
//!
//! Layout: digests partition into `2^BUCKET_BITS` buckets by their top
//! bits (content digests are uniformly distributed, so buckets stay
//! balanced without rebalancing machinery), each bucket keeps its
//! digest-sorted entries plus its aggregate, and a Fenwick tree over
//! the bucket aggregates answers a strict-prefix fingerprint in
//! `O(log buckets)`. Every range fingerprint is then the difference of
//! two prefixes — counts subtract, xors cancel — which is exact because
//! the aggregate pair forms a group (the property range-based set
//! reconciliation depends on; see the tests pinning the group laws).
//! Enumeration is digest-ascending everywhere, the deterministic order
//! the reconciliation rounds and the wire encoders build on.

/// The digest-space bucket count as a power of two: 1024 buckets. The
/// constant trades memory for scan bounds — a prefix query costs the
/// Fenwick walk over 1024 slots plus one partial bucket scan, and an
/// insertion moves one expected `len / 1024`-entry bucket — while
/// staying flat for every realistic catalog size.
const BUCKET_BITS: u32 = 10;
/// [`BUCKET_BITS`] as a bucket count.
const BUCKETS: usize = 1 << BUCKET_BITS;

/// The aggregate fingerprint of a set of item digests: how many digests
/// the set holds and their exclusive-or. The pair forms an abelian
/// group under [`Fingerprint::combine`] (component-wise count addition
/// and xor), with [`Fingerprint::remove`] as its inverse — the algebra
/// that makes a range's fingerprint the exact difference of its prefix
/// fingerprints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Fingerprint {
  /// The digest count in the aggregated set. Exact in every live index
  /// (it never exceeds the entry count); addition and subtraction are
  /// wrapping so the group inverse stays a true inverse.
  count: u64,
  /// The exclusive-or of every digest in the aggregated set; zero for
  /// the empty set.
  xor: u64,
}

impl Fingerprint {
  /// The identity element: the empty set's aggregate.
  pub(crate) const EMPTY: Self = Self { count: 0, xor: 0 };

  /// The aggregate of the one-digest set `{digest}`.
  pub(crate) const fn singleton(digest: u64) -> Self {
    Self {
      count: 1,
      xor: digest,
    }
  }

  /// The group operation: the aggregate of the disjoint union. It is
  /// commutative and associative, and combining with the aggregates of
  /// overlapping sets double-cancels the overlap's digests — callers
  /// must aggregate disjoint sets (or rely on that cancellation
  /// deliberately, as the prefix difference below does not).
  pub(crate) const fn combine(self, other: Self) -> Self {
    Self {
      count: self.count.wrapping_add(other.count),
      xor: self.xor ^ other.xor,
    }
  }

  /// The group inverse: the aggregate of the set difference, exact when
  /// `other` aggregates a subset of `self`'s set (the range query's
  /// prefix-of-prefix shape).
  pub(crate) const fn remove(self, other: Self) -> Self {
    Self {
      count: self.count.wrapping_sub(other.count),
      xor: self.xor ^ other.xor,
    }
  }

  /// The inverse element under [`Fingerprint::combine`]: combining
  /// `self` with its inverse yields the identity. The count negates
  /// (wrapping, so the inverse stays exact) while the xor is its own
  /// inverse and passes through unchanged. The Fenwick point update
  /// only folds deltas together, so a removal feeds it the
  /// singleton's inverse rather than the singleton itself.
  pub(crate) const fn inverse(self) -> Self {
    Self {
      count: self.count.wrapping_neg(),
      xor: self.xor,
    }
  }

  /// The aggregated digest count.
  pub(crate) const fn count(&self) -> u64 {
    self.count
  }

  /// The aggregated digest exclusive-or.
  pub(crate) const fn xor(&self) -> u64 {
    self.xor
  }

  /// The aggregate is the empty set's.
  pub(crate) const fn is_empty(&self) -> bool {
    self.count == 0
  }
}

/// One bucket: the digest-sorted entries below one top-bits prefix,
/// with the bucket's aggregate maintained on every mutation.
struct Bucket<V> {
  fingerprint: Fingerprint,
  entries: Vec<(u64, V)>,
}

impl<V> Bucket<V> {
  fn new() -> Self {
    Self {
      fingerprint: Fingerprint::EMPTY,
      entries: Vec::new(),
    }
  }
}

/// A digest-ordered map with maintained range aggregates: the derived
/// local view a reconciliation lane negotiates over.
///
/// Every operation is deterministic — bucket placement is a shift,
/// entry order is digest order, and no scheduling, hashing seed, or
/// clock participates — so two indexes over the same digest set are
/// byte-for-byte interchangeable in every observable: `root`, any
/// `prefix`/`range` fingerprint, and the `iter`/`range_entries`
/// enumeration order.
pub(crate) struct FingerprintIndex<V> {
  /// The buckets, indexed by a digest's top `BUCKET_BITS` bits.
  buckets: Vec<Bucket<V>>,
  /// The Fenwick group tree over the bucket aggregates, 1-indexed
  /// (slot 0 unused): prefix sums of fingerprints without maintaining
  /// a cumulative array per mutation.
  fenwick: Vec<Fingerprint>,
  /// The whole-set aggregate, maintained directly (every mutation
  /// touches it once).
  root: Fingerprint,
  /// The entry count.
  len: usize,
}

impl<V> FingerprintIndex<V> {
  /// The empty index.
  pub(crate) fn new() -> Self {
    let mut fenwick = Vec::with_capacity(BUCKETS + 1);
    fenwick.resize(BUCKETS + 1, Fingerprint::EMPTY);
    Self {
      buckets: (0..BUCKETS).map(|_| Bucket::new()).collect(),
      fenwick,
      root: Fingerprint::EMPTY,
      len: 0,
    }
  }

  /// The number of stored digests.
  pub(crate) fn len(&self) -> usize {
    self.len
  }

  /// No digest is stored.
  pub(crate) fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// The whole-set aggregate: the root fingerprint a session exchange
  /// starts from.
  pub(crate) fn root(&self) -> Fingerprint {
    self.root
  }

  /// The value stored under `digest`.
  pub(crate) fn get(&self, digest: u64) -> Option<&V> {
    let bucket = &self.buckets[bucket_of(digest)];
    let position = bucket.entries.partition_point(|(held, _)| *held < digest);
    match bucket.entries.get(position) {
      Some((held, value)) if *held == digest => Some(value),
      _ => None,
    }
  }

  /// `digest` is stored.
  pub(crate) fn contains(&self, digest: u64) -> bool {
    self.get(digest).is_some()
  }

  /// Stores `value` under `digest`. A repeated digest replaces the
  /// value and returns the old one — the fingerprint is over digests,
  /// so a re-inserted identical digest cannot change any aggregate
  /// (equal digests mean equal row bytes by the digest contract).
  pub(crate) fn insert(&mut self, digest: u64, value: V) -> Option<V> {
    let singleton = Fingerprint::singleton(digest);
    let bucket = &mut self.buckets[bucket_of(digest)];
    let position = bucket.entries.partition_point(|(held, _)| *held < digest);
    match bucket.entries.get_mut(position) {
      Some((held, previous)) if *held == digest => {
        let previous = std::mem::replace(previous, value);
        // The digest set is unchanged: no aggregate moves.
        Some(previous)
      }
      _ => {
        bucket.entries.insert(position, (digest, value));
        bucket.fingerprint = bucket.fingerprint.combine(singleton);
        let fenwick_slot = bucket_of(digest) + 1;
        self.fenwick_update(fenwick_slot, singleton);
        self.root = self.root.combine(singleton);
        self.len += 1;
        None
      }
    }
  }

  /// Removes and returns the value under `digest` (nothing when the
  /// digest is absent).
  pub(crate) fn remove(&mut self, digest: u64) -> Option<V> {
    let singleton = Fingerprint::singleton(digest);
    let bucket = &mut self.buckets[bucket_of(digest)];
    let position = bucket.entries.partition_point(|(held, _)| *held < digest);
    match bucket.entries.get(position) {
      Some((held, _)) if *held == digest => {
        let (removed, value) = bucket.entries.remove(position);
        debug_assert_eq!(removed, digest);
        bucket.fingerprint = bucket.fingerprint.remove(singleton);
        let fenwick_slot = bucket_of(digest) + 1;
        self.fenwick_update(fenwick_slot, singleton.inverse());
        self.root = self.root.remove(singleton);
        self.len -= 1;
        Some(value)
      }
      _ => None,
    }
  }

  /// The aggregate of every stored digest strictly below `bound`. Every
  /// range fingerprint composes from two of these (the group
  /// inverse turns a prefix difference into a range).
  pub(crate) fn prefix(&self, bound: u64) -> Fingerprint {
    let index = bucket_of(bound);
    let mut aggregate = self.fenwick_prefix(index);
    let bucket = &self.buckets[index];
    // The bucket's entries are digest-sorted, so everything strictly
    // below `bound` is a prefix of the bucket.
    for (held, _) in bucket.entries.iter().take_while(|(held, _)| *held < bound) {
      aggregate = aggregate.combine(Fingerprint::singleton(*held));
    }
    aggregate
  }

  /// The aggregate of the half-open range `[start, end)`: the prefix
  /// difference `prefix(end) ⊖ prefix(start)`. An empty or inverted
  /// range is the empty aggregate.
  pub(crate) fn range(&self, start: u64, end: u64) -> Fingerprint {
    if start >= end {
      Fingerprint::EMPTY
    } else {
      self.prefix(end).remove(self.prefix(start))
    }
  }

  /// Every stored `(digest, value)` in the half-open range
  /// `[start, end)`, digest-ascending.
  pub(crate) fn range_entries(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, &V)> + '_ {
    let span: &[Bucket<V>] = if start >= end {
      &[]
    } else {
      &self.buckets[bucket_of(start)..=bucket_of(end)]
    };
    span
      .iter()
      .flat_map(|bucket| bucket.entries.iter())
      .filter(move |(held, _)| *held >= start && *held < end)
      .map(|(held, value)| (*held, value))
  }

  /// Every stored `(digest, value)`, digest-ascending: the order the
  /// full-catalog reconciliation rounds enumerate in.
  pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, &V)> + '_ {
    self
      .buckets
      .iter()
      .flat_map(|bucket| bucket.entries.iter())
      .map(|(held, value)| (*held, value))
  }

  /// The Fenwick point update: fold `delta` into every tree slot whose
  /// span covers `slot` (the standard ascent by low bit).
  fn fenwick_update(&mut self, mut slot: usize, delta: Fingerprint) {
    while slot < self.fenwick.len() {
      self.fenwick[slot] = self.fenwick[slot].combine(delta);
      slot += slot.isolate_lowest_one();
    }
  }

  /// The Fenwick prefix query: the aggregate of the buckets below
  /// `count` (a bucket count, so slots are already 1-indexed).
  fn fenwick_prefix(&self, mut count: usize) -> Fingerprint {
    let mut aggregate = Fingerprint::EMPTY;
    while count > 0 {
      aggregate = aggregate.combine(self.fenwick[count]);
      count &= count - 1;
    }
    aggregate
  }
}

impl<V> Default for FingerprintIndex<V> {
  fn default() -> Self {
    Self::new()
  }
}

/// The bucket a digest belongs to: its top `BUCKET_BITS` bits. Always a
/// valid bucket index by construction (a shift of the full digest).
fn bucket_of(digest: u64) -> usize {
  (digest >> (64 - BUCKET_BITS)) as usize
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;

  use super::{BUCKET_BITS, Fingerprint, FingerprintIndex};

  /// A deterministic xorshift64* generator: the property loops below
  /// must reproduce bit-for-bit on every run and every host.
  struct Rng(u64);

  impl Rng {
    fn new(seed: u64) -> Self {
      Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
      let mut x = self.0;
      x ^= x >> 12;
      x ^= x << 25;
      x ^= x >> 27;
      self.0 = x;
      x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
  }

  /// The oracle aggregate: a fold over an explicit digest iteration.
  fn oracle(items: impl Iterator<Item = u64>) -> Fingerprint {
    items.fold(Fingerprint::EMPTY, |acc, digest| {
      acc.combine(Fingerprint::singleton(digest))
    })
  }

  /// The aggregate pair obeys the group laws the range queries rest on:
  /// identity, commutativity, associativity, and a true inverse.
  #[test]
  fn fingerprints_form_an_abelian_group() {
    let mut rng = Rng::new(0xF1A9_2026);
    for _ in 0..1_000 {
      let a = Fingerprint {
        count: rng.next(),
        xor: rng.next(),
      };
      let b = Fingerprint {
        count: rng.next(),
        xor: rng.next(),
      };
      let c = Fingerprint {
        count: rng.next(),
        xor: rng.next(),
      };
      assert_eq!(a.combine(Fingerprint::EMPTY), a, "identity");
      assert_eq!(a.combine(b), b.combine(a), "commutativity");
      assert_eq!(
        a.combine(b).combine(c),
        a.combine(b.combine(c)),
        "associativity"
      );
      assert_eq!(a.combine(b).remove(b), a, "inverse");
      assert_eq!(a.remove(a), Fingerprint::EMPTY, "self-inverse");
    }
  }

  /// Random operation sequences against a BTreeMap oracle: length,
  /// lookups, prefix/range fingerprints, and the root must always
  /// agree with the explicit fold, through interleaved inserts and
  /// removes. Digests draw from a 512-wide key space so the replace
  /// and remove-hit branches are both reached with real probability —
  /// uniform 64-bit digests would essentially never repeat.
  #[test]
  fn random_operations_match_the_btree_map_oracle() {
    let mut rng = Rng::new(0x0AC1_E000);
    let mut index: FingerprintIndex<u32> = FingerprintIndex::new();
    let mut oracle_map: BTreeMap<u64, u32> = BTreeMap::new();
    for step in 0..4_000u32 {
      let digest = rng.next() % 512;
      match rng.next() % 4 {
        0 | 1 => {
          let value = step % 97;
          let previous = index.insert(digest, value);
          assert_eq!(previous, oracle_map.insert(digest, value), "insert return");
        }
        2 => {
          let removed = index.remove(digest);
          assert_eq!(removed, oracle_map.remove(&digest), "remove return");
        }
        _ => {
          assert_eq!(index.get(digest), oracle_map.get(&digest), "lookup");
          assert_eq!(index.contains(digest), oracle_map.contains_key(&digest));
        }
      }
      assert_eq!(index.len(), oracle_map.len(), "length after step {step}");
      assert_eq!(
        index.root(),
        oracle(oracle_map.keys().copied()),
        "root after step {step}"
      );
      let bound = rng.next();
      let expected_prefix = oracle(oracle_map.range(..bound).map(|(digest, _)| *digest));
      assert_eq!(index.prefix(bound), expected_prefix, "prefix below {bound}");
      let start = rng.next();
      let end = rng.next();
      let expected = if start < end {
        oracle(oracle_map.range(start..end).map(|(digest, _)| *digest))
      } else {
        Fingerprint::EMPTY
      };
      assert_eq!(index.range(start, end), expected, "range [{start},{end})");
    }
  }

  /// Fingerprints are a property of the digest set, not of the
  /// insertion history: every rebuild order observes the same root and
  /// the same sampled ranges (the derived-view contract a restart
  /// rebuild relies on).
  #[test]
  fn construction_order_does_not_change_the_fingerprints() {
    let mut rng = Rng::new(0x0D0E_3210);
    let digests: Vec<u64> = (0..2_000).map(|_| rng.next()).collect();
    let mut forward: FingerprintIndex<u8> = FingerprintIndex::new();
    for digest in &digests {
      forward.insert(*digest, 1);
    }
    let mut reverse: FingerprintIndex<u8> = FingerprintIndex::new();
    for digest in digests.iter().rev() {
      reverse.insert(*digest, 1);
    }
    let mut interleaved: FingerprintIndex<u8> = FingerprintIndex::new();
    for (position, _digest) in digests.iter().enumerate() {
      let slot = if position % 2 == 0 {
        position / 2
      } else {
        digests.len() - 1 - position / 2
      };
      interleaved.insert(digests[slot], 1);
    }
    for probe in [0, 1, u64::MAX, rng.next(), rng.next()] {
      assert_eq!(forward.prefix(probe), reverse.prefix(probe));
      assert_eq!(forward.prefix(probe), interleaved.prefix(probe));
    }
    for _ in 0..64 {
      let start = rng.next();
      let end = rng.next().max(start);
      assert_eq!(forward.range(start, end), reverse.range(start, end));
      assert_eq!(forward.range(start, end), interleaved.range(start, end));
    }
    assert_eq!(forward.root(), reverse.root());
    assert_eq!(forward.root(), interleaved.root());
  }

  /// The exact bucket edges: digests at bucket boundaries, the two
  /// u64 extremes, and the strict-prefix boundary semantics. A
  /// re-inserted digest replaces the value without moving any
  /// aggregate, and remove-then-reinsert cycles restore them — with
  /// the tree-backed prefix and range asserted between the removal
  /// and the reinsertion.
  #[test]
  fn bucket_boundaries_and_strict_prefixes() {
    let shift = 64 - BUCKET_BITS;
    let edges = [
      0u64,
      1,
      (1u64 << shift) - 1,
      1u64 << shift,
      (1u64 << shift) + 1,
      (5u64 << shift) - 1,
      5u64 << shift,
      u64::MAX - 1,
      u64::MAX,
    ];
    let mut index: FingerprintIndex<&'static str> = FingerprintIndex::new();
    for digest in edges {
      index.insert(digest, "edge");
    }
    assert_eq!(index.len(), edges.len());
    let root = index.root();
    assert_eq!(root.count(), edges.len() as u64);
    for digest in edges {
      // The prefix at a stored digest excludes that digest itself.
      assert_eq!(
        index.prefix(digest).count(),
        edges.iter().filter(|edge| **edge < digest).count() as u64
      );
      assert_eq!(index.get(digest), Some(&"edge"));
    }
    // A repeated digest replaces the value; no aggregate moves.
    assert_eq!(index.insert(1u64 << shift, "replaced"), Some("edge"));
    assert_eq!(index.get(1u64 << shift), Some(&"replaced"));
    assert_eq!(index.root(), root);
    // Remove and reinsert restores the aggregate exactly. The second
    // removal comes from the low bucket, and its prefix/range are
    // asserted before the reinsert, so the tree path is observed
    // directly after a successful remove — not only through root.
    let removed = index.remove(u64::MAX).expect("the max digest is stored");
    assert_eq!(removed, "edge");
    assert_ne!(index.root(), root);
    let removed = index.remove(0).expect("the zero digest is stored");
    assert_eq!(removed, "edge");
    let low_bound = 1u64 << shift;
    let surviving: Vec<u64> = edges
      .iter()
      .copied()
      .filter(|edge| *edge != 0 && *edge != u64::MAX)
      .collect();
    assert_eq!(
      index.prefix(low_bound),
      oracle(surviving.iter().copied().filter(|edge| *edge < low_bound)),
      "tree prefix after the low-bucket remove"
    );
    assert_eq!(
      index.range(2, low_bound + 2),
      oracle(
        surviving
          .iter()
          .copied()
          .filter(|edge| *edge >= 2 && *edge < low_bound + 2)
      ),
      "tree range after the low-bucket remove"
    );
    index.insert(0, "edge");
    index.insert(u64::MAX, "edge");
    assert_eq!(index.root(), root);
  }

  /// Inverted and empty ranges are the empty aggregate and enumerate
  /// nothing, whatever the stored set.
  #[test]
  fn inverted_ranges_are_empty() {
    let mut rng = Rng::new(0x1A2B_3C4D);
    let mut index: FingerprintIndex<u16> = FingerprintIndex::new();
    for _ in 0..500 {
      index.insert(rng.next(), 7);
    }
    let equal = rng.next();
    assert_eq!(index.range(equal, equal), Fingerprint::EMPTY);
    assert_eq!(index.range_entries(equal, equal).count(), 0);
    let (low, high) = (rng.next(), rng.next());
    let (start, end) = (low.min(high), low.max(high));
    assert_eq!(index.range(end, start), Fingerprint::EMPTY);
    assert_eq!(index.range_entries(end, start).count(), 0);
    assert_eq!(index.range(42, 42), Fingerprint::EMPTY);
  }

  /// Range enumeration is digest-ascending and complete: the same
  /// digest set `iter` produces, filtered to a range.
  #[test]
  fn range_entries_enumerate_digest_ascending() {
    let mut rng = Rng::new(0xA5CE_D000);
    let mut index: FingerprintIndex<()> = FingerprintIndex::new();
    let mut digests: Vec<u64> = (0..1_000).map(|_| rng.next()).collect();
    digests.sort_unstable();
    digests.dedup();
    for &digest in &digests {
      index.insert(digest, ());
    }
    let everything: Vec<u64> = index.iter().map(|(digest, _)| digest).collect();
    assert_eq!(everything, digests, "iter is the sorted digest set");
    for _ in 0..64 {
      let start = rng.next();
      let end = rng.next().max(start);
      let enumerated: Vec<u64> = index
        .range_entries(start, end)
        .map(|(digest, _)| digest)
        .collect();
      let expected: Vec<u64> = digests
        .iter()
        .copied()
        .filter(|digest| *digest >= start && *digest < end)
        .collect();
      assert_eq!(enumerated, expected, "range [{start},{end})");
    }
  }
}
