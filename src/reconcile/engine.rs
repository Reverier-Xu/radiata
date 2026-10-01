//! The reconciliation engine: one per session and lane.
//!
//! The engine is the deterministic core of the reconciliation plane: a
//! pure state machine over the lane's [`FingerprintIndex`] that turns
//! drive inputs (a received message, a local change, an explicit root
//! exchange, a drain tick) into the exact set of messages to send the
//! peer. It performs no I/O, spawns nothing, measures no time, and
//! emits no diagnostics — identical state plus identical input sequence
//! yields byte-identical output, which is what the phase-3 session seam
//! and the phase-4 trigger layer build on. Re-drive is always safe:
//! every message processes idempotently, and loss recovery is a root
//! exchange away.
//!
//! # Negotiation algorithm
//!
//! Range-based set reconciliation over the item-digest space, in the
//! shape of the proposal §3 pseudocode: for every received range
//! fingerprint `r` over `[start, end]`, with `local` the engine's own
//! aggregate over the same range,
//!
//! - `local == r` — the range is reconciled; nothing is sent.
//! - `r.count == 0` — the peer proved it holds nothing here, so the engine
//!   sends its own rows in the range directly (ROWS). The peer's empty
//!   fingerprint is itself receiver-side evidence of lack, which is why no NEED
//!   round trip is spent on it.
//! - `local.count == 0` — the engine holds nothing here but the peer does, so
//!   the engine sends NEED for the range and the peer answers with ROWS.
//! - otherwise the range splits into [`FANOUT`] children and the engine answers
//!   with an OFFER carrying its aggregate for each child. The children cover
//!   the parent exactly; when the range is three digests wide or narrower the
//!   children are the singleton ranges themselves. Every level shrinks the
//!   range at least fourfold, so a divergence isolates in at most ⌈log₄(2⁶⁴)⌉ =
//!   32 OFFER rounds; at singleton width the two non-empty cases above are
//!   exhaustive (two rows with the same digest are the same row by the frozen
//!   digest contract), which is the termination argument.
//!
//! ## NEED direction semantics
//!
//! NEED is always sent by the side that locally observes itself lacking
//! (`local.count == 0`, `r.count > 0`): the requester asks, the
//! receiver answers with ROWS. The mirror case — the *peer* provably
//! lacking (`r.count == 0`, `local.count > 0`) — sends ROWS directly
//! rather than a NEED, because the empty fingerprint already proves the
//! peer lacks the range and a request round trip would add latency
//! without adding evidence. Both directions therefore converge with the
//! minimum one payload traversal per differing row, and the proposal's
//! "payload only crosses a session for ranges the receiver proves it
//! lacks" holds on both sides of the exchange.
//!
//! # Rounds, DONE, and the in-flight bound
//!
//! At most one negotiated round is in flight per engine. A round opens
//! when a drive observes divergence (a received ROOT or HINT against a
//! closed round, or a local change against known divergence) and the
//! engine initiates; message *responses* (answering OFFER, NEED, ROWS)
//! are not initiations and always process, whatever the round state —
//! correctness never depends on round accounting. A round closes on a
//! received DONE, on an observed whole-lane agreement, or when a drive
//! leaves the engine with an open round, an empty backlog, and no
//! generated work — the quiescence case, which also emits DONE. An
//! explicit root exchange ignores the open round and initiates on any
//! observed divergence: it is the loss-recovery re-drive (the R4
//! detection cadence), so a round can never wedge the engine shut.
//!
//! The DONE token is the emitter's whole-lane state digest at close
//! (root count and xor mixed through a fixed finalizer): when both
//! sides close the same round after converging, their tokens match,
//! which makes the pair of DONE messages a cheap agreement receipt.
//! Mismatched or stale DONEs are harmless — they close the local round
//! slot and nothing else; completeness is always re-established by
//! fingerprint evidence, never by message counting.
//!
//! # Bounds
//!
//! Every emitted message respects the wire constants (ranges and bounds
//! ≤ 32 per message, rows ≤ 64 per message, each ROWS body kept under
//! the 64 KiB envelope by a per-message byte budget). One drive returns
//! at most [`MESSAGE_BUDGET_PER_DRIVE`] messages; surplus work waits in
//! the outbound backlog and later drives drain it, so a malicious peer
//! cannot make one drive unbounded.
//!
//! # Lane seam (phase 3)
//!
//! The engine's row set is the lane's exact set of `(key, content)`
//! rows: content carries whatever merge state the lane encodes
//! (versions, tombstone markers), and the engine reconciles sets — key
//! replacement and merge semantics live in the lane's row encoding, not
//! here. The phase-3 migration maps each lane's store to one engine per
//! session: local writes feed [`Engine::insert_row`], session frames
//! decode to [`Drive::Message`], the session establishment and the R4
//! cadence drive [`Drive::RootExchange`], and returned messages encode
//! through [`super::wire`] onto the session.

use std::{collections::VecDeque, mem};

use super::{
  digest,
  fingerprint::{Fingerprint, FingerprintIndex},
  wire::{
    DigestRange, LaneId, MAX_RANGES_PER_MESSAGE, MAX_ROWS_PER_MESSAGE, Message, RangeFingerprint,
    Row,
  },
};
use crate::{Error, Result};

/// The recursion fan-out factor `b`: one OFFER carries the aggregates
/// of `b` children of each divergent range. A constant per the proposal
/// §3 — not a negotiation parameter — trading message size for round
/// count (log_b instead of log₂).
pub(crate) const FANOUT: u128 = 4;

/// The maximum messages one drive returns: 64 messages × up to 64 rows
/// each bounds a drive's row work at the 4 096-row drain discipline the
/// existing pump lanes use; surplus work waits in the backlog.
pub(crate) const MESSAGE_BUDGET_PER_DRIVE: usize = 64;

/// The row-byte budget of one ROWS message: headroom under the 64 KiB
/// wire envelope for the CBOR framing of up to 64 rows.
const ROW_BYTES_BUDGET: usize = 48 * 1_024;

/// One engine drive input.
#[derive(Debug)]
pub(crate) enum Drive {
  /// A decoded message received from the peer.
  Message(Message),
  /// Local rows changed since the last such drive: emit the coalesced
  /// HINT and initiate if divergence is already known.
  LocalChange,
  /// The explicit root exchange: emit ROOT, and initiate on any
  /// observed divergence regardless of an open round (the
  /// loss-recovery re-drive).
  RootExchange,
  /// Drain pending outbound work with no new input.
  Drain,
}

/// The reconciliation engine for one session and one lane.
pub(crate) struct Engine {
  /// The lane this engine reconciles; every message must carry it.
  lane: LaneId,
  /// The lane's rows, digest-ordered with maintained range aggregates.
  index: FingerprintIndex<Row>,
  /// The peer's whole-lane aggregate as last seen in a ROOT.
  peer_root: Option<Fingerprint>,
  /// Whether a negotiated round this engine initiated is in flight.
  round_open: bool,
  /// Locally changed digest ranges, coalesced into sorted disjoint
  /// inclusive bounds; `None` means the overflow fallback (the whole
  /// digest space). Cleared by every `Drive::LocalChange`.
  dirty: Option<Vec<(u64, u64)>>,
  /// Outbound work beyond the current drive's message budget.
  backlog: VecDeque<Message>,
}

impl Engine {
  /// The empty engine for one lane.
  pub(crate) fn new(lane: LaneId) -> Self {
    Self {
      lane,
      index: FingerprintIndex::new(),
      peer_root: None,
      round_open: false,
      dirty: Some(Vec::new()),
      backlog: VecDeque::new(),
    }
  }

  /// The lane this engine reconciles.
  pub(crate) fn lane(&self) -> LaneId {
    self.lane
  }

  /// The whole-lane aggregate: the ROOT fingerprint.
  pub(crate) fn root(&self) -> Fingerprint {
    self.index.root()
  }

  /// The number of rows held.
  pub(crate) fn len(&self) -> usize {
    self.index.len()
  }

  /// No row is held.
  pub(crate) fn is_empty(&self) -> bool {
    self.index.is_empty()
  }

  /// Stores one local row (an insert or an in-place replacement of the
  /// identical `(key, content)` pair). Row updates are the lane's
  /// concern: an update is a new `(key, content)` identity, and the old
  /// identity leaves the set only through the lane's own row encoding
  /// (versions or tombstones), never through this engine.
  pub(crate) fn insert_row(&mut self, key: &[u8], content: &[u8]) -> Result<()> {
    let row = Row {
      key: key.to_vec(),
      content: content.to_vec(),
    };
    let digest = digest::item_digest(key, content)?;
    self.index.insert(digest, row);
    self.mark_dirty(digest);
    Ok(())
  }

  /// Every held row, digest-ascending.
  pub(crate) fn rows(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
    self
      .index
      .iter()
      .map(|(_, row)| (row.key.as_slice(), row.content.as_slice()))
  }

  /// Drives the engine: returns the messages to send the peer, at most
  /// [`MESSAGE_BUDGET_PER_DRIVE`] of them, in a deterministic order
  /// (backlog first, then the input's generated work).
  pub(crate) fn drive(&mut self, drive: Drive) -> Result<Vec<Message>> {
    let mut out = Vec::new();
    self.drain_backlog(&mut out);
    let generated = match drive {
      Drive::Drain => 0,
      Drive::Message(message) => self.apply_message(message)?,
      Drive::LocalChange => self.drive_local_change()?,
      Drive::RootExchange => self.drive_root_exchange()?,
    };
    self.drain_backlog(&mut out);
    // Quiescence: an open round with nothing left to say closes with a
    // DONE receipt. Never fires while work was generated or backlog
    // remains — those are the round still in motion.
    if self.round_open && self.backlog.is_empty() && generated == 0 {
      self.round_open = false;
      let done = self.done_message();
      out.push(done);
    }
    Ok(out)
  }

  /// Processes one received message; returns how many backlog messages
  /// it generated.
  fn apply_message(&mut self, message: Message) -> Result<usize> {
    if message.lane() != self.lane {
      return Err(Error::invalid_input("reconcile lane mismatch"));
    }
    let before = self.backlog.len();
    match message {
      Message::Root { count, xor, .. } => {
        let peer = Fingerprint::new(count, xor);
        let local = self.index.root();
        self.peer_root = Some(peer);
        if peer == local {
          self.close_round_on_agreement();
        } else if !self.round_open {
          self.initiate(&[(0, u64::MAX, peer)])?;
        }
        // A divergent ROOT against an open round is suppressed: the
        // round's own exchange (or the next root re-drive) carries it.
      }
      Message::Hint { ranges, .. } => {
        if !self.round_open {
          let triples: Vec<(u64, u64, Fingerprint)> = ranges
            .iter()
            .map(|range| {
              (
                range.start,
                range.end,
                Fingerprint::new(range.count, range.xor),
              )
            })
            .collect();
          let divergent: Vec<(u64, u64, Fingerprint)> = triples
            .into_iter()
            .filter(|(start, end, peer)| self.range_fingerprint(*start, *end) != *peer)
            .collect();
          if !divergent.is_empty() {
            self.initiate(&divergent)?;
          }
        }
        // A hint against an open round (or one that matches entirely)
        // is silent: hints are advisory, and the next root exchange
        // re-discovers anything the round did not settle.
      }
      Message::Offer { ranges, .. } => {
        let triples: Vec<(u64, u64, Fingerprint)> = ranges
          .iter()
          .map(|range| {
            (
              range.start,
              range.end,
              Fingerprint::new(range.count, range.xor),
            )
          })
          .collect();
        self.process_ranges(&triples)?;
        if self.backlog.len() == before {
          // The offer matched everywhere (silent success): answer with
          // the DONE receipt so the peer's round closes without
          // waiting for a root exchange.
          self.round_open = false;
          let done = self.done_message();
          self.backlog.push_back(done);
        }
      }
      Message::Need { bounds, .. } => {
        for bound in &bounds {
          self.push_rows(bound.start, bound.end, true);
        }
      }
      Message::Rows { rows, .. } => {
        for row in rows {
          let digest = digest::item_digest(&row.key, &row.content)?;
          self.index.insert(digest, row);
          self.mark_dirty(digest);
        }
      }
      Message::Done { .. } => {
        self.round_open = false;
      }
    }
    Ok(self.backlog.len() - before)
  }

  /// The local-change drive: one coalesced HINT over the changed
  /// ranges, plus an initiation when divergence is already known.
  fn drive_local_change(&mut self) -> Result<usize> {
    let before = self.backlog.len();
    let bounds = self.dirty.replace(Vec::new());
    let bounds = bounds.unwrap_or_else(|| vec![(0, u64::MAX)]);
    let ranges: Vec<RangeFingerprint> = bounds
      .iter()
      .map(|&(start, end)| {
        let fingerprint = self.range_fingerprint(start, end);
        RangeFingerprint {
          start,
          end,
          count: fingerprint.count(),
          xor: fingerprint.xor(),
        }
      })
      .collect();
    if !ranges.is_empty() {
      let hint = Message::Hint {
        lane: self.lane,
        ranges,
      };
      self.backlog.push_back(hint);
    }
    if let Some(peer) = self.peer_root
      && peer != self.index.root()
      && !self.round_open
    {
      self.initiate(&[(0, u64::MAX, peer)])?;
    }
    Ok(self.backlog.len() - before)
  }

  /// The root-exchange drive: emit ROOT, then either close on observed
  /// agreement or initiate over the whole digest space — replacing any
  /// open round, because this drive is the loss-recovery re-drive.
  fn drive_root_exchange(&mut self) -> Result<usize> {
    let before = self.backlog.len();
    let root = self.index.root();
    let root_message = Message::Root {
      lane: self.lane,
      count: root.count(),
      xor: root.xor(),
    };
    self.backlog.push_back(root_message);
    if let Some(peer) = self.peer_root {
      if peer == root {
        self.close_round_on_agreement();
      } else {
        self.initiate(&[(0, u64::MAX, peer)])?;
      }
    }
    Ok(self.backlog.len() - before)
  }

  /// Closes an open round and emits the DONE agreement receipt.
  fn close_round_on_agreement(&mut self) {
    if self.round_open {
      self.round_open = false;
      let done = self.done_message();
      self.backlog.push_back(done);
    }
  }

  /// Opens a round and processes the divergent ranges: the one
  /// initiation path (ROOT, HINT, and local-change triggers all funnel
  /// here).
  fn initiate(&mut self, triples: &[(u64, u64, Fingerprint)]) -> Result<()> {
    self.round_open = true;
    self.process_ranges(triples)
  }

  /// The negotiation core: compares each `(range, peer fingerprint)`
  /// triple against the local aggregate and queues the response work —
  /// OFFERs first, then NEEDs, then pushed ROWS, deterministically.
  fn process_ranges(&mut self, triples: &[(u64, u64, Fingerprint)]) -> Result<()> {
    let mut offers: Vec<RangeFingerprint> = Vec::new();
    let mut needs: Vec<DigestRange> = Vec::new();
    let mut pushes: Vec<(u64, u64)> = Vec::new();
    for &(start, end, peer) in triples {
      let local = self.range_fingerprint(start, end);
      if local == peer {
        continue;
      }
      if peer.count() == 0 {
        // The peer proved it lacks the whole range: push the rows.
        pushes.push((start, end));
        continue;
      }
      if local.count() == 0 {
        // The engine lacks the whole range: pull the peer's rows.
        needs.push(DigestRange { start, end });
        continue;
      }
      if start == end {
        // Unreachable under the digest contract (two rows with one
        // digest are one row); the terminal collision fail-safe
        // exchanges both directions rather than recursing forever.
        pushes.push((start, end));
        needs.push(DigestRange { start, end });
        continue;
      }
      for (child_start, child_end) in split(start, end) {
        let fingerprint = self.range_fingerprint(child_start, child_end);
        offers.push(RangeFingerprint {
          start: child_start,
          end: child_end,
          count: fingerprint.count(),
          xor: fingerprint.xor(),
        });
      }
    }
    self.push_offers(offers);
    self.push_needs(needs);
    for (start, end) in pushes {
      self.push_rows(start, end, false);
    }
    Ok(())
  }

  /// Packs offered ranges into bounded OFFER messages.
  fn push_offers(&mut self, offers: Vec<RangeFingerprint>) {
    for chunk in offers.chunks(MAX_RANGES_PER_MESSAGE) {
      let offer = Message::Offer {
        lane: self.lane,
        ranges: chunk.to_vec(),
      };
      self.backlog.push_back(offer);
    }
  }

  /// Packs needed bounds into bounded NEED messages.
  fn push_needs(&mut self, needs: Vec<DigestRange>) {
    for chunk in needs.chunks(MAX_RANGES_PER_MESSAGE) {
      let need = Message::Need {
        lane: self.lane,
        bounds: chunk.to_vec(),
      };
      self.backlog.push_back(need);
    }
  }

  /// Queues the engine's rows in `[start, end]` as bounded ROWS
  /// messages. An `answer` to a NEED always emits a message — even an
  /// empty one — so the requester observes the request completed; a
  /// push emits nothing for an empty range.
  fn push_rows(&mut self, start: u64, end: u64, answer: bool) {
    let rows: Vec<Row> = if end < u64::MAX {
      self
        .index
        .range_entries(start, end + 1)
        .map(|(_, row)| row.clone())
        .collect()
    } else {
      self
        .index
        .iter()
        .filter(|(digest, _)| *digest >= start)
        .map(|(_, row)| row.clone())
        .collect()
    };
    let mut chunk: Vec<Row> = Vec::new();
    let mut bytes = 0;
    for row in rows {
      let cost = row.key.len() + row.content.len();
      if !chunk.is_empty()
        && (chunk.len() >= MAX_ROWS_PER_MESSAGE || bytes + cost > ROW_BYTES_BUDGET)
      {
        let message = Message::Rows {
          lane: self.lane,
          rows: mem::take(&mut chunk),
        };
        self.backlog.push_back(message);
        bytes = 0;
      }
      bytes += cost;
      chunk.push(row);
    }
    if !chunk.is_empty() || answer {
      let message = Message::Rows {
        lane: self.lane,
        rows: chunk,
      };
      self.backlog.push_back(message);
    }
  }

  /// The local aggregate over the inclusive range `[start, end]`. The
  /// top of the digest space goes through the group law (root minus
  /// prefix) because a strict-prefix query alone cannot express the
  /// last digest.
  fn range_fingerprint(&self, start: u64, end: u64) -> Fingerprint {
    if end < u64::MAX {
      self.index.range(start, end + 1)
    } else {
      self.index.root().remove(self.index.prefix(start))
    }
  }

  /// Records a locally changed digest in the coalesced dirty set:
  /// sorted, disjoint, non-adjacent inclusive bounds; overflowing the
  /// hint bound falls back to the whole digest space.
  fn mark_dirty(&mut self, digest: u64) {
    let Some(bounds) = self.dirty.as_mut() else {
      return;
    };
    let mut start = digest;
    let mut end = digest;
    let mut rest: Vec<(u64, u64)> = Vec::with_capacity(bounds.len() + 1);
    for &(bound_start, bound_end) in bounds.iter() {
      // Adjacent inclusive bounds merge: touching counts as overlap.
      if bound_start <= digest.saturating_add(1) && bound_end >= digest.saturating_sub(1) {
        start = start.min(bound_start);
        end = end.max(bound_end);
      } else {
        rest.push((bound_start, bound_end));
      }
    }
    rest.push((start, end));
    rest.sort_unstable();
    if rest.len() > MAX_RANGES_PER_MESSAGE {
      self.dirty = None;
    } else {
      *bounds = rest;
    }
  }

  /// Moves backlog messages into the drive output, up to the budget.
  fn drain_backlog(&mut self, out: &mut Vec<Message>) {
    while out.len() < MESSAGE_BUDGET_PER_DRIVE {
      let Some(message) = self.backlog.pop_front() else {
        return;
      };
      out.push(message);
    }
  }

  /// The DONE receipt: the whole-lane state digest at emission.
  fn done_message(&self) -> Message {
    let root = self.index.root();
    Message::Done {
      lane: self.lane,
      round_token: state_token(root),
    }
  }
}

/// Splits the inclusive range `[start, end]` into [`FANOUT`] children
/// that cover it exactly: four quarters while the range is wide, the
/// singleton ranges themselves once it is three digests wide or
/// narrower (the level where every comparison resolves without further
/// recursion).
fn split(start: u64, end: u64) -> Vec<(u64, u64)> {
  let width = u128::from(end) - u128::from(start) + 1;
  let quarter = (width / FANOUT) as u64;
  if quarter == 0 {
    return (start..=end).map(|digest| (digest, digest)).collect();
  }
  let first_edge = start + quarter;
  let second_edge = start + 2 * quarter;
  let third_edge = start + 3 * quarter;
  vec![
    (start, first_edge - 1),
    (first_edge, second_edge - 1),
    (second_edge, third_edge - 1),
    (third_edge, end),
  ]
}

/// The whole-lane state digest: the root aggregate mixed through the
/// splitmix64 finalizer. Both sides of a converged round compute the
/// same token, so crossing DONE messages with equal tokens are an
/// agreement receipt.
fn state_token(root: Fingerprint) -> u64 {
  mix64(root.count().wrapping_add(root.xor().rotate_left(32)))
}

/// The splitmix64 output mixer (constants as published): a fixed,
/// deterministic avalanching finalizer.
fn mix64(value: u64) -> u64 {
  let mut z = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
  z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
  z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
  z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;

  use proptest::prelude::*;

  use super::{Drive, Engine, FANOUT, MESSAGE_BUDGET_PER_DRIVE, mix64, split, state_token};
  use crate::reconcile::{
    digest::item_digest,
    fingerprint::Fingerprint,
    wire::{LaneId, MAX_RANGES_PER_MESSAGE, MAX_ROWS_PER_MESSAGE, Message},
  };

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

  fn row_set(engine: &Engine) -> Vec<(Vec<u8>, Vec<u8>)> {
    engine
      .rows()
      .map(|(key, content)| (key.to_vec(), content.to_vec()))
      .collect()
  }

  /// The split covers its parent exactly, respects the fan-out, and
  /// terminates: four strictly narrower children while the range is
  /// wide, the singleton ranges themselves once it is three digests
  /// wide or narrower.
  #[test]
  fn reconcile_split_covers_exactly_and_descends() {
    assert_eq!(
      split(0, u64::MAX),
      vec![
        (0, (1u64 << 62) - 1),
        (1u64 << 62, (1u64 << 63) - 1),
        (1u64 << 63, (3u64 << 62) - 1),
        (3u64 << 62, u64::MAX),
      ]
    );
    assert_eq!(split(5, 7), vec![(5, 5), (6, 6), (7, 7)]);
    assert_eq!(split(9, 9), vec![(9, 9)]);
    assert_eq!(split(10, 13), vec![(10, 10), (11, 11), (12, 12), (13, 13)]);
    let mut rng = Rng::new(0x5F1F_2026);
    for _ in 0..4_000 {
      let start = rng.next();
      let end = start.max(rng.next());
      let width = u128::from(end) - u128::from(start) + 1;
      let children = split(start, end);
      if width <= 3 {
        assert_eq!(children.len(), width as usize, "singletons for {width}");
        for (index, (digest, child)) in (start..=end).zip(children).enumerate() {
          assert_eq!(child, (digest, digest), "singleton {index}");
        }
      } else {
        assert_eq!(children.len(), FANOUT as usize, "fan-out for {width}");
        let cover: u128 = children
          .iter()
          .map(|(s, e)| u128::from(*e) - u128::from(*s) + 1)
          .sum();
        assert_eq!(cover, width, "exact cover of [{start},{end}]");
        for window in children.windows(2) {
          assert_eq!(window[0].1 + 1, window[1].0, "no gap or overlap");
        }
      }
    }
  }

  /// The state token and its mixer are frozen constants (the DONE
  /// receipt's wire meaning).
  #[test]
  fn reconcile_state_token_is_frozen() {
    assert_eq!(mix64(0), 0xE220_A839_7B1D_CDAF);
    assert_eq!(state_token(Fingerprint::new(0, 0)), 0xE220_A839_7B1D_CDAF);
    assert_eq!(
      state_token(Fingerprint::new(17, 0x2233)),
      0xEFA7_3A97_1927_E0CC
    );
  }

  /// The engine's range fingerprints are inclusive and reach the top
  /// digest: the group-law branch (`root ⊖ prefix`) matches an explicit
  /// fold oracle at every width, including ranges ending at `u64::MAX`.
  #[test]
  fn reconcile_range_fingerprints_are_inclusive_to_the_top() {
    let mut rng = Rng::new(0x0CC0_2026);
    let mut engine = Engine::new(LaneId::Resources);
    let mut digests: Vec<u64> = Vec::new();
    for index in 0..200u64 {
      let key = format!("key-{index}");
      let content = format!("content-{index}");
      let digest = item_digest(key.as_bytes(), content.as_bytes()).unwrap();
      engine
        .insert_row(key.as_bytes(), content.as_bytes())
        .unwrap();
      digests.push(digest);
    }
    digests.sort_unstable();
    digests.dedup();
    let oracle = |start: u64, end: u64| -> Fingerprint {
      digests
        .iter()
        .copied()
        .filter(|digest| *digest >= start && *digest <= end)
        .fold(Fingerprint::EMPTY, |acc, digest| {
          acc.combine(Fingerprint::singleton(digest))
        })
    };
    assert_eq!(engine.range_fingerprint(0, u64::MAX), engine.root());
    assert_eq!(engine.range_fingerprint(0, u64::MAX), oracle(0, u64::MAX));
    for _ in 0..200 {
      let start = rng.next();
      let end = start.max(rng.next());
      assert_eq!(engine.range_fingerprint(start, end), oracle(start, end));
    }
    for edge in [0u64, 1, u64::MAX - 1, u64::MAX] {
      assert_eq!(
        engine.range_fingerprint(edge, u64::MAX),
        oracle(edge, u64::MAX),
        "top-terminated range from {edge}"
      );
      let below = edge.min(u64::MAX - 1);
      assert_eq!(
        engine.range_fingerprint(below, below),
        oracle(below, below),
        "singleton at {below}"
      );
    }
  }

  /// The coalesced dirty set stays sorted, disjoint, and non-adjacent,
  /// and overflows to the whole-space fallback.
  #[test]
  fn reconcile_dirty_ranges_coalesce_and_overflow_to_full_space() {
    let mut engine = Engine::new(LaneId::Trust);
    for digest in [10u64, 11, 12] {
      engine.mark_dirty(digest);
    }
    assert_eq!(engine.dirty, Some(vec![(10, 12)]));
    engine.mark_dirty(20);
    engine.mark_dirty(14);
    assert_eq!(engine.dirty, Some(vec![(10, 12), (14, 14), (20, 20)]));
    engine.mark_dirty(13);
    assert_eq!(engine.dirty, Some(vec![(10, 14), (20, 20)]));
    for digest in (30u64..30 + 4 * MAX_RANGES_PER_MESSAGE as u64).step_by(2) {
      engine.mark_dirty(digest);
    }
    assert_eq!(engine.dirty, None, "overflow falls back to full space");
    engine.mark_dirty(0);
    assert_eq!(engine.dirty, None, "the fallback is sticky");
  }

  /// A message for another lane fails closed at the engine boundary.
  #[test]
  fn reconcile_engine_rejects_foreign_lane_messages() {
    let mut engine = Engine::new(LaneId::Descriptors);
    let error = engine
      .drive(Drive::Message(Message::Root {
        lane: LaneId::Trust,
        count: 0,
        xor: 0,
      }))
      .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
  }

  /// Identical peers exchange exactly one ROOT each way and fall quiet:
  /// the zero-traffic steady state of the plane.
  #[test]
  fn reconcile_identical_peers_exchange_roots_and_fall_quiet() {
    let rows: [(&[u8], &[u8]); 3] = [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")];
    let mut pair = Pair::new(&rows, &rows);
    pair.drive_root_exchange(Peer::A);
    pair.drive_root_exchange(Peer::B);
    pair.pump();
    assert!(pair.quiet());
    assert_eq!(pair.count_kind(Message::kind_is_root), 2);
    assert_eq!(pair.count_kind(Message::kind_is_offer), 0);
    assert_eq!(pair.count_kind(Message::kind_is_rows), 0);
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
  }

  /// An empty peer converges through both designed payload paths: the
  /// full side pushes its rows on the peer-proved-empty OFFER branches,
  /// and the empty side pulls with a NEED once it learns a non-empty
  /// peer root (the "local empty → request the peer's rows" case of the
  /// negotiation algorithm).
  #[test]
  fn reconcile_empty_peer_receives_rows_and_converges() {
    let rows: Vec<(String, String)> = (0..50)
      .map(|index| (format!("key-{index}"), format!("content-{index}")))
      .collect();
    let borrowed: Vec<(&[u8], &[u8])> = rows
      .iter()
      .map(|(key, content)| (key.as_bytes(), content.as_bytes()))
      .collect();
    let mut pair = Pair::new(&[], &borrowed);
    pair.settle();
    assert!(pair.quiet());
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    assert_eq!(pair.a.len(), 50);
    assert!(pair.count_kind(Message::kind_is_rows) > 0);
    assert!(pair.count_kind(Message::kind_is_need) >= 1);
  }

  /// Disjoint peers cross rows in both directions (NEED one way, direct
  /// pushes the other) and converge byte-exactly.
  #[test]
  fn reconcile_disjoint_peers_converge_both_directions() {
    let left: Vec<(String, String)> = (0..40)
      .map(|index| (format!("left-{index}"), format!("l-{index}")))
      .collect();
    let right: Vec<(String, String)> = (0..40)
      .map(|index| (format!("right-{index}"), format!("r-{index}")))
      .collect();
    let left_rows: Vec<(&[u8], &[u8])> = left
      .iter()
      .map(|(key, content)| (key.as_bytes(), content.as_bytes()))
      .collect();
    let right_rows: Vec<(&[u8], &[u8])> = right
      .iter()
      .map(|(key, content)| (key.as_bytes(), content.as_bytes()))
      .collect();
    let mut pair = Pair::new(&left_rows, &right_rows);
    pair.settle();
    assert!(pair.quiet());
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    assert_eq!(pair.a.len(), 80);
  }

  /// A single-row divergence against a shared base resolves within
  /// the log₄ round bound: the pair's combined OFFER count never
  /// exceeds twice the 32-round ceiling of a 64-bit digest space under
  /// fan-out 4 (b=4 quarters the round count a binary split would
  /// need, which is the constant's whole job).
  #[test]
  fn reconcile_single_row_divergence_respects_fanout_round_bound() {
    let mut shared: Vec<(String, String)> = (0..64)
      .map(|index| (format!("base-{index}"), format!("v-{index}")))
      .collect();
    shared.push(("extra".to_owned(), "row".to_owned()));
    let shared_rows: Vec<(&[u8], &[u8])> = shared
      .iter()
      .map(|(key, content)| (key.as_bytes(), content.as_bytes()))
      .collect();
    let mut base = shared_rows.clone();
    base.pop();
    let mut pair = Pair::new(&base, &shared_rows);
    pair.drive_root_exchange(Peer::A);
    pair.drive_root_exchange(Peer::B);
    pair.pump();
    assert!(pair.quiet());
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    let ceiling = 2 * (64 / FANOUT.ilog2() + 2) as usize;
    let offers = pair.count_kind(Message::kind_is_offer);
    assert!(offers <= ceiling, "{offers} offers exceeds {ceiling}");
    assert!(offers >= 2, "both sides of the descent emit offers");
  }

  /// Duplicate delivery is harmless: replaying the whole exchange to
  /// both engines changes no state.
  #[test]
  fn reconcile_duplicate_messages_apply_idempotently() {
    let left: [(&[u8], &[u8]); 2] = [(b"shared", b"1"), (b"left-only", b"2")];
    let right: [(&[u8], &[u8]); 2] = [(b"shared", b"1"), (b"right-only", b"3")];
    let mut pair = Pair::new(&left, &right);
    pair.settle();
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    let rows_before = row_set(&pair.a);
    // Replay every logged message to both engines — a superset of any
    // duplicate delivery an adversary can cause.
    let log = pair.log.clone();
    for message in &log {
      pair.deliver_raw(Peer::A, message.clone());
      pair.deliver_raw(Peer::B, message.clone());
    }
    pair.pump();
    assert!(pair.quiet());
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    assert_eq!(row_set(&pair.a), rows_before);
  }

  /// Large divergent sets converge through the bounded backlog: the
  /// message budget spreads the work across drives without ever
  /// emitting an over-bound message.
  #[test]
  fn reconcile_large_disjoint_sets_converge_through_the_backlog() {
    let left: Vec<(String, String)> = (0..1_500)
      .map(|index| (format!("l{index}"), format!("left-{index}")))
      .collect();
    let right: Vec<(String, String)> = (0..1_500)
      .map(|index| (format!("r{index}"), format!("right-{index}")))
      .collect();
    let left_rows: Vec<(&[u8], &[u8])> = left
      .iter()
      .map(|(key, content)| (key.as_bytes(), content.as_bytes()))
      .collect();
    let right_rows: Vec<(&[u8], &[u8])> = right
      .iter()
      .map(|(key, content)| (key.as_bytes(), content.as_bytes()))
      .collect();
    let mut pair = Pair::new(&left_rows, &right_rows);
    pair.settle();
    assert!(pair.quiet());
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    assert_eq!(pair.a.len(), 3_000);
    assert!(pair.max_drive_batch <= MESSAGE_BUDGET_PER_DRIVE);
  }

  /// Every emitted message respects the wire bounds across a whole
  /// exchange (checked over the complete log).
  #[test]
  fn reconcile_all_emitted_messages_respect_wire_bounds() {
    let left: [(&[u8], &[u8]); 3] = [(b"k1", b"v1"), (b"k2", b"v2"), (b"k3", b"v3")];
    let right: [(&[u8], &[u8]); 2] = [(b"k2", b"v2"), (b"k4", b"v4")];
    let mut pair = Pair::new(&left, &right);
    pair.settle();
    for message in &pair.log {
      match message {
        Message::Hint { ranges, .. } | Message::Offer { ranges, .. } => {
          assert!(ranges.len() <= MAX_RANGES_PER_MESSAGE);
        }
        Message::Need { bounds, .. } => {
          assert!(bounds.len() <= MAX_RANGES_PER_MESSAGE);
        }
        Message::Rows { rows, .. } => {
          assert!(rows.len() <= MAX_ROWS_PER_MESSAGE);
        }
        _ => {}
      }
    }
  }

  /// A scripted total-loss scenario: every message is dropped for a
  /// while, inserts accumulate, and the root re-drive recovers full
  /// convergence — the loss-recovery contract the detection cadence
  /// relies on.
  #[test]
  fn reconcile_total_loss_recovers_through_root_redrive() {
    let seed: [(&[u8], &[u8]); 1] = [(b"seed", b"0")];
    let mut pair = Pair::new(&seed, &[]);
    // Drop everything a few rounds while both sides keep changing.
    for round in 0..4 {
      pair.drive_root_exchange(Peer::A);
      pair.drive_root_exchange(Peer::B);
      while pair.to_b.pop_front().is_some() || pair.to_a.pop_front().is_some() {}
      let key = format!("lost-{round}");
      let content = format!("content-{round}");
      pair
        .a
        .insert_row(key.as_bytes(), content.as_bytes())
        .unwrap();
      pair.drive(Peer::A, Drive::LocalChange);
      while pair.to_b.pop_front().is_some() || pair.to_a.pop_front().is_some() {}
    }
    assert!(!row_set(&pair.a).is_empty());
    assert_eq!(pair.b.len(), 0);
    pair.settle();
    assert!(pair.quiet());
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    assert_eq!(pair.b.len(), 5);
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum Peer {
    A,
    B,
  }

  #[derive(Clone, Copy, Debug)]
  enum Op {
    Deliver,
    DropFront,
    DeferFront,
    Redrive(Peer),
    Insert(Peer, u16),
  }

  fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
      4 => Just(Op::Deliver),
      2 => Just(Op::DropFront),
      2 => Just(Op::DeferFront),
      3 => any::<bool>().prop_map(|left| Op::Redrive(if left { Peer::A } else { Peer::B })),
      3 => (any::<bool>(), any::<u16>()).prop_map(|(left, salt)| {
        Op::Insert(if left { Peer::A } else { Peer::B }, salt)
      }),
    ]
  }

  fn arb_row_source() -> impl Strategy<Value = Vec<(u8, u16)>> {
    proptest::collection::vec((any::<u8>(), any::<u16>()), 0..24)
  }

  fn owned_rows(source: &[(u8, u16)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    source
      .iter()
      .map(|(key, salt)| {
        (
          vec![b'k', b'-', b'0' + (key % 6)],
          format!("c-{salt}").into_bytes(),
        )
      })
      .collect()
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// The convergence property: arbitrary divergent starts (empty,
    /// overlapping, disjoint), adversarial loss, reordering, mid-flight
    /// inserts, then root re-drive — the pair always settles
    /// byte-identically, every message respects the wire bounds, and no
    /// drive exceeds the budget.
    #[test]
    fn reconcile_dual_instances_converge_under_adversarial_delivery(
      left in arb_row_source(),
      right in arb_row_source(),
      ops in proptest::collection::vec(arb_op(), 0..32),
    ) {
      let mut pair = Pair::from_owned(&owned_rows(&left), &owned_rows(&right));
      for op in ops {
        pair.apply(op);
      }
      pair.settle();
      prop_assert!(pair.quiet());
      prop_assert_eq!(row_set(&pair.a), row_set(&pair.b));
      for message in &pair.log {
        match message {
          Message::Hint { ranges, .. } | Message::Offer { ranges, .. } => {
            prop_assert!(ranges.len() <= MAX_RANGES_PER_MESSAGE);
          }
          Message::Need { bounds, .. } => {
            prop_assert!(bounds.len() <= MAX_RANGES_PER_MESSAGE);
          }
          Message::Rows { rows, .. } => {
            prop_assert!(rows.len() <= MAX_ROWS_PER_MESSAGE);
          }
          _ => {}
        }
      }
    }

    /// The engine is a pure function of state and input: two pairs
    /// replaying the identical adversarial scenario emit identical
    /// message logs and settle identically.
    #[test]
    fn reconcile_engine_replay_is_deterministic(
      left in arb_row_source(),
      right in arb_row_source(),
      ops in proptest::collection::vec(arb_op(), 0..24),
    ) {
      let mut first = Pair::from_owned(&owned_rows(&left), &owned_rows(&right));
      let mut second = Pair::from_owned(&owned_rows(&left), &owned_rows(&right));
      for op in &ops {
        first.apply(*op);
        second.apply(*op);
      }
      first.settle();
      second.settle();
      prop_assert_eq!(first.log, second.log);
      prop_assert_eq!(row_set(&first.a), row_set(&first.b));
    }
  }

  /// The two-instance in-process harness: drives, delivers, drops,
  /// defers, and settles a pair of engines against each other.
  struct Pair {
    a: Engine,
    b: Engine,
    to_b: VecDeque<Message>,
    to_a: VecDeque<Message>,
    /// Deferred messages with their delivery direction (`true` = was
    /// en route to `b`).
    deferred: Vec<(bool, Message)>,
    log: Vec<Message>,
    offers_a: usize,
    max_drive_batch: usize,
  }

  impl Message {
    fn kind_is_root(&self) -> bool {
      matches!(self, Message::Root { .. })
    }

    fn kind_is_offer(&self) -> bool {
      matches!(self, Message::Offer { .. })
    }

    fn kind_is_need(&self) -> bool {
      matches!(self, Message::Need { .. })
    }

    fn kind_is_rows(&self) -> bool {
      matches!(self, Message::Rows { .. })
    }
  }

  impl Pair {
    fn new(left: &[(&[u8], &[u8])], right: &[(&[u8], &[u8])]) -> Self {
      let to_owned = |rows: &[(&[u8], &[u8])]| {
        rows
          .iter()
          .map(|(key, content)| ((*key).to_vec(), (*content).to_vec()))
          .collect::<Vec<_>>()
      };
      Self::from_owned(&to_owned(left), &to_owned(right))
    }

    fn from_owned(left: &[(Vec<u8>, Vec<u8>)], right: &[(Vec<u8>, Vec<u8>)]) -> Self {
      let mut a = Engine::new(LaneId::Descriptors);
      for (key, content) in left {
        a.insert_row(key, content).unwrap();
      }
      let mut b = Engine::new(LaneId::Descriptors);
      for (key, content) in right {
        b.insert_row(key, content).unwrap();
      }
      Self {
        a,
        b,
        to_b: VecDeque::new(),
        to_a: VecDeque::new(),
        deferred: Vec::new(),
        log: Vec::new(),
        offers_a: 0,
        max_drive_batch: 0,
      }
    }

    fn engine(&mut self, peer: Peer) -> &mut Engine {
      match peer {
        Peer::A => &mut self.a,
        Peer::B => &mut self.b,
      }
    }

    fn record(&mut self, peer: Peer, out: Vec<Message>) {
      self.max_drive_batch = self.max_drive_batch.max(out.len());
      if peer == Peer::A {
        self.offers_a += out.iter().filter(|message| message.kind_is_offer()).count();
      }
      for message in out {
        self.log.push(message.clone());
        match peer {
          Peer::A => self.to_b.push_back(message),
          Peer::B => self.to_a.push_back(message),
        }
      }
    }

    fn drive(&mut self, peer: Peer, drive: Drive) {
      let out = self.engine(peer).drive(drive).unwrap();
      self.record(peer, out);
    }

    fn drive_root_exchange(&mut self, peer: Peer) {
      self.drive(peer, Drive::RootExchange);
    }

    /// Delivers one message straight into an engine (no direction
    /// bookkeeping): the idempotence replay path.
    fn deliver_raw(&mut self, peer: Peer, message: Message) {
      let out = self.engine(peer).drive(Drive::Message(message)).unwrap();
      self.record(peer, out);
    }

    /// Delivers everything currently queued (deferred messages stay
    /// deferred), processing responses and backlog drains, until both
    /// queues and both backlogs are empty.
    fn pump(&mut self) {
      let mut guard = 0;
      loop {
        guard += 1;
        assert!(guard < 100_000, "delivery pump did not quiesce");
        let mut activity = false;
        while let Some(message) = self.to_b.pop_front() {
          let out = self.b.drive(Drive::Message(message)).unwrap();
          self.record(Peer::B, out);
          activity = true;
        }
        while let Some(message) = self.to_a.pop_front() {
          let out = self.a.drive(Drive::Message(message)).unwrap();
          self.record(Peer::A, out);
          activity = true;
        }
        loop {
          let a_out = self.a.drive(Drive::Drain).unwrap();
          let b_out = self.b.drive(Drive::Drain).unwrap();
          self.record(Peer::A, a_out.clone());
          self.record(Peer::B, b_out.clone());
          if !a_out.is_empty()
            || !b_out.is_empty()
            || !self.a.backlog.is_empty()
            || !self.b.backlog.is_empty()
          {
            activity = true;
          }
          if self.a.backlog.is_empty() && self.b.backlog.is_empty() {
            break;
          }
        }
        if !activity {
          return;
        }
      }
    }

    /// Everything delivered — deferred messages in their deferral
    /// order — plus root re-drives, until the pair is both quiet and
    /// mutually confirmed converged (each side's last-seen peer root
    /// equals its own): quiet alone is not convergence, because a
    /// stale ROOT can close a round the divergence still lives in.
    fn settle(&mut self) {
      for (to_b, message) in self.deferred.drain(..) {
        if to_b {
          self.to_b.push_back(message);
        } else {
          self.to_a.push_back(message);
        }
      }
      for _ in 0..8 {
        self.drive_root_exchange(Peer::A);
        self.drive_root_exchange(Peer::B);
        self.pump();
        if self.quiet() && self.converged() {
          return;
        }
      }
      self.pump();
      assert!(
        self.quiet() && self.converged(),
        "settle did not converge: a={:?} b={:?}",
        row_set(&self.a),
        row_set(&self.b)
      );
    }

    /// Both sides' last-seen peer roots equal their own roots.
    fn converged(&self) -> bool {
      self.a.peer_root == Some(self.a.root()) && self.b.peer_root == Some(self.b.root())
    }

    fn quiet(&self) -> bool {
      self.to_b.is_empty()
        && self.to_a.is_empty()
        && self.a.backlog.is_empty()
        && self.b.backlog.is_empty()
    }

    fn count_kind(&self, predicate: impl Fn(&Message) -> bool) -> usize {
      self.log.iter().filter(|message| predicate(message)).count()
    }

    fn offers_by(&self, peer: Peer) -> usize {
      match peer {
        Peer::A => self.offers_a,
        // The pair is symmetric: the log records both directions.
        Peer::B => self.count_kind(Message::kind_is_offer) - self.offers_a,
      }
    }

    fn apply(&mut self, op: Op) {
      match op {
        Op::Deliver => self.pump(),
        Op::DropFront => {
          if self.to_b.pop_front().is_none() {
            let _ = self.to_a.pop_front();
          }
        }
        Op::DeferFront => {
          if let Some(message) = self.to_b.pop_front() {
            self.deferred.push((true, message));
          } else if let Some(message) = self.to_a.pop_front() {
            self.deferred.push((false, message));
          }
        }
        Op::Redrive(peer) => self.drive_root_exchange(peer),
        Op::Insert(peer, salt) => {
          let key = format!("k-{salt}");
          let content = format!("inserted-{salt}");
          self
            .engine(peer)
            .insert_row(key.as_bytes(), content.as_bytes())
            .unwrap();
          self.drive(peer, Drive::LocalChange);
        }
      }
    }
  }
}
