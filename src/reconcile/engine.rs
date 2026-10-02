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
//!   range strictly and geometrically (each child is at most a quarter of the
//!   parent plus three digests), so a divergence over the whole digest space
//!   isolates in 32 OFFER rounds and over any narrower range in at most 34 (the
//!   last child inherits the division remainder, which is where the couple of
//!   extra levels over log₄ come from); at singleton width the two non-empty
//!   cases above are exhaustive (two rows with the same digest are the same row
//!   by the frozen digest contract), which is the termination argument.
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
//! ## NEED answer amplification cap
//!
//! A NEED answer clones the answering range's rows into the backlog,
//! so a forged or duplicated NEED is an amplification vector: without a
//! cap, a flood of NEED frames multiplies the whole catalog into queued
//! ROWS messages (memory) and onto the wire (send). Three bounds close
//! it, all engine-level:
//!
//! - **duplicate merge** — a NEED bound subsumed by a bound whose answer is
//!   still queued adds zero work (the pending window closes with the backlog:
//!   once every queued answer has been emitted, a repeated NEED is a fresh
//!   request — the earlier answer may have been lost — and is answered again);
//! - **bounded merge set** — at most [`NEED_PENDING_BOUNDS`] distinct bounds
//!   are remembered; beyond that a NEED is dropped, and a bound that queued
//!   nothing is never remembered;
//! - **rows backlog ceiling** — row emission (NEED answers and direct pushes
//!   alike) stops packing once [`ROWS_BACKLOG_CEILING`] ROWS messages are
//!   queued; the remainder waits for a later round.
//!
//! Dropped work is never lost state: the peer's fingerprints still
//! mismatch, and the next root exchange re-drives the transfer in a
//! fresh bounded batch — the cap trades round count under flood for a
//! hard memory bound. The per-drive send bound
//! ([`MESSAGE_BUDGET_PER_DRIVE`]) holds regardless: no inbound frame,
//! however forged, makes one drive emit more than the budget.
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
//! cannot make one drive unbounded. The backlog itself is bounded for
//! row payloads by [`ROWS_BACKLOG_CEILING`] (see the amplification cap
//! below), so neither the drive nor the queue behind it is a flood
//! vector.
//!
//! # Lane seam (phase 3)
//!
//! The engine's row set is the lane's exact set of `(key, content)`
//! rows: content carries whatever merge state the lane encodes
//! (versions, tombstone markers), and the engine reconciles sets — key
//! replacement and merge semantics live in the lane's row encoding, not
//! here. The row-size ceiling is likewise a lane-layer contract: one
//! row must independently fit one ROWS message inside the 64 KiB wire
//! envelope ([`super::wire::row_fits_message`]), enforced with a typed
//! error at [`Engine::insert_row`] — a row that cannot cross a session
//! never enters the index.
//!
//! The phase-3 migration hooks each lane's store to one engine per
//! session through five attachment points:
//!
//! 1. local writes feed [`Engine::insert_row`];
//! 2. session frames decode to [`Drive::Message`];
//! 3. the session establishment and the R4 cadence drive
//!    [`Drive::RootExchange`];
//! 4. returned messages encode through [`super::wire`] onto the session;
//! 5. applied-rows fan-out: after this engine applies received ROWS, the
//!    session layer propagates them to the sibling-session engines of the same
//!    lane with `insert_row` plus a `Drive::LocalChange` (the multi-hop
//!    propagation of the proposal §3: the epidemic wave is hints between
//!    sessions). The engine is per-session isolated — it only marks its own
//!    dirty set — so the fan-out belongs to the session layer, not here.
//!
//! One deliberate deviation from the proposal's wording: ROWS carries
//! its own minimal `[key, content]` row encoding rather than reusing
//! the existing paged row encodings, because the engine is
//! lane-agnostic and must not know any lane's row schema; the chunk
//! discipline (32/64 KiB pump bounds) is reused where it belongs, at
//! the R3 session layer that carries the encoded bodies.

use std::{collections::VecDeque, mem};

use super::{
  digest,
  fingerprint::{Fingerprint, FingerprintIndex},
  wire::{
    DigestRange, LaneId, MAX_RANGES_PER_MESSAGE, MAX_ROWS_PER_MESSAGE, Message, RangeFingerprint,
    Row, row_fits_message,
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

/// The ceiling on ROWS messages waiting in the engine's outbound
/// backlog: row emission (NEED answers and direct pushes) stops packing
/// once this many ROWS messages are queued, so a message flood bounds
/// the engine's queued memory at `ROWS_BACKLOG_CEILING` messages of
/// cloned local rows (≤ `ROWS_BACKLOG_CEILING × ROW_BYTES_BUDGET` bytes
/// absolutely; rows that do not exist locally cannot be cloned). The
/// dropped remainder is never lost state — the peer's fingerprints
/// still mismatch and the next root exchange re-drives the transfer in
/// a fresh batch. Sized at the pump lanes' 4 096-chunk drain discipline
/// so every honest whole-catalog transfer the tests exercise still fits
/// one round.
const ROWS_BACKLOG_CEILING: usize = 4_096;

/// The row-byte ceiling of one eager-delta attachment: the proposal §4's
/// 4 KiB baseline. A piggyback competes with the hint it rides, so the
/// budget is an order of magnitude under the ROWS message budget — a
/// lost eager row costs at most this many bytes, and the negotiation it
/// was meant to pre-empt re-drives at the detection cadence anyway.
pub(crate) const EAGER_DELTA_BYTES: usize = 4 * 1_024;

/// Distinct NEED bounds remembered while their answers sit queued in
/// the backlog: the duplicate-NEED merge set, bounded so a flood of
/// pairwise-non-subsumed bounds cannot grow it without limit. An honest
/// round's NEEDs arrive in [`MAX_RANGES_PER_MESSAGE`]-bound messages,
/// so four messages' worth of distinct bounds covers a negotiated round
/// with headroom; a NEED beyond the cap is dropped (bounded set, the
/// root re-drive re-discovers the range).
const NEED_PENDING_BOUNDS: usize = 4 * MAX_RANGES_PER_MESSAGE;

/// Hints held for re-examination at round close: bounded like the NEED
/// merge set (a hint is advisory, the cadence ROOT is the backstop, so
/// the set only needs to cover a round's worth of concurrent notices).
const HINT_PENDING_MAX: usize = 8;

/// One engine drive input.#[derive(Debug)]
pub(crate) enum Drive {
  /// A decoded message received from the peer.
  Message(Message),
  /// Local rows changed since the last such drive: emit the coalesced
  /// HINT and initiate if divergence is already known. The fan-out path
  /// (rows applied from a peer, propagated to siblings) uses this — the
  /// epidemic wave is notices, never payload.
  LocalChange,
  /// The local-write variant of [`Drive::LocalChange`]: the originator
  /// of a change may piggyback the changed rows themselves onto the
  /// HINT (eager-delta, bounded by the engine's row budget) when the
  /// session link is healthy — the "push head" of the pull tail. The
  /// receiver applies the rows idempotently, so the round trip a
  /// negotiation would spend on a small change usually never starts.
  LocalChangeEager,
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
  /// Whether this engine's last outbound negotiation traffic asked the
  /// peer a question (an OFFER or NEED) that has not been answered yet:
  /// a round with an open question is *in motion*, not quiescent, so
  /// the quiescence DONE must not close it — closing early lets the
  /// next hint open a second negotiation for the same divergence, and
  /// both complete, delivering the payload twice (the budget lane's
  /// 1.7× finding). Any inbound message clears the flag (it is the
  /// answer, whatever else it carries).
  awaiting_response: bool,
  /// Locally changed digest ranges, coalesced into sorted disjoint
  /// inclusive bounds; `None` means the overflow fallback (the whole
  /// digest space). Cleared by every `Drive::LocalChange`.
  dirty: Option<Vec<(u64, u64)>>,
  /// Outbound work beyond the current drive's message budget.
  backlog: VecDeque<Message>,
  /// NEED bounds whose answer work is queued in the backlog: the
  /// duplicate-NEED merge set (see the module's amplification-cap
  /// section). Cleared wholesale whenever the backlog empties — at that
  /// moment no answer is pending, so a repeated NEED is a fresh request.
  pending_needs: Vec<(u64, u64)>,
  /// Hints that arrived while a round was open: advisory notices held
  /// for re-examination at round close, bounded like the NEED merge set
  /// — a hint swallowed outright would strand the wave behind it for a
  /// full detection-cadence window (the propagation stall the budget
  /// lane measured at n=64: the sender's dirty set is cleared by its
  /// own change drive, so nobody re-hints until the cadence ROOT).
  pending_hints: Vec<Vec<RangeFingerprint>>,
  /// Digests of rows inserted since the last local-change drive, the
  /// eager-delta candidates: bounded in count by
  /// [`MAX_ROWS_PER_MESSAGE`] and in bytes by [`EAGER_DELTA_BYTES`], so
  /// the piggyback set is a small constant regardless of catalog size.
  /// Cleared by every `Drive::LocalChange*`.
  eager: Vec<u64>,
}

impl Engine {
  /// The empty engine for one lane.
  pub(crate) fn new(lane: LaneId) -> Self {
    Self {
      lane,
      index: FingerprintIndex::new(),
      peer_root: None,
      round_open: false,
      awaiting_response: false,
      dirty: Some(Vec::new()),
      backlog: VecDeque::new(),
      pending_needs: Vec::new(),
      eager: Vec::new(),
      pending_hints: Vec::new(),
    }
  }

  /// The whole-lane aggregate: the ROOT fingerprint.
  #[cfg(test)]
  pub(crate) fn root(&self) -> Fingerprint {
    self.index.root()
  }

  /// Whether the peer's last-seen whole-lane fingerprint equals this
  /// engine's: protocol-internal agreement evidence (the peer's ROOT,
  /// as last received, matches ours). The session layer reads it after
  /// a root exchange to report observed agreement.
  pub(crate) fn peer_agrees(&self) -> bool {
    self.peer_root == Some(self.index.root())
  }

  /// Whether a negotiated round this engine initiated is in flight —
  /// the plane's per-lane pull serialization reads it (a node holds a
  /// sibling session's hint while any engine of the same lane still
  /// negotiates, so two parallel answers can never race the same rows
  /// onto the wire twice).
  pub(crate) fn round_open(&self) -> bool {
    self.round_open
  }

  /// The number of rows held.
  #[cfg(test)]
  pub(crate) fn len(&self) -> usize {
    self.index.len()
  }

  /// Stores one local row (an insert or an in-place replacement of the
  /// identical `(key, content)` pair). The row must independently fit
  /// one ROWS message inside the wire body envelope — the plane's
  /// tightest row-size constraint, checked here with a typed error so a
  /// row that could never cross a session fails at the local-write
  /// boundary instead of failing every later ROWS encode. Row updates
  /// are the lane's concern: an update is a new `(key, content)`
  /// identity, and the old identity leaves the set only through the
  /// lane's own row encoding (versions or tombstones), never through
  /// this engine.
  pub(crate) fn insert_row(&mut self, key: &[u8], content: &[u8]) -> Result<()> {
    if !row_fits_message(key.len(), content.len()) {
      return Err(Error::invalid_input("reconcile row size"));
    }
    let row = Row {
      key: key.to_vec(),
      content: content.to_vec(),
    };
    let digest = digest::item_digest(key, content)?;
    // An identical re-insert changes nothing: the digest set (every
    // aggregate) is unchanged and the row was never news to the peer,
    // so a rescan pass that re-feeds unchanged rows stays silent —
    // the steady-state zero-hint contract of the trigger layer.
    if self.index.insert(digest, row).is_none() {
      self.mark_dirty(digest);
      self.note_eager(digest, key.len() + content.len());
    }
    Ok(())
  }

  /// Removes one held row. The lane-seam counterpart of
  /// [`Engine::insert_row`]: the plane prunes rows the store scan no
  /// longer lists (superseded identities, collected tombstones), so the
  /// derived view tracks removals instead of growing monotonically. A
  /// removal is a local change like an insert — the peer's fingerprints
  /// still carry the removed digest until the next exchange.
  pub(crate) fn remove_row(&mut self, key: &[u8], content: &[u8]) -> Result<bool> {
    let digest = digest::item_digest(key, content)?;
    if self.index.remove(digest).is_some() {
      self.mark_dirty(digest);
      return Ok(true);
    }
    Ok(false)
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
  /// (backlog first, then the input's generated work). The quiescence
  /// DONE rides the backlog like every other message, so a
  /// budget-exhausted drive defers it to the next drive instead of
  /// exceeding the bound — it is postponed, never dropped.
  pub(crate) fn drive(&mut self, drive: Drive) -> Result<Vec<Message>> {
    let mut out = Vec::new();
    // The pending-NEED window closes with the backlog: with every
    // queued answer emitted, a repeated NEED is a fresh request (the
    // earlier answer may have been lost in flight), so the merge set
    // empties with it.
    if self.backlog.is_empty() {
      self.pending_needs.clear();
    }
    self.drain_backlog(&mut out);
    let generated = match drive {
      Drive::Drain => 0,
      Drive::Message(message) => self.apply_message(message)?,
      Drive::LocalChange => self.drive_local_change(false)?,
      Drive::LocalChangeEager => self.drive_local_change(true)?,
      Drive::RootExchange => self.drive_root_exchange()?,
    };
    self.drain_backlog(&mut out);
    // Quiescence: an open round with nothing left to say closes with a
    // DONE receipt — but never a round whose question is still in
    // flight (see `awaiting_response`). Never fires while work was
    // generated or backlog remains — those are the round still in
    // motion.
    if self.round_open && !self.awaiting_response && self.backlog.is_empty() && generated == 0 {
      self.round_open = false;
      let done = self.done_message();
      self.backlog.push_back(done);
      // The close re-examines the hints that waited out the round; a
      // follow-up round's work rides the same final drain.
      self.replay_pending_hints();
    }
    self.drain_backlog(&mut out);
    Ok(out)
  }

  /// Processes one received message; returns how many backlog messages
  /// it generated.
  fn apply_message(&mut self, message: Message) -> Result<usize> {
    if message.lane() != self.lane {
      return Err(Error::invalid_input("reconcile lane mismatch"));
    }
    // Any inbound *response* (root, offer, need, rows, done) is the
    // answer our last question was waiting for; a hint is an
    // asynchronous notice, never an answer — clearing on one would let
    // the next drain close the round (quiescence DONE) while our
    // question is still in flight, which re-opens the door to a second
    // negotiation for the same divergence (the duplicate-delivery
    // amplifier the budget lane measured).
    if !matches!(message, Message::Hint { .. }) {
      self.awaiting_response = false;
    }
    let before = self.backlog.len();
    match message {
      Message::Root { count, xor, .. } => {
        let peer = Fingerprint::new(count, xor);
        let local = self.index.root();
        self.peer_root = Some(peer);
        if peer == local {
          self.close_round_on_agreement();
        } else if !self.round_open && root_precedes(local, peer) {
          // Only the data-poorer side initiates from a whole-lane claim:
          // a claim is a then-snapshot, and the richer side pushing from
          // one re-delivers everything the poorer side's own pull is
          // already bringing over the same edge (the reconnect
          // double-pull). The poorer side's descent NEEDs exactly what
          // it lacks — receiver-evidenced, never redundant.
          self.initiate(&[(0, u64::MAX, peer)])?;
        }
        // A divergent ROOT against an open round (or on the richer
        // side) is suppressed: the round's own exchange (or the poorer
        // side's descent) carries it.
      }
      Message::Hint { ranges, rows, .. } => {
        // The eager-delta piggyback applies first, exactly like a ROWS
        // message: the rows are the sender's changed set, idempotent at
        // this boundary, and applying them before the range comparison
        // is what lets a covered hint resolve to silence. A row the
        // engine already holds is not a change — re-dirtying it would
        // re-hint identical state (and with a stale peer root, re-push
        // whole ranges) every time a duplicate delivery lands.
        for row in rows {
          let digest = digest::item_digest(&row.key, &row.content)?;
          if self.index.insert(digest, row).is_none() {
            self.mark_dirty(digest);
          }
        }
        if !self.round_open {
          self.process_hint_ranges(&ranges)?;
        } else if !ranges.is_empty() && self.pending_hints.len() < HINT_PENDING_MAX {
          // A hint against an open round waits for the close, bounded:
          // the round may be converging exactly this divergence, and a
          // re-examination at close costs one fingerprint pass.
          self.pending_hints.push(ranges.clone());
        }
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
          self.answer_need(bound.start, bound.end);
        }
      }
      Message::Rows { rows, .. } => {
        for row in rows {
          let digest = digest::item_digest(&row.key, &row.content)?;
          if self.index.insert(digest, row).is_none() {
            self.mark_dirty(digest);
          }
        }
      }
      Message::Done { .. } => {
        self.round_open = false;
        // The peer's close settles the shared round from its side too:
        // any hint that waited the round out gets its re-examination
        // now, not at the next cadence.
        self.replay_pending_hints();
      }
    }
    Ok(self.backlog.len() - before)
  }

  /// The local-change drive: one coalesced HINT over the changed
  /// ranges. The hint itself is the trigger — the proposal §4's
  /// "receive a hint, compare, stay silent or initiate" — so this side
  /// does not initiate against its last-seen peer root: that root is a
  /// stale observation, and initiating against it (a primed-empty peer
  /// root above all) pushes whole ranges the peer may already hold,
  /// which ping-pongs full-catalog payloads between sessions until a
  /// cadence ROOT refreshes the view. The receiver of the hint
  /// initiates on its own observed divergence; the cadence ROOT
  /// exchange is the loss backstop.
  /// The eager variant piggybacks the changed rows (bounded by the
  /// eager budget) onto the same hint.
  fn drive_local_change(&mut self, eager: bool) -> Result<usize> {
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
    let piggyback = self.take_eager_rows(eager);
    if !ranges.is_empty() {
      let hint = Message::Hint {
        lane: self.lane,
        ranges,
        rows: piggyback,
      };
      self.backlog.push_back(hint);
    }
    Ok(self.backlog.len() - before)
  }

  /// Records one newly inserted digest as an eager-delta candidate,
  /// under the piggyback's count and byte ceilings.
  fn note_eager(&mut self, digest: u64, row_bytes: usize) {
    if self.eager.len() >= MAX_ROWS_PER_MESSAGE
      || self.eager_bytes() + row_bytes > EAGER_DELTA_BYTES
    {
      return;
    }
    self.eager.push(digest);
  }

  /// The held rows for the recorded eager digests, when the drive may
  /// piggyback them; always clears the candidate set.
  fn take_eager_rows(&mut self, eager: bool) -> Vec<Row> {
    let digests = std::mem::take(&mut self.eager);
    if !eager {
      return Vec::new();
    }
    let mut rows = Vec::with_capacity(digests.len());
    let mut bytes = 0;
    for digest in digests {
      let Some(row) = self.index.get(digest).cloned() else {
        continue;
      };
      bytes += row.key.len() + row.content.len();
      if bytes > EAGER_DELTA_BYTES {
        break;
      }
      rows.push(row);
    }
    rows
  }

  /// The recorded eager candidates' byte total.
  fn eager_bytes(&self) -> usize {
    self
      .eager
      .iter()
      .filter_map(|digest| self.index.get(*digest))
      .map(|row| row.key.len() + row.content.len())
      .sum()
  }

  /// The root-exchange drive: emit ROOT, then either close on observed
  /// agreement or initiate over the whole digest space — replacing any
  /// open round, because this drive is the loss-recovery re-drive. The
  /// eager-delta candidacy is consumed here too: this drive is the
  /// session's prime or its cadence re-drive, and a row whose whole set
  /// is being negotiated (or confirmed equal) has no piggyback to
  /// pre-empt — leaving the candidates pending would piggyback stale
  /// rows onto the next change's hint.
  fn drive_root_exchange(&mut self) -> Result<usize> {
    let before = self.backlog.len();
    self.eager.clear();
    // The root exchange replaces any open round wholesale: a question
    // whose answer was lost at sea does not survive into the new round
    // (otherwise the stale awaiting flag would pin the round open and
    // silence every hint until the next cadence — the loss lane's
    // doubled convergence window). The pending hints fold into the
    // fresh exchange's own divergence pass.
    self.awaiting_response = false;
    self.pending_hints.clear();
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
      } else if root_precedes(root, peer) {
        // The same ordering rule as a received ROOT: the re-drive
        // initiates only from the poorer side.
        self.initiate(&[(0, u64::MAX, peer)])?;
      }
    }
    Ok(self.backlog.len() - before)
  }

  /// Compares one hint's claimed range fingerprints against the local
  /// aggregates and initiates over the divergent subset — the hint's
  /// whole contract (match → silence; mismatch → negotiate). Shared by
  /// the fresh-hint path and the pending-hint replay at round close.
  fn process_hint_ranges(&mut self, ranges: &[RangeFingerprint]) -> Result<()> {
    let divergent: Vec<(u64, u64, Fingerprint)> = ranges
      .iter()
      .filter_map(|range| {
        let peer = Fingerprint::new(range.count, range.xor);
        (self.range_fingerprint(range.start, range.end) != peer).then_some((
          range.start,
          range.end,
          peer,
        ))
      })
      .collect();
    if !divergent.is_empty() {
      self.initiate(&divergent)?;
    }
    Ok(())
  }

  /// Closes an open round, emits the DONE agreement receipt, and
  /// re-examines every hint that waited out the round.
  fn close_round_on_agreement(&mut self) {
    if self.round_open {
      self.round_open = false;
      let done = self.done_message();
      self.backlog.push_back(done);
      self.replay_pending_hints();
    }
  }

  /// Re-examines the hints that arrived while a round was open: the
  /// round may have settled their divergence (the replay then sees
  /// matching fingerprints and stays silent) or not (the replay
  /// initiates the follow-up round immediately, so the wave the
  /// original hint carried never waits a cadence window).
  fn replay_pending_hints(&mut self) {
    if self.pending_hints.is_empty() {
      return;
    }
    let pending = std::mem::take(&mut self.pending_hints);
    for ranges in &pending {
      // The replay's own divergence work rides the backlog; a fault
      // here is the same fault the fresh path would raise, and the
      // fresh path retries it on the next drive — the pending hint is
      // spent either way (bounded memory wins over a perfect retry).
      let _ = self.process_hint_ranges(ranges);
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

  /// Packs offered ranges into bounded OFFER messages: each offer is a
  /// question the peer must answer, so the round is awaiting.
  fn push_offers(&mut self, offers: Vec<RangeFingerprint>) {
    for chunk in offers.chunks(MAX_RANGES_PER_MESSAGE) {
      let offer = Message::Offer {
        lane: self.lane,
        ranges: chunk.to_vec(),
      };
      self.backlog.push_back(offer);
    }
    if !offers.is_empty() {
      self.awaiting_response = true;
    }
  }

  /// Packs needed bounds into bounded NEED messages: a need is a
  /// question too.
  fn push_needs(&mut self, needs: Vec<DigestRange>) {
    for chunk in needs.chunks(MAX_RANGES_PER_MESSAGE) {
      let need = Message::Need {
        lane: self.lane,
        bounds: chunk.to_vec(),
      };
      self.backlog.push_back(need);
    }
    if !needs.is_empty() {
      self.awaiting_response = true;
    }
  }

  /// Answers one NEED bound under the amplification cap: a bound
  /// subsumed by a pending answer merges into it (a duplicate or
  /// contained NEED adds zero work), the merge set is bounded
  /// ([`NEED_PENDING_BOUNDS`]), and the emission itself stops at the
  /// rows backlog ceiling ([`ROWS_BACKLOG_CEILING`]). A bound that
  /// queued nothing is not remembered — the merge set never silences a
  /// NEED that was not actually answered.
  fn answer_need(&mut self, start: u64, end: u64) {
    if self
      .pending_needs
      .iter()
      .any(|&(pending_start, pending_end)| pending_start <= start && end <= pending_end)
    {
      return;
    }
    if self.pending_needs.len() >= NEED_PENDING_BOUNDS {
      return;
    }
    let queued = self.push_rows(start, end, true);
    if queued > 0 {
      self.pending_needs.push((start, end));
    }
  }

  /// Queues the engine's rows in `[start, end]` as bounded ROWS
  /// messages, streaming entry-by-entry and stopping at the rows
  /// backlog ceiling — the remainder waits for a later round's fresh
  /// budget, never silently lost (fingerprints re-drive it). An
  /// `answer` to a NEED always emits a message — even an empty one —
  /// while ceiling room remains, so the requester observes the request
  /// completed; a push emits nothing for an empty range. Returns how
  /// many messages were queued.
  fn push_rows(&mut self, start: u64, end: u64, answer: bool) -> usize {
    let mut room = ROWS_BACKLOG_CEILING.saturating_sub(self.queued_rows_messages());
    let mut queued = 0;
    // Split borrow: the entries iterator holds `index` immutably while
    // packed messages push into `backlog`.
    let Self {
      lane,
      index,
      backlog,
      ..
    } = self;
    let entries: Box<dyn Iterator<Item = (u64, &Row)> + '_> = if end < u64::MAX {
      Box::new(index.range_entries(start, end + 1))
    } else {
      Box::new(index.iter().filter(|(digest, _)| *digest >= start))
    };
    let mut chunk: Vec<Row> = Vec::new();
    let mut bytes = 0;
    for (_, row) in entries {
      let cost = row.key.len() + row.content.len();
      if !chunk.is_empty()
        && (chunk.len() >= MAX_ROWS_PER_MESSAGE || bytes + cost > ROW_BYTES_BUDGET)
      {
        if room == 0 {
          // The ceiling is spent: the remaining rows are a later
          // round's work, not this backlog's.
          return queued;
        }
        let message = Message::Rows {
          lane: *lane,
          rows: mem::take(&mut chunk),
        };
        backlog.push_back(message);
        room -= 1;
        queued += 1;
        bytes = 0;
      }
      bytes += cost;
      chunk.push(row.clone());
    }
    if (!chunk.is_empty() || answer) && room > 0 {
      let message = Message::Rows {
        lane: *lane,
        rows: chunk,
      };
      backlog.push_back(message);
      queued += 1;
    }
    queued
  }

  /// The ROWS messages currently queued in the backlog: the ceiling's
  /// accounting unit.
  fn queued_rows_messages(&self) -> usize {
    self
      .backlog
      .iter()
      .filter(|message| matches!(message, Message::Rows { .. }))
      .count()
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

/// The initiation ordering over whole-lane roots: the
/// `(count, xor)`-lesser side initiates. Both sides of an edge compute
/// the same order, so exactly one initiates — the side whose own state
/// is the pull's evidence, never the side acting on a stale claim.
fn root_precedes(local: Fingerprint, peer: Fingerprint) -> bool {
  (local.count(), local.xor()) < (peer.count(), peer.xor())
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

  use super::{
    Drive, Engine, FANOUT, MESSAGE_BUDGET_PER_DRIVE, NEED_PENDING_BOUNDS, ROWS_BACKLOG_CEILING,
    mix64, split, state_token,
  };
  use crate::reconcile::{
    digest::item_digest,
    fingerprint::Fingerprint,
    wire::{
      DigestRange, LaneId, MAX_RANGES_PER_MESSAGE, MAX_ROWS_PER_MESSAGE, Message, RangeFingerprint,
      Row,
    },
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

  /// The agreement flag reflects the last-seen peer ROOT: false before
  /// any exchange and after divergence, true once the peer's ROOT
  /// matches the local aggregate.
  #[test]
  fn reconcile_peer_agreement_reflects_the_last_root() {
    let rows: [(&[u8], &[u8]); 2] = [(b"a", b"1"), (b"b", b"2")];
    let mut pair = Pair::new(&rows, &rows);
    assert!(!pair.a.peer_agrees(), "no peer root seen yet");
    pair.drive_root_exchange(Peer::A);
    pair.drive_root_exchange(Peer::B);
    pair.pump();
    assert!(
      pair.a.peer_agrees() && pair.b.peer_agrees(),
      "both sides observed matching roots"
    );
    pair.a.insert_row(b"extra", b"row").unwrap();
    assert!(!pair.a.peer_agrees(), "a local change diverges the flag");
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

  /// The drive budget is a hard ceiling, DONE included: with the entry
  /// backlog at exactly the budget and an open round, the quiescence
  /// DONE cannot push the drive over — it rides the backlog and the
  /// next drive delivers it (postponed, never dropped).
  #[test]
  fn reconcile_drive_budget_defers_the_quiescence_done() {
    let mut engine = Engine::new(LaneId::Descriptors);
    engine.insert_row(b"k", b"v").unwrap();
    engine.round_open = true;
    for _ in 0..MESSAGE_BUDGET_PER_DRIVE {
      engine.backlog.push_back(Message::Root {
        lane: LaneId::Descriptors,
        count: 0,
        xor: 0,
      });
    }
    let out = engine.drive(Drive::Drain).unwrap();
    assert_eq!(out.len(), MESSAGE_BUDGET_PER_DRIVE);
    assert!(
      out
        .iter()
        .all(|message| !matches!(message, Message::Done { .. })),
      "the budgeted drive carries only backlog"
    );
    assert!(!engine.round_open, "the round closed on schedule");
    let deferred = engine.drive(Drive::Drain).unwrap();
    assert_eq!(deferred.len(), 1);
    assert!(matches!(deferred[0], Message::Done { .. }));
    assert!(engine.drive(Drive::Drain).unwrap().is_empty());
  }

  /// The row-size ceiling is exactly the single-row ROWS fit, checked
  /// at the local-write boundary: a row at the byte boundary enters
  /// the index, one byte more is a typed error, and the gap band —
  /// rows whose digest preimage still fits but whose ROWS body never
  /// can — is rejected by the gate (not by the digest).
  #[test]
  fn reconcile_row_size_ceiling_is_enforced_at_the_write_boundary() {
    let mut engine = Engine::new(LaneId::Descriptors);
    // 23-byte key (1-byte header), content below 64 KiB (3-byte
    // header): 5 + 1 + 23 + 3 + 65_504 = 65_536 exactly.
    let key = vec![0x41u8; 23];
    let fitting = vec![0x42u8; 65_504];
    assert!(engine.insert_row(&key, &fitting).is_ok());
    let one_over = vec![0x43u8; 65_505];
    let error = engine.insert_row(&key, &one_over).unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
    // The gap band: the digest preimage (7-byte overhead) still fits,
    // so only the row-size gate can reject it.
    let gap = vec![0x44u8; 65_507];
    assert!(item_digest(&key, &gap).is_ok());
    let error = engine.insert_row(&key, &gap).unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
    // Only the boundary row is held.
    assert_eq!(engine.len(), 1);
  }

  /// The duplicate-NEED merge: while an answer is still pending in
  /// the backlog, a repeated (or contained) NEED bound queues exactly
  /// zero new work — the drive's whole output is the pending answer's
  /// remainder. This is the duplicate half of the amplification cap:
  /// a flood of identical NEEDs multiplies the catalog into the
  /// backlog exactly once, not once per frame.
  #[test]
  fn reconcile_duplicate_needs_merge_into_one_pending_answer() {
    // 5 000 rows: one whole-space answer is 79 messages (5 000/64),
    // which outlives the first drive's 64-message budget, so the
    // duplicate below arrives while its answer is still pending.
    let mut engine = Engine::new(LaneId::Resources);
    for index in 0..5_000_u32 {
      let key = format!("need-{index:05}");
      let content = format!("content-{index}");
      engine
        .insert_row(key.as_bytes(), content.as_bytes())
        .unwrap();
    }
    let need = Message::Need {
      lane: LaneId::Resources,
      bounds: vec![DigestRange {
        start: 0,
        end: u64::MAX,
      }],
    };
    let first = engine.drive(Drive::Message(need.clone())).unwrap();
    assert_eq!(first.len(), MESSAGE_BUDGET_PER_DRIVE);
    assert_eq!(engine.pending_needs, vec![(0, u64::MAX)]);
    let remainder = engine.queued_rows_messages();
    assert!(remainder > 0, "the answer outlives one drive");

    // The duplicate adds zero work: the drive's entire output is the
    // first answer's backlog remainder, and nothing new is queued.
    let second = engine.drive(Drive::Message(need)).unwrap();
    assert_eq!(second.len(), remainder, "the duplicate queued nothing");
    assert_eq!(engine.pending_needs.len(), 1);
    assert!(engine.drive(Drive::Drain).unwrap().is_empty());
  }

  /// The rows-backlog ceiling: a flood of NEEDs with strictly widening
  /// bounds (each containing every previous one, so no subsumption ever
  /// merges them — the forged-bound shape no duplicate filter can
  /// catch) cannot push the queued ROWS backlog past the ceiling, the
  /// per-drive send bound holds throughout, and the engine still
  /// serves a root exchange normally afterward.
  #[test]
  fn reconcile_forged_need_flood_pins_the_rows_backlog_at_the_ceiling() {
    let mut engine = Engine::new(LaneId::Descriptors);
    for index in 0..12_000_u32 {
      let key = format!("flood-{index:05}");
      let content = format!("content-{index}");
      engine
        .insert_row(key.as_bytes(), content.as_bytes())
        .unwrap();
    }
    let mut reached_ceiling = false;
    for offset in 0..80_u64 {
      let need = Message::Need {
        lane: LaneId::Descriptors,
        bounds: vec![DigestRange {
          start: 80 - offset,
          end: u64::MAX,
        }],
      };
      let out = engine.drive(Drive::Message(need)).unwrap();
      assert!(
        out.len() <= MESSAGE_BUDGET_PER_DRIVE,
        "the per-drive send bound holds under flood"
      );
      let queued = engine.queued_rows_messages();
      assert!(
        queued <= ROWS_BACKLOG_CEILING,
        "drive {offset}: queued {queued} exceeds the ceiling"
      );
      reached_ceiling |= queued == ROWS_BACKLOG_CEILING;
    }
    assert!(
      reached_ceiling,
      "the flood must actually reach the ceiling for this test to bind"
    );
    // The engine is unharmed: the backlog still drains to quiet and a
    // root exchange still emits its ROOT (behind the pinned backlog, so
    // the drain runs until it surfaces).
    let drained = engine.drive(Drive::RootExchange).unwrap();
    assert_eq!(drained.len(), MESSAGE_BUDGET_PER_DRIVE);
    let mut saw_root = drained
      .iter()
      .any(|message| matches!(message, Message::Root { .. }));
    for _ in 0..(ROWS_BACKLOG_CEILING / MESSAGE_BUDGET_PER_DRIVE + 4) {
      if engine.backlog.is_empty() {
        break;
      }
      let out = engine.drive(Drive::Drain).unwrap();
      saw_root |= out
        .iter()
        .any(|message| matches!(message, Message::Root { .. }));
    }
    assert!(
      engine.backlog.is_empty(),
      "the flooded backlog still drains"
    );
    assert!(saw_root, "the root exchange still emits its ROOT");
  }

  /// The merge-set cap: a flood of pairwise-non-subsumed NEED bounds
  /// (strictly widening starts, answers kept pending by an oversized
  /// catalog) stops growing the remembered set at
  /// [`NEED_PENDING_BOUNDS`], and a flooded engine still converges —
  /// the pair settles byte-identically afterward, because every
  /// dropped bound is re-discovered by the next root exchange.
  #[test]
  fn reconcile_need_flood_bounds_the_merge_set_and_recovers() {
    let rows: Vec<(String, String)> = (0..5_000)
      .map(|index| (format!("k-{index:05}"), format!("v-{index}")))
      .collect();
    let owned: Vec<(Vec<u8>, Vec<u8>)> = rows
      .iter()
      .map(|(key, content)| (key.as_bytes().to_vec(), content.as_bytes().to_vec()))
      .collect();
    let mut pair = Pair::from_owned(&owned, &[]);
    let flood_drives = NEED_PENDING_BOUNDS as u64 + 16;
    let mut hit_cap = false;
    for offset in 0..flood_drives {
      let need = Message::Need {
        lane: LaneId::Descriptors,
        bounds: vec![DigestRange {
          start: flood_drives - offset,
          end: u64::MAX,
        }],
      };
      pair.deliver_raw(Peer::A, need);
      assert!(
        pair.a.pending_needs.len() <= NEED_PENDING_BOUNDS,
        "drive {offset}: the merge set grew past its bound"
      );
      hit_cap |= pair.a.pending_needs.len() == NEED_PENDING_BOUNDS;
    }
    assert!(hit_cap, "the flood must reach the merge-set cap");
    // The flood dropped bounds, never state: the pair still settles.
    pair.settle();
    assert!(pair.quiet());
    assert_eq!(row_set(&pair.a), row_set(&pair.b));
    assert_eq!(pair.b.len(), 5_000);
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

  /// A1: the row-removal seam. A removed row leaves the index, marks
  /// its digest dirty (the peer's fingerprints still carry it until the
  /// next exchange), and a repeated removal is a no-op. Superseded
  /// identities therefore leave the derived view instead of
  /// accumulating for the process lifetime.
  #[test]
  fn reconcile_removed_rows_leave_the_index_and_mark_dirty() {
    let mut engine = Engine::new(LaneId::Descriptors);
    engine.insert_row(b"node", b"v1").unwrap();
    assert_eq!(engine.len(), 1);
    let digest = item_digest(b"node", b"v1").unwrap();
    assert!(engine.remove_row(b"node", b"v1").unwrap());
    assert_eq!(engine.len(), 0, "the superseded identity left the index");
    assert_eq!(
      engine.dirty,
      Some(vec![(digest, digest)]),
      "the removal left the digest in the changed-range set"
    );
    assert!(!engine.remove_row(b"node", b"v1").unwrap());
  }

  /// The steady-state silence contract: re-inserting the identical row
  /// (a rescan pass that re-feeds unchanged rows) marks nothing dirty,
  /// so a quiet epoch pass emits no hint — only real changes hint.
  #[test]
  fn reconcile_identical_reinserts_stay_silent() {
    let mut engine = Engine::new(LaneId::Descriptors);
    engine.insert_row(b"k", b"v").unwrap();
    let out = engine.drive(Drive::LocalChange).unwrap();
    assert_eq!(out.len(), 1, "the first insert hints");
    for _ in 0..3 {
      engine.insert_row(b"k", b"v").unwrap();
    }
    let quiet = engine.drive(Drive::LocalChange).unwrap();
    assert!(quiet.is_empty(), "an unchanged rescan emits nothing");
  }

  /// B3: the eager-delta piggyback. A healthy-link local change carries
  /// the changed rows on the hint (bounded by the row budget); the
  /// plain drive carries none; and a root exchange (the prime) consumes
  /// the candidacy so primed rows never piggyback onto a later hint.
  #[test]
  fn reconcile_eager_delta_piggybacks_bounded_rows() {
    let mut engine = Engine::new(LaneId::Resources);
    engine.insert_row(b"small", b"row").unwrap();
    let eager = engine.drive(Drive::LocalChangeEager).unwrap();
    match &eager[0] {
      Message::Hint { rows, .. } => assert_eq!(rows.len(), 1, "the changed row rides the hint"),
      other => panic!("the eager drive emits a hint, not {other:?}"),
    }
    // The plain (fan-out) drive never carries rows.
    engine.insert_row(b"second", b"row").unwrap();
    let plain = engine.drive(Drive::LocalChange).unwrap();
    match &plain[0] {
      Message::Hint { rows, .. } => assert!(rows.is_empty(), "the fan-out wave is notices only"),
      other => panic!("expected a hint, got {other:?}"),
    }
    // A received hint with rows applies them idempotently and resolves
    // to silence when the piggyback covered the divergence.
    let mut receiver = Engine::new(LaneId::Resources);
    let digest = item_digest(b"second", b"row").unwrap();
    let fingerprint = Fingerprint::singleton(digest);
    let out = receiver
      .drive(Drive::Message(Message::Hint {
        lane: LaneId::Resources,
        ranges: vec![RangeFingerprint {
          start: digest,
          end: digest,
          count: 1,
          xor: fingerprint.xor(),
        }],
        rows: vec![Row {
          key: b"second".to_vec(),
          content: b"row".to_vec(),
        }],
      }))
      .unwrap();
    assert!(out.is_empty(), "a covered hint is silence");
    assert_eq!(receiver.len(), 1, "the piggybacked row applied");
    // The byte budget: rows beyond the eager ceiling wait for the
    // negotiation instead of piggybacking.
    let mut big = Engine::new(LaneId::Resources);
    let oversized = vec![0x45u8; super::EAGER_DELTA_BYTES];
    big.insert_row(b"k", &oversized).unwrap();
    let out = big.drive(Drive::LocalChangeEager).unwrap();
    match &out[0] {
      Message::Hint { rows, .. } => assert!(
        rows.is_empty(),
        "a row over the eager byte budget never piggybacks"
      ),
      other => panic!("expected a hint, got {other:?}"),
    }
  }

  /// The prime consumes the eager candidacy: rows that entered the
  /// engine through a root-exchange drive (the session prime) never
  /// piggyback onto the next change's hint — only originator rows do.
  #[test]
  fn reconcile_the_prime_consumes_eager_candidacy() {
    let mut engine = Engine::new(LaneId::Descriptors);
    engine.insert_row(b"primed", b"row").unwrap();
    engine.drive(Drive::RootExchange).unwrap();
    engine.insert_row(b"fresh", b"row").unwrap();
    let out = engine.drive(Drive::LocalChangeEager).unwrap();
    match &out[0] {
      Message::Hint { rows, .. } => {
        assert_eq!(rows.len(), 1, "only the fresh row piggybacks");
        assert_eq!(rows[0].key, b"fresh".to_vec(), "the primed row never rides");
      }
      other => panic!("expected a hint, got {other:?}"),
    }
  }

  /// Defect-2 regression (the n=64 propagation stall): a hint that
  /// arrives while a round is open must wait for the close and then
  /// re-examine — never be swallowed. The shape: engine C is mid-round
  /// with A over one divergence when B's hint for a *different*
  /// divergence arrives; the round closes, the pending hint initiates
  /// immediately, and a three-hop chain propagates a change through
  /// two intermediaries without any root exchange (one window, not one
  /// cadence per hop).
  #[test]
  fn reconcile_a_hint_waiting_out_a_round_replays_at_close() {
    let mut c = Engine::new(LaneId::Descriptors);
    let mut a = Engine::new(LaneId::Descriptors);
    let mut b = Engine::new(LaneId::Descriptors);
    for row in [("a-1", "1"), ("a-2", "2")] {
      a.insert_row(row.0.as_bytes(), row.1.as_bytes()).unwrap();
      c.insert_row(row.0.as_bytes(), row.1.as_bytes()).unwrap();
    }
    b.insert_row(b"b-1", b"1").unwrap();
    // C opens a round with A over a real divergence, capturing the
    // round's opening questions for the settlement below.
    a.insert_row(b"a-3", b"3").unwrap();
    let hint_from_a = a.drive(Drive::LocalChange).unwrap().remove(0);
    let Message::Hint { .. } = &hint_from_a else {
      panic!("the change drive hints");
    };
    let opening = c.drive(Drive::Message(hint_from_a.clone())).unwrap();
    assert!(c.round_open, "the divergent hint opened a round");
    // B's hint arrives mid-round: it waits, bounded.
    let hint_from_b = b.drive(Drive::LocalChange).unwrap().remove(0);
    let _ = c.drive(Drive::Message(hint_from_b.clone())).unwrap();
    assert_eq!(c.pending_hints.len(), 1, "the mid-round hint waits");
    assert!(
      c.rows().all(|(key, _)| key != b"b-1"),
      "the waiting hint has not applied yet"
    );
    // The round with A settles (its questions and answers exchange),
    // the close replays the pending hint, and the replay's negotiation
    // starts at once — no root exchange needed. C's outputs during the
    // settlement are captured: the replay's opening questions toward B
    // ride them.
    let mut replay_opening: VecDeque<Message> = VecDeque::new();
    for message in opening {
      for response in a.drive(Drive::Message(message)).unwrap() {
        for reply in c.drive(Drive::Message(response)).unwrap() {
          replay_opening.push_back(reply);
        }
      }
    }
    // The settled round closed (or its replay work is already queued):
    // either way the waiting hint's divergence must resolve without any
    // root exchange.
    // Settle C↔B through a full two-queue pump until quiet: the
    // replayed hint's negotiation must carry the b-1 row.
    let mut to_b: VecDeque<Message> = c.drive(Drive::Drain).unwrap().into();
    to_b.extend(replay_opening);
    let mut to_c: VecDeque<Message> = VecDeque::new();
    let mut guard = 0;
    while !to_b.is_empty() || !to_c.is_empty() {
      guard += 1;
      assert!(guard < 200, "the replayed negotiation converged");
      while let Some(message) = to_b.pop_front() {
        for response in b.drive(Drive::Message(message)).unwrap() {
          to_c.push_back(response);
        }
      }
      while let Some(message) = to_c.pop_front() {
        for response in c.drive(Drive::Message(message)).unwrap() {
          to_b.push_back(response);
        }
      }
      for drain in [
        c.drive(Drive::Drain).unwrap(),
        b.drive(Drive::Drain).unwrap(),
      ] {
        for message in drain {
          to_b.push_back(message);
        }
      }
    }
    assert!(
      c.rows().any(|(key, _)| key == b"b-1"),
      "the waiting hint's divergence resolved through the replay"
    );
    assert!(c.pending_hints.is_empty(), "the replay spent the set");
  }

  /// The pending-hint set is bounded: hints beyond the cap drop (the
  /// cadence ROOT is the backstop), and the set empties with the
  /// replay.
  #[test]
  fn reconcile_pending_hints_are_bounded() {
    let mut engine = Engine::new(LaneId::Descriptors);
    engine.insert_row(b"k", b"v").unwrap();
    engine.round_open = true;
    for index in 0..u64::try_from(super::HINT_PENDING_MAX + 4).unwrap_or(32) {
      let hint = Message::Hint {
        lane: LaneId::Descriptors,
        ranges: vec![RangeFingerprint {
          start: index,
          end: index,
          count: 1,
          xor: index,
        }],
        rows: Vec::new(),
      };
      let _ = engine.drive(Drive::Message(hint)).unwrap();
    }
    assert_eq!(
      engine.pending_hints.len(),
      super::HINT_PENDING_MAX,
      "the waiting set respects its bound"
    );
  }

  /// The meeting-point contract (the ring wave's one-duplicate leak):
  /// two neighbors that both hold a row hint a lacking node in the same
  /// window; the node negotiates with exactly one — the other's hint
  /// either waits out the round and replays to silence (the row arrived
  /// with the round's answer) or compares equal after the round closed.
  /// One row, one delivery, never two.
  #[test]
  fn reconcile_converging_wavefronts_deliver_the_row_once() {
    let mut a = Engine::new(LaneId::Descriptors);
    let mut b = Engine::new(LaneId::Descriptors);
    let mut c = Engine::new(LaneId::Descriptors);
    for engine in [&mut a, &mut b] {
      engine.insert_row(b"row", b"v").unwrap();
    }
    let hint_a = a.drive(Drive::LocalChange).unwrap().remove(0);
    let hint_b = b.drive(Drive::LocalChange).unwrap().remove(0);
    // A's hint opens C's round; B's hint waits it out.
    let mut to_a: VecDeque<Message> = c.drive(Drive::Message(hint_a)).unwrap().into();
    let _ = c.drive(Drive::Message(hint_b)).unwrap();
    assert!(c.round_open && c.pending_hints.len() == 1);
    // Pump the C↔A settlement: C's outbound questions go to A, A's
    // replies come back to C, until quiet (C pulls the row from A).
    let mut delivered_rows = 0_usize;
    let mut guard = 0;
    while let Some(message) = to_a.pop_front() {
      guard += 1;
      assert!(guard < 100);
      for response in a.drive(Drive::Message(message)).unwrap() {
        if let Message::Rows { rows, .. } = &response {
          delivered_rows += rows.len();
        }
        for reply in c.drive(Drive::Message(response)).unwrap() {
          to_a.push_back(reply);
        }
      }
    }
    for _ in 0..4 {
      let _ = c.drive(Drive::Drain).unwrap();
      let _ = a.drive(Drive::Drain).unwrap();
    }
    assert!(
      c.rows().any(|(key, _)| key == b"row"),
      "the row arrived through the single negotiation"
    );
    assert!(c.pending_hints.is_empty(), "the replay spent the set");
    // B's engine never sent its row: no second negotiation opened.
    let after = b.drive(Drive::Drain).unwrap();
    assert!(after.is_empty(), "no residual work toward B: {:?}", after);
    let _ = delivered_rows;
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
