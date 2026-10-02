//! The reconciliation wire contract, version 1.
//!
//! Six message kinds ride one reconcile protocol stream, multiplexed by
//! the lane identifier every message carries: `ROOT` (my whole-lane
//! aggregate), `HINT` (best-effort changed-range notice), `OFFER` (my
//! fingerprints for negotiated ranges), `NEED` (the ranges whose rows I
//! lack), `ROWS` (row payloads), and `DONE` (round-close receipt). The
//! shapes follow `docs/research/06-architecture-proposal.md` §3; the
//! lane field rides every message — not just `ROOT` — because one
//! protocol stream carries all four lanes and dispatch happens at the
//! session seam.
//!
//! Every body is canonical CBOR through the crate's single canonical
//! encoder/decoder (`crate::protocol::cbor`): decode re-encodes and
//! byte-compares, so exactly one byte string represents one message.
//! Decoding is fail-closed on unknown message kinds, unknown lanes,
//! non-canonical encodings, inverted ranges, and over-bound list shapes
//! (the bounds are wire constants, enforced on both encode and decode).
//!
//! A range is a half-open-free **inclusive** digest interval
//! `[start, end]`: inclusivity is what makes the full digest space
//! `[0, u64::MAX]` representable without a sentinel end value. Every
//! message shape is pinned by golden vectors; the encoding is frozen
//! and additive-only in the future.

use minicbor::{Decode, Decoder, Encode, bytes::ByteVec};

use crate::{
  Error, Result,
  protocol::{CborLimits, MAX_BODY_BYTES, decode_canonical_strict, encode_canonical},
};

/// The maximum fingerprint-range entries one HINT or OFFER message, and
/// the maximum bound entries one NEED message, may carry. The HINT bound
/// is the proposal's ≤32 discipline; OFFER and NEED share it so one
/// negotiation message never exceeds the hint budget.
pub(crate) const MAX_RANGES_PER_MESSAGE: usize = 32;

/// The maximum row entries one ROWS message may carry: a constant
/// per-message ceiling (64 rows) that, with the engine's per-message
/// byte budget, keeps every ROWS body far inside the 64 KiB control
/// envelope. Over-bound shapes fail closed on both directions.
pub(crate) const MAX_ROWS_PER_MESSAGE: usize = 64;

/// The CBOR budget of every reconcile message body: shared control-plane
/// body ceiling, shallow fixed-shape nesting, and item counts far below
/// the collection bound (the shape checks below are the real limits).
pub(crate) const RECONCILE_CBOR_LIMITS: CborLimits = CborLimits::new(8, 1_024, MAX_BODY_BYTES);

/// The message-kind code of `ROOT`.
pub(crate) const KIND_ROOT: u8 = 1;
/// The message-kind code of `HINT`.
pub(crate) const KIND_HINT: u8 = 2;
/// The message-kind code of `OFFER`.
pub(crate) const KIND_OFFER: u8 = 3;
/// The message-kind code of `NEED`.
pub(crate) const KIND_NEED: u8 = 4;
/// The message-kind code of `ROWS`.
pub(crate) const KIND_ROWS: u8 = 5;
/// The message-kind code of `DONE`.
pub(crate) const KIND_DONE: u8 = 6;

/// One reconciliation lane: an independently converging key space. The
/// registry is closed — an unknown lane code fails closed at decode,
/// and an engine never accepts a message for another lane.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum LaneId {
  /// Member descriptor rows.
  Descriptors,
  /// Issuer trust snapshot pages.
  Trust,
  /// Resource metadata rows.
  Resources,
  /// Leave/cleanup/revocation/checkpoint rows.
  Tombstones,
}

impl LaneId {
  /// Every lane, in wire-code order.
  #[cfg(test)]
  pub(crate) const ALL: [Self; 4] = [
    Self::Descriptors,
    Self::Trust,
    Self::Resources,
    Self::Tombstones,
  ];

  /// The immutable wire code of the lane.
  pub(crate) const fn code(self) -> u8 {
    match self {
      Self::Descriptors => 1,
      Self::Trust => 2,
      Self::Resources => 3,
      Self::Tombstones => 4,
    }
  }

  /// Resolves a wire code to a lane; unknown codes are `None` and fail
  /// closed at the decode boundary.
  pub(crate) const fn from_code(code: u8) -> Option<Self> {
    match code {
      1 => Some(Self::Descriptors),
      2 => Some(Self::Trust),
      3 => Some(Self::Resources),
      4 => Some(Self::Tombstones),
      _ => None,
    }
  }
}

/// One inclusive digest range `[start, end]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DigestRange {
  /// The first digest of the range.
  pub(crate) start: u64,
  /// The last digest of the range (inclusive).
  pub(crate) end: u64,
}

/// One inclusive digest range together with the sender's aggregate over
/// it: how many rows the sender holds inside the range and the
/// exclusive-or of their item digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RangeFingerprint {
  /// The first digest of the range.
  pub(crate) start: u64,
  /// The last digest of the range (inclusive).
  pub(crate) end: u64,
  /// The sender's row count inside the range.
  pub(crate) count: u64,
  /// The sender's digest exclusive-or inside the range.
  pub(crate) xor: u64,
}

/// One reconciled row: its lane key bytes and its content bytes. The
/// wire never carries a digest — the receiver recomputes it with the
/// frozen digest function, so a sender cannot misattribute a payload to
/// a digest it does not hash to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Row {
  /// The row's lane key, in the lane's own canonical encoding.
  pub(crate) key: Vec<u8>,
  /// The row's content bytes, in the lane's own canonical encoding.
  pub(crate) content: Vec<u8>,
}

/// One decoded reconcile-v1 message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Message {
  /// The sender's whole-lane aggregate: count and xor over every row it
  /// holds in the lane.
  Root {
    /// The sender's lane.
    lane: LaneId,
    /// The sender's whole-lane row count.
    count: u64,
    /// The sender's whole-lane digest exclusive-or.
    xor: u64,
  },
  /// A best-effort notice that the sender's rows inside these ranges
  /// changed. Lossy, duplicable, ignorable by design. The eager-delta
  /// piggyback (the proposal §4): a healthy-link originator may carry
  /// the changed rows themselves (at most [`MAX_ROWS_PER_MESSAGE`],
  /// byte-bounded by the engine's eager budget) so the receiver's
  /// idempotent apply usually closes the change without a negotiation.
  /// An empty list is the plain notice.
  Hint {
    /// The sender's lane.
    lane: LaneId,
    /// The changed ranges with the sender's current aggregates (at most
    /// [`MAX_RANGES_PER_MESSAGE`]).
    ranges: Vec<RangeFingerprint>,
    /// The eager-delta rows (at most [`MAX_ROWS_PER_MESSAGE`], each row
    /// within the single-row ROWS fit contract).
    rows: Vec<Row>,
  },
  /// The sender's aggregates for the negotiated ranges: one recursion
  /// level of a reconciliation round.
  Offer {
    /// The sender's lane.
    lane: LaneId,
    /// The offered ranges with the sender's aggregates (at most
    /// [`MAX_RANGES_PER_MESSAGE`]).
    ranges: Vec<RangeFingerprint>,
  },
  /// The sender lacks the rows inside these ranges and asks the
  /// receiver to send its rows there.
  Need {
    /// The sender's lane.
    lane: LaneId,
    /// The requested ranges (at most [`MAX_RANGES_PER_MESSAGE`]).
    bounds: Vec<DigestRange>,
  },
  /// Row payloads, applied idempotently by the receiver.
  Rows {
    /// The sender's lane.
    lane: LaneId,
    /// The carried rows (at most [`MAX_ROWS_PER_MESSAGE`]).
    rows: Vec<Row>,
  },
  /// The sender closed its round. The token is the sender's whole-lane
  /// state digest at close (see the engine): matching tokens across the
  /// pair's DONE messages are a cheap agreement receipt.
  Done {
    /// The sender's lane.
    lane: LaneId,
    /// The sender's state token at round close.
    round_token: u64,
  },
}

impl Message {
  /// The lane every message carries (session-seam dispatch key).
  pub(crate) fn lane(&self) -> LaneId {
    match self {
      Self::Root { lane, .. }
      | Self::Hint { lane, .. }
      | Self::Offer { lane, .. }
      | Self::Need { lane, .. }
      | Self::Rows { lane, .. }
      | Self::Done { lane, .. } => *lane,
    }
  }
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct RootWire {
  #[n(0)]
  kind: u8,
  #[n(1)]
  lane: u8,
  #[n(2)]
  count: u64,
  #[n(3)]
  xor: u64,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct RangeWire {
  #[n(0)]
  start: u64,
  #[n(1)]
  end: u64,
  #[n(2)]
  count: u64,
  #[n(3)]
  xor: u64,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct BoundWire {
  #[n(0)]
  start: u64,
  #[n(1)]
  end: u64,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct RowWire {
  #[n(0)]
  key: ByteVec,
  #[n(1)]
  content: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct HintWire {
  #[n(0)]
  kind: u8,
  #[n(1)]
  lane: u8,
  #[n(2)]
  ranges: Vec<RangeWire>,
  #[n(3)]
  rows: Vec<RowWire>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct OfferWire {
  #[n(0)]
  kind: u8,
  #[n(1)]
  lane: u8,
  #[n(2)]
  ranges: Vec<RangeWire>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct NeedWire {
  #[n(0)]
  kind: u8,
  #[n(1)]
  lane: u8,
  #[n(2)]
  bounds: Vec<BoundWire>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct RowsWire {
  #[n(0)]
  kind: u8,
  #[n(1)]
  lane: u8,
  #[n(2)]
  rows: Vec<RowWire>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct DoneWire {
  #[n(0)]
  kind: u8,
  #[n(1)]
  lane: u8,
  #[n(2)]
  round_token: u64,
}

/// Encodes one reconcile-v1 message body in canonical CBOR. Shape
/// violations (over-bound lists, inverted ranges, unknown lanes) fail
/// closed before any byte is emitted.
pub(crate) fn encode(message: &Message) -> Result<Vec<u8>> {
  match message {
    Message::Root { lane, count, xor } => encode_canonical(
      &RootWire {
        kind: KIND_ROOT,
        lane: lane.code(),
        count: *count,
        xor: *xor,
      },
      RECONCILE_CBOR_LIMITS,
    ),
    Message::Hint { lane, ranges, rows } => {
      let ranges = ranges_to_wire(ranges)?;
      let rows = rows_to_wire(rows)?;
      encode_canonical(
        &HintWire {
          kind: KIND_HINT,
          lane: lane.code(),
          ranges,
          rows,
        },
        RECONCILE_CBOR_LIMITS,
      )
    }
    Message::Offer { lane, ranges } => {
      let ranges = ranges_to_wire(ranges)?;
      encode_canonical(
        &OfferWire {
          kind: KIND_OFFER,
          lane: lane.code(),
          ranges,
        },
        RECONCILE_CBOR_LIMITS,
      )
    }
    Message::Need { lane, bounds } => {
      let bounds = bounds_to_wire(bounds)?;
      encode_canonical(
        &NeedWire {
          kind: KIND_NEED,
          lane: lane.code(),
          bounds,
        },
        RECONCILE_CBOR_LIMITS,
      )
    }
    Message::Rows { lane, rows } => {
      let rows = rows_to_wire(rows)?;
      encode_canonical(
        &RowsWire {
          kind: KIND_ROWS,
          lane: lane.code(),
          rows,
        },
        RECONCILE_CBOR_LIMITS,
      )
    }
    Message::Done { lane, round_token } => encode_canonical(
      &DoneWire {
        kind: KIND_DONE,
        lane: lane.code(),
        round_token: *round_token,
      },
      RECONCILE_CBOR_LIMITS,
    ),
  }
}

/// Decodes one reconcile-v1 message body, fail-closed on every
/// contract violation: unknown kinds, unknown lanes, non-canonical
/// bytes, wrong arity, trailing data, over-bound lists, and inverted
/// ranges all return typed errors.
pub(crate) fn decode(bytes: &[u8]) -> Result<Message> {
  match probe_kind(bytes)? {
    KIND_ROOT => {
      let wire: RootWire =
        decode_canonical_strict(bytes, RECONCILE_CBOR_LIMITS, "reconcile root canonical")?;
      Ok(Message::Root {
        lane: lane_from(wire.lane)?,
        count: wire.count,
        xor: wire.xor,
      })
    }
    KIND_HINT => {
      let wire: HintWire =
        decode_canonical_strict(bytes, RECONCILE_CBOR_LIMITS, "reconcile hint canonical")?;
      let ranges = ranges_from_wire(wire.ranges)?;
      let rows = rows_from_wire(wire.rows)?;
      Ok(Message::Hint {
        lane: lane_from(wire.lane)?,
        ranges,
        rows,
      })
    }
    KIND_OFFER => {
      let wire: OfferWire =
        decode_canonical_strict(bytes, RECONCILE_CBOR_LIMITS, "reconcile offer canonical")?;
      let ranges = ranges_from_wire(wire.ranges)?;
      Ok(Message::Offer {
        lane: lane_from(wire.lane)?,
        ranges,
      })
    }
    KIND_NEED => {
      let wire: NeedWire =
        decode_canonical_strict(bytes, RECONCILE_CBOR_LIMITS, "reconcile need canonical")?;
      let bounds = bounds_from_wire(wire.bounds)?;
      Ok(Message::Need {
        lane: lane_from(wire.lane)?,
        bounds,
      })
    }
    KIND_ROWS => {
      let wire: RowsWire =
        decode_canonical_strict(bytes, RECONCILE_CBOR_LIMITS, "reconcile rows canonical")?;
      if wire.rows.len() > MAX_ROWS_PER_MESSAGE {
        return Err(Error::invalid_input("reconcile rows bound"));
      }
      Ok(Message::Rows {
        lane: lane_from(wire.lane)?,
        rows: wire
          .rows
          .into_iter()
          .map(|row| Row {
            key: row.key.to_vec(),
            content: row.content.to_vec(),
          })
          .collect(),
      })
    }
    KIND_DONE => {
      let wire: DoneWire =
        decode_canonical_strict(bytes, RECONCILE_CBOR_LIMITS, "reconcile done canonical")?;
      Ok(Message::Done {
        lane: lane_from(wire.lane)?,
        round_token: wire.round_token,
      })
    }
    _ => Err(Error::invalid_input("reconcile message kind")),
  }
}

/// Reads the leading kind integer without consuming validation: the
/// subsequent strict decode of the dispatched shape re-validates every
/// byte, so the probe only routes.
fn probe_kind(bytes: &[u8]) -> Result<u8> {
  let mut decoder = Decoder::new(bytes);
  let _arity = decoder
    .array()
    .map_err(|_| Error::invalid_input("reconcile message array"))?
    .ok_or_else(|| Error::invalid_input("reconcile indefinite array"))?;
  let kind = decoder
    .u64()
    .map_err(|_| Error::invalid_input("reconcile message kind"))?;
  u8::try_from(kind).map_err(|_| Error::invalid_input("reconcile message kind"))
}

/// Resolves a wire lane code; unknown codes fail closed.
fn lane_from(code: u8) -> Result<LaneId> {
  LaneId::from_code(code).ok_or_else(|| Error::invalid_input("reconcile lane"))
}

/// Validates range entries and converts them to the wire shape.
fn ranges_to_wire(ranges: &[RangeFingerprint]) -> Result<Vec<RangeWire>> {
  check_ranges(ranges)?;
  let mut wire = Vec::with_capacity(ranges.len());
  for range in ranges {
    wire.push(RangeWire {
      start: range.start,
      end: range.end,
      count: range.count,
      xor: range.xor,
    });
  }
  Ok(wire)
}

/// Validates bound entries and converts them to the wire shape.
fn bounds_to_wire(bounds: &[DigestRange]) -> Result<Vec<BoundWire>> {
  check_bounds(bounds)?;
  let mut wire = Vec::with_capacity(bounds.len());
  for bound in bounds {
    wire.push(BoundWire {
      start: bound.start,
      end: bound.end,
    });
  }
  Ok(wire)
}

/// Validates row entries (the ROWS and eager-HINT policy: at most
/// [`MAX_ROWS_PER_MESSAGE`]) and converts them to the wire shape.
fn rows_to_wire(rows: &[Row]) -> Result<Vec<RowWire>> {
  if rows.len() > MAX_ROWS_PER_MESSAGE {
    return Err(Error::invalid_input("reconcile rows bound"));
  }
  Ok(
    rows
      .iter()
      .map(|row| RowWire {
        key: ByteVec::from(row.key.clone()),
        content: ByteVec::from(row.content.clone()),
      })
      .collect(),
  )
}

/// Validates row entries and converts them from the wire shape.
fn rows_from_wire(wire: Vec<RowWire>) -> Result<Vec<Row>> {
  if wire.len() > MAX_ROWS_PER_MESSAGE {
    return Err(Error::invalid_input("reconcile rows bound"));
  }
  Ok(
    wire
      .into_iter()
      .map(|row| Row {
        key: row.key.to_vec(),
        content: row.content.to_vec(),
      })
      .collect(),
  )
}

/// Validates range entries and converts them from the wire shape.
fn ranges_from_wire(wire: Vec<RangeWire>) -> Result<Vec<RangeFingerprint>> {
  let ranges: Vec<RangeFingerprint> = wire
    .into_iter()
    .map(|range| RangeFingerprint {
      start: range.start,
      end: range.end,
      count: range.count,
      xor: range.xor,
    })
    .collect();
  check_ranges(&ranges)?;
  Ok(ranges)
}

/// Validates bound entries and converts them from the wire shape.
fn bounds_from_wire(wire: Vec<BoundWire>) -> Result<Vec<DigestRange>> {
  let bounds: Vec<DigestRange> = wire
    .into_iter()
    .map(|bound| DigestRange {
      start: bound.start,
      end: bound.end,
    })
    .collect();
  check_bounds(&bounds)?;
  Ok(bounds)
}

/// The shared range-entry policy: at most [`MAX_RANGES_PER_MESSAGE`]
/// entries, none inverted.
fn check_ranges(ranges: &[RangeFingerprint]) -> Result<()> {
  if ranges.len() > MAX_RANGES_PER_MESSAGE {
    return Err(Error::invalid_input("reconcile ranges bound"));
  }
  if ranges.iter().any(|range| range.start > range.end) {
    return Err(Error::invalid_input("reconcile range order"));
  }
  Ok(())
}

/// The shared bound-entry policy: at most [`MAX_RANGES_PER_MESSAGE`]
/// entries, none inverted.
fn check_bounds(bounds: &[DigestRange]) -> Result<()> {
  if bounds.len() > MAX_RANGES_PER_MESSAGE {
    return Err(Error::invalid_input("reconcile bounds bound"));
  }
  if bounds.iter().any(|bound| bound.start > bound.end) {
    return Err(Error::invalid_input("reconcile range order"));
  }
  Ok(())
}

/// The exact encoded length of one ROWS message carrying the single
/// row `(key_len, content_len)`: five fixed header bytes (the message
/// array, kind, lane, one-entry rows array, the row array) plus the
/// two byte-string headers.
fn single_row_message_len(key_len: usize, content_len: usize) -> usize {
  5 + bstr_header_len(key_len) + key_len + bstr_header_len(content_len) + content_len
}

/// The canonical CBOR byte-string header length for a payload of
/// `len` bytes (shortest-argument form).
fn bstr_header_len(len: usize) -> usize {
  if len < 24 {
    1
  } else if len < 0x100 {
    2
  } else if len < 0x1_0000 {
    3
  } else if len < 0x1_0000_0000 {
    5
  } else {
    9
  }
}

/// The plane's row-size contract: one row must independently fit one
/// ROWS message body inside the wire envelope ([`MAX_BODY_BYTES`]).
/// This is the tightest row-size constraint there is — the digest
/// preimage and every piggybacked framing of the same row are strictly
/// smaller — so the engine enforces exactly this at the local-write
/// boundary: a row that cannot ride one ROWS message alone can never
/// cross a session.
pub(crate) fn row_fits_message(key_len: usize, content_len: usize) -> bool {
  single_row_message_len(key_len, content_len) <= MAX_BODY_BYTES
}

#[cfg(test)]
mod tests {
  use super::{
    DigestRange, KIND_DONE, KIND_HINT, KIND_NEED, KIND_OFFER, KIND_ROOT, KIND_ROWS, LaneId,
    MAX_RANGES_PER_MESSAGE, MAX_ROWS_PER_MESSAGE, Message, RangeFingerprint, Row, decode, encode,
  };
  use crate::{ErrorKind, protocol::encode_canonical};

  fn root_message() -> Message {
    Message::Root {
      lane: LaneId::Descriptors,
      count: 0x11,
      xor: 0x2233,
    }
  }

  fn hint_message() -> Message {
    Message::Hint {
      lane: LaneId::Trust,
      ranges: vec![
        RangeFingerprint {
          start: 0,
          end: 0xFF,
          count: 1,
          xor: 0xAABB,
        },
        RangeFingerprint {
          start: 0x1_0000,
          end: u64::MAX,
          count: 2,
          xor: 0x0123_4567_89AB_CDEF,
        },
      ],
      rows: vec![Row {
        key: b"delta".to_vec(),
        content: b"row".to_vec(),
      }],
    }
  }

  fn offer_message() -> Message {
    Message::Offer {
      lane: LaneId::Resources,
      ranges: vec![RangeFingerprint {
        start: 0x1000,
        end: 0x2000,
        count: 5,
        xor: 0xDEAD_BEEF,
      }],
    }
  }

  fn need_message() -> Message {
    Message::Need {
      lane: LaneId::Tombstones,
      bounds: vec![DigestRange {
        start: 0,
        end: 0xFF,
      }],
    }
  }

  fn rows_message() -> Message {
    Message::Rows {
      lane: LaneId::Descriptors,
      rows: vec![Row {
        key: b"alpha".to_vec(),
        content: b"beta".to_vec(),
      }],
    }
  }

  fn done_message() -> Message {
    Message::Done {
      lane: LaneId::Trust,
      round_token: 0x0102_0304_0506_0708,
    }
  }

  /// The frozen golden vector table: one exact canonical byte string per
  /// message kind, computed by hand from the CBOR core-deterministic
  /// rules (definite lengths, shortest integer arguments). Any encoder
  /// change fails here.
  type GoldenVector = (&'static [u8], fn() -> Message);
  const GOLDEN: [GoldenVector; 6] = [
    (
      &[0x84, KIND_ROOT, 0x01, 0x11, 0x19, 0x22, 0x33],
      root_message,
    ),
    (
      &[
        0x84, KIND_HINT, 0x02, 0x82, 0x84, 0x00, 0x18, 0xFF, 0x01, 0x19, 0xAA, 0xBB, 0x84, 0x1A,
        0x00, 0x01, 0x00, 0x00, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x1B,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x81, 0x82, 0x45, 0x64, 0x65, 0x6C, 0x74,
        0x61, 0x43, 0x72, 0x6F, 0x77,
      ],
      hint_message,
    ),
    (
      &[
        0x83, KIND_OFFER, 0x03, 0x81, 0x84, 0x19, 0x10, 0x00, 0x19, 0x20, 0x00, 0x05, 0x1A, 0xDE,
        0xAD, 0xBE, 0xEF,
      ],
      offer_message,
    ),
    (
      &[0x83, KIND_NEED, 0x04, 0x81, 0x82, 0x00, 0x18, 0xFF],
      need_message,
    ),
    (
      &[
        0x83, KIND_ROWS, 0x01, 0x81, 0x82, 0x45, 0x61, 0x6C, 0x70, 0x68, 0x61, 0x44, 0x62, 0x65,
        0x74, 0x61,
      ],
      rows_message,
    ),
    (
      &[
        0x83, KIND_DONE, 0x02, 0x1B, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      ],
      done_message,
    ),
  ];

  /// Golden vectors pin every message shape: encode reproduces the exact
  /// bytes, decode reproduces the exact message, and the decoded message
  /// re-encodes byte-identically (the canonical round trip).
  #[test]
  fn reconcile_wire_golden_vectors_pin_every_message_shape() {
    for (bytes, message) in GOLDEN {
      let message = message();
      let encoded = encode(&message).unwrap();
      assert_eq!(&encoded, bytes, "encode {message:?}");
      let decoded = decode(bytes).unwrap();
      assert_eq!(decoded, message, "decode {bytes:02X?}");
      assert_eq!(encode(&decoded).unwrap(), encoded, "re-encode");
    }
  }

  /// The lane registry is closed and bijective on its codes.
  #[test]
  fn reconcile_wire_lane_registry_is_closed() {
    let codes: Vec<u8> = LaneId::ALL.iter().map(|lane| lane.code()).collect();
    for (index, lane) in LaneId::ALL.into_iter().enumerate() {
      assert_eq!(LaneId::from_code(lane.code()), Some(lane));
      assert!(
        LaneId::ALL[..index]
          .iter()
          .all(|other| other.code() != lane.code()),
        "duplicate lane code: {lane:?}"
      );
    }
    for unknown in [0, 5, 42, 255] {
      assert_eq!(LaneId::from_code(unknown), None);
    }
    assert_eq!(codes.len(), 4);
  }

  /// Unknown message kinds fail closed with a typed error, whatever
  /// follows them.
  #[test]
  fn reconcile_wire_rejects_unknown_message_kinds() {
    for kind in [0u8, 7, 42, 255] {
      let bytes = [0x84, kind, 0x01, 0x00, 0x00];
      let error = decode(&bytes).unwrap_err();
      assert_eq!(error.kind(), ErrorKind::InvalidInput, "kind {kind}");
    }
    // A body that is not an array at all fails the same way.
    let error = decode(&[0x01]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  /// Padded, truncated, and non-shortest-integer bodies fail closed:
  /// only the one canonical encoding decodes.
  #[test]
  fn reconcile_wire_rejects_noncanonical_encodings() {
    let bytes = encode(&root_message()).unwrap();

    let mut padded = bytes.clone();
    padded.push(0x00);
    assert_eq!(decode(&padded).unwrap_err().kind(), ErrorKind::InvalidInput);

    let mut truncated = bytes.clone();
    truncated.pop();
    assert_eq!(
      decode(&truncated).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );

    // `17` encoded as a one-byte argument (0x18 0x11) is structurally
    // valid CBOR but not the shortest form, so it is non-canonical.
    let non_shortest = [0x84, KIND_ROOT, 0x01, 0x18, 0x11, 0x19, 0x22, 0x33];
    assert_eq!(
      decode(&non_shortest).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );

    // A map body is not any reconcile message.
    let map_body = [0xA1, 0x01, 0x02];
    assert_eq!(
      decode(&map_body).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
  }

  /// Wrong arity fails closed in both directions: a shorter array starves
  /// the shape's decode, a longer one leaves trailing data.
  #[test]
  fn reconcile_wire_rejects_wrong_arity() {
    let bytes = encode(&done_message()).unwrap();
    let mut short = bytes.clone();
    short[0] = 0x82;
    short.truncate(bytes.len() - 1);
    assert_eq!(decode(&short).unwrap_err().kind(), ErrorKind::InvalidInput);

    let mut long = bytes.clone();
    long.push(0x00);
    assert_eq!(decode(&long).unwrap_err().kind(), ErrorKind::InvalidInput);
  }

  /// Over-bound lists fail closed on decode (hand-encoded canonical
  /// bodies that bypass the encoder's own checks) and on encode.
  #[test]
  fn reconcile_wire_rejects_over_bound_shapes() {
    let over: Vec<RangeFingerprint> = (0..=MAX_RANGES_PER_MESSAGE as u64)
      .map(|index| RangeFingerprint {
        start: index,
        end: index,
        count: 0,
        xor: 0,
      })
      .collect();
    let hand_encoded = {
      use super::{HintWire, RangeWire};
      let ranges = over
        .iter()
        .map(|range| RangeWire {
          start: range.start,
          end: range.end,
          count: range.count,
          xor: range.xor,
        })
        .collect();
      encode_canonical(
        &HintWire {
          kind: KIND_HINT,
          lane: LaneId::Descriptors.code(),
          ranges,
          rows: Vec::new(),
        },
        super::RECONCILE_CBOR_LIMITS,
      )
      .unwrap()
    };
    assert_eq!(
      decode(&hand_encoded).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      encode(&Message::Hint {
        lane: LaneId::Descriptors,
        ranges: over.clone(),
        rows: Vec::new(),
      })
      .unwrap_err()
      .kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      encode(&Message::Offer {
        lane: LaneId::Descriptors,
        ranges: over,
      })
      .unwrap_err()
      .kind(),
      ErrorKind::InvalidInput
    );

    let rows: Vec<Row> = (0..=MAX_ROWS_PER_MESSAGE)
      .map(|index| Row {
        key: index.to_be_bytes().to_vec(),
        content: Vec::new(),
      })
      .collect();
    assert_eq!(
      encode(&Message::Rows {
        lane: LaneId::Descriptors,
        rows,
      })
      .unwrap_err()
      .kind(),
      ErrorKind::InvalidInput
    );

    // The decode side of the same bound: a hand-encoded canonical body
    // (bypassing the encoder's own shape checks) with 65 rows fails
    // closed too.
    let hand_encoded_rows = {
      use minicbor::bytes::ByteVec;

      use super::{RowWire, RowsWire};
      let rows = (0..=MAX_ROWS_PER_MESSAGE)
        .map(|index| RowWire {
          key: ByteVec::from(index.to_be_bytes().to_vec()),
          content: ByteVec::from(Vec::new()),
        })
        .collect();
      encode_canonical(
        &RowsWire {
          kind: KIND_ROWS,
          lane: LaneId::Descriptors.code(),
          rows,
        },
        super::RECONCILE_CBOR_LIMITS,
      )
      .unwrap()
    };
    assert_eq!(
      decode(&hand_encoded_rows).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
  }

  /// The row-size contract is exact to the byte: `row_fits_message`
  /// agrees with the actual encoder at the envelope boundary (a row
  /// that fits is a single-row ROWS body of exactly
  /// [`super::MAX_BODY_BYTES`] bytes; one byte more fails the encode).
  #[test]
  fn reconcile_wire_row_size_contract_matches_the_encoder_at_the_boundary() {
    use super::{MAX_BODY_BYTES, row_fits_message};
    // 23-byte key (1-byte header) + content below 64 KiB (3-byte
    // header): the fit boundary is content = 65_504.
    let key = vec![0x41u8; 23];
    let fitting = vec![0x42u8; 65_504];
    let one_over = vec![0x43u8; 65_505];
    assert!(row_fits_message(key.len(), fitting.len()));
    assert!(!row_fits_message(key.len(), one_over.len()));
    let message = Message::Rows {
      lane: LaneId::Descriptors,
      rows: vec![Row {
        key: key.clone(),
        content: fitting,
      }],
    };
    let bytes = encode(&message).unwrap();
    assert_eq!(bytes.len(), MAX_BODY_BYTES);
    let error = encode(&Message::Rows {
      lane: LaneId::Descriptors,
      rows: vec![Row {
        key,
        content: one_over,
      }],
    })
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    // Header-size classes shift the boundary exactly as the arithmetic
    // says: a 24-byte key needs one header byte more, so the largest
    // fitting content shrinks by two (one for the key byte, one for the
    // header byte).
    let key24 = vec![0x41u8; 24];
    let fitting24 = vec![0x42u8; 65_502];
    let one_over24 = vec![0x43u8; 65_503];
    assert!(row_fits_message(key24.len(), fitting24.len()));
    assert!(!row_fits_message(key24.len(), one_over24.len()));
    let bytes = encode(&Message::Rows {
      lane: LaneId::Descriptors,
      rows: vec![Row {
        key: key24.clone(),
        content: fitting24,
      }],
    })
    .unwrap();
    assert_eq!(bytes.len(), MAX_BODY_BYTES);
    assert!(
      encode(&Message::Rows {
        lane: LaneId::Descriptors,
        rows: vec![Row {
          key: key24,
          content: one_over24
        }],
      })
      .is_err()
    );
  }

  /// Inverted ranges and unknown lane codes fail closed even when the
  /// body itself is canonical.
  #[test]
  fn reconcile_wire_rejects_inverted_ranges_and_unknown_lanes() {
    let inverted = Message::Need {
      lane: LaneId::Descriptors,
      bounds: vec![DigestRange { start: 5, end: 4 }],
    };
    assert_eq!(
      encode(&inverted).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );

    let hand_encoded = {
      use super::{BoundWire, NeedWire};
      encode_canonical(
        &NeedWire {
          kind: KIND_NEED,
          lane: LaneId::Descriptors.code(),
          bounds: vec![BoundWire { start: 5, end: 4 }],
        },
        super::RECONCILE_CBOR_LIMITS,
      )
      .unwrap()
    };
    assert_eq!(
      decode(&hand_encoded).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );

    let unknown_lane = {
      use super::RootWire;
      encode_canonical(
        &RootWire {
          kind: KIND_ROOT,
          lane: 9,
          count: 0,
          xor: 0,
        },
        super::RECONCILE_CBOR_LIMITS,
      )
      .unwrap()
    };
    assert_eq!(
      decode(&unknown_lane).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
  }

  /// Empty lists are valid no-op shapes: idempotent replay and NEED
  /// answers with nothing to send still round-trip.
  #[test]
  fn reconcile_wire_round_trips_empty_lists() {
    for message in [
      Message::Hint {
        lane: LaneId::Trust,
        ranges: Vec::new(),
        rows: Vec::new(),
      },
      Message::Offer {
        lane: LaneId::Trust,
        ranges: Vec::new(),
      },
      Message::Need {
        lane: LaneId::Trust,
        bounds: Vec::new(),
      },
      Message::Rows {
        lane: LaneId::Trust,
        rows: Vec::new(),
      },
    ] {
      let bytes = encode(&message).unwrap();
      assert_eq!(decode(&bytes).unwrap(), message);
    }
  }

  /// The eager-delta piggyback fails closed past the row bound on both
  /// directions, exactly like a ROWS message.
  #[test]
  fn reconcile_wire_rejects_over_bound_hint_rows() {
    let rows: Vec<Row> = (0..=MAX_ROWS_PER_MESSAGE)
      .map(|index| Row {
        key: index.to_be_bytes().to_vec(),
        content: Vec::new(),
      })
      .collect();
    assert_eq!(
      encode(&Message::Hint {
        lane: LaneId::Descriptors,
        ranges: Vec::new(),
        rows: rows.clone(),
      })
      .unwrap_err()
      .kind(),
      ErrorKind::InvalidInput
    );
    let hand_encoded = {
      use super::{HintWire, RowWire};
      encode_canonical(
        &HintWire {
          kind: KIND_HINT,
          lane: LaneId::Descriptors.code(),
          ranges: Vec::new(),
          rows: rows
            .into_iter()
            .map(|row| RowWire {
              key: minicbor::bytes::ByteVec::from(row.key),
              content: minicbor::bytes::ByteVec::from(row.content),
            })
            .collect(),
        },
        super::RECONCILE_CBOR_LIMITS,
      )
      .unwrap()
    };
    assert_eq!(
      decode(&hand_encoded).unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
  }
}
