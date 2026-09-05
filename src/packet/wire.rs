//! Packet-stream wire frames under base schema `0x0001` (ADR-0002,
//! ADR-0007).
//!
//! Four deterministic-CBOR bodies ride the closed kind registry's packet
//! kinds (`0x0010..=0x0013`): open carries the trace ID, both
//! session-authenticated endpoints, the protocol tag, and the bounded
//! canonical metadata map; chunk carries an ordered sequence number and up
//! to [`MAX_CHUNK_BYTES`] payload bytes; end terminates a stream; ack
//! reports current-process admission or a typed rejection. Every decoder
//! re-encodes and byte-compares so noncanonical encodings fail closed.

use std::sync::Arc;

use minicbor::{Decode, Encode, bytes::ByteVec};

use super::{MAX_CHUNK_BYTES, StreamMetadata};
use crate::{
  Error, ErrorKind, NodeId, ProtocolTag, Result, TraceId,
  protocol::{
    CONTROL_CBOR_LIMITS, CborLimits, decode_canonical, decode_canonical_strict, encode_canonical,
  },
  routing::HopState,
};

/// Packet frames share the authentication phase's frame budget: one frame
/// never exceeds the 64 KiB handshake control limit.
const PACKET_CBOR_LIMITS: CborLimits = CONTROL_CBOR_LIMITS;

/// The wire admission outcome of one open frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckStatus {
  /// Admitted to the destination's bounded incoming stream.
  Admitted,
  /// Rejected before admission: protocol tag or owning feature unknown.
  Unsupported,
  /// Rejected before admission: the bounded incoming queue is saturated.
  Overloaded,
  /// A hop along the route failed after the open was relayed (session
  /// interruption); no admission claim is made either way. Additive code;
  /// older peers fail closed on it (mixed-binary compat is T-G10-02).
  Failed,
}

impl AckStatus {
  /// The single source of truth for `ErrorKind` → wire status: a relayed
  /// rejection keeps its precise kind while any other failure collapses to
  /// the additive generic-failure code (mixed-binary compat is T-G10-02).
  pub(crate) fn from_kind(kind: ErrorKind) -> Self {
    match kind {
      ErrorKind::Unsupported => Self::Unsupported,
      ErrorKind::Overloaded => Self::Overloaded,
      _ => Self::Failed,
    }
  }

  /// The inverse of [`AckStatus::from_kind`]: the typed failure the origin
  /// observes for a rejected or interrupted open. `Admitted` is success and
  /// carries no kind.
  pub(crate) fn to_kind(self) -> Option<ErrorKind> {
    match self {
      Self::Admitted => None,
      Self::Unsupported => Some(ErrorKind::Unsupported),
      Self::Overloaded => Some(ErrorKind::Overloaded),
      Self::Failed => Some(ErrorKind::StreamInterrupted),
    }
  }

  const fn code(self) -> u8 {
    match self {
      Self::Admitted => 0,
      Self::Unsupported => 1,
      Self::Overloaded => 2,
      Self::Failed => 3,
    }
  }

  fn from_code(code: u8) -> Option<Self> {
    match code {
      0 => Some(Self::Admitted),
      1 => Some(Self::Unsupported),
      2 => Some(Self::Overloaded),
      3 => Some(Self::Failed),
      _ => None,
    }
  }
}

/// A decoded packet-open frame.
#[derive(Clone, Debug)]
pub(crate) struct OpenFrame {
  pub(crate) trace_id: TraceId,
  pub(crate) source: NodeId,
  pub(crate) destination: NodeId,
  pub(crate) protocol: ProtocolTag,
  pub(crate) metadata: StreamMetadata,
  /// The per-hop route envelope. `None` is the previous fixture shape: a
  /// direct delivery where the authenticated source sent the frame
  /// straight to this node (T-G06-01).
  pub(crate) route: Option<HopState>,
}

/// A decoded packet-ack frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AckFrame {
  pub(crate) trace_id: TraceId,
  pub(crate) status: AckStatus,
  /// Milliseconds since the Unix epoch at the destination's admission.
  pub(crate) admitted_at_millis: u64,
}

/// A decoded packet-chunk frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkFrame {
  pub(crate) trace_id: TraceId,
  pub(crate) sequence: u64,
  pub(crate) bytes: ByteVec,
}

/// A decoded packet-end frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EndFrame {
  pub(crate) trace_id: TraceId,
}

/// The wire-carried per-hop route state of one routed open frame
/// (canonical, bounded): the current upstream holder, the visited chain,
/// and the remaining caller-selected hop budget. Identity fields (trace,
/// source, destination) ride the frame itself and are not duplicated.
#[derive(Encode, Decode)]
#[cbor(array)]
struct RouteWire {
  #[n(0)]
  current: String,
  #[n(1)]
  visited: Vec<String>,
  #[n(2)]
  remaining_hops: u32,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct OpenWire {
  #[n(0)]
  trace_id: String,
  #[n(1)]
  source: String,
  #[n(2)]
  destination: String,
  #[n(3)]
  protocol: String,
  /// Canonical metadata: key/value pairs sorted by key text, unique keys.
  #[n(4)]
  metadata: Vec<(String, ByteVec)>,
  /// Present only on routed frames; direct frames end at `metadata`
  /// (the previous fixture shape decodes without it).
  #[n(5)]
  route: Option<RouteWire>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct OpenWireV1 {
  #[n(0)]
  trace_id: String,
  #[n(1)]
  source: String,
  #[n(2)]
  destination: String,
  #[n(3)]
  protocol: String,
  #[n(4)]
  metadata: Vec<(String, ByteVec)>,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct ChunkWire {
  #[n(0)]
  trace_id: String,
  #[n(1)]
  sequence: u64,
  #[n(2)]
  bytes: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct EndWire {
  #[n(0)]
  trace_id: String,
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct AckWire {
  #[n(0)]
  trace_id: String,
  #[n(1)]
  outcome: u8,
  #[n(2)]
  admitted_at_millis: u64,
}

/// Encodes one packet-open frame body.
pub(crate) fn encode_open(frame: &OpenFrame) -> Result<Vec<u8>> {
  let metadata = frame
    .metadata
    .entries()
    .map(|(key, value)| (key.as_str().to_owned(), ByteVec::from(value.to_vec())))
    .collect();
  let route = frame.route.as_ref().map(|route| RouteWire {
    current: route.current.to_string(),
    visited: route.visited.iter().map(NodeId::to_string).collect(),
    remaining_hops: route.remaining_hops,
  });
  encode_canonical(
    &OpenWire {
      trace_id: frame.trace_id.to_string(),
      source: frame.source.to_string(),
      destination: frame.destination.to_string(),
      protocol: frame.protocol.to_string(),
      metadata,
      route,
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-open frame body, enforcing canonical encoding,
/// canonical metadata ordering, the bounded metadata map, and — for routed
/// frames — a duplicate-free visited chain. The caller-selected parser
/// limits bound every decode allocation (G3's checked finite limits).
pub(crate) fn decode_open(body: &[u8], limits: CborLimits) -> Result<OpenFrame> {
  // The current frame shape carries the optional route element.
  if let Ok(wire) = decode_canonical::<OpenWire>(body, limits)
    && encode_canonical(&wire, PACKET_CBOR_LIMITS).is_ok_and(|encoded| encoded == body)
  {
    return open_from_wire(wire);
  }
  // The previous fixture shape ends at the metadata element.
  let wire: OpenWireV1 =
    decode_canonical(body, limits).map_err(|_| Error::invalid_input("packet open decode"))?;
  if !encode_canonical(&wire, PACKET_CBOR_LIMITS).is_ok_and(|encoded| encoded == body) {
    return Err(Error::invalid_input("packet open canonical"));
  }
  open_from_wire(OpenWire {
    trace_id: wire.trace_id,
    source: wire.source,
    destination: wire.destination,
    protocol: wire.protocol,
    metadata: wire.metadata,
    route: None,
  })
}

fn open_from_wire(wire: OpenWire) -> Result<OpenFrame> {
  if !wire.metadata.windows(2).all(|pair| pair[0].0 < pair[1].0) {
    return Err(Error::invalid_input("packet metadata order"));
  }
  let mut metadata = StreamMetadata::new();
  for (key, value) in wire.metadata {
    metadata = metadata.insert(key.parse()?, Arc::from(value.as_slice()))?;
  }
  let route = match wire.route {
    Some(route) => {
      let current = route.current.parse()?;
      let mut visited: Vec<NodeId> = Vec::with_capacity(route.visited.len());
      for node in route.visited {
        visited.push(node.parse()?);
      }
      // A duplicate-free chain fails closed at the wire boundary.
      let mut seen: std::collections::BTreeSet<NodeId> = std::collections::BTreeSet::new();
      for node in &visited {
        if !seen.insert(node.clone()) {
          return Err(Error::invalid_input("packet route chain"));
        }
      }
      Some(HopState {
        current,
        visited,
        remaining_hops: route.remaining_hops,
      })
    }
    None => None,
  };
  Ok(OpenFrame {
    trace_id: wire.trace_id.parse()?,
    source: wire.source.parse()?,
    destination: wire.destination.parse()?,
    protocol: wire.protocol.parse()?,
    metadata,
    route,
  })
}

/// Encodes one packet-chunk frame body. Chunks above the streaming quantum
/// are rejected before encoding.
pub(crate) fn encode_chunk(frame: &ChunkFrame) -> Result<Vec<u8>> {
  if frame.bytes.len() > MAX_CHUNK_BYTES {
    return Err(Error::invalid_input("packet chunk"));
  }
  encode_canonical(
    &ChunkWire {
      trace_id: frame.trace_id.to_string(),
      sequence: frame.sequence,
      bytes: frame.bytes.clone(),
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-chunk frame body, enforcing the streaming quantum.
pub(crate) fn decode_chunk(body: &[u8], limits: CborLimits) -> Result<ChunkFrame> {
  let wire: ChunkWire = decode_canonical_strict(body, limits, "packet frame canonical")?;
  if wire.bytes.len() > MAX_CHUNK_BYTES {
    return Err(Error::invalid_input("packet chunk"));
  }
  Ok(ChunkFrame {
    trace_id: wire.trace_id.parse()?,
    sequence: wire.sequence,
    bytes: wire.bytes,
  })
}

/// Encodes one packet-end frame body.
pub(crate) fn encode_end(frame: &EndFrame) -> Result<Vec<u8>> {
  encode_canonical(
    &EndWire {
      trace_id: frame.trace_id.to_string(),
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-end frame body.
pub(crate) fn decode_end(body: &[u8], limits: CborLimits) -> Result<EndFrame> {
  let wire: EndWire = decode_canonical_strict(body, limits, "packet frame canonical")?;
  Ok(EndFrame {
    trace_id: wire.trace_id.parse()?,
  })
}

/// Encodes one packet-ack frame body.
pub(crate) fn encode_ack(frame: &AckFrame) -> Result<Vec<u8>> {
  encode_canonical(
    &AckWire {
      trace_id: frame.trace_id.to_string(),
      outcome: frame.status.code(),
      admitted_at_millis: frame.admitted_at_millis,
    },
    PACKET_CBOR_LIMITS,
  )
}

/// Decodes one packet-ack frame body. Unknown outcome codes fail closed.
pub(crate) fn decode_ack(body: &[u8], limits: CborLimits) -> Result<AckFrame> {
  let wire: AckWire = decode_canonical_strict(body, limits, "packet frame canonical")?;
  let status =
    AckStatus::from_code(wire.outcome).ok_or_else(|| Error::invalid_input("packet ack outcome"))?;
  Ok(AckFrame {
    trace_id: wire.trace_id.parse()?,
    status,
    admitted_at_millis: wire.admitted_at_millis,
  })
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use minicbor::bytes::ByteVec;

  use super::{
    AckFrame, AckStatus, ChunkFrame, EndFrame, MAX_CHUNK_BYTES, OpenFrame, PACKET_CBOR_LIMITS,
    decode_ack, decode_chunk, decode_end, decode_open, encode_ack, encode_chunk, encode_end,
    encode_open,
  };
  use crate::{
    ErrorKind, NodeId, ProtocolTag, StreamMetadata, TraceId,
    protocol::{CONTROL_CBOR_LIMITS, encode_canonical},
  };

  fn ids() -> (TraceId, NodeId, NodeId) {
    (
      TraceId::parse("trace_000000000000000000001").unwrap(),
      NodeId::parse("node_000000000000000000001").unwrap(),
      NodeId::parse("node_000000000000000000002").unwrap(),
    )
  }

  fn open_frame() -> OpenFrame {
    let (trace_id, source, destination) = ids();
    let metadata = StreamMetadata::new()
      .insert(
        "radiata.woooo.tech/labels/alpha".parse().unwrap(),
        Arc::from(&b"one"[..]),
      )
      .unwrap()
      .insert(
        "radiata.woooo.tech/labels/beta".parse().unwrap(),
        Arc::from(&b"two"[..]),
      )
      .unwrap();
    OpenFrame {
      trace_id,
      source,
      destination,
      protocol: ProtocolTag::parse("radiata.woooo.tech/protocols/test-packets").unwrap(),
      metadata,
      route: None,
    }
  }

  #[test]
  fn tls_transport_packet_open_frame_round_trips_canonically() {
    let frame = open_frame();
    let body = encode_open(&frame).unwrap();
    let decoded = decode_open(&body, PACKET_CBOR_LIMITS).unwrap();
    assert_eq!(decoded.trace_id, frame.trace_id);
    assert_eq!(decoded.source, frame.source);
    assert_eq!(decoded.destination, frame.destination);
    assert_eq!(decoded.protocol, frame.protocol);
    assert_eq!(decoded.metadata, frame.metadata);
    assert_eq!(encode_open(&decoded).unwrap(), body);
  }

  #[test]
  fn tls_transport_packet_open_frame_rejects_unordered_metadata() {
    let (trace_id, source, destination) = ids();
    let wire = super::OpenWire {
      trace_id: trace_id.to_string(),
      source: source.to_string(),
      destination: destination.to_string(),
      protocol: "radiata.woooo.tech/protocols/test-packets".to_owned(),
      metadata: vec![
        (
          "radiata.woooo.tech/labels/zeta".to_owned(),
          ByteVec::from(b"1".to_vec()),
        ),
        (
          "radiata.woooo.tech/labels/alpha".to_owned(),
          ByteVec::from(b"2".to_vec()),
        ),
      ],
      route: None,
    };
    let body = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    let error = decode_open(&body, PACKET_CBOR_LIMITS).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  /// A routed frame whose route chain contains a duplicate node fails

  #[test]
  fn tls_transport_packet_open_frame_rejects_noncanonical_padding() {
    let body = encode_open(&open_frame()).unwrap();
    let mut padded = body.clone();
    padded.push(0);
    assert!(decode_open(&padded, PACKET_CBOR_LIMITS).is_err());
    let mut truncated = body;
    truncated.pop();
    assert!(decode_open(&truncated, PACKET_CBOR_LIMITS).is_err());
  }

  #[test]
  fn tls_transport_packet_chunk_frame_round_trips_and_enforces_quantum() {
    let (trace_id, ..) = ids();
    let frame = ChunkFrame {
      trace_id: trace_id.clone(),
      sequence: 7,
      bytes: ByteVec::from(vec![0xAB; 1_024]),
    };
    let body = encode_chunk(&frame).unwrap();
    let decoded = decode_chunk(&body, PACKET_CBOR_LIMITS).unwrap();
    assert_eq!(decoded, frame);

    let oversize = ChunkFrame {
      trace_id: trace_id.clone(),
      sequence: 8,
      bytes: ByteVec::from(vec![0xAB; MAX_CHUNK_BYTES + 1]),
    };
    let error = encode_chunk(&oversize).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    // A hand-encoded oversize chunk (bypassing the encoder) is rejected at
    // decode as well.
    let wire = super::ChunkWire {
      trace_id: trace_id.to_string(),
      sequence: 9,
      bytes: ByteVec::from(vec![0xAB; MAX_CHUNK_BYTES + 1]),
    };
    let body = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    let error = decode_chunk(&body, PACKET_CBOR_LIMITS).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn tls_transport_packet_end_and_ack_frames_round_trip() {
    let (trace_id, ..) = ids();
    let end = EndFrame {
      trace_id: trace_id.clone(),
    };
    let decoded = decode_end(&encode_end(&end).unwrap(), PACKET_CBOR_LIMITS).unwrap();
    assert_eq!(decoded, end);

    for status in [
      AckStatus::Admitted,
      AckStatus::Unsupported,
      AckStatus::Overloaded,
    ] {
      let ack = AckFrame {
        trace_id: trace_id.clone(),
        status,
        admitted_at_millis: 1_700_000_000_000,
      };
      let decoded = decode_ack(&encode_ack(&ack).unwrap(), PACKET_CBOR_LIMITS).unwrap();
      assert_eq!(decoded, ack);
    }
  }

  #[test]
  fn tls_transport_packet_ack_rejects_unknown_outcome() {
    let (trace_id, ..) = ids();
    let wire = super::AckWire {
      trace_id: trace_id.to_string(),
      outcome: 9,
      admitted_at_millis: 0,
    };
    let body = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    let error = decode_ack(&body, PACKET_CBOR_LIMITS).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn tls_transport_packet_frames_reject_malformed_ids() {
    let wire = super::EndWire {
      trace_id: "trace_NOT-CANONICAL".to_owned(),
    };
    let body = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    let error = decode_end(&body, PACKET_CBOR_LIMITS).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    let wire = super::OpenWire {
      trace_id: "trace_000000000000000000001".to_owned(),
      source: "node_000000000000000000001".to_owned(),
      destination: "node_000000000000000000002".to_owned(),
      protocol: "radiata.woooo.tech/features/not-a-protocol".to_owned(),
      metadata: Vec::new(),
      route: None,
    };
    let body = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    let error = decode_open(&body, PACKET_CBOR_LIMITS).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
  }

  #[test]
  fn tls_transport_decode_checked_rejects_wrong_type() {
    // A chunk body is not a valid end frame even though both are arrays.
    let (trace_id, ..) = ids();
    let chunk = ChunkFrame {
      trace_id,
      sequence: 0,
      bytes: ByteVec::from(b"payload".to_vec()),
    };
    let body = encode_chunk(&chunk).unwrap();
    assert!(decode_end(&body, PACKET_CBOR_LIMITS).is_err());
  }
}

#[cfg(test)]
mod route_tests {
  use std::sync::Arc;

  use minicbor::bytes::ByteVec;

  use super::{OpenFrame, OpenWireV1, PACKET_CBOR_LIMITS, RouteWire, decode_open, encode_open};
  use crate::{
    NodeId, ProtocolTag, StreamMetadata, TraceId,
    protocol::{CONTROL_CBOR_LIMITS, encode_canonical},
    routing::HopState,
  };

  fn ids() -> (TraceId, NodeId, NodeId, NodeId) {
    (
      TraceId::parse("trace_000000000000000000001").unwrap(),
      NodeId::parse("node_000000000000000000001").unwrap(),
      NodeId::parse("node_000000000000000000002").unwrap(),
      NodeId::parse("node_000000000000000000003").unwrap(),
    )
  }

  /// The current routed-frame shape round-trips canonically with its
  /// per-hop state.
  #[test]
  fn routed_open_frame_round_trips_canonically() {
    let (trace_id, source, destination, holder) = ids();
    let frame = OpenFrame {
      trace_id,
      source: source.clone(),
      destination: destination.clone(),
      protocol: ProtocolTag::parse("radiata.woooo.tech/protocols/test-packets").unwrap(),
      metadata: StreamMetadata::new(),
      route: Some(HopState {
        current: holder.clone(),
        visited: vec![source],
        remaining_hops: 3,
      }),
    };
    let body = encode_open(&frame).unwrap();
    let decoded = decode_open(&body, PACKET_CBOR_LIMITS).unwrap();
    assert_eq!(decoded.destination, destination);
    // Canonical: re-encoding reproduces the exact bytes.
    assert_eq!(encode_open(&decoded).unwrap(), body);
    let route = decoded.route.unwrap();
    assert_eq!(route.current, holder);
    assert_eq!(
      route.visited,
      vec![NodeId::parse("node_000000000000000000001").unwrap()]
    );
    assert_eq!(route.remaining_hops, 3);
  }

  /// The previous fixture shape (no route element) decodes with `None`
  /// route state — direct delivery stays wire-compatible.
  #[test]
  fn direct_open_frame_decodes_without_route_state() {
    let (trace_id, source, destination, _) = ids();
    let wire = OpenWireV1 {
      trace_id: trace_id.to_string(),
      source: source.to_string(),
      destination: destination.to_string(),
      protocol: "radiata.woooo.tech/protocols/test-packets".to_owned(),
      metadata: Vec::new(),
    };
    let body = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    let decoded = decode_open(&body, PACKET_CBOR_LIMITS).unwrap();
    assert!(decoded.route.is_none());
    assert_eq!(decoded.source, source);
    assert_eq!(decoded.destination, destination);
  }

  /// A duplicate-free chain is enforced at the wire boundary; reordered
  /// (non-canonical) label maps and padded frames fail closed.
  #[test]
  fn routed_open_frame_rejects_duplicate_chain_entries() {
    let (trace_id, source, destination, _) = ids();
    let wire = super::OpenWire {
      trace_id: trace_id.to_string(),
      source: source.to_string(),
      destination: destination.to_string(),
      protocol: "radiata.woooo.tech/protocols/test-packets".to_owned(),
      metadata: Vec::new(),
      route: Some(RouteWire {
        current: "node_000000000000000000009".to_owned(),
        visited: vec![
          "node_000000000000000000005".to_owned(),
          "node_000000000000000000005".to_owned(),
        ],
        remaining_hops: 2,
      }),
    };
    let body = encode_canonical(&wire, CONTROL_CBOR_LIMITS).unwrap();
    assert!(decode_open(&body, PACKET_CBOR_LIMITS).is_err());

    // Truncation and padding stay rejected on routed frames too.
    let frame = OpenFrame {
      trace_id,
      source,
      destination,
      protocol: ProtocolTag::parse("radiata.woooo.tech/protocols/test-packets").unwrap(),
      metadata: StreamMetadata::new()
        .insert(
          "radiata.woooo.tech/labels/alpha".parse().unwrap(),
          Arc::from(&b"v"[..]),
        )
        .unwrap(),
      route: Some(HopState {
        current: NodeId::parse("node_000000000000000000009").unwrap(),
        visited: Vec::new(),
        remaining_hops: 1,
      }),
    };
    let body = encode_open(&frame).unwrap();
    let mut truncated = body.clone();
    truncated.pop();
    assert!(decode_open(&truncated, PACKET_CBOR_LIMITS).is_err());
    let _ = ByteVec::from(Vec::<u8>::new());
  }
}
