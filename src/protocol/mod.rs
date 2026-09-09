pub(crate) mod cbor;
pub(crate) mod credential;
pub(crate) mod envelope;
pub(crate) mod feature;
pub(crate) mod handshake;
pub(crate) mod offer;
pub(crate) mod selection;
pub(crate) mod tag;
pub(crate) mod wire;

/// The handshake/control body ceiling: one wire body never exceeds
/// it, and every derived limit (parser defaults, aggregate WebSocket
/// messages) derives from this constant instead of restating the number.
pub(crate) const ADR0002_BODY_BYTES: usize = 65_536;

/// The control-plane CBOR budget shared by every authenticated-phase body:
/// handshake messages, feature offers and selections, trust snapshots,
/// membership pages, and packet frames all live inside one wire-body
/// envelope, so one limit constant covers them all. It lives at the
/// protocol root — not under `offer` — because it bounds the whole
/// control plane, not just feature offers.
pub(crate) const CONTROL_CBOR_LIMITS: CborLimits = CborLimits::new(16, 1_024, ADR0002_BODY_BYTES);

pub(crate) use cbor::{
  CborLimits, StrictDecodeFailure, decode_canonical, decode_canonical_strict,
  decode_canonical_strict_or, encode_canonical, validate_canonical,
};
pub(crate) use envelope::{PRELUDE_LEN, Prelude, check_frame, split_message};
pub use feature::FeatureDefinition;
pub use tag::{DiscoveryTag, FeatureTag, ProtocolTag, QualifiedTag, TransportTag};
