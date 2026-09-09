use super::wire::MAGIC_BYTES as MAGIC;
use crate::{Error, Result};
pub(crate) const PRELUDE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Prelude {
  schema_id: u16,
  kind_id: u16,
  flags: u16,
  body_len: u32,
}

impl Prelude {
  pub(crate) const fn new(schema_id: u16, kind_id: u16, flags: u16, body_len: u32) -> Self {
    Self {
      schema_id,
      kind_id,
      flags,
      body_len,
    }
  }

  pub(crate) const fn schema_id(self) -> u16 {
    self.schema_id
  }

  pub(crate) const fn kind_id(self) -> u16 {
    self.kind_id
  }

  pub(crate) const fn flags(self) -> u16 {
    self.flags
  }

  pub(crate) fn encode(self) -> [u8; PRELUDE_LEN] {
    let schema = self.schema_id.to_be_bytes();
    let kind = self.kind_id.to_be_bytes();
    let flags = self.flags.to_be_bytes();
    let body_len = self.body_len.to_be_bytes();
    [
      MAGIC[0],
      MAGIC[1],
      MAGIC[2],
      MAGIC[3],
      schema[0],
      schema[1],
      kind[0],
      kind[1],
      flags[0],
      flags[1],
      0,
      0,
      body_len[0],
      body_len[1],
      body_len[2],
      body_len[3],
    ]
  }

  fn decode(bytes: &[u8]) -> Result<Self> {
    if bytes.len() < PRELUDE_LEN || bytes[..4] != MAGIC {
      return Err(Error::invalid_input("wire prelude"));
    }
    if bytes[10] != 0 || bytes[11] != 0 {
      return Err(Error::invalid_input("wire reserved bits"));
    }

    Ok(Self {
      schema_id: u16::from_be_bytes([bytes[4], bytes[5]]),
      kind_id: u16::from_be_bytes([bytes[6], bytes[7]]),
      flags: u16::from_be_bytes([bytes[8], bytes[9]]),
      body_len: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    })
  }
}

/// The declared/flags/message-limit validation shared by the encode
/// (transport `encode_frame`) and decode (`split_message`) directions, so
/// a local bug fails fast instead of emitting bytes the peer must reject.
/// The send side deliberately skips `receive_limit`: that bound protects
/// the receiving peer's body allocation, so only `split_message` applies
/// it on arrival — never the sender.
pub(crate) fn check_frame<IsDeclared>(
  prelude: Prelude, allowed_flags: u16, message_limit: u32, is_declared: IsDeclared,
) -> Result<()>
where
  IsDeclared: FnOnce(u16, u16) -> bool, {
  if !is_declared(prelude.schema_id(), prelude.kind_id())
    || prelude.flags() & !allowed_flags != 0
    || prelude.body_len > message_limit
  {
    return Err(Error::invalid_input("wire limits"));
  }
  Ok(())
}

pub(crate) fn split_message<IsDeclared>(
  message: &[u8], allowed_flags: u16, message_limit: u32, receive_limit: u32,
  is_declared: IsDeclared,
) -> Result<(Prelude, &[u8])>
where
  IsDeclared: FnOnce(u16, u16) -> bool, {
  let prelude = Prelude::decode(message)?;
  check_frame(prelude, allowed_flags, message_limit, is_declared)?;
  // The receive limit guards this side's body allocation; the send
  // direction never applies it.
  if prelude.body_len > receive_limit {
    return Err(Error::invalid_input("wire limits"));
  }

  let body_len =
    usize::try_from(prelude.body_len).map_err(|_| Error::invalid_input("wire body length"))?;
  let expected_len = PRELUDE_LEN
    .checked_add(body_len)
    .ok_or_else(|| Error::invalid_input("wire body length"))?;
  if message.len() != expected_len {
    return Err(Error::invalid_input("wire body length"));
  }

  Ok((prelude, &message[PRELUDE_LEN..]))
}

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use minicbor::{Encode, Encoder, encode::Write};
  use proptest::prelude::*;

  use super::{
    super::cbor::{CborLimits, decode_canonical, encode_canonical},
    Prelude, split_message,
  };

  const LIMITS: CborLimits = CborLimits::new(8, 16, 1_024);

  #[derive(Debug, Eq, PartialEq, minicbor::Decode, minicbor::Encode)]
  #[cbor(map)]
  struct TestBody {
    #[n(0)]
    sequence: u64,
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    payload: Vec<u8>,
  }

  struct Ignored;

  impl<'bytes, Context> minicbor::Decode<'bytes, Context> for Ignored {
    fn decode(
      decoder: &mut minicbor::Decoder<'bytes>, _context: &mut Context,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
      decoder.skip()?;
      Ok(Self)
    }
  }

  struct RepeatedBody {
    accepted_items: Cell<usize>,
  }

  impl<Context> Encode<Context> for RepeatedBody {
    fn encode<Writer: Write>(
      &self, encoder: &mut Encoder<Writer>, _context: &mut Context,
    ) -> core::result::Result<(), minicbor::encode::Error<Writer::Error>> {
      for _ in 0..100 {
        encoder.bytes(&[0; 16])?;
        self.accepted_items.set(self.accepted_items.get() + 1);
      }
      Ok(())
    }
  }

  #[test]
  fn core_prelude_uses_exact_network_order_bytes() {
    let encoded = Prelude::new(0x0001, 0x0203, 0x0004, 5).encode();

    assert_eq!(
      encoded,
      [
        b'M', b'R', b'L', b'Y', 0x00, 0x01, 0x02, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05,
      ],
    );
  }

  proptest! {
    #[test]
    fn core_prelude_round_trips_without_copying_body(
      schema in any::<u16>(),
      kind in any::<u16>(),
      flags in 0_u16..=0x000f,
      body in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
      let mut message = Vec::from(Prelude::new(schema, kind, flags, body.len() as u32).encode());
      message.extend_from_slice(&body);

      let (decoded, decoded_body) =
        split_message(&message, 0x000f, 256, 512, |declared_schema, declared_kind| {
          declared_schema == schema && declared_kind == kind
        })
        .unwrap();
      prop_assert_eq!(decoded.schema_id(), schema);
      prop_assert_eq!(decoded.kind_id(), kind);
      prop_assert_eq!(decoded.flags(), flags);
      prop_assert_eq!(decoded_body.as_ptr(), message[16..].as_ptr());
      prop_assert_eq!(decoded_body, body);
    }

    #[test]
    fn core_hostile_wire_and_cbor_bytes_never_panic(
      input in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
      let wire_result = std::panic::catch_unwind(|| {
        split_message(&input, 0, 256, 512, |schema, kind| schema == 1 && kind == 1)
      });
      let cbor_result = std::panic::catch_unwind(|| {
        decode_canonical::<Ignored>(&input, CborLimits::new(8, 16, 512))
      });

      prop_assert!(wire_result.is_ok());
      prop_assert!(cbor_result.is_ok());
    }

    #[test]
    fn core_equivalent_cbor_values_encode_identically(
      sequence in any::<u64>(),
      payload in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
      let first = TestBody { sequence, payload: payload.clone() };
      let second = TestBody { sequence, payload };

      prop_assert_eq!(encode_canonical(&first, LIMITS).unwrap(), encode_canonical(&second, LIMITS).unwrap());
    }
  }

  #[test]
  fn core_prelude_rejects_malformed_and_over_limit_messages() {
    let canonical = message(0, &[0x01]);
    assert!(split_message(&canonical[..15], 0, 8, 8, declared).is_err());

    let mut wrong_magic = canonical.clone();
    wrong_magic[0] = b'X';
    assert!(split_message(&wrong_magic, 0, 8, 8, declared).is_err());

    let mut unknown_flags = canonical.clone();
    unknown_flags[9] = 1;
    assert!(split_message(&unknown_flags, 0, 8, 8, declared).is_err());

    let mut reserved = canonical.clone();
    reserved[11] = 1;
    assert!(split_message(&reserved, 0, 8, 8, declared).is_err());

    let mut wrong_length = canonical.clone();
    wrong_length[15] = 2;
    assert!(split_message(&wrong_length, 0, 8, 8, declared).is_err());

    assert!(split_message(&canonical, 0, 8, 8, |_, _| false).is_err());
    assert!(split_message(&canonical, 0, 0, 8, declared).is_err());
    assert!(split_message(&canonical, 0, 8, 0, declared).is_err());
  }

  #[test]
  fn core_cbor_encodes_and_decodes_exact_canonical_bytes() {
    let body = TestBody {
      sequence: 1,
      payload: b"ok".to_vec(),
    };

    let encoded = encode_canonical(&body, LIMITS).unwrap();
    assert_eq!(encoded, [0xA2, 0x00, 0x01, 0x01, 0x42, b'o', b'k']);
    assert_eq!(
      decode_canonical::<TestBody>(&encoded, LIMITS).unwrap(),
      body
    );
  }

  #[test]
  fn core_cbor_rejects_noncanonical_or_unsupported_forms() {
    for bytes in [
      &[0x18, 0x01][..],
      &[0x9F, 0xFF],
      &[0xA2, 0x00, 0x01, 0x00, 0x02],
      &[0xA2, 0x01, 0x01, 0x00, 0x02],
      &[0xC0, 0x00],
      &[0xF9, 0x00, 0x00],
      &[0x00, 0x00],
    ] {
      assert!(decode_canonical::<Ignored>(bytes, LIMITS).is_err());
    }
  }

  #[test]
  fn core_cbor_enforces_caller_selected_limits() {
    assert!(decode_canonical::<Ignored>(&[0x81, 0x81, 0x00], CborLimits::new(1, 8, 8)).is_err());
    assert!(
      decode_canonical::<Ignored>(&[0x83, 0x00, 0x01, 0x02], CborLimits::new(4, 2, 8)).is_err()
    );
    assert!(decode_canonical::<Ignored>(&[0x00], CborLimits::new(0, 2, 8)).is_err());
    assert!(decode_canonical::<Ignored>(&[0x00], CborLimits::new(4, 0, 8)).is_err());
    assert!(decode_canonical::<Ignored>(&[0x00], CborLimits::new(4, 2, 0)).is_err());
  }

  #[test]
  fn core_cbor_accepts_generous_caller_selected_limits() {
    let mut deep = vec![0x81; 40];
    deep.push(0x00);
    decode_canonical::<Ignored>(&deep, CborLimits::new(40, 1, deep.len())).unwrap();

    let mut collection = Vec::with_capacity(4_100);
    collection.extend_from_slice(&[0x99, 0x10, 0x01]);
    collection.resize(4_100, 0x00);
    decode_canonical::<Ignored>(&collection, CborLimits::new(1, 4_097, collection.len())).unwrap();

    let value_len = 8 * 1024 * 1024 + 1;
    let mut body = Vec::with_capacity(value_len + 5);
    body.push(0x5A);
    body.extend_from_slice(&(value_len as u32).to_be_bytes());
    body.resize(value_len + 5, 0);
    decode_canonical::<Ignored>(&body, CborLimits::new(1, 1, body.len())).unwrap();
  }

  #[test]
  fn core_cbor_bounds_output_before_encoding_growth() {
    let body = RepeatedBody {
      accepted_items: Cell::new(0),
    };

    assert!(encode_canonical(&body, CborLimits::new(4, 8, 32)).is_err());
    assert!(body.accepted_items.get() <= 1);
  }

  fn declared(schema: u16, kind: u16) -> bool {
    schema == 1 && kind == 1
  }

  fn message(flags: u16, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::from(Prelude::new(1, 1, flags, body.len() as u32).encode());
    message.extend_from_slice(body);
    message
  }
}
