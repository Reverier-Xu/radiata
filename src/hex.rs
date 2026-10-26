//! Crate-private canonical lowercase hexadecimal codec.
//!
//! Every wire transcript, persisted document, purpose string, and digest
//! rendering in the crate uses the same lowercase hex form. Keeping the
//! codec in one module prevents the divergence (uppercase vs lowercase,
//! lookup-table vs nibble-loop) that would silently corrupt golden
//! fixtures, JSON documents, and durable purpose strings.

use crate::{Error, Result};

/// Encodes bytes as lowercase hexadecimal, two digits per byte.
pub(crate) fn encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0F)]));
  }
  output
}

/// Decodes an even-length lowercase-hex string into bytes.
pub(crate) fn decode(value: &str, context: &'static str) -> Result<Vec<u8>> {
  if !value.len().is_multiple_of(2) || !value.bytes().all(is_hex_digit) {
    return Err(Error::invalid_input(context));
  }
  let mut output = Vec::with_capacity(value.len() / 2);
  for pair in value.as_bytes().as_chunks::<2>().0 {
    output.push(hex_value(pair[0], context)? << 4 | hex_value(pair[1], context)?);
  }
  Ok(output)
}

/// Decodes an even-length lowercase-hex string into a fixed-size array.
pub(crate) fn decode_array<const LENGTH: usize>(
  value: &str, context: &'static str,
) -> Result<[u8; LENGTH]> {
  let bytes = decode(value, context)?;
  crate::error::fixed_bytes(bytes.as_slice(), context)
}

fn is_hex_digit(byte: u8) -> bool {
  byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn hex_value(byte: u8, context: &'static str) -> Result<u8> {
  match byte {
    b'0'..=b'9' => Ok(byte - b'0'),
    b'a'..=b'f' => Ok(byte - b'a' + 10),
    _ => Err(Error::invalid_input(context)),
  }
}

#[cfg(test)]
mod tests {
  use super::{decode, decode_array, encode};
  use crate::ErrorKind;

  #[test]
  fn hex_round_trips_bytes() {
    let bytes = [0x00_u8, 0x0F, 0x10, 0xFF, 0xAB, 0xCD];
    let text = encode(&bytes);
    assert_eq!(text, "000f10ffabcd");
    assert_eq!(decode(&text, "round trip").unwrap(), bytes);
    assert_eq!(decode_array::<6>(&text, "round trip").unwrap(), bytes);
  }

  #[test]
  fn hex_rejects_odd_length_upper_case_and_non_hex() {
    assert_eq!(
      decode("abc", "odd").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      decode("ABCD", "upper").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      decode("abcz", "non-hex").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
    assert_eq!(
      decode_array::<2>("aabbcc", "length").unwrap_err().kind(),
      ErrorKind::InvalidInput
    );
  }
}
