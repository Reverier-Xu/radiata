use std::fmt;

macro_rules! byte_value {
  ($name:ident, $length:literal) => {
    #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct $name([u8; $length]);

    impl $name {
      pub const fn from_bytes(value: [u8; $length]) -> Self {
        Self(value)
      }

      pub const fn as_bytes(&self) -> &[u8; $length] {
        &self.0
      }
    }

    impl fmt::Debug for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(concat!(stringify!($name), "(..)"))
      }
    }
  };
}

byte_value!(Digest, 32);
byte_value!(PublicKey, 32);
byte_value!(Signature, 64);
