//! ASCII encoding and decoding routines.

/// A base58-encoded type.
pub trait AsciiEncoded: Sized {
    /// Decodes the value from the given slice.
    fn from_bytes(b: &[u8]) -> Option<Self>;

    /// Encodes the value as bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Decodes the value from the given string.
    fn from_ascii(s: &str) -> Option<Self> {
        Self::from_bytes(&bs58::decode(s).into_vec().ok()?)
    }

    /// Encodes the value as a base58 string.
    fn to_ascii(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }
}
