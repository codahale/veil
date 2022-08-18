use std::fmt::Display;
use std::str::FromStr;

/// The `AsciiEncoded` trait allows for encoding and decoding types as base58.
pub trait AsciiEncoded<const LEN: usize>: Sized + FromStr + Display {
    /// The associated error which can be returned from parsing.
    type Err: From<bs58::decode::Error>;

    /// Decode a value from bytes.
    ///
    /// # Errors
    ///
    /// If `b` is not a valid encoding, returns an error.
    fn from_bytes(b: &[u8]) -> Result<Self, <Self as AsciiEncoded<LEN>>::Err>;

    /// Encode a value as bytes.
    #[must_use]
    fn to_bytes(&self) -> [u8; LEN];

    /// Decode a value from a base58 string.
    ///
    /// # Errors
    ///
    /// If `s` is valid Base58 or not a valid encoding, returns an error.
    fn from_ascii(s: &str) -> Result<Self, <Self as AsciiEncoded<LEN>>::Err> {
        let mut b = [0u8; LEN];
        bs58::decode(s).into(&mut b)?;
        Self::from_bytes(&b)
    }

    /// Encode a value as a base58 string.
    #[must_use]
    fn to_ascii(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }
}
