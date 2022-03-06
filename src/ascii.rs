use std::fmt::Display;
use std::str::FromStr;

/// The `AsciiEncoded` trait allows for encoding and decoding types as base58.
pub trait AsciiEncoded: Sized + FromStr + Display {
    /// The associated error which can be returned from parsing.
    type Err: From<bs58::decode::Error>;

    /// Decode a value from bytes.
    fn from_bytes(b: &[u8]) -> Result<Self, <Self as AsciiEncoded>::Err>;

    /// Encode a value as bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Decode a value from a base58 string.
    fn from_ascii(s: &str) -> Result<Self, <Self as AsciiEncoded>::Err> {
        Self::from_bytes(&bs58::decode(s).into_vec()?)
    }

    /// Encode a value as a base58 string.
    fn to_ascii(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }
}
