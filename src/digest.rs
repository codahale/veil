use std::fmt::Formatter;
use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};
use subtle::ConstantTimeEq;

use crate::duplex::{Absorb, Squeeze, UnkeyedDuplex};
use crate::{AsciiEncoded, ParseDigestError};

/// The digest of a set of metadata and a message.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Digest([u8; DIGEST_LEN]);

impl AsciiEncoded<DIGEST_LEN> for Digest {
    type Err = ParseDigestError;

    fn from_bytes(b: &[u8]) -> Result<Self, <Self as AsciiEncoded<DIGEST_LEN>>::Err> {
        Ok(Digest(b.try_into().map_err(|_| ParseDigestError::InvalidLength)?))
    }

    fn to_bytes(&self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

impl FromStr for Digest {
    type Err = ParseDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Digest::from_ascii(s)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii())
    }
}

impl Digest {
    /// Create a digest from a set of metadata strings and a reader.
    ///
    /// # Errors
    ///
    /// Returns any error returned by operations on `reader`.
    pub fn new(metadata: &[impl AsRef<[u8]>], reader: impl Read) -> io::Result<Digest> {
        // Initialize an unkeyed duplex.
        let mut digest = UnkeyedDuplex::new("veil.digest");

        // Absorb the metadata values in order.
        for v in metadata {
            digest.absorb(v.as_ref());
        }

        // Absorb the reader contents.
        digest.absorb_reader(reader)?;

        // Squeeze N bytes as a digest.
        Ok(Digest(digest.squeeze::<DIGEST_LEN>()))
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

const DIGEST_LEN: usize = 64;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn round_trip() -> io::Result<()> {
        let a = Digest::new(&["one", "two"], &mut Cursor::new(b"this is an example"))?;
        let b = Digest::new(&["one", "two"], &mut Cursor::new(b"this is an example"))?;

        assert_eq!(a, b, "inconsistent digests");

        Ok(())
    }

    #[test]
    fn different_metadata() -> io::Result<()> {
        let a = Digest::new(&["one", "two"], &mut Cursor::new(b"this is an example"))?;
        let b = Digest::new(&["two", "one"], &mut Cursor::new(b"this is an example"))?;

        assert_ne!(a, b, "collision on metadata");

        Ok(())
    }

    #[test]
    fn different_messages() -> io::Result<()> {
        let a = Digest::new(&["one", "two"], &mut Cursor::new(b"this is an example"))?;
        let b = Digest::new(&["one", "two"], &mut Cursor::new(b"this is another example"))?;

        assert_ne!(a, b, "collision on message");

        Ok(())
    }

    #[test]
    fn encoding() {
        let sig = Digest([69u8; DIGEST_LEN]);
        assert_eq!(
            "2PKwbVQ1YMFEexCmUDyxy8cuwb69VWcvoeodZCLegqof62ro8siurvh9QCnFzdsdTixDC94tCMzH7dMuqL5Gi2CC",
            sig.to_string(),
            "invalid encoded signature"
        );

        let decoded = "2PKwbVQ1YMFEexCmUDyxy8cuwb69VWcvoeodZCLegqof62ro8siurvh9QCnFzdsdTixDC94tCMzH7dMuqL5Gi2CC".parse::<Digest>();
        assert_eq!(Ok(sig), decoded, "error parsing signature");

        assert_eq!(
            Err(ParseDigestError::InvalidEncoding(bs58::decode::Error::InvalidCharacter {
                character: ' ',
                index: 4,
            })),
            "woot woot".parse::<Digest>(),
            "parsed invalid signature"
        );
    }
}
