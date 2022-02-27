use std::fmt::Formatter;
use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};

use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;

use crate::duplex::Duplex;

/// Error due to invalid digest format.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid digest")]
pub struct DigestError;

/// The digest of a set of metadata and a message.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Digest([u8; DIGEST_LEN]);

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bs58::decode(s)
            .into_vec()
            .ok()
            .and_then(|b| Some(Digest(b.try_into().ok()?)))
            .ok_or(DigestError)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl Digest {
    /// Create a digest from a set of metadata strings and a reader.
    pub fn new<R, T>(metadata: &[T], reader: &mut R) -> io::Result<Digest>
    where
        T: AsRef<[u8]>,
        R: Read,
    {
        // Initialize the duplex.
        let mut digest = Duplex::new("veil.digest");

        // Absorb the metadata values in order.
        for v in metadata {
            digest.absorb(v.as_ref());
        }

        // Absorb the reader contents.
        let mut digest = digest.absorb_stream(io::sink());
        io::copy(reader, &mut digest)?;

        // Unwrap the duplex and squeeze N bytes as a digest.
        let (mut digest, _, _) = digest.into_inner()?;
        Ok(Digest(digest.squeeze(64).try_into().expect("invalid digest len")))
    }
}

impl ConstantTimeEq for Digest {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
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

        assert_eq!(Err(DigestError), "woot woot".parse::<Digest>(), "parsed invalid signature");
    }
}
