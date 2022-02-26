use std::fmt::Formatter;
use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};

use thiserror::Error;

use crate::ascii::AsciiEncoded;
use crate::duplex::Duplex;

const DIGEST_LEN: usize = 64;

/// Error due to invalid digest format.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid digest")]
pub struct DigestError;

/// The digest of a set of metadata and a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; DIGEST_LEN]);

impl AsciiEncoded for Digest {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(Digest(b.try_into().ok()?))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Digest::from_ascii(s).ok_or(DigestError)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii())
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
