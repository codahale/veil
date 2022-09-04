use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};

use constant_time_eq::constant_time_eq_n;

use crate::duplex::{Absorb, Squeeze, UnkeyedDuplex};
use crate::ParseDigestError;

/// The digest of a sequence of metadata values and a message.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Digest([u8; DIGEST_LEN]);

impl Digest {
    /// Create a digest from a sequence of metadata values and a reader.
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

        // Squeeze 32 bytes as a digest.
        Ok(Digest(digest.squeeze()))
    }

    /// Create a digest from a 32-byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<Digest> {
        Some(Digest(b.as_ref().try_into().ok()?))
    }

    /// Encode the digest as a 32-byte array.
    #[must_use]
    pub const fn encode(&self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

impl FromStr for Digest {
    type Err = ParseDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Digest::decode(bs58::decode(s).into_vec()?.as_slice())
            .ok_or(ParseDigestError::InvalidLength)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

const DIGEST_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn round_trip() {
        let a = Digest::new(&["one", "two"], Cursor::new(b"this is an example"))
            .expect("error hashing");
        let b = Digest::new(&["one", "two"], Cursor::new(b"this is an example"))
            .expect("error hashing");

        assert_eq!(a, b, "inconsistent digests");
    }

    #[test]
    fn different_metadata() {
        let a = Digest::new(&["one", "two"], Cursor::new(b"this is an example"))
            .expect("error hashing");
        let b = Digest::new(&["two", "one"], Cursor::new(b"this is an example"))
            .expect("error hashing");

        assert_ne!(a, b, "collision on metadata");
    }

    #[test]
    fn different_messages() {
        let a = Digest::new(&["one", "two"], Cursor::new(b"this is an example"))
            .expect("error hashing");
        let b = Digest::new(&["one", "two"], Cursor::new(b"this is another example"))
            .expect("error hashing");

        assert_ne!(a, b, "collision on message");
    }

    #[test]
    fn encoding() {
        let sig = Digest([69u8; DIGEST_LEN]);
        assert_eq!(
            "5fQPsn8hoaVddFG26cWQ5QFdqxWtUPNaZ9zH2E6LYzFn",
            sig.to_string(),
            "invalid encoded digest"
        );

        let decoded = "5fQPsn8hoaVddFG26cWQ5QFdqxWtUPNaZ9zH2E6LYzFn".parse::<Digest>();
        assert_eq!(Ok(sig), decoded, "error parsing signature");

        assert_eq!(
            Err(ParseDigestError::InvalidEncoding(bs58::decode::Error::InvalidCharacter {
                character: ' ',
                index: 4,
            })),
            "woot woot".parse::<Digest>(),
            "parsed invalid digest"
        );
    }
}
