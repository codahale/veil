use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};

use lockstitch::Protocol;

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
    pub fn new(metadata: &[impl AsRef<[u8]>], mut reader: impl Read) -> io::Result<Digest> {
        // Initialize a protocol.
        let mut digest = Protocol::new("veil.digest");

        // Mix the metadata values in order into the protocol.
        for v in metadata {
            digest.mix(b"metadata", v.as_ref());
        }

        // Mix the reader contents into the protocol.
        let mut writer = digest.mix_writer(b"message", io::sink());
        io::copy(&mut reader, &mut writer)?;
        let (mut digest, _) = writer.into_inner();

        // Derive 32 bytes as a digest.
        Ok(Digest(digest.derive_array(b"digest")))
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
        lockstitch::ct_eq(&self.0, &other.0)
    }
}

const DIGEST_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let message = rng.gen::<[u8; 64]>();
        let md_one = rng.gen::<[u8; 16]>();
        let md_two = rng.gen::<[u8; 16]>();

        let a = Digest::new(&[&md_one, &md_two], Cursor::new(&message))
            .expect("cursor reads should be infallible");
        let b = Digest::new(&[&md_one, &md_two], Cursor::new(&message))
            .expect("cursor reads should be infallible");

        assert_eq!(a, b, "inconsistent digests");
    }

    #[test]
    fn different_metadata() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let message = rng.gen::<[u8; 64]>();
        let md_one = rng.gen::<[u8; 16]>();
        let md_two = rng.gen::<[u8; 16]>();

        let a = Digest::new(&[&md_one, &md_two], Cursor::new(&message))
            .expect("cursor reads should be infallible");
        let b = Digest::new(&[&md_two, &md_one], Cursor::new(&message))
            .expect("cursor reads should be infallible");

        assert_ne!(a, b, "collision on metadata");
    }

    #[test]
    fn different_messages() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let message = rng.gen::<[u8; 64]>();
        let md_one = rng.gen::<[u8; 16]>();
        let md_two = rng.gen::<[u8; 16]>();
        let different_message = rng.gen::<[u8; 64]>();

        let a = Digest::new(&[&md_one, &md_two], Cursor::new(&message))
            .expect("cursor reads should be infallible");
        let b = Digest::new(&[&md_one, &md_two], Cursor::new(&different_message))
            .expect("cursor reads should be infallible");

        assert_ne!(a, b, "collision on message");
    }

    #[test]
    fn encoding() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sig = Digest(rng.gen());

        assert_eq!(
            "9tKd8hrpibubFKGV6QELAQ9q5if5fWuGH2rfHML4vZyL",
            sig.to_string(),
            "invalid encoded digest"
        );

        let decoded = "9tKd8hrpibubFKGV6QELAQ9q5if5fWuGH2rfHML4vZyL".parse::<Digest>();
        assert_eq!(Ok(sig), decoded, "error parsing signature");

        assert_eq!(
            Err(ParseDigestError::InvalidEncoding(bs58::decode::Error::InvalidCharacter {
                character: 'l',
                index: 4,
            })),
            "invalid digest".parse::<Digest>(),
            "parsed invalid digest"
        );
    }
}
