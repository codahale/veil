use std::fmt::{Debug, Formatter};

use crrl::gls254::{Point, Scalar};
use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

/// The length of a secret in bytes.
pub const SECRET_LEN: usize = SCALAR_LEN + NONCE_LEN;

/// The length of a nonce in bytes.
pub const NONCE_LEN: usize = 64;

/// The length of an encoded scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// The length of an encoded point in bytes.
pub const POINT_LEN: usize = 32;

/// A public key, including its canonical encoded form.
#[derive(Clone, Copy)]
pub struct PubKey {
    /// The decoded point.
    pub q: Point,

    /// The point's canonical encoded form.
    pub encoded: [u8; POINT_LEN],
}

impl PubKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<PubKey> {
        let encoded = <[u8; POINT_LEN]>::try_from(b.as_ref()).ok()?;
        let q = Point::decode(&encoded)?;
        (q.isneutral() == 0).then_some(PubKey { q, encoded })
    }
}

impl Debug for PubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.encoded)
    }
}

impl Eq for PubKey {}

impl PartialEq for PubKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

/// A private key, including its public key.
pub struct PrivKey {
    /// The private scalar; always non-zero.
    pub d: Scalar,

    /// The corresponding [`PubKey`] for the private key; always derived from `d`.
    pub pub_key: PubKey,

    /// The scalar's canonical encoded form and the nonce.
    pub encoded: [u8; SECRET_LEN],
}

impl PrivKey {
    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PrivKey {
        let d = Scalar::decode_reduce(&rng.gen::<[u8; SCALAR_LEN]>());
        let q = Point::mulgen(&d);
        let mut encoded = [0u8; SECRET_LEN];
        encoded[..SCALAR_LEN].copy_from_slice(&d.encode());
        rng.fill_bytes(&mut encoded[SCALAR_LEN..]);
        PrivKey { d, pub_key: PubKey { q, encoded: q.encode() }, encoded }
    }

    /// Uses the key's nonce and a clone of the given protocol to deterministically create a
    /// commitment scalar for the protocol's state.
    #[must_use]
    pub fn commitment(&self, protocol: &Protocol) -> Scalar {
        let mut clone = protocol.clone();
        clone.mix("signer-nonce", &self.encoded[SCALAR_LEN..]);
        Scalar::decode_reduce(&clone.derive_array::<32>("commitment-scalar"))
    }

    /// Decodes the given slice as a private key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<PrivKey> {
        let encoded = <[u8; SECRET_LEN]>::try_from(b.as_ref()).ok()?;
        let d = Scalar::decode(&encoded[..SCALAR_LEN])?;
        let q = Point::mulgen(&d);
        Some(PrivKey { d, pub_key: PubKey { q, encoded: q.encode() }, encoded })
    }
}

impl Eq for PrivKey {}

impl PartialEq for PrivKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_neutral_points() {
        assert_eq!(None, PubKey::from_canonical_bytes(Point::NEUTRAL.encode()));
    }
}
