use std::fmt::{Debug, Formatter};

use crrl::gls254::{Point, Scalar};
use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

/// The length of a secret in bytes.
pub const SECRET_LEN: usize = 64;

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

    /// Generates a random public key for which no private key is known.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PubKey {
        let q = Point::hash_to_curve("", &rng.gen::<[u8; 64]>());
        PubKey { q, encoded: q.encode() }
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
    /// The derived private scalar; always non-zero.
    pub d: Scalar,
    /// The corresponding [`PubKey`] for the private key; always derived from `d`.
    pub pub_key: PubKey,
    /// The original secret value.
    pub secret: [u8; SECRET_LEN],
    /// The derived nonce value; intended to be unique per secret.
    nonce: [u8; SECRET_LEN],
}

impl PrivKey {
    /// Derives a private key from the given secret.
    pub fn from_secret_bytes(secret: [u8; SECRET_LEN]) -> PrivKey {
        let mut skd = Protocol::new("veil.skd");
        skd.mix("secret", &secret);

        let d = Scalar::decode_reduce(&skd.derive_array::<32>("scalar"));
        let q = Point::mulgen(&d);
        let nonce = skd.derive_array("nonce");

        PrivKey { d, pub_key: PubKey { q, encoded: q.encode() }, secret, nonce }
    }

    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PrivKey {
        PrivKey::from_secret_bytes(rng.gen())
    }

    /// Uses the key's nonce and a clone of the given protocol to deterministically create a
    /// commitment scalar for the protocol's state.
    #[must_use]
    pub fn commitment(&self, protocol: &Protocol) -> Scalar {
        let mut clone = protocol.clone();
        clone.mix("signer-nonce", &self.nonce);
        Scalar::decode_reduce(&clone.derive_array::<32>("commitment-scalar"))
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
