use std::fmt::{Debug, Formatter};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::{CryptoRng, Rng};

/// The length of an encoded scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// The length of an encoded point in bytes.
pub const POINT_LEN: usize = 32;

/// A public key, including its canonical encoded form.
#[derive(Clone, Copy)]
pub struct PubKey {
    /// The decoded point.
    pub q: RistrettoPoint,

    /// The point's canonical encoded form.
    pub encoded: [u8; POINT_LEN],
}

impl PubKey {
    /// Decodes the given slice as a public key, if possible.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PubKey> {
        let encoded = <[u8; POINT_LEN]>::try_from(b.as_ref()).ok()?;
        let q = CompressedRistretto::from_slice(&encoded).decompress()?;
        (!q.is_identity()).then_some(PubKey { q, encoded })
    }

    /// Generates a random public key for which no private key is known.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PubKey {
        let q = RistrettoPoint::random(&mut rng);
        PubKey { q, encoded: q.compress().to_bytes() }
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
    /// The decoded scalar; always non-zero.
    pub d: Scalar,

    /// The corresponding [`PubKey`] for the private key; always derived from `d`.
    pub pub_key: PubKey,
}

impl PrivKey {
    /// Decodes the given slice as a canonically encoded private key, if possible.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PrivKey> {
        let d: Option<Scalar> = Scalar::from_canonical_bytes(b.as_ref().try_into().ok()?).into();
        d.filter(|d| d != &Scalar::ZERO).map(PrivKey::from_scalar)
    }

    /// Decodes the given slice as a private key, if possible.
    #[must_use]
    pub fn decode_reduce(b: impl AsRef<[u8]>) -> Option<PrivKey> {
        let d: Option<Scalar> = Scalar::from_bytes_mod_order(b.as_ref().try_into().ok()?).into();
        d.filter(|d| d != &Scalar::ZERO).map(PrivKey::from_scalar)
    }

    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PrivKey {
        loop {
            let d = Scalar::random(&mut rng);
            if d != Scalar::ZERO {
                return PrivKey::from_scalar(d);
            }
        }
    }

    #[must_use]
    fn from_scalar(d: Scalar) -> PrivKey {
        let q = &d * &RISTRETTO_BASEPOINT_TABLE;
        PrivKey { d, pub_key: PubKey { q, encoded: q.compress().to_bytes() } }
    }
}

impl Eq for PrivKey {}

impl PartialEq for PrivKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}
