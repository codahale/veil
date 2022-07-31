//! Elliptic curve cryptography functions.

use rand::{CryptoRng, Rng, RngCore};

/// A scalar value for the elliptic curve.
pub(crate) type Scalar = crrl::ristretto255::Scalar;

/// A point on the elliptic curve. Never the additive identity.
pub(crate) type Point = crrl::ristretto255::Point;

pub trait CanonicallyEncoded<const LEN: usize>: Sized {
    const LEN: usize = LEN;

    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self>;

    fn as_canonical_bytes(&self) -> [u8; LEN];

    fn random(rng: impl RngCore + CryptoRng) -> Self;
}

impl CanonicallyEncoded<32> for Scalar {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self> {
        let (v, _) = Scalar::decode32(b.as_ref());
        (v.iszero() == 0).then_some(v)
    }

    fn as_canonical_bytes(&self) -> [u8; 32] {
        self.encode32()
    }

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut b = [0u8; Self::LEN];
        loop {
            rng.fill_bytes(&mut b);
            if let Some(v) = Self::from_canonical_bytes(&b) {
                return v;
            }
        }
    }
}

impl CanonicallyEncoded<32> for Point {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self> {
        Point::decode(b.as_ref()).filter(|q| q.isneutral() == 0)
    }

    fn as_canonical_bytes(&self) -> [u8; 32] {
        self.encode()
    }

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Point::one_way_map(&rng.gen::<[u8; 64]>())
    }
}
