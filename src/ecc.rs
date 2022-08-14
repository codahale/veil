//! Elliptic curve cryptography functions.

use rand::{CryptoRng, Rng, RngCore};

/// A scalar value for the elliptic curve.
pub(crate) type Scalar = crrl::ristretto255::Scalar;

/// The length of an encoded scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// A point on the elliptic curve. Never the additive identity.
pub(crate) type Point = crrl::ristretto255::Point;

/// The length of an encoded point in bytes.
pub const POINT_LEN: usize = 32;

pub trait CanonicallyEncoded<const LEN: usize>: Sized {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self>;

    fn as_canonical_bytes(&self) -> [u8; LEN];

    fn random(rng: impl RngCore + CryptoRng) -> Self;
}

impl CanonicallyEncoded<SCALAR_LEN> for Scalar {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self> {
        let (v, ok) = Scalar::decode32(b.as_ref());
        (ok != 0).then_some(v)
    }

    fn as_canonical_bytes(&self) -> [u8; SCALAR_LEN] {
        self.encode32()
    }

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        loop {
            let v = Scalar::decode_reduce(&rng.gen::<[u8; 64]>());
            if v.iszero() == 0 {
                return v;
            }
        }
    }
}

impl CanonicallyEncoded<POINT_LEN> for Point {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self> {
        Point::decode(b.as_ref())
    }

    fn as_canonical_bytes(&self) -> [u8; POINT_LEN] {
        self.encode()
    }

    fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Point::one_way_map(&rng.gen::<[u8; 64]>())
    }
}
