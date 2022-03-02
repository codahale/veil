//! Utility functions for Ristretto operations.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable};
use curve25519_dalek::traits::IsIdentity;

/// A scalar on the Ristretto255 curve.
pub type Scalar = curve25519_dalek::scalar::Scalar;

/// A point on the Ristretto255 curve.
pub type Point = curve25519_dalek::ristretto::RistrettoPoint;

/// The generator for the Ristretto group. Use the table version, which contains precomputed
/// multiples, for performance.
pub const G: RistrettoBasepointTable = RISTRETTO_BASEPOINT_TABLE;

/// The length of a compressed ristretto255 point in bytes.
pub const POINT_LEN: usize = 32;

/// The length of a ristretto255 scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// An extension trait to centralize canonical encoding of scalars and points.
pub trait CanonicallyEncoded<const N: usize>: Sized {
    /// Parses the given slice and decodes it iff the encoding is canonical.
    #[must_use]
    fn from_canonical_encoding(b: &[u8]) -> Option<Self>;

    /// Canonically encodes the value.
    #[must_use]
    fn to_canonical_encoding(&self) -> [u8; N];
}

impl CanonicallyEncoded<SCALAR_LEN> for Scalar {
    fn from_canonical_encoding(b: &[u8]) -> Option<Self> {
        Scalar::from_canonical_bytes(b.try_into().ok()?).filter(|d| d != &Scalar::zero())
    }

    fn to_canonical_encoding(&self) -> [u8; SCALAR_LEN] {
        debug_assert!(self.is_canonical());
        debug_assert!(self != &Scalar::zero());

        self.to_bytes()
    }
}

impl CanonicallyEncoded<POINT_LEN> for Point {
    fn from_canonical_encoding(b: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(b).decompress().filter(|q| !q.is_identity())
    }

    fn to_canonical_encoding(&self) -> [u8; POINT_LEN] {
        debug_assert!(!self.is_identity());

        self.compress().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_round_trip() {
        let d = Scalar::random(&mut rand::thread_rng());
        let b = d.to_canonical_encoding();
        let d_p = Scalar::from_canonical_encoding(&b);

        assert_eq!(Some(d), d_p);
    }

    #[test]
    fn point_round_trip() {
        let q = Point::random(&mut rand::thread_rng());
        let b = q.to_canonical_encoding();
        let q_p = Point::from_canonical_encoding(&b);

        assert_eq!(Some(q), q_p);
    }

    #[test]
    fn identity_scalars() {
        assert_eq!(None, Scalar::from_canonical_encoding(&[0u8; 32]));
    }

    #[test]
    fn identity_points() {
        assert_eq!(None, Point::from_canonical_encoding(&[0u8; 32]));
    }
}
