//! Utility functions for Ristretto operations.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

/// The generator for the Ristretto group. Use the table version, which contains precomputed
/// multiples, for performance.
pub const G: RistrettoBasepointTable = RISTRETTO_BASEPOINT_TABLE;

/// An extension trait to centralize canonical encoding of scalars and points.
pub trait CanonicallyEncoded<const N: usize>: Sized {
    /// The length of the encoded values in bytes.
    const ENCODED_LEN: usize = N;

    /// Parses the given slice and decodes it iff the encoding is canonical.
    #[must_use]
    fn from_canonical_encoding(b: &[u8]) -> Option<Self>;

    /// Canonically encodes the value.
    #[must_use]
    fn to_canonical_encoding(&self) -> [u8; N];
}

impl CanonicallyEncoded<32> for Scalar {
    fn from_canonical_encoding(b: &[u8]) -> Option<Self> {
        Scalar::from_canonical_bytes(b.try_into().ok()?).filter(|d| d != &Scalar::zero())
    }

    fn to_canonical_encoding(&self) -> [u8; 32] {
        debug_assert!(self.is_canonical());
        debug_assert!(self != &Scalar::zero());

        self.to_bytes()
    }
}

impl CanonicallyEncoded<32> for RistrettoPoint {
    fn from_canonical_encoding(b: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(b).decompress().filter(|q| !q.is_identity())
    }

    fn to_canonical_encoding(&self) -> [u8; 32] {
        debug_assert!(!self.is_identity());

        self.compress().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn scalar_round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let b = d.to_canonical_encoding();
        let d_p = Scalar::from_canonical_encoding(&b);

        assert_eq!(Some(d), d_p);
    }

    #[test]
    fn point_round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let q = RistrettoPoint::random(&mut rng);
        let b = q.to_canonical_encoding();
        let q_p = RistrettoPoint::from_canonical_encoding(&b);

        assert_eq!(Some(q), q_p);
    }

    #[test]
    fn identity_scalars() {
        assert_eq!(None, Scalar::from_canonical_encoding(&[0u8; 32]));
    }

    #[test]
    fn identity_points() {
        assert_eq!(None, RistrettoPoint::from_canonical_encoding(&[0u8; 32]));
    }
}
