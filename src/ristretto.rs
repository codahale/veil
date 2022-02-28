//! Utility functions for Ristretto operations.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint};
pub use curve25519_dalek::traits::Identity;

/// A scalar on the Ristretto255 curve.
pub type Scalar = curve25519_dalek::scalar::Scalar;

/// A point on the Ristretto255 curve.
pub type Point = RistrettoPoint;

/// The generator for the Ristretto group. Use the table version, which contains precomputed
/// multiples, for performance.
pub const G: RistrettoBasepointTable = RISTRETTO_BASEPOINT_TABLE;

/// The length of a compressed ristretto255 point in bytes.
pub const POINT_LEN: usize = 32;

/// The length of a ristretto255 scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// An extension trait to centralize canonical encoding of scalars and points.
pub trait CanonicallyEncoded: Sized {
    /// Parses the given slice and decodes it iff the encoding is canonical.
    #[must_use]
    fn from_canonical_encoding(b: &[u8]) -> Option<Self>;

    /// Canonically encodes the value.
    #[must_use]
    fn to_canonical_encoding(&self) -> Vec<u8>;
}

impl CanonicallyEncoded for Scalar {
    fn from_canonical_encoding(b: &[u8]) -> Option<Self> {
        Scalar::from_canonical_bytes(b.try_into().ok()?)
    }

    fn to_canonical_encoding(&self) -> Vec<u8> {
        debug_assert!(self.is_canonical());
        self.to_bytes().to_vec()
    }
}

impl CanonicallyEncoded for RistrettoPoint {
    fn from_canonical_encoding(b: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(b).decompress()
    }

    fn to_canonical_encoding(&self) -> Vec<u8> {
        self.compress().to_bytes().to_vec()
    }
}
