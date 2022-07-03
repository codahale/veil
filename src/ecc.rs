use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Group;
use p256::CompressedPoint;
use subtle::CtOption;

/// The length of an encoded point in bytes.
pub(crate) const POINT_LEN: usize = 33;

/// The length of an encoded scalar in bytes.
pub(crate) const SCALAR_LEN: usize = 32;

/// A scalar value for the elliptic curve. Never zero.
pub(crate) type Scalar = p256::NonZeroScalar;

/// A point on the elliptic curve. Never the additive identity.
pub(crate) type Point = p256::ProjectivePoint;

pub trait FromCanonicalBytes: Sized {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self>;
}

impl FromCanonicalBytes for Scalar {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self> {
        Scalar::from_repr(GenericArray::clone_from_slice(b.as_ref())).into()
    }
}

impl FromCanonicalBytes for Point {
    fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<Self> {
        Point::from_bytes(CompressedPoint::from_slice(b.as_ref()))
            .and_then(|p| CtOption::new(p, !p.is_identity()))
            .into()
    }
}
