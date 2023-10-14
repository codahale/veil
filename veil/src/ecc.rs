use std::ops::{Add, Mul, Sub};

use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::ops::{MulByGenerator, ReduceNonZero};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::PrimeField;
use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint};
use rand::{CryptoRng, Rng};

/// The length of an encoded scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// The length of an encoded point in bytes.
pub const POINT_LEN: usize = 33;

#[derive(Debug, Clone, Copy)]
pub struct Scalar(p256::Scalar);

impl Scalar {
    pub fn reduce(b: [u8; SCALAR_LEN]) -> Scalar {
        Scalar(p256::Scalar::reduce_nonzero_bytes(&b.into()))
    }

    pub fn from_bytes(b: [u8; SCALAR_LEN]) -> Option<Scalar> {
        p256::Scalar::from_repr(b.into()).map(Scalar).into()
    }

    pub fn to_bytes(self) -> [u8; SCALAR_LEN] {
        self.0.to_bytes().into()
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0 + rhs.0)
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0 * rhs.0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Point(ProjectivePoint);

impl Point {
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> Point {
        loop {
            let q = NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(
                &[&rng.gen::<[u8; 64]>()],
                &[b"veil-random-key-generator"],
            )
            .and_then(|q| p256::PublicKey::from_affine(q.to_affine()));
            if let Ok(q) = q {
                return Point(q.to_projective());
            }
        }
    }

    pub fn from_bytes(b: &[u8; POINT_LEN]) -> Option<Point> {
        let q = EncodedPoint::from_bytes(b).ok()?;
        let q = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&q))?;
        bool::from(!q.is_identity()).then_some(Point(q.into()))
    }

    pub fn to_bytes(self) -> [u8; POINT_LEN] {
        let q: EncodedPoint = self.0.to_affine().to_encoded_point(true);
        q.as_bytes().try_into().expect("point should be POINT_LEN bytes")
    }

    pub fn mul_base(d: &Scalar) -> Point {
        Point(ProjectivePoint::mul_by_generator(&d.0))
    }
}

impl Add<Point> for Point {
    type Output = Point;

    fn add(self, rhs: Point) -> Self::Output {
        Point(self.0 + rhs.0)
    }
}

impl Sub<Point> for Point {
    type Output = Point;

    fn sub(self, rhs: Point) -> Self::Output {
        Point(self.0 - rhs.0)
    }
}

impl Mul<Scalar> for Point {
    type Output = Point;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Point(self.0 * rhs.0)
    }
}
