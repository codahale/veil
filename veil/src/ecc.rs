use std::ops::{Add, Mul, Neg, Sub};

use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::ops::{LinearCombination, MulByGenerator, ReduceNonZero};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, Group, PrimeField};
use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint};
use rand::{CryptoRng, Rng};
use subtle::CtOption;

/// The length of an encoded scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// The length of an encoded point in bytes.
pub const POINT_LEN: usize = 33;

/// A scalar of the NIST P-256 curve.
#[derive(Debug, Clone, Copy)]
pub struct Scalar(p256::Scalar);

impl Scalar {
    /// Interprets the given bytes as an integer and performs a modular reduction to a non-zero
    /// scalar.
    pub fn reduce(b: [u8; SCALAR_LEN]) -> Scalar {
        Scalar(p256::Scalar::reduce_nonzero_bytes(&b.into()))
    }

    /// Interprets the given bytes as an SEC1-encoded integer `d` and returns `Some(d)` iff `d` is
    /// non-zero.
    pub fn from_bytes(b: [u8; SCALAR_LEN]) -> Option<Scalar> {
        p256::Scalar::from_repr(b.into())
            .and_then(|d| CtOption::new(d, !d.is_zero()))
            .map(Scalar)
            .into()
    }

    /// Returns the SEC1 encoding of the scalar.
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

/// A NIST P-256 point. Guaranteed to not be the identity point.
#[derive(Debug, Clone, Copy)]
pub struct Point(ProjectivePoint);

impl Point {
    /// Generates a random point for which no private key is known.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> Point {
        Point(
            NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(
                &[&rng.gen::<[u8; 64]>()],
                &[b"veil-random-key-generator"],
            )
            .expect("hash2curve should be infallible"),
        )
    }

    /// Decodes the given array as a point, if possible. If the array encodes a non-identity point
    /// `q` on the curve, returns `Some(q)`.
    pub fn from_bytes(b: &[u8; POINT_LEN]) -> Option<Point> {
        EncodedPoint::from_bytes(b).ok().and_then(|q| {
            AffinePoint::from_encoded_point(&q)
                .and_then(|q| CtOption::new(q, !q.is_identity()))
                .map(|q| Point(q.into()))
                .into()
        })
    }

    /// Encodes the point as a SEC1-encoded compressed point.
    pub fn to_bytes(self) -> [u8; POINT_LEN] {
        self.0
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("point should be POINT_LEN bytes")
    }

    /// Multiplies the curve's generator by the given scalar.
    pub fn mul_gen(d: &Scalar) -> Point {
        Point(ProjectivePoint::mul_by_generator(&d.0))
    }

    /// Calculates `G * k + y * l`.
    pub fn lincomb(k: &Scalar, y: &Point, l: &Scalar) -> Point {
        Point(ProjectivePoint::lincomb(&ProjectivePoint::generator(), &k.0, &y.0, &l.0))
    }
}

impl Add<Point> for Point {
    type Output = Point;

    fn add(self, rhs: Point) -> Self::Output {
        Point(self.0 + rhs.0)
    }
}

impl Neg for Point {
    type Output = Point;

    fn neg(self) -> Self::Output {
        Point(-self.0)
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
