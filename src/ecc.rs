//! Elliptic curve cryptography functions.

use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{Field, Group};
use hex_literal::hex;
use p256::{
    AffinePoint, CompressedPoint, EncodedPoint, FieldElement, NonZeroScalar, ProjectivePoint,
};
use rand::{CryptoRng, RngCore};
use subtle::CtOption;

/// The length of an encoded point in bytes.
pub(crate) const POINT_LEN: usize = 33;

/// The length of an Elligator Squared representative in bytes.
pub(crate) const REPRESENTATIVE_LEN: usize = 64;

/// The length of an encoded scalar in bytes.
pub(crate) const SCALAR_LEN: usize = 32;

/// A scalar value for the elliptic curve. Never zero.
pub(crate) type Scalar = NonZeroScalar;

/// A point on the elliptic curve. Never the additive identity.
pub(crate) type Point = ProjectivePoint;

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

/// Decodes the uniform representative into the originally encoded point.
pub fn representative_to_point(b: &[u8; REPRESENTATIVE_LEN]) -> Option<ProjectivePoint> {
    let u: [u8; 32] = b[..32].try_into().ok()?;
    let v: [u8; 32] = b[32..].try_into().ok()?;
    FieldElement::from_bytes(&u.into())
        .and_then(|u| {
            FieldElement::from_bytes(&v.into()).map(|v| f(&u).to_curve() + f(&v).to_curve())
        })
        .into()
}

/// Encodes the given point as a random, uniform representative.
pub fn point_to_representative(
    p: &ProjectivePoint,
    mut rng: impl RngCore + CryptoRng,
) -> [u8; REPRESENTATIVE_LEN] {
    // Iterate through no more than one thousand candidates. On average, we try N(P) candidates.
    for _ in 0..1_000 {
        // Generate a random field element \not\in {-1, 0, 1}.
        let u = FieldElement::random(&mut rng);
        if u == -FieldElement::ONE || u == FieldElement::ZERO || u == FieldElement::ONE {
            continue;
        }

        // Map the field element to a point and calculate the difference between the random point
        // and the input point.
        let q = p - &f(&u);

        // If we managed to randomly generate -p, congratulate ourselves on the improbable and keep
        // trying.
        if q.is_identity().into() {
            continue;
        }

        // Pick a random biquadratic root from [0,4).
        let j = rng.next_u32() as usize % 4;

        // If the Jth biquadratic root exists for the delta point, return our random field element
        // and our preimage field element.
        let v: Option<FieldElement> = r(&q, j).into();
        if let Some(v) = v {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&u.to_bytes());
            b[32..].copy_from_slice(&v.to_bytes());
            return b;
        }
    }

    // Statistically, it's more likely the RNG is broken than we found one thousand candidates in a
    // row with no valid preimage.
    unreachable!("failed to find candidate, suspect RNG failure")
}

fn g(x: &FieldElement) -> FieldElement {
    x.cube() + (curve_a() * x) + curve_b()
}

fn f(u: &FieldElement) -> AffinePoint {
    // Case 1: u \in {-1, 0, 1}
    // return: infinity
    if u == &-FieldElement::ONE || u == &FieldElement::ZERO || u == &FieldElement::ONE {
        return AffinePoint::IDENTITY;
    }

    // Case 2: u \not\in {-1, 0, 1} and g(X_0(u)) is a square
    // return: (X_0(u), \sqrt{g(X_0(u))})
    let x = x_0(u);
    let y = g(&x);
    if let Some(y) = y.sqrt().into() {
        return coordinates_to_point(&x, &y);
    }

    // Case 3: u \not\in {-1, 0, 1} and g(X_0(u)) is not a square
    // return: (X_1(u), -\sqrt{g(X_1(u))})
    let x = x_1(u);
    let y = -g(&x).sqrt().unwrap();

    coordinates_to_point(&x, &y)
}

fn x_0(u: &FieldElement) -> FieldElement {
    -(curve_b() * curve_a().invert().unwrap())
        * (FieldElement::ONE + ((u.square() * u.square()) - u.square()).invert().unwrap())
}

fn x_1(u: &FieldElement) -> FieldElement {
    -u.square() * x_0(u)
}

fn r(q: &ProjectivePoint, j: usize) -> CtOption<FieldElement> {
    let (x, y) = point_to_coordinates(q.to_affine());

    // Inverting `f` requires two branches, one for X_0 and one for X_1, each of which has four
    // roots. omega is constant across all of them.
    let omega = ((curve_a() * curve_b().invert().unwrap()) * x) + FieldElement::ONE;

    (omega.square() - (FOUR * omega)).sqrt().and_then(|a| {
        // The first division in roots comes at \sqrt{\omega^2 - 4 \omega}. The first and second
        // roots have positive values, the third and fourth roots have negative values.
        let a = if j == 0 || j == 1 { a } else { -a };

        // If g(x) is square, then, x=X_0(u); otherwise x=X_1(u).
        (if y.sqrt().is_some().into() {
            // If x=X_0(u), then we divide by 2 \omega.
            (TWO * omega).invert()
        } else {
            // If x=X_1(u), then we divide by 2.
            TWO.invert()
        })
        .and_then(|b| {
            ((omega + a) * b)
                .sqrt()
                // The second division in roots comes here. The first and third roots have positive
                // values, the second and fourth roots have negative values.
                .map(|c| if j == 0 || j == 2 { c } else { -c })
        })
    })
}

// There isn't a constructor available for converting FieldElement coordinates into an AffinePoint
// directly, so we're stuck having to make an EncodedPoint as an intermediary.
fn coordinates_to_point(x: &FieldElement, y: &FieldElement) -> AffinePoint {
    let enc = EncodedPoint::from_affine_coordinates(&x.to_bytes(), &y.to_bytes(), false);
    AffinePoint::from_encoded_point(&enc).unwrap()
}

// Similarly, there isn't an accessor for the y-coordinate of AffinePoint, so we're stuck encoding
// the point without compression and then decoding the coordinates manually.
fn point_to_coordinates(q: AffinePoint) -> (FieldElement, FieldElement) {
    let enc = q.to_encoded_point(false);
    let x = FieldElement::from_bytes(enc.x().unwrap()).unwrap();
    let y = FieldElement::from_bytes(enc.y().unwrap()).unwrap();
    (x, y)
}

const TWO: FieldElement = FieldElement::add(&FieldElement::ONE, &FieldElement::ONE);
const FOUR: FieldElement = TWO.square();

const fn curve_a() -> FieldElement {
    // a = -3
    FieldElement::ZERO
        .subtract(&FieldElement::ONE)
        .subtract(&FieldElement::ONE)
        .subtract(&FieldElement::ONE)
}

// A final bummer is that p256 doesn't provide access to curve constants _and_ doesn't provide a
// const FieldElement constructor.
fn curve_b() -> FieldElement {
    // b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    FieldElement::from_bytes(
        &hex!("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B").into(),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn swu_encoding() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEAD_BEEF);
        for _ in 0..1_000 {
            let u = FieldElement::random(&mut rng);
            let q = f(&u);

            // Check to see if the point is actually on the curve.
            let b = q.to_bytes();
            let q_p: Option<AffinePoint> = AffinePoint::from_bytes(&b).into();
            assert_eq!(Some(q), q_p);
        }
    }

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEAD_BEEF);
        for _ in 0..100 {
            let p = ProjectivePoint::random(&mut rng);
            let b = point_to_representative(&p, &mut rng);
            let p2 = representative_to_point(&b).expect("should have decoded");

            assert_eq!(p, p2);
        }
    }
}
