use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::util::{StrobeExt, G};

// https://tools.ietf.org/id/draft-irtf-cfrg-vrf-08.html

pub fn prove(d: &Scalar, q: &RistrettoPoint, alpha: &[u8]) -> (RistrettoPoint, Scalar, Scalar) {
    // Initialize the protocol.
    let mut vrf = Strobe::new(b"veil.vrf", SecParam::B128);

    // Add the public key as authenticated data.
    vrf.ad_point(q);

    // Key with the VRF input.
    vrf.key(alpha, false);

    // Extract a point.
    let h = vrf.prf_point();

    // Calculate the proof point.
    let gamma = h * d;

    // Generate a random nonce and calculate the verification points.
    let k = vrf.hedge(d.as_bytes(), StrobeExt::prf_scalar);
    let u = G * &k;
    let v = h * k;

    // Include the proof point and verification points as authenticated data. Unlike ECVRF, we don't
    // need to include H here, as it is dependent on the protocol's previous state.
    vrf.ad_point(&gamma);
    vrf.ad_point(&u);
    vrf.ad_point(&v);

    // Extract the challenge scalar and calculate the signature scalar.
    let c = vrf.prf_scalar();
    let s = k - (c * d);

    // Return the proof point, challenge scalar, and signature scalar.
    (gamma, c, s)
}

pub fn verify(
    q: &RistrettoPoint,
    alpha: &[u8],
    gamma: &RistrettoPoint,
    c: &Scalar,
    s: &Scalar,
) -> bool {
    // Initialize the protocol.
    let mut vrf = Strobe::new(b"veil.vrf", SecParam::B128);

    // Add the public key as authenticated data.
    vrf.ad_point(q);

    // Key with the VRF input.
    vrf.key(alpha, false);

    // Extract a point.
    let h = vrf.prf_point();

    // Calculate the verification points from the challenge and signature scalars.
    let u = (q * c) + (G * s);
    let v = (gamma * c) + (h * s);

    // Include the proof point and verification points as authenticated data.
    vrf.ad_point(gamma);
    vrf.ad_point(&u);
    vrf.ad_point(&v);

    // Extract the challenge scalar from the protocol.
    let c_p = vrf.prf_scalar();

    // Return true iff c' == c.
    c_p == *c
}

pub fn proof_to_hash(gamma: &RistrettoPoint) -> [u8; 32] {
    let mut vrf = Strobe::new(b"veil.vrf.proof", SecParam::B128);
    vrf.key(gamma.compress().as_bytes(), false);
    vrf.prf_array()
}

#[cfg(test)]
mod test {
    use curve25519_dalek::scalar::Scalar;

    use super::*;

    #[test]
    fn vrf_proofs() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;
        let alpha = b"this is a secret";

        let (gamma, c, s) = prove(&d, &q, alpha);

        assert!(verify(&q, alpha, &gamma, &c, &s));

        let y = Scalar::random(&mut rand::thread_rng());
        let z = RistrettoPoint::random(&mut rand::thread_rng());

        assert!(!verify(&z, alpha, &gamma, &c, &s));
        assert!(!verify(&q, b"this is not a secret", &gamma, &c, &s));
        assert!(!verify(&q, alpha, &z, &c, &s));
        assert!(!verify(&q, alpha, &gamma, &y, &s));
        assert!(!verify(&q, alpha, &gamma, &c, &y));
    }
}
