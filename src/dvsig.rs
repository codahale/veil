use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::strobe::StrobeExt;

// TODO document this construction and these functions
// https://www.iacr.org/archive/pkc2004/29470087/29470087.pdf

pub fn sign(
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    q_v: &RistrettoPoint,
    m: &[u8],
) -> (RistrettoPoint, RistrettoPoint) {
    let mut dvsig = Strobe::new(b"veil.dvsig", SecParam::B128);
    dvsig.ad_point(q_s);
    dvsig.ad_point(q_v);

    let k = dvsig.hedge(d_s.as_bytes(), StrobeExt::prf_scalar);
    let u = &G * &k;

    dvsig.ad(m, false);
    dvsig.ad_point(&u);

    let r = dvsig.prf_scalar();
    let s = k + (r * d_s);

    (u, q_v * s)
}

pub fn verify(
    d_v: &Scalar,
    q_v: &RistrettoPoint,
    q_s: &RistrettoPoint,
    m: &[u8],
    (u, k): (RistrettoPoint, RistrettoPoint),
) -> bool {
    let mut dvsig = Strobe::new(b"veil.dvsig", SecParam::B128);
    dvsig.ad_point(q_s);
    dvsig.ad_point(q_v);

    dvsig.ad(m, false);
    dvsig.ad_point(&u);

    let r = dvsig.prf_scalar();
    let k_p = (u + (q_s * r)) * d_v;

    k == k_p
}

#[cfg(test)]
mod test {
    use crate::akem::tests::setup;

    use super::*;

    #[test]
    fn sign_and_verify() {
        let (d_s, q_s, d_v, q_v, _, _) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(verify(&d_v, &q_v, &q_s, b"ok this is good", sig));
    }

    #[test]
    fn wrong_verifier_private_key() {
        let (d_s, q_s, _, q_v, s, _) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(!verify(&s, &q_v, &q_s, b"ok this is good", sig));
    }

    #[test]
    fn wrong_verifier_public_key() {
        let (d_s, q_s, d_v, q_v, _, x) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(!verify(&d_v, &x, &q_s, b"ok this is good", sig));
    }

    #[test]
    fn wrong_signer_public_key() {
        let (d_s, q_s, d_v, q_v, _, x) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(!verify(&d_v, &q_v, &x, b"ok this is good", sig));
    }

    #[test]
    fn wrong_message() {
        let (d_s, q_s, d_v, q_v, _, _) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(!verify(&d_v, &q_v, &q_s, b"ok this is NOT good", sig));
    }

    #[test]
    fn wrong_sig1() {
        let (d_s, q_s, d_v, q_v, _, x) = setup();
        let (_, k) = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(!verify(&d_v, &q_v, &q_s, b"ok this is good", (x, k)));
    }

    #[test]
    fn wrong_sig2() {
        let (d_s, q_s, d_v, q_v, _, x) = setup();
        let (u, _) = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(!verify(&d_v, &q_v, &q_s, b"ok this is good", (u, x)));
    }
}
