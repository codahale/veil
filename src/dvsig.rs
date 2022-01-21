use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::constants::POINT_LEN;
use crate::strobe::StrobeExt;

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = POINT_LEN * 2;

/// Create a signature of message `m` which is only verifiable with the verifier's private key.
pub fn sign(
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    q_v: &RistrettoPoint,
    m: &[u8],
) -> [u8; SIGNATURE_LEN] {
    // Initialize the protocol.
    let mut dvsig = Strobe::new(b"veil.dvsig", SecParam::B128);

    // Include the signer and verifier as associated data.
    dvsig.ad_point(q_s);
    dvsig.ad_point(q_v);

    // Hedge a nonce scalar and calculate the commitment point.
    let k = dvsig.hedge(d_s.as_bytes(), StrobeExt::prf_scalar);
    let u = &G * &k;

    // Include the message and commitment point as associated data.
    dvsig.ad(m, false);
    dvsig.ad_point(&u);

    // Extract a challenge scalar and calculate a signature scalar.
    let r = dvsig.prf_scalar();
    let s = k + (r * d_s);

    // Convert the signature scalar to a signature point with the verifier's public key.
    let k = q_v * s;

    // Encode the commitment point and signature point and return.
    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..POINT_LEN].copy_from_slice(u.compress().as_bytes());
    sig[POINT_LEN..].copy_from_slice(k.compress().as_bytes());
    sig
}

/// Verify the signature and message. Returns `true` iff the signature was created by the signer of
/// the given message with the designated verifier.
pub fn verify(
    d_v: &Scalar,
    q_v: &RistrettoPoint,
    q_s: &RistrettoPoint,
    m: &[u8],
    sig: [u8; SIGNATURE_LEN],
) -> bool {
    // Decode the commitment point and signature point, if possible.
    let (u, k) = match (
        CompressedRistretto::from_slice(&sig[..POINT_LEN]).decompress(),
        CompressedRistretto::from_slice(&sig[POINT_LEN..]).decompress(),
    ) {
        (Some(u), Some(k)) => (u, k),
        _ => return false,
    };

    // Initialize the protocol.
    let mut dvsig = Strobe::new(b"veil.dvsig", SecParam::B128);

    // Include the signer and verifier as associated data.
    dvsig.ad_point(q_s);
    dvsig.ad_point(q_v);

    // Include the message and commitment point as associated data.
    dvsig.ad(m, false);
    dvsig.ad_point(&u);

    // Extract a challenge scalar and calculate the signature point.
    let r = dvsig.prf_scalar();
    let k_p = (u + (q_s * r)) * d_v;

    // Return true iff k' == k.
    k == k_p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let (d_s, q_s, d_v, q_v) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(verify(&d_v, &q_v, &q_s, b"ok this is good", sig));
    }

    #[test]
    fn wrong_verifier_private_key() {
        let (d_s, q_s, _, q_v) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");
        let s = Scalar::random(&mut rand::thread_rng());

        assert!(!verify(&s, &q_v, &q_s, b"ok this is good", sig));
    }

    #[test]
    fn wrong_verifier_public_key() {
        let (d_s, q_s, d_v, q_v) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");
        let x = RistrettoPoint::random(&mut rand::thread_rng());

        assert!(!verify(&d_v, &x, &q_s, b"ok this is good", sig));
    }

    #[test]
    fn wrong_signer_public_key() {
        let (d_s, q_s, d_v, q_v) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");
        let x = RistrettoPoint::random(&mut rand::thread_rng());

        assert!(!verify(&d_v, &q_v, &x, b"ok this is good", sig));
    }

    #[test]
    fn wrong_message() {
        let (d_s, q_s, d_v, q_v) = setup();
        let sig = sign(&d_s, &q_s, &q_v, b"ok this is good");

        assert!(!verify(&d_v, &q_v, &q_s, b"ok this is NOT good", sig));
    }

    #[test]
    fn wrong_sig1() {
        let (d_s, q_s, d_v, q_v) = setup();
        let mut sig = sign(&d_s, &q_s, &q_v, b"ok this is good");
        sig[14] ^= 1;

        assert!(!verify(&d_v, &q_v, &q_s, b"ok this is good", sig));
    }

    #[test]
    fn wrong_sig2() {
        let (d_s, q_s, d_v, q_v) = setup();
        let mut sig = sign(&d_s, &q_s, &q_v, b"ok this is good");
        sig[54] ^= 1;

        assert!(!verify(&d_v, &q_v, &q_s, b"ok this is good", sig));
    }

    fn setup() -> (Scalar, RistrettoPoint, Scalar, RistrettoPoint) {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        (d_s, q_s, d_r, q_r)
    }
}
