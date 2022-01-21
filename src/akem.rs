use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use strobe_rs::{SecParam, Strobe};

use crate::constants::{MAC_LEN, POINT_LEN};
use crate::dvsig;
use crate::dvsig::SIGNATURE_LEN;
use crate::strobe::StrobeExt;

/// The number of bytes encapsulation adds to a plaintext.
pub const OVERHEAD: usize = POINT_LEN + SIGNATURE_LEN + MAC_LEN;

/// Given a sender's key pair, an ephemeral key pair, and the recipient's public key, encrypt the
/// given plaintext.
#[must_use]
pub fn encapsulate(
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    d_e: &Scalar,
    q_e: &RistrettoPoint,
    q_r: &RistrettoPoint,
    plaintext: &[u8],
) -> Vec<u8> {
    // TODO document this addition
    // Allocate a buffer for output and fill it with the ephemeral public key, a signature of the
    // ephemeral public key with the recipient as the designated verifier, and the plaintext.
    let mut out = vec![0u8; OVERHEAD + plaintext.len()];
    out[..POINT_LEN].copy_from_slice(q_e.compress().as_bytes());
    let sig = dvsig::sign(d_s, q_s, q_r, &out[..POINT_LEN]);
    out[POINT_LEN..POINT_LEN + SIGNATURE_LEN].copy_from_slice(&sig);
    out[POINT_LEN + SIGNATURE_LEN..POINT_LEN + SIGNATURE_LEN + plaintext.len()]
        .copy_from_slice(plaintext);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B128);
    akem.meta_ad_u32(MAC_LEN as u32);

    // Include the sender and receiver as associated data.
    akem.ad_point(q_s);
    akem.ad_point(q_r);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key(&diffie_hellman(d_s, q_r), false);

    // Encrypt the ephemeral public key.
    akem.send_enc(&mut out[..POINT_LEN], false);

    // Encrypt the signature of the ephemeral public key.
    akem.send_enc(&mut out[POINT_LEN..POINT_LEN + SIGNATURE_LEN], false);

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.key(&diffie_hellman(d_e, q_r), false);

    // Encrypt the plaintext.
    akem.send_enc(
        &mut out[POINT_LEN + SIGNATURE_LEN..POINT_LEN + SIGNATURE_LEN + plaintext.len()],
        false,
    );

    // Calculate a MAC of the entire operation transcript.
    akem.send_mac(&mut out[POINT_LEN + SIGNATURE_LEN + plaintext.len()..], false);

    // Return the encrypted ephemeral public key, the ciphertext, and the MAC.
    out
}

/// Given a recipient's key pair and sender's public key, recover the ephemeral public key and
/// plaintext from the given ciphertext.
#[must_use]
pub fn decapsulate(
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
    ciphertext: &[u8],
) -> Option<(RistrettoPoint, Vec<u8>)> {
    // Ensure the ciphertext has a point, a signature, and a MAC, at least.
    if ciphertext.len() < POINT_LEN + SIGNATURE_LEN + MAC_LEN {
        return None;
    }

    // Break the input up into its components.
    let mut q_e = Vec::from(ciphertext);
    let mut sig = q_e.split_off(POINT_LEN);
    let mut ciphertext = sig.split_off(SIGNATURE_LEN);
    let mut mac = ciphertext.split_off(ciphertext.len() - MAC_LEN);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B128);
    akem.meta_ad_u32(MAC_LEN as u32);

    // Include the sender and receiver as associated data.
    akem.ad_point(q_s);
    akem.ad_point(q_r);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key(&diffie_hellman(d_r, q_s), false);

    // Decrypt and decode the ephemeral public key.
    akem.recv_enc(&mut q_e, false);

    // Decrypt and verify the signature.
    akem.recv_enc(&mut sig, false);

    // Verify the signature of the ephemeral public key.
    if !dvsig::verify(d_r, q_r, q_s, &q_e, sig.try_into().expect("invalid sig len")) {
        return None;
    }

    // Decode the ephemeral public key.
    let q_e = CompressedRistretto::from_slice(&q_e).decompress()?;

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.key(&diffie_hellman(d_r, &q_e), false);

    // Decrypt the plaintext.
    akem.recv_enc(&mut ciphertext, false);
    let plaintext = ciphertext;

    // Verify the MAC.
    akem.recv_mac(&mut mac).ok()?;

    // Return the ephemeral public key and the plaintext.
    Some((q_e, plaintext))
}

#[must_use]
fn diffie_hellman(d: &Scalar, q: &RistrettoPoint) -> [u8; 32] {
    let zz = q * d;
    if zz.is_identity() {
        panic!("non-contributory ECDH");
    }

    zz.compress().to_bytes()
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    use super::*;

    #[test]
    fn round_trip() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        let (pk, plaintext) = decapsulate(&d_r, &q_r, &q_s, &ciphertext).expect("decapsulate");

        assert_eq!(q_e, pk);
        assert_eq!(b"this is an example".to_vec(), plaintext);
    }

    #[test]
    fn bad_ephemeral_public_key() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[0] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_signature() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[POINT_LEN + 1] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_ciphertext() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[POINT_LEN + SIGNATURE_LEN + 1] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_mac() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        let n = ciphertext.len() - MAC_LEN + (MAC_LEN / 2);
        ciphertext[n] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    fn setup() -> (Scalar, RistrettoPoint, Scalar, RistrettoPoint, Scalar, RistrettoPoint) {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_e = Scalar::random(&mut rand::thread_rng());
        let q_e = &G * &d_e;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        (d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
