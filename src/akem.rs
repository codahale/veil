use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use strobe_rs::{SecParam, Strobe};

use crate::constants::{MAC_LEN, POINT_LEN};
use crate::dvsig;
use crate::strobe::StrobeExt;

/// The number of bytes encapsulation adds to a plaintext.
pub const OVERHEAD: usize = POINT_LEN * 3 + MAC_LEN;

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
    // Sign the ephemeral public key with the recipient as the designated verifier.
    let m_q_e = q_e.compress().to_bytes();
    let (u, k) = dvsig::sign(d_s, q_s, q_r, &m_q_e);

    // Allocate a buffer for output and fill it with the ephemeral public key, the signature, and
    // the plaintext.
    let mut out = vec![0u8; POINT_LEN * 3 + plaintext.len() + MAC_LEN];
    out[..POINT_LEN].copy_from_slice(&m_q_e);
    out[POINT_LEN..POINT_LEN * 2].copy_from_slice(u.compress().as_bytes());
    out[POINT_LEN * 2..POINT_LEN * 3].copy_from_slice(k.compress().as_bytes());
    out[POINT_LEN * 3..POINT_LEN * 3 + plaintext.len()].copy_from_slice(plaintext);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B128);
    akem.meta_ad_u32(MAC_LEN as u32);

    // Include the sender and receiver as associated data.
    akem.ad_point(q_s);
    akem.ad_point(q_r);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key(&diffie_hellman(d_s, q_r), false);

    // Encrypt the ephemeral public key and signature.
    akem.send_enc(&mut out[..POINT_LEN * 3], false);

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.key(&diffie_hellman(d_e, q_r), false);

    // Encrypt the plaintext.
    akem.send_enc(&mut out[POINT_LEN * 3..POINT_LEN * 3 + plaintext.len()], false);

    // Calculate a MAC of the entire operation transcript.
    akem.send_mac(&mut out[POINT_LEN * 3 + plaintext.len()..], false);

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
    if ciphertext.len() < POINT_LEN * 3 + MAC_LEN {
        return None;
    }

    // Break the input up into its components.
    let mut pk = Vec::from(ciphertext);
    let mut ciphertext = pk.split_off(POINT_LEN * 3);
    let mut mac = ciphertext.split_off(ciphertext.len() - MAC_LEN);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B128);
    akem.meta_ad_u32(MAC_LEN as u32);

    // Include the sender and receiver as associated data.
    akem.ad_point(q_s);
    akem.ad_point(q_r);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key(&diffie_hellman(d_r, q_s), false);

    // Decrypt the ephemeral public key and signature.
    akem.recv_enc(&mut pk, false);

    // Decode the signature points.
    let u = CompressedRistretto::from_slice(&pk[POINT_LEN..POINT_LEN * 2]).decompress()?;
    let k = CompressedRistretto::from_slice(&pk[POINT_LEN * 2..POINT_LEN * 3]).decompress()?;

    // Verify the signature of the ephemeral public key.
    if !dvsig::verify(d_r, q_r, q_s, &pk[..POINT_LEN], (u, k)) {
        return None;
    }

    // Decode the ephemeral public key.
    let q_e = CompressedRistretto::from_slice(&pk[..POINT_LEN]).decompress()?;

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
pub mod tests {
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
    fn bad_ciphertext() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[36] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_mac() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[64] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    pub fn setup() -> (Scalar, RistrettoPoint, Scalar, RistrettoPoint, Scalar, RistrettoPoint) {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_e = Scalar::random(&mut rand::thread_rng());
        let q_e = &G * &d_e;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        (d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
