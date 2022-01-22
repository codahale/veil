use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use strobe_rs::{SecParam, Strobe};

use crate::constants::{MAC_LEN, POINT_LEN};
use crate::strobe::StrobeExt;

/// The number of bytes encapsulation adds to a plaintext.
pub const OVERHEAD: usize = POINT_LEN + POINT_LEN + POINT_LEN + MAC_LEN;

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
    // Allocate a buffer for output and fill it with the ephemeral public key and the plaintext.
    let mut out = vec![0u8; OVERHEAD + plaintext.len()];
    out[..POINT_LEN].copy_from_slice(q_e.compress().as_bytes());
    out[POINT_LEN * 3..POINT_LEN * 3 + plaintext.len()].copy_from_slice(plaintext);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B128);

    // Include the sender and receiver as associated data.
    akem.metadata("sender-public-key", &(POINT_LEN as u32));
    akem.send_clr(q_s.compress().as_bytes(), false);

    // Receive the receiver's public key as cleartext.
    akem.metadata("receiver-public-key", &(POINT_LEN as u32));
    akem.recv_clr(q_r.compress().as_bytes(), false);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.metadata("static-shared-secret", &(POINT_LEN as u32));
    akem.key(&diffie_hellman(d_s, q_r), false);

    // Encrypt the ephemeral public key.
    akem.metadata("ephemeral-public-key", &(POINT_LEN as u32));
    akem.send_enc(&mut out[..POINT_LEN], false);

    // Hedge a commitment scalar and calculate the commitment point.
    let k = akem.hedge(d_s.as_bytes(), |clone| clone.prf_scalar("commitment-scalar"));
    let u = &G * &k;

    // Encode the commitment point in the buffer and encrypt it.
    out[POINT_LEN..POINT_LEN * 2].copy_from_slice(u.compress().as_bytes());
    akem.metadata("commitment-point", &(POINT_LEN as u32));
    akem.send_enc(&mut out[POINT_LEN..POINT_LEN * 2], false);

    // Extract a challenge scalar and calculate a signature scalar.
    let r = akem.prf_scalar("challenge-scalar");
    let s = k + (r * d_s);

    // Convert the signature scalar to a signature point with the recipient's public key.
    let k = q_r * s;

    // Encode the signature point in the buffer and encrypt it.
    out[POINT_LEN * 2..POINT_LEN * 3].copy_from_slice(k.compress().as_bytes());
    akem.metadata("signature-point", &(POINT_LEN as u32));
    akem.send_enc(&mut out[POINT_LEN * 2..POINT_LEN * 3], false);

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.metadata("ephemeral-shared-secret", &(POINT_LEN as u32));
    akem.key(&diffie_hellman(d_e, q_r), false);

    // Encrypt the plaintext.
    akem.metadata("ciphertext", &(plaintext.len() as u32));
    akem.send_enc(&mut out[POINT_LEN * 3..POINT_LEN * 3 + plaintext.len()], false);

    // Calculate a MAC of the entire operation transcript.
    akem.metadata("mac", &(MAC_LEN as u32));
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
    // Valid ciphertexts will have a minimum length.
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Break the input up into its components.
    let mut q_e = Vec::from(ciphertext);
    let mut u = q_e.split_off(POINT_LEN);
    let mut k = u.split_off(POINT_LEN);
    let mut ciphertext = k.split_off(POINT_LEN);
    let mut mac = ciphertext.split_off(ciphertext.len() - MAC_LEN);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B128);

    // Receive the sender's public key as cleartext.
    akem.metadata("sender-public-key", &(POINT_LEN as u32));
    akem.recv_clr(q_s.compress().as_bytes(), false);

    // Send the receiver's public key as cleartext.
    akem.metadata("receiver-public-key", &(POINT_LEN as u32));
    akem.send_clr(q_r.compress().as_bytes(), false);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.metadata("static-shared-secret", &(POINT_LEN as u32));
    akem.key(&diffie_hellman(d_r, q_s), false);

    // Decrypt and decode the ephemeral public key.
    akem.metadata("ephemeral-public-key", &(POINT_LEN as u32));
    akem.recv_enc(&mut q_e, false);
    let q_e = CompressedRistretto::from_slice(&q_e).decompress()?;

    // Decrypt and decode the commitment point.
    akem.metadata("commitment-point", &(POINT_LEN as u32));
    akem.recv_enc(&mut u, false);
    let u = CompressedRistretto::from_slice(&u).decompress()?;

    // Extract a challenge scalar.
    let r = akem.prf_scalar("challenge-scalar");

    // Decrypt and decode the signature point.
    akem.metadata("signature-point", &(POINT_LEN as u32));
    akem.recv_enc(&mut k, false);
    let k = CompressedRistretto::from_slice(&k).decompress()?;

    // Calculate the counterfactual signature point and check k' == k.
    let k_p = (u + (q_s * r)) * d_r;
    if k_p != k {
        return None;
    }

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.metadata("ephemeral-shared-secret", &(POINT_LEN as u32));
    akem.key(&diffie_hellman(d_r, &q_e), false);

    // Decrypt the plaintext.
    akem.metadata("ciphertext", &(ciphertext.len() as u32));
    akem.recv_enc(&mut ciphertext, false);
    let plaintext = ciphertext;

    // Verify the MAC.
    akem.metadata("mac", &(MAC_LEN as u32));
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
    fn bad_u() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[POINT_LEN + 1] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_k() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[POINT_LEN * 2 + 1] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_ciphertext() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[POINT_LEN * 3 + 1] ^= 1;

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
