use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use secrecy::{ExposeSecret, Secret, Zeroize};

use crate::constants::{MAC_LEN, POINT_LEN};
use crate::strobe::Protocol;

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
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Initialize the protocol.
    let mut akem = Protocol::new("veil.akem");

    // Include the sender and receiver as associated data.
    akem.send("sender-public-key", q_s.compress().as_bytes());

    // Receive the receiver's public key as cleartext.
    akem.receive("receiver-public-key", q_r.compress().as_bytes());

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key("static-shared-secret", diffie_hellman(d_s, q_r).expose_secret());

    // Encode and encrypt the ephemeral public key.
    out.extend(akem.encrypt("ephemeral-public-key", q_e.compress().as_bytes()));

    // Hedge a commitment scalar and calculate the commitment point.
    let k = akem.hedge(d_s.as_bytes(), |clone| clone.prf_scalar("commitment-scalar"));
    let u = &G * k.expose_secret();

    // Encode the commitment point in the buffer and encrypt it.
    out.extend(akem.encrypt("commitment-point", u.compress().as_bytes()));

    // Extract a challenge scalar and calculate a proof scalar.
    let r = akem.prf_scalar("challenge-scalar");
    let s = d_s * r + k.expose_secret();

    // Convert the proof scalar to a designated-verifier proof point with the recipient's public
    // key.
    let k = q_r * s;

    // Encode the signature point in the buffer and encrypt it.
    out.extend(akem.encrypt("signature-point", k.compress().as_bytes()));

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.key("ephemeral-shared-secret", diffie_hellman(d_e, q_r).expose_secret());

    // Encrypt the plaintext.
    out.extend(akem.encrypt("ciphertext", plaintext));

    // Calculate a MAC of the entire operation transcript.
    out.extend(akem.mac::<MAC_LEN>("mac"));

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

    // Initialize the protocol.
    let mut akem = Protocol::new("veil.akem");

    // Receive the sender's public key as cleartext.
    akem.receive("sender-public-key", q_s.compress().as_bytes());

    // Send the receiver's public key as cleartext.
    akem.send("receiver-public-key", q_r.compress().as_bytes());

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key("static-shared-secret", diffie_hellman(d_r, q_s).expose_secret());

    // Decrypt and decode the ephemeral public key.
    let (q_e, ciphertext) = ciphertext.split_at(POINT_LEN);
    let q_e = akem.decrypt("ephemeral-public-key", q_e);
    let q_e = CompressedRistretto::from_slice(&q_e).decompress()?;

    // Decrypt and decode the commitment point.
    let (u, ciphertext) = ciphertext.split_at(POINT_LEN);
    let u = akem.decrypt("commitment-point", u);
    let u = CompressedRistretto::from_slice(&u).decompress()?;

    // Extract a challenge scalar.
    let r = akem.prf_scalar("challenge-scalar");

    // Decrypt and decode the signature point.
    let (k, ciphertext) = ciphertext.split_at(POINT_LEN);
    let k = akem.decrypt("signature-point", k);
    let k = CompressedRistretto::from_slice(&k).decompress()?;

    // Calculate the counterfactual signature point and check k' == k.
    let k_p = (u + (q_s * r)) * d_r;
    if k_p != k {
        return None;
    }

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.key("ephemeral-shared-secret", diffie_hellman(d_r, &q_e).expose_secret());

    // Decrypt the plaintext.
    let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - MAC_LEN);
    let plaintext = akem.decrypt("ciphertext", ciphertext);

    // Verify the MAC.
    akem.verify_mac("mac", mac)?;

    // Return the ephemeral public key and the plaintext.
    Some((q_e, plaintext))
}

#[must_use]
fn diffie_hellman(d: &Scalar, q: &RistrettoPoint) -> Secret<[u8; 32]> {
    let mut zz = q * d;
    if zz.is_identity() {
        panic!("non-contributory ECDH");
    }

    let km = zz.compress().to_bytes().into();
    zz.zeroize();
    km
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
