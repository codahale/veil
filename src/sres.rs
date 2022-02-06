//! A single-recipient, hybrid cryptosystem.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret, SecretVec, Zeroize};

use crate::akem;
use crate::constants::{MAC_LEN, SCALAR_LEN};
use crate::strobe::Protocol;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = NONCE_LEN + SCALAR_LEN + SCALAR_LEN + MAC_LEN + MAC_LEN;

/// Given the sender's key pair, the recipient's public key, and a plaintext, encrypts the given
/// plaintext and returns the ciphertext.
pub fn encrypt(
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    q_r: &RistrettoPoint,
    plaintext: &[u8],
) -> Vec<u8> {
    // Allocate an output buffer.
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Initialize the protocol.
    let mut sres = Protocol::new("veil.sres");

    // Send the sender's public key as cleartext.
    sres.send("sender-public-key", q_s.compress().as_bytes());

    // Receive the receiver's public key as cleartext.
    sres.receive("receiver-public-key", q_r.compress().as_bytes());

    // Generate a random nonce and send it as cleartext.
    let mut nonce = vec![0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    out.extend(sres.send("nonce", &nonce));

    // Calculate the static Diffie-Hellman shared secret and use it to key the protocol.
    let z = diffie_hellman(d_s, q_r);
    sres.key("dh-shared-secret", z.expose_secret());

    // Encapsulate the plaintext, returning an encryption key and a two-scalar signature.
    let (k, (r, s)) = akem::encapsulate(d_s, q_s, q_r, plaintext);

    // Encrypt and send both signature scalars.
    out.extend(sres.encrypt("challenge-scalar", r.as_bytes()));
    out.extend(sres.encrypt("proof-scalar", s.as_bytes()));

    // Send the MAC of the scalars.
    out.extend(sres.mac("dh-mac"));

    // Key the protocol with the AKEM key.
    sres.key("akem-shared-secret", k.expose_secret());

    // Encrypt and send the plaintext.
    out.extend(sres.encrypt("plaintext", plaintext));

    // Generate and send a MAC of the plaintext.
    out.extend(sres.mac("akem-mac"));

    out
}

/// Given the recipient's key pair, the sender's public key, and a ciphertext, decrypts the given
/// ciphertext and returns the plaintext iff the ciphertext was encrypted for the recipient by the
/// sender.
pub fn decrypt(
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
    ciphertext: &[u8],
) -> Option<SecretVec<u8>> {
    // Check for too-small ciphertexts.
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (nonce, ciphertext) = ciphertext.split_at(NONCE_LEN);
    let (r, ciphertext) = ciphertext.split_at(SCALAR_LEN);
    let (s, ciphertext) = ciphertext.split_at(SCALAR_LEN);
    let (dh_mac, ciphertext) = ciphertext.split_at(MAC_LEN);
    let (ciphertext, akem_mac) = ciphertext.split_at(ciphertext.len() - MAC_LEN);

    // Initialize the protocol.
    let mut sres = Protocol::new("veil.sres");

    // Receive the sender's public key as cleartext.
    sres.receive("sender-public-key", q_s.compress().as_bytes());

    // Send the receiver's public key as cleartext.
    sres.send("receiver-public-key", q_r.compress().as_bytes());

    // Receive the nonce as plaintext.
    sres.receive("nonce", nonce);

    // Calculate the static Diffie-Hellman shared secret and use it to key the protocol.
    let z = diffie_hellman(d_r, q_s);
    sres.key("dh-shared-secret", z.expose_secret());

    // Decrypt the veil.akem scalars.
    let r = sres.decrypt("challenge-scalar", r);
    let s = sres.decrypt("proof-scalar", s);

    // Verify the MAC of the scalars.
    sres.verify_mac("dh-mac", dh_mac);

    // Decode the scalars, having authenticated them with the MAC.
    let r = r.expose_secret().to_vec().try_into().expect("invalid scalar len");
    let r = Scalar::from_canonical_bytes(r)?;
    let s = s.expose_secret().to_vec().try_into().expect("invalid scalar len");
    let s = Scalar::from_canonical_bytes(s)?;

    // Decapsulate the AKEM key and decrypt the ciphertext.
    akem::decapsulate(d_r, q_r, q_s, &r, &s, |k| {
        // Key the protocol with the AKEM key.
        sres.key("akem-shared-secret", k.expose_secret());

        // Decrypt the ciphertext.
        let plaintext = sres.decrypt("plaintext", ciphertext);

        // Verify the MAC.
        sres.verify_mac("akem-mac", akem_mac)?;

        Some(plaintext)
    })
}

#[must_use]
fn diffie_hellman(d: &Scalar, q: &RistrettoPoint) -> Secret<[u8; 32]> {
    let mut z = q * d;
    if z.is_identity() {
        panic!("non-contributory ECDH");
    }

    let km = z.compress().to_bytes().into();
    z.zeroize();
    km
}

const NONCE_LEN: usize = 16;

#[cfg(test)]
pub mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;

    use super::*;

    #[test]
    fn round_trip() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let recovered = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert!(recovered.is_some());
        assert_eq!(plaintext.as_slice(), recovered.unwrap().expose_secret());
    }

    #[test]
    fn wrong_recipient_private_key() {
        let (d_s, q_s, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let d_r = Scalar::random(&mut rand::thread_rng());

        assert!(decrypt(&d_r, &q_r, &q_s, &ciphertext).is_none());
    }

    #[test]
    fn wrong_recipient_public_key() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let q_r = RistrettoPoint::random(&mut rand::thread_rng());

        assert!(decrypt(&d_r, &q_r, &q_s, &ciphertext).is_none());
    }

    #[test]
    fn wrong_sender_public_key() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let q_s = RistrettoPoint::random(&mut rand::thread_rng());

        assert!(decrypt(&d_r, &q_r, &q_s, &ciphertext).is_none());
    }

    #[test]
    fn flip_every_bit() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                assert!(decrypt(&d_r, &q_r, &q_s, &ciphertext).is_none());
            }
        }
    }

    pub fn setup() -> (Scalar, RistrettoPoint, Scalar, RistrettoPoint) {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        (d_s, q_s, d_r, q_r)
    }
}
