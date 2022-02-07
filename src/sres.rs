//! A single-recipient, hybrid cryptosystem.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use secrecy::{ExposeSecret, SecretVec};

use crate::akem;
use crate::constants::{MAC_LEN, SCALAR_LEN};
use crate::strobe::Protocol;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = SCALAR_LEN + SCALAR_LEN + MAC_LEN;

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

    // Encapsulate the plaintext, returning an encryption key and two KEM scalars.
    let (k, (r, s)) = akem::encapsulate(d_s, q_s, q_r, plaintext);

    // Mask and send both KEM scalars as cleartext.
    out.extend(sres.send("challenge-scalar", &mask_scalar(&r)));
    out.extend(sres.send("proof-scalar", &mask_scalar(&s)));

    // Key the protocol with the AKEM key.
    sres.key("shared-secret", k.expose_secret());

    // Encrypt and send the plaintext.
    out.extend(sres.encrypt("plaintext", plaintext));

    // Generate and send a MAC.
    out.extend(sres.mac("mac"));

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
    let (r, ciphertext) = ciphertext.split_at(SCALAR_LEN);
    let (s, ciphertext) = ciphertext.split_at(SCALAR_LEN);
    let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - MAC_LEN);

    // Initialize the protocol.
    let mut sres = Protocol::new("veil.sres");

    // Receive the sender's public key as cleartext.
    sres.receive("sender-public-key", q_s.compress().as_bytes());

    // Send the receiver's public key as cleartext.
    sres.send("receiver-public-key", q_r.compress().as_bytes());

    // Receive the masked KEM scalars as cleartext
    let r = sres.receive("challenge-scalar", r);
    let s = sres.receive("proof-scalar", s);

    // Unmask the scalars.
    let r = unmask_scalar(r.try_into().expect("invalid scalar len"));
    let s = unmask_scalar(s.try_into().expect("invalid scalar len"));

    // Decapsulate the AKEM key and decrypt the ciphertext.
    akem::decapsulate(d_r, q_r, q_s, &r, &s, |k| {
        // Key the protocol with the AKEM key.
        sres.key("shared-secret", k.expose_secret());

        // Decrypt the ciphertext.
        let plaintext = sres.decrypt("plaintext", ciphertext);

        // Verify the MAC.
        sres.verify_mac("mac", mac)?;

        Some(plaintext)
    })
}

/// Return a randomly masked, encoded form of `s` indistinguishable from random noise.
#[inline]
fn mask_scalar(s: &Scalar) -> [u8; 32] {
    // Use the top four bits of a random byte to mask the top byte of the encoded scalar.
    let mask = rand::thread_rng().gen::<u8>() & 0b1111_0000;

    // Encode the scalar canonically.
    let mut b = s.to_bytes();

    // Mask the top byte.
    b[31] |= mask;

    // Return the masked value.
    b
}

/// Unmask the output of `mask_scalar`.
#[inline]
fn unmask_scalar(mut b: [u8; 32]) -> Scalar {
    // Ensure the top four bits aren't set.
    b[31] &= 0b0000_1111;

    // Decode the scalar canonically.
    Scalar::from_canonical_bytes(b).expect("invalid unmasked scalar")
}

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

    #[test]
    fn scalar_masking() {
        let s = Scalar::random(&mut rand::thread_rng());
        let masked = mask_scalar(&s);
        let unmasked = unmask_scalar(masked);
        assert_eq!(s, unmasked);
    }

    pub fn setup() -> (Scalar, RistrettoPoint, Scalar, RistrettoPoint) {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        (d_s, q_s, d_r, q_r)
    }
}
