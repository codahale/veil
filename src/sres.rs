//! An insider-secure hybrid signcryption implementation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use secrecy::{ExposeSecret, Secret, SecretVec};

use crate::constants::SCALAR_LEN;
use crate::duplex::Duplex;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = SCALAR_LEN + SCALAR_LEN;

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

    // Initialize a duplex.
    let mut sres = Duplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(q_s.compress().as_bytes());

    // Absorb the receiver's public key.
    sres.absorb(q_r.compress().as_bytes());

    // Generate and absorb a random masking byte.
    let mask = rand::thread_rng().gen::<u8>();
    sres.absorb(&[mask]);

    // Generate a secret commitment scalar.
    let x = sres.hedge(d_s.as_bytes(), |clone| {
        // Also hedge with the plaintext message to ensure (d_s, plaintext, x) uniqueness.
        clone.absorb(plaintext);
        clone.squeeze_scalar()
    });

    // Re-key with the shared secret.
    let k = q_r * x.expose_secret();
    sres.rekey(compress_secret(k).expose_secret());

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Ratchet the duplex state to prevent rollback.
    sres.ratchet();

    // Squeeze a challenge scalar.
    let r = sres.squeeze_scalar();

    // Calculate the proof scalar.
    let s = {
        let y = r + d_s;
        if y == Scalar::zero() {
            // If the proof scalar is undefined, try again with a different commitment scalar.
            return encrypt(d_s, q_s, q_r, plaintext);
        }
        x.expose_secret() * y.invert()
    };

    // Mask the challenge scalar with the top 4 bits of the mask byte.
    out.extend(mask_scalar(r, mask & 0xF0));

    // Mask the proof scalar with the bottom 4 bits of the mask byte.
    out.extend(mask_scalar(s, mask << 4));

    // Return the full ciphertext.
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
    let (ciphertext, mr) = ciphertext.split_at(ciphertext.len() - OVERHEAD);
    let (mr, ms) = mr.split_at(SCALAR_LEN);

    // Initialize a duplex.
    let mut sres = Duplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(q_s.compress().as_bytes());

    // Absorb the receiver's public key.
    sres.absorb(q_r.compress().as_bytes());

    // Unmask the scalars.
    let (r, mr) = unmask_scalar(mr);
    let (s, ms) = unmask_scalar(ms);

    // Calculate the masking byte and absorb it.
    sres.absorb(&[mr | (ms >> 4)]);

    // Re-key with the shared secret.
    let k = (q_s + (&G * &r)) * (d_r * s);
    sres.rekey(compress_secret(k).expose_secret());

    // Decrypt the ciphertext.
    let plaintext = sres.decrypt(ciphertext);

    // Ratchet the protocol state.
    sres.ratchet();

    // If the counterfactual challenge scalar is valid, return the plaintext.
    if r == sres.squeeze_scalar() {
        Some(plaintext.trust())
    } else {
        None
    }
}

// Use the bottom four bits of `mask` to mask the top four bits of `v`.
#[inline]
fn mask_scalar(v: Scalar, mask: u8) -> [u8; 32] {
    let mut b = v.to_bytes();
    b[31] |= mask;
    b
}

// Zero out the top four bits of `b` and decode it as a scalar, returning the scalar and the mask.
#[inline]
fn unmask_scalar(b: &[u8]) -> (Scalar, u8) {
    let mut v: [u8; 32] = b.try_into().expect("invalid scalar len");
    let m = v[31] & 0xF0;
    v[31] &= 0x0F;
    (Scalar::from_canonical_bytes(v).expect("invalid scalar mask"), m)
}

/// Encode a shared secret point in a way which zeroizes all temporary values.
#[inline]
fn compress_secret(z: RistrettoPoint) -> Secret<[u8; 32]> {
    let z = Secret::new(z);
    let z = Secret::new(z.expose_secret().compress());
    Secret::new(z.expose_secret().to_bytes())
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;

    use super::*;

    #[test]
    fn round_trip() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let recovered = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        let recovered = recovered.map(|s| s.expose_secret().to_vec());
        assert_eq!(Some(plaintext.to_vec()), recovered, "invalid plaintext");
    }

    #[test]
    fn wrong_recipient_private_key() {
        let (d_s, q_s, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let d_r = Scalar::from_bytes_mod_order(rand::thread_rng().gen());

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        let plaintext = plaintext.map(|s| s.expose_secret().to_vec());
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_recipient_public_key() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let q_r = RistrettoPoint::random(&mut rand::thread_rng());

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        let plaintext = plaintext.map(|s| s.expose_secret().to_vec());
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let q_s = RistrettoPoint::random(&mut rand::thread_rng());

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        let plaintext = plaintext.map(|s| s.expose_secret().to_vec());
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
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
                assert!(
                    decrypt(&d_r, &q_r, &q_s, &ciphertext).is_none(),
                    "bit flip at byte {}, bit {} produced a valid message",
                    i,
                    j
                );
            }
        }
    }

    fn setup() -> (Scalar, RistrettoPoint, Scalar, RistrettoPoint) {
        let d_s = Scalar::from_bytes_mod_order(rand::thread_rng().gen());
        let q_s = &G * &d_s;

        let d_r = Scalar::from_bytes_mod_order(rand::thread_rng().gen());
        let q_r = &G * &d_r;

        (d_s, q_s, d_r, q_r)
    }
}
