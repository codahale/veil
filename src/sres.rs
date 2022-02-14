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
        // Also hedge with the plaintext message to ensure (d_s, plaintext, t) uniqueness.
        clone.absorb(plaintext);
        clone.squeeze_scalar()
    });

    // Re-key with the shared secret.
    let k = q_r * x.expose_secret();
    sres.rekey(compress_secret(k).expose_secret());

    // Encrypt the plaintext.
    out.extend(sres.encrypt_unauthenticated(plaintext));

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
    let mut mr = r.to_bytes();
    mr[31] |= (mask >> 4) << 4;
    out.extend(&mr);

    // Mask the proof scalar with the bottom 4 bits of the mask byte.
    let mut ms = s.to_bytes();
    ms[31] |= mask << 4;
    out.extend(&ms);

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

    // Calculate the masking byte and absorb it.
    let mask = (mr[31] & 0xF0) | ((ms[31] & 0xF0) >> 4);
    sres.absorb(&[mask]);

    // Unmask the scalars.
    let mut r: [u8; 32] = mr.try_into().expect("invalid scalar len");
    r[31] &= 0x0F;
    let r = Scalar::from_canonical_bytes(r).expect("invalid scalar mask");

    let mut s: [u8; 32] = ms.try_into().expect("invalid scalar len");
    s[31] &= 0x0F;
    let s = Scalar::from_canonical_bytes(s).expect("invalid scalar mask");

    // Re-key with the shared secret.
    let k = (q_s + (&G * &r)) * (d_r * s);
    sres.rekey(compress_secret(k).expose_secret());

    // Decrypt the ciphertext.
    let plaintext = sres.decrypt_unauthenticated(ciphertext);

    // Ratchet the protocol state.
    sres.ratchet();

    // If the counterfactual challenge scalar is valid, return the plaintext.
    if r == sres.squeeze_scalar() {
        Some(plaintext)
    } else {
        None
    }
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

        let d_r = Scalar::random(&mut rand::thread_rng());

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
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        (d_s, q_s, d_r, q_r)
    }
}
