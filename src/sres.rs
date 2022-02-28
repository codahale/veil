//! An insider-secure hybrid signcryption implementation.

use curve25519_dalek::traits::IsIdentity;
use rand::Rng;

use crate::duplex::Duplex;
use crate::ristretto::{CanonicallyEncoded, G, SCALAR_LEN};
use crate::ristretto::{Point, Scalar};

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = SCALAR_LEN + SCALAR_LEN;

/// Given the sender's key pair, the recipient's public key, and a plaintext, encrypts the given
/// plaintext and returns the ciphertext.
pub fn encrypt(d_s: &Scalar, q_s: &Point, q_r: &Point, plaintext: &[u8]) -> Vec<u8> {
    // Allocate an output buffer.
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Initialize a duplex.
    let mut sres = Duplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(&q_s.to_canonical_encoding());

    // Absorb the receiver's public key.
    sres.absorb(&q_r.to_canonical_encoding());

    // Generate and absorb a random masking byte.
    let mask = rand::thread_rng().gen::<u8>();
    sres.absorb(&[mask]);

    // Generate a secret commitment scalar.
    let x = sres.hedge(d_s, |clone| {
        // Also hedge with the plaintext message to ensure (d_s, plaintext, x) uniqueness.
        clone.absorb(plaintext);
        clone.squeeze_scalar()
    });

    // Re-key with the shared secret.
    let k = x * q_r;
    sres.rekey(&k.to_canonical_encoding());

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Ratchet the duplex state to prevent rollback.
    sres.ratchet();

    // Squeeze a challenge scalar.
    let r = sres.squeeze_scalar();
    if &-r == d_s {
        // If we magically happen to extract a challenge scalar which is the same as the sender's
        // private key but negative, x/(r+dS) will be undefined. Re-try this operation with a
        // different random commitment scalar.
        return encrypt(d_s, q_s, q_r, plaintext);
    }

    // Calculate the proof scalar.
    let s = x * (r + d_s).invert();

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
pub fn decrypt(d_r: &Scalar, q_r: &Point, q_s: &Point, ciphertext: &[u8]) -> Option<Vec<u8>> {
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
    sres.absorb(&q_s.to_canonical_encoding());

    // Absorb the receiver's public key.
    sres.absorb(&q_r.to_canonical_encoding());

    // Unmask the scalars.
    let (r, mr) = unmask_scalar(mr);
    let (s, ms) = unmask_scalar(ms);

    // Calculate the masking byte and absorb it.
    sres.absorb(&[mr | (ms >> 4)]);

    // Calculate the shared secret and return an error if it's the identity point. If the point is
    // the identity point, an attacker tried slipping a zero in for the proof scalar.
    let k = (d_r * s) * ((&r * &G) + q_s);
    if k.is_identity() {
        return None;
    }

    // Re-key the protocol with the shared secret.
    sres.rekey(&k.to_canonical_encoding());

    // Decrypt the ciphertext.
    let plaintext = sres.decrypt(ciphertext);

    // Ratchet the protocol state.
    sres.ratchet();

    // If the counterfactual challenge scalar is valid, return the plaintext.
    if r == sres.squeeze_scalar() {
        Some(plaintext)
    } else {
        None
    }
}

// Use the bottom four bits of `mask` to mask the top four bits of `v`.
#[inline]
fn mask_scalar(v: Scalar, mask: u8) -> Vec<u8> {
    let mut b = v.to_canonical_encoding();
    b[31] |= mask;
    b
}

// Zero out the top four bits of `b` and decode it as a scalar, returning the scalar and the mask.
#[inline]
fn unmask_scalar(b: &[u8]) -> (Scalar, u8) {
    let mut v: [u8; 32] = b.try_into().expect("invalid scalar len");
    let m = v[31] & 0xF0;
    v[31] &= 0x0F;
    (Scalar::from_canonical_encoding(&v).expect("invalid scalar mask"), m)
}

#[cfg(test)]
mod tests {
    use crate::ristretto::{Identity, Point};

    use super::*;

    #[test]
    fn round_trip() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let recovered = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert_eq!(Some(plaintext.to_vec()), recovered, "invalid plaintext");
    }

    #[test]
    fn wrong_recipient_private_key() {
        let (d_s, q_s, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let d_r = Scalar::random(&mut rand::thread_rng());

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_recipient_public_key() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let q_r = Point::random(&mut rand::thread_rng());

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (d_s, q_s, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&d_s, &q_s, &q_r, plaintext);

        let q_s = Point::random(&mut rand::thread_rng());

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
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

    #[test]
    fn non_contributory_scalars() {
        let (_, q_s, d_r, q_r) = setup();
        let fake = b"this is a fake";
        let mut out = Vec::with_capacity(fake.len() + OVERHEAD);
        let mut sres = Duplex::new("veil.sres");
        sres.absorb(&q_s.to_canonical_encoding());
        sres.absorb(&q_r.to_canonical_encoding());
        sres.absorb(&[0]);
        sres.rekey(&Point::identity().to_canonical_encoding());
        out.extend(sres.encrypt(fake));
        sres.ratchet();
        out.extend(sres.squeeze_scalar().to_canonical_encoding());
        out.extend(Scalar::zero().to_canonical_encoding());

        assert!(decrypt(&d_r, &q_r, &q_s, &out).is_none());
    }

    fn setup() -> (Scalar, Point, Scalar, Point) {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &d_s * &G;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &d_r * &G;

        (d_s, q_s, d_r, q_r)
    }
}
