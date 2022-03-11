//! An insider-secure hybrid signcryption implementation.

use rand::{CryptoRng, Rng};

use crate::duplex::Duplex;
use crate::ristretto::{CanonicallyEncoded, Point, Scalar, G, POINT_LEN, SCALAR_LEN};

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = POINT_LEN + SCALAR_LEN + SCALAR_LEN;

/// Given the sender's key pair, the ephemeral key pair, the recipient's public key, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    d_s: &Scalar,
    q_s: &Point,
    d_e: &Scalar,
    q_e: &Point,
    q_r: &Point,
    plaintext: &[u8],
) -> Vec<u8> {
    // Allocate an output buffer.
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Initialize a duplex.
    let mut sres = Duplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(&q_s.to_canonical_encoding());

    // Absorb the receiver's public key.
    sres.absorb(&q_r.to_canonical_encoding());

    // Generate and absorb a random masking byte.
    let mask = rng.gen::<u8>();
    sres.absorb(&[mask]);

    // Generate a secret commitment scalar.
    let x = sres.hedge(&mut rng, d_s, |clone| {
        // Also hedge with the plaintext message to ensure (d_s, plaintext, x) uniqueness.
        clone.absorb(plaintext);
        clone.squeeze_scalar()
    });

    // Re-key with the shared secret.
    let k = x * q_r;
    sres.rekey(&k.to_canonical_encoding());

    // Encrypt a copy of the ephemeral public key.
    out.extend(sres.encrypt(&q_e.to_canonical_encoding()));

    // Re-key with the ephemeral Diffie-Hellman shared secret.
    sres.rekey(&(d_e * q_r).to_canonical_encoding());

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
        return encrypt(rng, d_s, q_s, d_e, q_e, q_r, plaintext);
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
/// ciphertext and returns the ephemeral public key and plaintext iff the ciphertext was encrypted
/// for the recipient by the sender.
pub fn decrypt(
    d_r: &Scalar,
    q_r: &Point,
    q_s: &Point,
    ciphertext: &[u8],
) -> Option<(Point, Vec<u8>)> {
    // Check for too-small ciphertexts.
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (q_e, ciphertext) = ciphertext.split_at(POINT_LEN);
    let (ciphertext, mr) = ciphertext.split_at(ciphertext.len() - SCALAR_LEN - SCALAR_LEN);
    let (mr, ms) = mr.split_at(SCALAR_LEN);

    // Initialize a duplex.
    let mut sres = Duplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(&q_s.to_canonical_encoding());

    // Absorb the receiver's public key.
    sres.absorb(&q_r.to_canonical_encoding());

    // Unmask the scalars. Early exit if either of them are zero.
    let (r, mr) = unmask_scalar(mr)?;
    let (s, ms) = unmask_scalar(ms)?;

    // Calculate the masking byte and absorb it.
    sres.absorb(&[mr | (ms >> 4)]);

    // Calculate the shared secret. Having validated `r` and `s` as non-zero scalars, we are assured
    // here of contributory behavior.
    let k = (d_r * s) * ((&r * &G) + q_s);

    // Re-key the protocol with the shared secret.
    sres.rekey(&k.to_canonical_encoding());

    // Decrypt and decode the ephemeral public key.
    let q_e = Point::from_canonical_encoding(&sres.decrypt(q_e))?;

    // Re-key the protocol with the Diffie-Hellman shared secret.
    sres.rekey(&(d_r * q_e).to_canonical_encoding());

    // Decrypt the ciphertext.
    let plaintext = sres.decrypt(ciphertext);

    // Ratchet the protocol state.
    sres.ratchet();

    // If the counterfactual challenge scalar is valid, return the plaintext.
    if r == sres.squeeze_scalar() {
        Some((q_e, plaintext))
    } else {
        None
    }
}

// Use the bottom four bits of `mask` to mask the top four bits of `v`.
#[inline]
fn mask_scalar(v: Scalar, mask: u8) -> [u8; SCALAR_LEN] {
    let mut b = v.to_canonical_encoding();
    b[31] |= mask;
    b
}

// Zero out the top four bits of `b` and decode it as a scalar, returning the scalar and the mask.
#[inline]
fn unmask_scalar(b: &[u8]) -> Option<(Scalar, u8)> {
    let mut v: [u8; 32] = b.try_into().expect("invalid scalar len");
    let m = v[31] & 0xF0;
    v[31] &= 0x0F;
    Scalar::from_canonical_encoding(&v).map(|d| (d, m))
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::ristretto::Point;

    use super::*;

    #[test]
    fn round_trip() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let recovered = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert_eq!(Some((q_e, plaintext.to_vec())), recovered, "invalid plaintext");
    }

    #[test]
    fn wrong_recipient_private_key() {
        let (mut rng, d_s, q_s, d_e, q_e, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let d_r = Scalar::random(&mut rng);

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_recipient_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let q_r = Point::random(&mut rng);

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let q_s = Point::random(&mut rng);

        let plaintext = decrypt(&d_r, &q_r, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn flip_every_bit() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

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
        // No need for the sender's private key; we're forging a message.
        let (_, _, q_s, _, _, d_r, q_r) = setup();

        let fake = b"this is a fake";
        let mut out = Vec::with_capacity(fake.len() + OVERHEAD);

        // Start encrypting the message like usual.
        let mut sres = Duplex::new("veil.sres");
        sres.absorb(&q_s.to_canonical_encoding());
        sres.absorb(&q_r.to_canonical_encoding());

        // Use zero for the masking byte.
        sres.absorb(&[0]);

        // Use the identity point for the shared secret.
        sres.rekey(&[0u8; 32]);

        // Encrypt the identity point as the DH shared secret.
        out.extend(sres.encrypt(&[0u8; 32]));

        // Use the identity point for the shared secret again.
        sres.rekey(&[0u8; 32]);

        // Encrypt the fake message.
        out.extend(sres.encrypt(fake));

        // Ratchet the state and output a challenge scalar.
        sres.ratchet();
        out.extend(sres.squeeze_scalar().to_canonical_encoding());

        // Send a zero as the proof scalar.
        out.extend([0u8; 32]);

        // If we're not checking for contributory behavior, [d_r * s]([r]G + Q_s) will be
        // [0]([r]G + Q_s), which will be 0. The recipient will use the identity point as the shared
        // secret, the challenge scalar will be the same, and we'll have forged a message.
        assert!(decrypt(&d_r, &q_r, &q_s, &out).is_none());
    }

    fn setup() -> (ChaChaRng, Scalar, Point, Scalar, Point, Scalar, Point) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d_s = Scalar::random(&mut rng);
        let q_s = &d_s * &G;

        let d_e = Scalar::random(&mut rng);
        let q_e = &d_e * &G;

        let d_r = Scalar::random(&mut rng);
        let q_r = &d_r * &G;

        (rng, d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
