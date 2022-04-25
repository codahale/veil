//! An insider-secure hybrid signcryption implementation.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::{CryptoRng, Rng};

use crate::duplex::Duplex;
use crate::schnorr;
use crate::POINT_LEN;

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = POINT_LEN + POINT_LEN;

/// Given the sender's key pair, the ephemeral key pair, the receiver's public key, a nonce, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    rng: impl Rng + CryptoRng,
    (d_s, q_s): (&Scalar, &RistrettoPoint),
    (d_e, q_e): (&Scalar, &RistrettoPoint),
    q_r: &RistrettoPoint,
    nonce: &[u8],
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

    // Absorb the ephemeral public public key.
    sres.absorb(q_e.compress().as_bytes());

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the ECDH shared secret.
    sres.absorb((d_e * q_r).compress().as_bytes());

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Derive a commitment scalar from the duplex's current state, the sender's private key,
    // and a random nonce.
    let k = sres.hedge(rng, d_s, Duplex::squeeze_scalar);

    // Create a Schnorr signature using the duplex.
    let (i, s) = schnorr::sign_duplex(&mut sres, d_s, k);
    out.extend(i);

    // Calculate the proof point and encrypt it.
    let x = s * q_r;
    out.extend(sres.encrypt(x.compress().as_bytes()));

    // Return the ciphertext, encrypted commitment point, and encrypted proof point.
    out
}

/// Given the receiver's key pair, the ephemeral public key, the sender's public key, a nonce, and
/// a ciphertext, decrypts the given ciphertext and returns the plaintext iff the ciphertext was
/// encrypted for the receiver by the sender.
pub fn decrypt(
    (d_r, q_r): (&Scalar, &RistrettoPoint),
    q_e: &RistrettoPoint,
    q_s: &RistrettoPoint,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    // Check for too-small ciphertexts.
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (ciphertext, i) = ciphertext.split_at(ciphertext.len() - OVERHEAD);
    let (i, x) = i.split_at(POINT_LEN);

    // Initialize a duplex.
    let mut sres = Duplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(q_s.compress().as_bytes());

    // Absorb the receiver's public key.
    sres.absorb(q_r.compress().as_bytes());

    // Absorb the ephemeral public public key.
    sres.absorb(q_e.compress().as_bytes());

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the ECDH shared secret.
    sres.absorb((d_r * q_e).compress().as_bytes());

    // Decrypt the plaintext.
    let plaintext = sres.decrypt(ciphertext);

    // Decrypt the decode the commitment point. Return None if it's the identity point.
    let i = sres.decrypt(i);
    let i = CompressedRistretto::from_slice(&i).decompress().filter(|i| !i.is_identity())?;

    // Squeeze a challenge scalar from the public keys, plaintext, and commitment point.
    let r = sres.squeeze_scalar();

    // Decrypt the decode the proof point. Return None if it's the identity point.
    let x = sres.decrypt(x);
    let x = CompressedRistretto::from_slice(&x).decompress().filter(|x| !x.is_identity())?;

    // Re-calculate the proof point.
    let x_p = d_r * (i + (r * q_s));

    // If the re-calculated proof point matches the decrypted proof point, return the authenticated
    // plaintext.
    if x == x_p {
        Some(plaintext)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::G;

    use super::*;

    #[test]
    fn round_trip() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let recovered = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(Some(plaintext.to_vec()), recovered, "invalid plaintext");
    }

    #[test]
    fn wrong_receiver_private_key() {
        let (mut rng, d_s, q_s, d_e, q_e, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let d_r = Scalar::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_receiver_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let q_r = RistrettoPoint::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_ephemeral_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let q_e = RistrettoPoint::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let q_s = RistrettoPoint::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_tag() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let tag = b"this is not a tag";

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn flip_every_bit() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                assert!(
                    decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext).is_none(),
                    "bit flip at byte {}, bit {} produced a valid message",
                    i,
                    j
                );
            }
        }
    }

    fn setup() -> (ChaChaRng, Scalar, RistrettoPoint, Scalar, RistrettoPoint, Scalar, RistrettoPoint)
    {
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
