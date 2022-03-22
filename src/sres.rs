//! An insider-secure hybrid signcryption implementation.

use rand::{CryptoRng, Rng};

use crate::duplex::Duplex;
use crate::ristretto::{CanonicallyEncoded, Point, Scalar, POINT_LEN};
use crate::schnorr;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = POINT_LEN + POINT_LEN;

/// Given the sender's key pair, the ephemeral key pair, the recipient's public key, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    rng: impl Rng + CryptoRng,
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

    // Absorb the ephemeral public public key.
    sres.absorb(&q_e.to_canonical_encoding());

    // Re-key the duplex with the ephemeral Diffie-Hellman shared secret.
    sres.rekey(&(d_e * q_r).to_canonical_encoding());

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Derive a commitment scalar from the duplex's current state, the sender's private key,
    // and a random nonce.
    let k = sres.hedge(rng, d_s, Duplex::squeeze_scalar);

    // Create a Schnorr signature using the duplex.
    let (i, s) = schnorr::sign(&mut sres, d_s, k);
    out.extend(i);

    // Calculate the proof point and encrypt it.
    let x = s * q_r;
    out.extend(sres.encrypt(&x.to_canonical_encoding()));

    // Return the encrypted ephemeral public key, plaintext, commitment point, and proof point.
    out
}

/// Given the recipient's key pair, the sender's public key, and a ciphertext, decrypts the given
/// ciphertext and returns the ephemeral public key and plaintext iff the ciphertext was encrypted
/// for the recipient by the sender.
pub fn decrypt(
    d_r: &Scalar,
    q_r: &Point,
    q_e: &Point,
    q_s: &Point,
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
    sres.absorb(&q_s.to_canonical_encoding());

    // Absorb the receiver's public key.
    sres.absorb(&q_r.to_canonical_encoding());

    // Absorb the ephemeral public public key.
    sres.absorb(&q_e.to_canonical_encoding());

    // Re-key the duplex with the ephemeral Diffie-Hellman shared secret.
    sres.rekey(&(d_r * q_e).to_canonical_encoding());

    // Decrypt the plaintext.
    let plaintext = sres.decrypt(ciphertext);

    // Decrypt the decode the commitment point.
    let i = sres.decrypt(i);
    let i = Point::from_canonical_encoding(&i)?;

    // Squeeze a challenge scalar from the public keys, plaintext, and commitment point.
    let r = sres.squeeze_scalar();

    // Decrypt the decode the proof point.
    let x = sres.decrypt(x);
    let x = Point::from_canonical_encoding(&x)?;

    // Re-calculate the proof point.
    let x_p = d_r * (i + (r * q_s));

    // If the re-calculated proof point matches the decrypted proof point, return the authenticated
    // ephemeral public key and plaintext.
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

    use crate::ristretto::{Point, G};

    use super::*;

    #[test]
    fn round_trip() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let recovered = decrypt(&d_r, &q_r, &q_e, &q_s, &ciphertext);
        assert_eq!(Some(plaintext.to_vec()), recovered, "invalid plaintext");
    }

    #[test]
    fn wrong_recipient_private_key() {
        let (mut rng, d_s, q_s, d_e, q_e, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let d_r = Scalar::random(&mut rng);

        let plaintext = decrypt(&d_r, &q_r, &q_e, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_recipient_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let q_r = Point::random(&mut rng);

        let plaintext = decrypt(&d_r, &q_r, &q_e, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_ephemeral_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let q_e = Point::random(&mut rng);

        let plaintext = decrypt(&d_r, &q_r, &q_e, &q_s, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let ciphertext = encrypt(&mut rng, &d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

        let q_s = Point::random(&mut rng);

        let plaintext = decrypt(&d_r, &q_r, &q_e, &q_s, &ciphertext);
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
                    decrypt(&d_r, &q_r, &q_e, &q_s, &ciphertext).is_none(),
                    "bit flip at byte {}, bit {} produced a valid message",
                    i,
                    j
                );
            }
        }
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
