//! An insider-secure hybrid signcryption implementation.

use rand::{CryptoRng, Rng};

use crate::duplex::Duplex;
use crate::ristretto::{CanonicallyEncoded, Point, Scalar, G, POINT_LEN, SCALAR_LEN};

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = NONCE_LEN + POINT_LEN + POINT_LEN + POINT_LEN;

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

    // Re-key the duplex with the static Diffie-Hellman shared secret.
    sres.rekey(&(d_s * q_r).to_canonical_encoding());

    // Generate and absorb a random nonce.
    let nonce: [u8; NONCE_LEN] = rng.gen();
    sres.absorb(&nonce);
    out.extend(nonce);

    // Encrypt the ephemeral public key.
    out.extend(sres.encrypt(&q_e.to_canonical_encoding()));

    // Re-key the duplex with the ephemeral Diffie-Hellman shared secret.
    sres.rekey(&(d_e * q_r).to_canonical_encoding());

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Squeeze a commitment scalar from the sender's private key, the ephemeral public key, and the
    // plaintext.
    let k = sres.hedge(rng, d_s, Duplex::squeeze_scalar);

    // Calculate the commitment point and encrypt it.
    let i = &k * &G;
    out.extend(sres.encrypt(&i.to_canonical_encoding()));

    // Squeeze a challenge scalar from the public keys, plaintext, and commitment point.
    let r = sres.squeeze_scalar();

    // Calculate the proof scalar.
    let s = d_s * r + k;

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
    q_s: &Point,
    ciphertext: &[u8],
) -> Option<(Point, Vec<u8>)> {
    // Check for too-small ciphertexts.
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (nonce, q_e) = ciphertext.split_at(NONCE_LEN);
    let (q_e, ciphertext) = q_e.split_at(POINT_LEN);
    let (ciphertext, i) = ciphertext.split_at(ciphertext.len() - POINT_LEN - POINT_LEN);
    let (i, x) = i.split_at(SCALAR_LEN);

    // Initialize a duplex.
    let mut sres = Duplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(&q_s.to_canonical_encoding());

    // Absorb the receiver's public key.
    sres.absorb(&q_r.to_canonical_encoding());

    // Re-key the duplex with the static Diffie-Hellman shared secret.
    sres.rekey(&(d_r * q_s).to_canonical_encoding());

    // Absorb the nonce.
    sres.absorb(nonce);

    // Decrypt and decode the ephemeral public key.
    let q_e = sres.decrypt(q_e);
    let q_e = Point::from_canonical_encoding(&q_e)?;

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
        Some((q_e, plaintext))
    } else {
        None
    }
}

const NONCE_LEN: usize = 16;

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
