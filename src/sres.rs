//! An insider-secure hybrid signcryption implementation.

use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, Squeeze, UnkeyedDuplex};
use crate::ecc::{CanonicallyEncoded, Point, Scalar};
use crate::schnorr;

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = Point::LEN + Point::LEN + Point::LEN;

/// Given the sender's key pair, the ephemeral key pair, the receiver's public key, a nonce, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    rng: impl Rng + CryptoRng,
    (d_s, q_s): (&Scalar, &Point),
    (d_e, q_e): (&Scalar, &Point),
    q_r: &Point,
    nonce: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    // Allocate an output buffer.
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Initialize an unkeyed duplex.
    let mut sres = UnkeyedDuplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb_point(q_s);

    // Absorb the receiver's public key.
    sres.absorb_point(q_r);

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the static ECDH shared secret.
    sres.absorb_point(&(q_r * d_s));

    // Convert the unkeyed duplex to a keyed duplex.
    let mut sres = sres.into_keyed();

    // Encrypt the ephemeral public key.
    out.extend(sres.encrypt(&q_e.as_canonical_bytes()));

    // Absorb the ephemeral ECDH shared secret.
    sres.absorb_point(&(q_r * d_e));

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Create a Schnorr signature using the duplex.
    let (i, s) = schnorr::sign_duplex(&mut sres, rng, d_s);
    out.extend(i);

    // Calculate the proof point and encrypt it.
    let x = q_r * s;
    out.extend(sres.encrypt(&x.as_canonical_bytes()));

    // Return the ciphertext, encrypted commitment point, and encrypted proof point.
    out
}

/// Given the receiver's key pair, the sender's public key, a nonce, and a ciphertext, decrypts the
/// given ciphertext and returns the ephemeral public key and plaintext iff the ciphertext was
/// encrypted for the receiver by the sender.
pub fn decrypt(
    (d_r, q_r): (&Scalar, &Point),
    q_s: &Point,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Option<(Point, Vec<u8>)> {
    // Check for too-small ciphertexts.
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (q_e, ciphertext) = ciphertext.split_at(Point::LEN);
    let (ciphertext, i) = ciphertext.split_at(ciphertext.len() - Point::LEN - Point::LEN);
    let (i, x) = i.split_at(Point::LEN);

    // Initialize an unkeyed duplex.
    let mut sres = UnkeyedDuplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb_point(q_s);

    // Absorb the receiver's public key.
    sres.absorb_point(q_r);

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the static ECDH shared secret.
    sres.absorb_point(&(q_s * d_r));

    // Convert the unkeyed duplex to a keyed duplex.
    let mut sres = sres.into_keyed();

    // Decrypt and decode the ephemeral public key.
    let q_e = Point::from_canonical_bytes(&sres.decrypt(q_e))?;

    // Absorb the ephemral ECDH shared secret.
    sres.absorb_point(&(q_e * d_r));

    // Decrypt the plaintext.
    let plaintext = sres.decrypt(ciphertext);

    // Decrypt the decode the commitment point.
    let i = Point::from_canonical_bytes(sres.decrypt(i))?;

    // Squeeze a challenge scalar from the public keys, plaintext, and commitment point.
    let r_p = sres.squeeze_scalar();

    // Decrypt the proof point.
    let x = Point::from_canonical_bytes(&sres.decrypt(x))?;

    // Re-calculate the proof point.
    let x_p = (i + (q_s * r_p)) * d_r;

    // If the re-calculated proof point matches the decrypted proof point, return the authenticated
    // plaintext.
    (x.equals(x_p) != 0).then_some((q_e, plaintext))
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        if let Some((q_e_p, plaintext_p)) = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext) {
            assert_ne!(q_e.equals(q_e_p), 0, "invalid ephemeral public key");
            assert_eq!(plaintext.as_slice(), plaintext_p.as_slice());
        } else {
            unreachable!("invalid plaintext")
        }
    }

    #[test]
    fn wrong_receiver_private_key() {
        let (mut rng, d_s, q_s, d_e, q_e, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let d_r = Scalar::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_receiver_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let q_r = Point::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let q_s = Point::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_nonce() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let nonce = b"this is not a nonce";

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn flip_every_bit() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                assert!(
                    decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext).is_none(),
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
        let q_s = Point::mulgen(&d_s);

        let d_e = Scalar::random(&mut rng);
        let q_e = Point::mulgen(&d_e);

        let d_r = Scalar::random(&mut rng);
        let q_r = Point::mulgen(&d_r);

        (rng, d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
