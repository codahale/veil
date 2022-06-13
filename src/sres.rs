//! An insider-secure hybrid signcryption implementation.

use qdsa::dv::hazmat::verify_challenge;
use qdsa::hazmat::{Point, Scalar};
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, Squeeze, UnkeyedDuplex};
use crate::{schnorr, POINT_LEN};

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = POINT_LEN + POINT_LEN;

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

    // Absorb the ephemeral public public key.
    sres.absorb_point(q_e);

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the ECDH shared secret.
    sres.absorb_point(&(q_r * d_e));

    // Convert the unkeyed duplex to a keyed duplex.
    let mut sres = sres.into_keyed();

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Create a Schnorr signature using the duplex.
    let (i, s) = schnorr::sign_duplex(&mut sres, rng, d_s);
    out.extend(i);

    // Calculate the proof point and encrypt it.
    let x = q_r * &s;
    out.extend(sres.encrypt(&x.as_bytes()));

    // Return the ciphertext, encrypted commitment point, and encrypted proof point.
    out
}

/// Given the receiver's key pair, the ephemeral public key, the sender's public key, a nonce, and
/// a ciphertext, decrypts the given ciphertext and returns the plaintext iff the ciphertext was
/// encrypted for the receiver by the sender.
pub fn decrypt(
    (d_r, q_r): (&Scalar, &Point),
    q_e: &Point,
    q_s: &Point,
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

    // Initialize an unkeyed duplex.
    let mut sres = UnkeyedDuplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb_point(q_s);

    // Absorb the receiver's public key.
    sres.absorb_point(q_r);

    // Absorb the ephemeral public public key.
    sres.absorb_point(q_e);

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the ECDH shared secret.
    sres.absorb_point(&(q_e * d_r));

    // Convert the unkeyed duplex to a keyed duplex.
    let mut sres = sres.into_keyed();

    // Decrypt the plaintext.
    let plaintext = sres.decrypt(ciphertext);

    // Decrypt the decode the commitment point.
    let i = sres.decrypt(i);
    let i = Point::from_bytes(&i.try_into().expect("invalid point len"));

    // Squeeze a challenge scalar from the public keys, plaintext, and commitment point.
    let r_p = sres.squeeze_scalar();

    // Decrypt the decode the proof point, checking for canonical encoding. Nothing depends on the
    // bit encoding of this value, so we ensure it is, at least, a canonically-encoded point (i.e.
    // has a 0 high bit).
    let x = sres.decrypt(x);
    let x = Point::from_canonical_bytes(&x)?;

    // If the signature is valid, return the plaintext.
    if verify_challenge(q_s, d_r, &r_p, &i, &x) {
        Some(plaintext)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use qdsa::hazmat::G;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

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

        let d_r = Scalar::clamp(&rng.gen());

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_receiver_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let q_r = Point::from_elligator(&rng.gen());

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_ephemeral_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let q_e = Point::from_elligator(&rng.gen());

        let plaintext = decrypt((&d_r, &q_r), &q_e, &q_s, tag, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let tag = b"this is a tag";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, tag, plaintext);

        let q_s = Point::from_elligator(&rng.gen());

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

    fn setup() -> (ChaChaRng, Scalar, Point, Scalar, Point, Scalar, Point) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d_s = Scalar::clamp(&rng.gen());
        let q_s = &G * &d_s;

        let d_e = Scalar::clamp(&rng.gen());
        let q_e = &G * &d_e;

        let d_r = Scalar::clamp(&rng.gen());
        let q_r = &G * &d_r;

        (rng, d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
