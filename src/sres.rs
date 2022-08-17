//! An insider-secure hybrid signcryption implementation.

use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, Squeeze, UnkeyedDuplex};
use crate::ecc::{CanonicallyEncoded, Point, Scalar, POINT_LEN};

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = POINT_LEN + POINT_LEN + POINT_LEN;

/// Given the sender's key pair, the ephemeral key pair, the receiver's public key, a nonce, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    rng: impl Rng + CryptoRng,
    (d_s, q_s): (&Scalar, &Point),
    (d_e, q_e): (&Scalar, &Point),
    q_r: &Point,
    nonce: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (out_q_e, out_ciphertext) = ciphertext.split_at_mut(POINT_LEN);
    let (out_ciphertext, out_i) = out_ciphertext.split_at_mut(plaintext.len());
    let (out_i, out_x) = out_i.split_at_mut(POINT_LEN);

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
    out_q_e.copy_from_slice(&q_e.as_canonical_bytes());
    sres.encrypt_mut(out_q_e);

    // Absorb the ephemeral ECDH shared secret.
    sres.absorb_point(&(q_r * d_e));

    // Encrypt the plaintext.
    out_ciphertext.copy_from_slice(plaintext);
    sres.encrypt_mut(out_ciphertext);

    // Derive a commitment scalar from the duplex's current state, the sender's private key,
    // and a random nonce.
    let k = sres.hedge(rng, &d_s.as_canonical_bytes(), Squeeze::squeeze_scalar);

    // Calculate and encrypt the commitment point.
    out_i.copy_from_slice(&Point::mulgen(&k).as_canonical_bytes());
    sres.encrypt_mut(out_i);

    // Squeeze a challenge scalar.
    let r = sres.squeeze_scalar();

    // Calculate and encrypt the designated proof point.
    let x = q_r * ((d_s * r) + k);
    out_x.copy_from_slice(&x.as_canonical_bytes());
    sres.encrypt_mut(out_x);
}

/// Given the receiver's key pair, the sender's public key, a nonce, and a ciphertext, decrypts the
/// given ciphertext and returns the ephemeral public key and plaintext iff the ciphertext was
/// encrypted for the receiver by the sender.
pub fn decrypt<'a>(
    (d_r, q_r): (&Scalar, &Point),
    q_s: &Point,
    nonce: &[u8],
    in_out: &'a mut [u8],
) -> Option<(Point, &'a [u8])> {
    // Check for too-small ciphertexts.
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (q_e, ciphertext) = in_out.split_at_mut(POINT_LEN);
    let (ciphertext, i) = ciphertext.split_at_mut(ciphertext.len() - POINT_LEN - POINT_LEN);
    let (i, x) = i.split_at_mut(POINT_LEN);

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
    sres.decrypt_mut(q_e);
    let q_e = Point::from_canonical_bytes(q_e)?;

    // Absorb the ephemeral ECDH shared secret.
    sres.absorb_point(&(q_e * d_r));

    // Decrypt the plaintext.
    sres.decrypt_mut(ciphertext);

    // Decrypt and decode the commitment point.
    sres.decrypt_mut(i);
    let i = Point::from_canonical_bytes(i)?;

    // Re-derive the challenge scalar.
    let r_p = sres.squeeze_scalar();

    // Decrypt the designated proof point.
    sres.decrypt_mut(x);

    // Re-calculate the proof point.
    let x_p = (i + (q_s * r_p)) * d_r;

    // Return the ephemeral public key and plaintext iff the canonical encoding of the re-calculated
    // proof point matches the encoding of the decrypted proof point.
    (x == x_p.as_canonical_bytes().as_slice()).then_some((q_e, ciphertext))
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
        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext, &mut ciphertext);

        if let Some((q_e_p, plaintext_p)) = decrypt((&d_r, &q_r), &q_s, nonce, &mut ciphertext) {
            assert_ne!(q_e.equals(q_e_p), 0, "invalid ephemeral public key");
            assert_eq!(plaintext.as_slice(), plaintext_p);
        } else {
            unreachable!("invalid plaintext")
        }
    }

    #[test]
    fn wrong_receiver_private_key() {
        let (mut rng, d_s, q_s, d_e, q_e, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext, &mut ciphertext);

        let d_r = Scalar::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &mut ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_receiver_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext, &mut ciphertext);

        let q_r = Point::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &mut ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext, &mut ciphertext);

        let q_s = Point::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &mut ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_nonce() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext, &mut ciphertext);

        let nonce = b"this is not a nonce";

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &mut ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn flip_every_bit() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext, &mut ciphertext);

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                assert!(
                    decrypt((&d_r, &q_r), &q_s, nonce, &mut ciphertext).is_none(),
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
