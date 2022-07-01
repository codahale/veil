//! An insider-secure hybrid signcryption implementation.

use p256::{NonZeroScalar, ProjectivePoint};
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, Squeeze, UnkeyedDuplex};
use crate::{decode_point, schnorr, GroupEncoding, POINT_LEN};

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = POINT_LEN + POINT_LEN + POINT_LEN;

/// Given the sender's key pair, the ephemeral key pair, the receiver's public key, a nonce, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    rng: impl Rng + CryptoRng,
    (d_s, q_s): (&NonZeroScalar, &ProjectivePoint),
    (d_e, q_e): (&NonZeroScalar, &ProjectivePoint),
    q_r: &ProjectivePoint,
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

    // Encrypt a copy of the ephemeral public key.
    out.extend(sres.encrypt(&q_e.to_bytes()));

    // Absorb the ephemeral ECDH shared secret.
    sres.absorb_point(&(q_r * d_e));

    // Encrypt the plaintext.
    out.extend(sres.encrypt(plaintext));

    // Create a Schnorr signature using the duplex.
    let (i, s) = schnorr::sign_duplex(&mut sres, rng, d_s);
    out.extend(i);

    // Calculate the proof point and encrypt it.
    let x = q_r * &s;
    out.extend(sres.encrypt(&x.to_bytes()));

    // Return the ciphertext, encrypted commitment point, and encrypted proof point.
    out
}

/// Given the receiver's key pair, the sender's public key, a nonce, and a ciphertext, decrypts the
/// given ciphertext and returns the plaintext and the ephemeral public key iff the ciphertext was
/// encrypted for the receiver by the sender.
pub fn decrypt(
    (d_r, q_r): (&NonZeroScalar, &ProjectivePoint),
    q_s: &ProjectivePoint,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Option<(ProjectivePoint, Vec<u8>)> {
    // Check for too-small ciphertexts.
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (q_e, ciphertext) = ciphertext.split_at(POINT_LEN);
    let (ciphertext, i) = ciphertext.split_at(ciphertext.len() - POINT_LEN - POINT_LEN);
    let (i, x) = i.split_at(POINT_LEN);

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
    let q_e = decode_point(&sres.decrypt(q_e))?;

    // Absorb the ephemeral ECDH shared secret.
    sres.absorb_point(&(&q_e * d_r));

    // Decrypt the plaintext.
    let plaintext = sres.decrypt(ciphertext);

    // Decrypt the decode the commitment point.
    let i = decode_point(&sres.decrypt(i))?;

    // Squeeze a challenge scalar from the public keys, plaintext, and commitment point.
    let r_p = sres.squeeze_scalar();

    // Decrypt the decode the proof point, checking for canonical encoding. Nothing depends on the
    // bit encoding of this value, so we ensure it is, at least, a canonically-encoded point (i.e.
    // has a 0 high bit).
    let x = decode_point(&sres.decrypt(x))?;

    // Re-calculate the proof point.
    let x_p = &(i + (q_s * &r_p)) * d_r;

    // If the re-calculated proof point matches the decrypted proof point, return the authenticated
    // ephemeral public key and plaintext.
    if x == x_p {
        Some((q_e, plaintext))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::Group;

    use super::*;

    #[test]
    fn round_trip() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let recovered = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert_eq!(Some((q_e, plaintext.to_vec())), recovered, "invalid plaintext");
    }

    #[test]
    fn wrong_receiver_private_key() {
        let (mut rng, d_s, q_s, d_e, q_e, _, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let d_r = NonZeroScalar::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_receiver_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let q_r = ProjectivePoint::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let q_s = ProjectivePoint::random(&mut rng);

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_nonce() {
        let (mut rng, d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let ciphertext = encrypt(&mut rng, (&d_s, &q_s), (&d_e, &q_e), &q_r, nonce, plaintext);

        let nonce = b"this is not a nonce";

        let plaintext = decrypt((&d_r, &q_r), &q_s, nonce, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
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

    fn setup() -> (
        ChaChaRng,
        NonZeroScalar,
        ProjectivePoint,
        NonZeroScalar,
        ProjectivePoint,
        NonZeroScalar,
        ProjectivePoint,
    ) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d_s = NonZeroScalar::random(&mut rng);
        let q_s = &ProjectivePoint::GENERATOR * &d_s;

        let d_e = NonZeroScalar::random(&mut rng);
        let q_e = &ProjectivePoint::GENERATOR * &d_e;

        let d_r = NonZeroScalar::random(&mut rng);
        let q_r = &ProjectivePoint::GENERATOR * &d_r;

        (rng, d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
