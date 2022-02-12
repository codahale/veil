//! An insider-secure hybrid signcryption implementation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use secrecy::{ExposeSecret, Secret, SecretVec};
use xoodyak::{XoodyakCommon, XoodyakHash, XoodyakTag, XOODYAK_AUTH_TAG_BYTES};

use crate::constants::{MAC_LEN, SCALAR_LEN};
use crate::xoodoo::{XoodyakExt, XoodyakHashExt};

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = SCALAR_LEN + SCALAR_LEN + MAC_LEN;

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

    // Initialize a hash.
    let mut sres = XoodyakHash::new();
    sres.absorb(b"veil.sres");

    // Absorb the sender's public key.
    sres.absorb(q_s.compress().as_bytes());

    // Absorb the receiver's public key.
    sres.absorb(q_r.compress().as_bytes());

    // Generate a secret commitment scalar.
    let x = sres.hedge(d_s.as_bytes(), |clone| {
        // Also hedge with the plaintext message to ensure (d_s, plaintext, t) uniqueness.
        clone.absorb(plaintext);
        clone.squeeze_scalar()
    });

    // Calculate the shared secret and use it to key the protocol.
    let k = q_r * x.expose_secret();
    sres.absorb(compress_secret(k).expose_secret());
    let mut sres = sres.to_keyed("veil.sres");

    // Encrypt and send the plaintext.
    out.extend(sres.encrypt_to_vec(plaintext).expect("invalid decryption"));

    // Ratchet the protocol state to prevent rollback.
    sres.ratchet();

    // Extract a challenge scalar from PRF output.
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

    // Mask and absorb the scalars in cleartext.
    let mr = mask_scalar(&r);
    sres.absorb(&mr);
    out.extend(&mr);

    let ms = mask_scalar(&s);
    sres.absorb(&ms);
    out.extend(&ms);

    // Generate and send a MAC.
    out.extend(sres.squeeze_to_vec(XOODYAK_AUTH_TAG_BYTES));

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
    let (ms, tag) = ms.split_at(SCALAR_LEN);
    let tag: [u8; XOODYAK_AUTH_TAG_BYTES] = tag.try_into().expect("invalid tag len");
    let tag = XoodyakTag::from(tag);

    // Unmask the scalars.
    let r = unmask_scalar(mr.try_into().expect("invalid scalar len"));
    let s = unmask_scalar(ms.try_into().expect("invalid scalar len"));

    // Initialize a hash.
    let mut sres = XoodyakHash::new();
    sres.absorb(b"veil.sres");

    // Absorb the sender's public key.
    sres.absorb(q_s.compress().as_bytes());

    // Absorb the receiver's public key.
    sres.absorb(q_r.compress().as_bytes());

    // Calculate the shared secret and use it to key the protocol.
    let z = (q_s + (&G * &r)) * (d_r * s);
    sres.absorb(compress_secret(z).expose_secret());
    let mut sres = sres.to_keyed("veil.sres");

    // Decrypt the ciphertext.
    let plaintext = sres.decrypt_to_vec(ciphertext).expect("invalid decryption").into();

    // Ratchet the protocol state.
    sres.ratchet();

    // Extract a challenge scalar from PRF output and check it against the received scalar.
    if r != sres.squeeze_scalar() {
        return None;
    }

    // Absorb the masked scalars.
    sres.absorb(mr);
    sres.absorb(ms);

    // Verify the MAC.
    let tag_p: [u8; XOODYAK_AUTH_TAG_BYTES] =
        sres.squeeze_to_vec(XOODYAK_AUTH_TAG_BYTES).try_into().expect("invalid tag len");
    if tag.verify(tag_p).is_ok() {
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

/// Return a randomly masked, encoded form of `s` indistinguishable from random noise.
#[inline]
fn mask_scalar(s: &Scalar) -> [u8; 32] {
    // Use the top four bits of a random byte to mask the top byte of the encoded scalar.
    let mask = rand::thread_rng().gen::<u8>() & 0b1111_0000;

    // Encode the scalar canonically.
    let mut b = s.to_bytes();

    // Mask the top byte.
    b[31] |= mask;

    // Return the masked value.
    b
}

/// Unmask the output of `mask_scalar`.
#[inline]
fn unmask_scalar(mut b: [u8; 32]) -> Scalar {
    // Ensure the top four bits aren't set.
    b[31] &= 0b0000_1111;

    // Decode the scalar canonically.
    Scalar::from_canonical_bytes(b).expect("invalid unmasked scalar")
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;

    use super::*;

    #[test]
    fn scalar_masking() {
        let s = Scalar::random(&mut rand::thread_rng());
        let masked = mask_scalar(&s);
        let unmasked = unmask_scalar(masked);
        assert_eq!(s, unmasked, "non-bijective unmasking");
    }

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
