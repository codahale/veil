//! An insider-secure hybrid signcryption implementation.

use crrl::jq255e::Point;
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, Squeeze, UnkeyedDuplex};
use crate::keys::{PrivKey, PubKey, POINT_LEN};

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = POINT_LEN + POINT_LEN + POINT_LEN;

/// Given the sender's key pair, the ephemeral key pair, the receiver's public key, a nonce, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    rng: impl Rng + CryptoRng,
    sender: &PrivKey,
    ephemeral: &PrivKey,
    receiver: &PubKey,
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
    sres.absorb(&sender.pub_key.encoded);

    // Absorb the receiver's public key.
    sres.absorb(&receiver.encoded);

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the static ECDH shared secret.
    sres.absorb(&ecdh(sender, receiver));

    // Convert the unkeyed duplex to a keyed duplex.
    let mut sres = sres.into_keyed();

    // Encrypt the ephemeral public key.
    out_q_e.copy_from_slice(&ephemeral.pub_key.encoded);
    sres.encrypt_mut(out_q_e);

    // Absorb the ephemeral ECDH shared secret.
    sres.absorb(&ecdh(ephemeral, receiver));

    // Encrypt the plaintext.
    out_ciphertext.copy_from_slice(plaintext);
    sres.encrypt_mut(out_ciphertext);

    // Derive a commitment scalar from the duplex's current state, the sender's private key,
    // and a random nonce.
    let k = sres.hedge(rng, sender, Squeeze::squeeze_scalar);

    // Calculate and encrypt the commitment point.
    out_i.copy_from_slice(&Point::mulgen(&k).encode());
    sres.encrypt_mut(out_i);

    // Squeeze a challenge scalar.
    let r = sres.squeeze_scalar();

    // Calculate and encrypt the designated proof point.
    let x = receiver.q * ((sender.d * r) + k);
    out_x.copy_from_slice(&x.encode());
    sres.encrypt_mut(out_x);
}

/// Given the receiver's key pair, the sender's public key, a nonce, and a ciphertext, decrypts the
/// given ciphertext and returns the ephemeral public key and plaintext iff the ciphertext was
/// encrypted for the receiver by the sender.
#[must_use]
pub fn decrypt<'a>(
    receiver: &PrivKey,
    sender: &PubKey,
    nonce: &[u8],
    in_out: &'a mut [u8],
) -> Option<(PubKey, &'a [u8])> {
    // Check for too-small ciphertexts.
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (ephemeral, ciphertext) = in_out.split_at_mut(POINT_LEN);
    let (ciphertext, i) = ciphertext.split_at_mut(ciphertext.len() - POINT_LEN - POINT_LEN);
    let (i, x) = i.split_at_mut(POINT_LEN);

    // Initialize an unkeyed duplex.
    let mut sres = UnkeyedDuplex::new("veil.sres");

    // Absorb the sender's public key.
    sres.absorb(&sender.encoded);

    // Absorb the receiver's public key.
    sres.absorb(&receiver.pub_key.encoded);

    // Absorb the nonce.
    sres.absorb(nonce);

    // Absorb the static ECDH shared secret.
    sres.absorb(&ecdh(receiver, sender));

    // Convert the unkeyed duplex to a keyed duplex.
    let mut sres = sres.into_keyed();

    // Decrypt and decode the ephemeral public key.
    sres.decrypt_mut(ephemeral);
    let ephemeral = PubKey::decode(ephemeral)?;

    // Absorb the ephemeral ECDH shared secret.
    sres.absorb(&ecdh(receiver, &ephemeral));

    // Decrypt the plaintext.
    sres.decrypt_mut(ciphertext);

    // Decrypt and decode the commitment point.
    sres.decrypt_mut(i);
    let i = Point::decode(i)?;

    // Re-derive the challenge scalar.
    let r_p = sres.squeeze_scalar();

    // Decrypt the designated proof point.
    sres.decrypt_mut(x);

    // Re-calculate the proof point.
    let x_p = (i + (sender.q * r_p)) * receiver.d;

    // Return the ephemeral public key and plaintext iff the canonical encoding of the re-calculated
    // proof point matches the encoding of the decrypted proof point.
    (x == x_p.encode().as_slice()).then_some((ephemeral, ciphertext))
}

/// Calculate the ECDH shared secret, deterministically substituting `(Q ^ d)` if the peer public
/// key is the neutral point.
#[must_use]
#[allow(clippy::as_conversions)]
fn ecdh(a: &PrivKey, b: &PubKey) -> [u8; POINT_LEN] {
    // Pornin's algorithm for safe, constant-time ECDH.
    let mut zz_ab = (a.d * b.q).encode();
    let zz_aa = a.d.encode32();
    let non_contributory = b.q.isneutral() as u8;
    for i in 0..POINT_LEN {
        zz_ab[i] ^= non_contributory & (zz_ab[i] ^ zz_aa[i]);
    }
    zz_ab
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let ephemeral = PrivKey::random(&mut rng);
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(
            &mut rng,
            &sender,
            &ephemeral,
            &receiver.pub_key,
            nonce,
            plaintext,
            &mut ciphertext,
        );

        if let Some((ephemeral_q, plaintext_p)) =
            decrypt(&receiver, &sender.pub_key, nonce, &mut ciphertext)
        {
            assert_eq!(ephemeral.pub_key.encoded, ephemeral_q.encoded);
            assert_eq!(plaintext.as_slice(), plaintext_p);
        } else {
            unreachable!("invalid plaintext")
        }
    }

    #[test]
    fn wrong_receiver() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let wrong_receiver = PrivKey::random(&mut rng);
        let ephemeral = PrivKey::random(&mut rng);
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(
            &mut rng,
            &sender,
            &ephemeral,
            &receiver.pub_key,
            nonce,
            plaintext,
            &mut ciphertext,
        );

        let plaintext = decrypt(&wrong_receiver, &sender.pub_key, nonce, &mut ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_sender() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let wrong_sender = PrivKey::random(&mut rng);
        let ephemeral = PrivKey::random(&mut rng);
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(
            &mut rng,
            &sender,
            &ephemeral,
            &receiver.pub_key,
            nonce,
            plaintext,
            &mut ciphertext,
        );

        let plaintext = decrypt(&receiver, &wrong_sender.pub_key, nonce, &mut ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn wrong_nonce() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let ephemeral = PrivKey::random(&mut rng);
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";
        let wrong_nonce = b"this is NOT a nonce";

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(
            &mut rng,
            &sender,
            &ephemeral,
            &receiver.pub_key,
            nonce,
            plaintext,
            &mut ciphertext,
        );

        let plaintext = decrypt(&receiver, &sender.pub_key, wrong_nonce, &mut ciphertext);
        assert!(plaintext.is_none(), "decrypted an invalid ciphertext");
    }

    #[test]
    fn flip_every_bit() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let ephemeral = PrivKey::random(&mut rng);
        let plaintext = b"ok this is fun";
        let nonce = b"this is a nonce";

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(
            &mut rng,
            &sender,
            &ephemeral,
            &receiver.pub_key,
            nonce,
            plaintext,
            &mut ciphertext,
        );

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                assert!(
                    decrypt(&receiver, &sender.pub_key, nonce, &mut ciphertext).is_none(),
                    "bit flip at byte {}, bit {} produced a valid message",
                    i,
                    j
                );
            }
        }
    }
}
