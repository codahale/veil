//! An insider-secure hybrid signcryption implementation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use lockstitch::Protocol;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

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

    // Initialize a protocol.
    let mut sres = Protocol::new("veil.sres");

    // Mix the sender's public key into the protocol.
    sres.mix(&sender.pub_key.encoded);

    // Mix the receiver's public key into the protocol.
    sres.mix(&receiver.encoded);

    // Mix the nonce into the protocol.
    sres.mix(nonce);

    // Mix the static ECDH shared secret into the protocol.
    sres.mix(&ecdh(&sender.d, &receiver.q));

    // Encrypt the ephemeral public key.
    out_q_e.copy_from_slice(&ephemeral.pub_key.encoded);
    sres.encrypt(out_q_e);

    // Mix the ephemeral ECDH shared secret into the protocol.
    sres.mix(&ecdh(&ephemeral.d, &receiver.q));

    // Encrypt the plaintext.
    out_ciphertext.copy_from_slice(plaintext);
    sres.encrypt(out_ciphertext);

    // Derive a commitment scalar from the protocol's current state, the sender's private key,
    // and a random nonce.
    let k = sres.hedge(rng, &[sender.d.as_bytes()], |clone| {
        Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array::<64>()))
    });

    // Calculate and encrypt the commitment point.
    out_i.copy_from_slice((&k * RISTRETTO_BASEPOINT_TABLE).compress().as_bytes());
    sres.encrypt(out_i);

    // Derive a challenge scalar.
    let r = Scalar::from_bytes_mod_order_wide(&sres.derive_array::<64>());

    // Calculate and encrypt the designated proof point: X = [d_S*r+k]Q_R
    let x = ((sender.d * r) + k) * receiver.q;
    out_x.copy_from_slice(x.compress().as_bytes());
    sres.encrypt(out_x);
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

    // Initialize a protocol.
    let mut sres = Protocol::new("veil.sres");

    // Mix the sender's public key into the protocol.
    sres.mix(&sender.encoded);

    // Mix the receiver's public key into the protocol.
    sres.mix(&receiver.pub_key.encoded);

    // Mix the nonce into the protocol.
    sres.mix(nonce);

    // Mix the static ECDH shared secret into the protocol.
    sres.mix(&ecdh(&receiver.d, &sender.q));

    // Decrypt and decode the ephemeral public key.
    sres.decrypt(ephemeral);
    let ephemeral = PubKey::from_canonical_bytes(ephemeral)?;

    // Mix the ephemeral ECDH shared secret into the protocol.
    sres.mix(&ecdh(&receiver.d, &ephemeral.q));

    // Decrypt the plaintext.
    sres.decrypt(ciphertext);

    // Decrypt and decode the commitment point.
    sres.decrypt(i);
    let i = CompressedRistretto::from_slice(i).ok()?.decompress()?;

    // Re-derive the challenge scalar.
    let r_p = Scalar::from_bytes_mod_order_wide(&sres.derive_array::<64>());

    // Decrypt the designated proof point.
    sres.decrypt(x);

    // Re-calculate the proof point: X' = [d_R](I + [r']Q_R)
    let x_p = receiver.d * (i + (r_p * sender.q));

    // Return the ephemeral public key and plaintext iff the canonical encoding of the re-calculated
    // proof point matches the encoding of the decrypted proof point.
    bool::from(x.ct_eq(x_p.compress().as_bytes())).then_some((ephemeral, ciphertext))
}

/// Calculate the ECDH shared secret, deterministically substituting `(Q ^ d)` if the peer public
/// key is the neutral point.
#[must_use]
#[allow(clippy::as_conversions)]
fn ecdh(d: &Scalar, q: &RistrettoPoint) -> [u8; POINT_LEN] {
    // Pornin's algorithm for safe, constant-time ECDH.
    let mut zz_ab = (d * q).compress().to_bytes();
    let zz_aa = d.as_bytes();
    let non_contributory = if q.is_identity() { 0xFF } else { 0x00 };
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
        let (_, sender, receiver, ephemeral, plaintext, nonce, mut ciphertext) = setup();

        assert_eq!(
            Some((ephemeral.pub_key, plaintext.as_slice())),
            decrypt(&receiver, &sender.pub_key, &nonce, &mut ciphertext)
        );
    }

    #[test]
    fn wrong_receiver() {
        let (mut rng, sender, _, _, _, nonce, mut ciphertext) = setup();

        let wrong_receiver = PrivKey::random(&mut rng);
        assert_eq!(None, decrypt(&wrong_receiver, &sender.pub_key, &nonce, &mut ciphertext));
    }

    #[test]
    fn wrong_sender() {
        let (mut rng, _, receiver, _, _, nonce, mut ciphertext) = setup();

        let wrong_sender = PrivKey::random(&mut rng);
        assert_eq!(None, decrypt(&receiver, &wrong_sender.pub_key, &nonce, &mut ciphertext));
    }

    #[test]
    fn wrong_nonce() {
        let (mut rng, sender, receiver, _, _, _, mut ciphertext) = setup();

        let wrong_nonce = rng.gen::<[u8; NONCE_LEN]>();
        assert_eq!(None, decrypt(&receiver, &sender.pub_key, &wrong_nonce, &mut ciphertext));
    }

    #[test]
    fn flip_every_bit() {
        let (_, sender, receiver, _, _, nonce, ciphertext) = setup();

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                assert!(
                    decrypt(&receiver, &sender.pub_key, &nonce, &mut ciphertext).is_none(),
                    "bit flip at byte {i}, bit {j} produced a valid message",
                );
            }
        }
    }

    fn setup() -> (ChaChaRng, PrivKey, PrivKey, PrivKey, [u8; 64], [u8; NONCE_LEN], Vec<u8>) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let ephemeral = PrivKey::random(&mut rng);
        let plaintext = rng.gen::<[u8; 64]>();
        let nonce = rng.gen::<[u8; NONCE_LEN]>();

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(
            &mut rng,
            &sender,
            &ephemeral,
            &receiver.pub_key,
            &nonce,
            &plaintext,
            &mut ciphertext,
        );

        (rng, sender, receiver, ephemeral, plaintext, nonce, ciphertext)
    }
}
