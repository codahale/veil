//! Passphrase-based encryption.

use std::mem;

use crrl::jq255e::Point;
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex, TAG_LEN};

/// The number of bytes encryption adds to a plaintext.
pub const OVERHEAD: usize = mem::size_of::<u8>() + SALT_LEN + TAG_LEN;

/// Encrypt the given plaintext using the given passphrase.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    passphrase: &[u8],
    cost: u8,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (out_cost, out_salt) = ciphertext.split_at_mut(mem::size_of::<u8>());
    let (out_salt, out_ciphertext) = out_salt.split_at_mut(SALT_LEN);

    // Encode the cost and generate a random salt.
    out_cost[0] = cost;
    rng.fill_bytes(out_salt);

    // Expand the passphrase and salt into a keyed duplex.
    let mut pbenc = expand(passphrase, out_salt, cost);

    // Encrypt the plaintext.
    out_ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    pbenc.seal_mut(out_ciphertext);
}

/// Decrypt the given ciphertext using the given passphrase.
#[must_use]
pub fn decrypt<'a>(passphrase: &[u8], in_out: &'a mut [u8]) -> Option<&'a [u8]> {
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Decode the parameters.
    let (cost, salt) = in_out.split_at_mut(mem::size_of::<u8>());
    let (salt, ciphertext) = salt.split_at_mut(SALT_LEN);

    // Expand the passphrase and salt into a keyed duplex.
    let mut pbenc = expand(passphrase, salt, cost[0]);

    // Decrypt the ciphertext.
    pbenc.unseal_mut(ciphertext)
}

fn expand(passphrase: &[u8], salt: &[u8], cost: u8) -> KeyedDuplex {
    // Initialize an unkeyed duplex.
    let mut pbenc = UnkeyedDuplex::new("veil.pbenc");

    // Absorb the passphrase, salt, and cost factor.
    pbenc.absorb(passphrase);
    pbenc.absorb(salt);
    pbenc.absorb(&[cost]);

    // Perform 2^cost iterations.
    for i in 0..1u64 << cost {
        // Absorb the counter.
        pbenc.absorb(&i.to_le_bytes());

        // Squeeze a scalar.
        let d = pbenc.squeeze_scalar();

        // Multiple the base point by the scalar.
        let q = Point::mulgen(&d);

        // Absorb the point.
        pbenc.absorb(&q.encode());
    }

    // Convert the duplex to a keyed duplex.
    pbenc.into_keyed()
}

const SALT_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 0, message, &mut ciphertext);

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(Some(message.as_slice()), plaintext, "invalid plaintext");
    }

    #[test]
    fn wrong_passphrase() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 0, message, &mut ciphertext);

        let plaintext = decrypt(b"whoops", &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_cost() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 0, message, &mut ciphertext);
        ciphertext[0] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_salt() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 0, message, &mut ciphertext);
        ciphertext[2] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_ciphertext() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 0, message, &mut ciphertext);
        ciphertext[OVERHEAD - TAG_LEN + 1] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_tag() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 0, message, &mut ciphertext);
        ciphertext[message.len() + OVERHEAD - 1] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }
}
