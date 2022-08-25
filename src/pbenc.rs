//! Passphrase-based encryption with Argon2id.

use std::mem;

use argon2::{Algorithm, Argon2, Params, Version};
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, UnkeyedDuplex, TAG_LEN};

/// The number of bytes encryption adds to a plaintext.
pub const OVERHEAD: usize = mem::size_of::<u32>() + mem::size_of::<u32>() + SALT_LEN + TAG_LEN;

/// Encrypt the given plaintext using the given passphrase.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    passphrase: &[u8],
    m_cost: u32,
    t_cost: u32,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (out_m_cost, out_t_cost) = ciphertext.split_at_mut(mem::size_of::<u32>());
    let (out_t_cost, out_salt) = out_t_cost.split_at_mut(mem::size_of::<u32>());
    let (out_salt, out_ciphertext) = out_salt.split_at_mut(SALT_LEN);

    // Encode the time and space parameters.
    out_m_cost.copy_from_slice(&m_cost.to_le_bytes());
    out_t_cost.copy_from_slice(&t_cost.to_le_bytes());

    // Generate a random salt.
    rng.fill_bytes(out_salt);

    // Hash the passphrase with Argon2id.
    let key = argon2id(passphrase, out_salt, m_cost, t_cost);

    // Initialize an unkeyed duplex and absorb the key.
    let mut pbenc = UnkeyedDuplex::new("veil.pbenc");
    pbenc.absorb(&key);
    let mut pbenc = pbenc.into_keyed();

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
    let (m_cost, ciphertext) = in_out.split_at_mut(mem::size_of::<u32>());
    let (t_cost, ciphertext) = ciphertext.split_at_mut(mem::size_of::<u32>());
    let (salt, ciphertext) = ciphertext.split_at_mut(SALT_LEN);

    // Hash the passphrase with Argon2id.
    let m_cost = u32::from_le_bytes(m_cost.try_into().expect("invalid int len"));
    let t_cost = u32::from_le_bytes(t_cost.try_into().expect("invalid int len"));
    let key = argon2id(passphrase, salt, m_cost, t_cost);

    // Initialize an unkeyed duplex and absorb the key.
    let mut pbenc = UnkeyedDuplex::new("veil.pbenc");
    pbenc.absorb(&key);
    let mut pbenc = pbenc.into_keyed();

    // Decrypt the ciphertext.
    pbenc.unseal_mut(ciphertext)
}

fn argon2id(passphrase: &[u8], salt: &[u8], m_cost: u32, t_cost: u32) -> [u8; KEY_LEN] {
    let params = Params::new(m_cost, t_cost, 1, Some(KEY_LEN)).expect("invalid Argon2id params");
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    kdf.hash_password_into(passphrase, salt, &mut key).expect("error hashing passphrase");
    key
}

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 64;

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
        encrypt(&mut rng, passphrase, 8, 1, message, &mut ciphertext);

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(Some(message.as_slice()), plaintext, "invalid plaintext");
    }

    #[test]
    fn wrong_passphrase() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 1, message, &mut ciphertext);

        let plaintext = decrypt(b"whoops", &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_m_cost() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 1, message, &mut ciphertext);
        ciphertext[0] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_t_cost() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 1, message, &mut ciphertext);
        ciphertext[4] ^= 7;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_salt() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 1, message, &mut ciphertext);
        ciphertext[9] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_ciphertext() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 1, message, &mut ciphertext);
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
        encrypt(&mut rng, passphrase, 8, 1, message, &mut ciphertext);
        ciphertext[message.len() + OVERHEAD - 1] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }
}
