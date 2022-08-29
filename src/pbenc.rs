//! Passphrase-based encryption based on Balloon Hashing.

use std::mem;

use argon2::{Algorithm, Argon2, Params, Version};
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, KeyedDuplex, UnkeyedDuplex, TAG_LEN};
use crate::EncryptError;

/// The number of bytes encryption adds to a plaintext.
pub const OVERHEAD: usize =
    mem::size_of::<u32>() + mem::size_of::<u32>() + mem::size_of::<u32>() + SALT_LEN + TAG_LEN;

/// Encrypt the given plaintext using the given passphrase.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    passphrase: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), EncryptError> {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (ct_m_cost, ct_t_cost) = ciphertext.split_at_mut(mem::size_of::<u32>());
    let (ct_t_cost, ct_p_cost) = ct_t_cost.split_at_mut(mem::size_of::<u32>());
    let (ct_p_cost, ct_salt) = ct_p_cost.split_at_mut(mem::size_of::<u32>());
    let (ct_salt, ct_ciphertext) = ct_salt.split_at_mut(SALT_LEN);

    // Encode the parameters.
    ct_m_cost.copy_from_slice(&m_cost.to_le_bytes());
    ct_t_cost.copy_from_slice(&t_cost.to_le_bytes());
    ct_p_cost.copy_from_slice(&p_cost.to_le_bytes());

    // Generate a random salt.
    rng.fill_bytes(ct_salt);

    // Use Argon2id to create a keyed duplex.
    let mut pbenc = kdf(passphrase, ct_salt, m_cost, t_cost, p_cost)?;

    // Encrypt the plaintext.
    ct_ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    pbenc.seal_mut(ct_ciphertext);

    Ok(())
}

/// Decrypt the given ciphertext using the given passphrase.
#[must_use]
pub fn decrypt<'a>(passphrase: &[u8], in_out: &'a mut [u8]) -> Option<&'a [u8]> {
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Split up the input buffer.
    let (ct_m_cost, ct_t_cost) = in_out.split_at_mut(mem::size_of::<u32>());
    let (ct_t_cost, ct_p_cost) = ct_t_cost.split_at_mut(mem::size_of::<u32>());
    let (ct_p_cost, ct_salt) = ct_p_cost.split_at_mut(mem::size_of::<u32>());
    let (ct_salt, ct_ciphertext) = ct_salt.split_at_mut(SALT_LEN);

    // Decode the parameters.
    let m_cost = u32::from_le_bytes(ct_m_cost.try_into().expect("invalid int len"));
    let t_cost = u32::from_le_bytes(ct_t_cost.try_into().expect("invalid int len"));
    let p_cost = u32::from_le_bytes(ct_p_cost.try_into().expect("invalid int len"));

    // Use Argon2id to create a keyed duplex.
    let mut pbenc = kdf(passphrase, ct_salt, m_cost, t_cost, p_cost).ok()?;

    // Decrypt the ciphertext.
    pbenc.unseal_mut(ct_ciphertext)
}

fn kdf(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<KeyedDuplex, argon2::Error> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KDF_LEN))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KDF_LEN];
    argon.hash_password_into(passphrase, salt, &mut key)?;

    let mut pbenc = UnkeyedDuplex::new("veil.pbenc");
    pbenc.absorb(&key);
    Ok(pbenc.into_keyed())
}

const SALT_LEN: usize = 16;
const KDF_LEN: usize = 64;

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
        encrypt(&mut rng, passphrase, 8, 6, 1, message, &mut ciphertext).expect("error encrypting");

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(Some(message.as_slice()), plaintext, "invalid plaintext");
    }

    #[test]
    fn wrong_passphrase() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 6, 1, message, &mut ciphertext).expect("error encrypting");

        let plaintext = decrypt(b"whoops", &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_time() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 6, 1, message, &mut ciphertext).expect("error encrypting");
        ciphertext[0] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_space() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 6, 1, message, &mut ciphertext).expect("error encrypting");
        ciphertext[1] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_salt() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 8, 6, 1, message, &mut ciphertext).expect("error encrypting");
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
        encrypt(&mut rng, passphrase, 8, 6, 1, message, &mut ciphertext).expect("error encrypting");
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
        encrypt(&mut rng, passphrase, 8, 6, 1, message, &mut ciphertext).expect("error encrypting");
        ciphertext[message.len() + OVERHEAD - 1] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }
}
