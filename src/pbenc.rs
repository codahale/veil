//! Passphrase-based encryption based on Balloon Hashing.

use std::convert::TryInto;
use std::mem;

use rand::{CryptoRng, Rng};
use unicode_normalization::UnicodeNormalization;

use crate::duplex::{Duplex, TAG_LEN};

/// The number of bytes encryption adds to a plaintext.
pub const OVERHEAD: usize = U32_LEN + U32_LEN + SALT_LEN + TAG_LEN;

/// Encrypt the given plaintext using the given passphrase.
#[must_use]
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    passphrase: &str,
    time: u32,
    space: u32,
    plaintext: &[u8],
) -> Vec<u8> {
    // Generate a random salt.
    let salt: [u8; SALT_LEN] = rng.gen();

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase, &salt, time, space);

    // Allocate an output buffer.
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Encode the time, space, and block size parameters.
    out.extend(time.to_le_bytes());
    out.extend(space.to_le_bytes());

    // Copy the salt.
    out.extend(salt);

    // Encrypt the ciphertext.
    out.extend(pbenc.seal(plaintext));

    out
}

/// Decrypt the given ciphertext using the given passphrase.
#[must_use]
pub fn decrypt(passphrase: &str, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < OVERHEAD {
        return None;
    }

    // Decode the parameters.
    let (time, ciphertext) = ciphertext.split_at(U32_LEN);
    let time = u32::from_le_bytes(time.try_into().expect("invalid u32 len"));
    let (space, ciphertext) = ciphertext.split_at(U32_LEN);
    let space = u32::from_le_bytes(space.try_into().expect("invalid u32 len"));

    // Perform the balloon hashing.
    let (salt, ciphertext) = ciphertext.split_at(SALT_LEN);
    let mut pbenc = init(passphrase, salt, time, space);

    // Decrypt the ciphertext.
    pbenc.unseal(ciphertext)
}

macro_rules! hash_counter {
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr) => {
        $pbenc.absorb(&$ctr.to_le_bytes());
        $ctr += 1;

        $pbenc.absorb(&$left);
        $pbenc.absorb(&$right);
    };
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr, $out:expr) => {
        hash_counter!($pbenc, $ctr, $left, $right);
        $pbenc.squeeze_into(&mut $out);
    };
}

fn init(passphrase: &str, salt: &[u8], time: u32, space: u32) -> Duplex {
    // Normalize the passphrase into NFKC form.
    let passphrase = normalize(passphrase);

    // Initialize the duplex.
    let mut pbenc = Duplex::new("veil.pbenc");

    // Absorb the passphrase.
    pbenc.absorb(&passphrase);

    // Absorb the salt, time, space, block size, and delta parameters.
    pbenc.absorb(salt);
    pbenc.absorb(&time.to_le_bytes());
    pbenc.absorb(&space.to_le_bytes());
    pbenc.absorb(&(N as u32).to_le_bytes());
    pbenc.absorb(&(DELTA as u32).to_le_bytes());

    // Convert params.
    let time = time as usize;
    let space = space as usize;

    // Allocate buffers.
    let mut ctr = 0u64;
    let mut buf = vec![[0u8; N]; space];

    // Step 1: Expand input into buffer.
    hash_counter!(pbenc, ctr, &passphrase, salt, buf[0]);
    for m in 1..space {
        hash_counter!(pbenc, ctr, buf[m - 1], [], buf[m]);
    }

    // Step 2: Mix buffer contents.
    for t in 0..time {
        for m in 0..space {
            // Step 2a: Hash last and current blocks.
            let prev = (m as isize - 1).rem_euclid(space as isize) as usize;
            // wrap 0 to last block
            hash_counter!(pbenc, ctr, buf[prev], buf[m], buf[m]);

            // Step 2b: Hash in pseudo-randomly chosen blocks.
            for i in 0..DELTA {
                // Map indexes to a block and hash it and the salt.
                let mut idx = Vec::with_capacity(mem::size_of::<u64>() * 3);
                idx.extend((t as u64).to_le_bytes());
                idx.extend((m as u64).to_le_bytes());
                idx.extend((i as u64).to_le_bytes());
                hash_counter!(pbenc, ctr, salt, idx);

                // Map the PRF output to a block index.
                let mut idx = [0u8; mem::size_of::<u64>()];
                pbenc.squeeze_into(&mut idx);
                let idx = u64::from_le_bytes(idx) % space as u64;

                // Hash the pseudo-randomly selected block.
                hash_counter!(pbenc, ctr, buf[idx as usize], [], buf[m]);
            }
        }
    }

    // Step 3: Extract key from buffer.
    pbenc.rekey(&buf[buf.len() - 1]);

    pbenc
}

#[inline]
fn normalize(passphrase: &str) -> Vec<u8> {
    passphrase.nfkc().collect::<String>().as_bytes().to_vec()
}

const SALT_LEN: usize = 16;
const DELTA: usize = 3;
const N: usize = 32;
const U32_LEN: usize = mem::size_of::<u32>();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let ciphertext = encrypt(rand::thread_rng(), passphrase, 5, 3, message);

        let plaintext = decrypt(passphrase, &ciphertext);
        assert_eq!(Some(message.to_vec()), plaintext, "invalid plaintext");
    }

    #[test]
    fn bad_passphrase() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let ciphertext = encrypt(rand::thread_rng(), passphrase, 5, 3, message);

        let plaintext = decrypt("whoops", &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn bad_time() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(rand::thread_rng(), passphrase, 5, 3, message);
        ciphertext[0] ^= 1;

        let plaintext = decrypt(passphrase, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn bad_space() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(rand::thread_rng(), passphrase, 5, 3, message);
        ciphertext[8] ^= 1;

        let plaintext = decrypt(passphrase, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn bad_salt() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(rand::thread_rng(), passphrase, 5, 3, message);
        ciphertext[9] ^= 1;

        let plaintext = decrypt(passphrase, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn bad_ciphertext() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(rand::thread_rng(), passphrase, 5, 3, message);
        ciphertext[OVERHEAD - TAG_LEN + 1] ^= 1;

        let plaintext = decrypt(passphrase, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn bad_tag() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(rand::thread_rng(), passphrase, 5, 3, message);
        ciphertext[message.len() + OVERHEAD - 1] ^= 1;

        let plaintext = decrypt(passphrase, &ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }
}
