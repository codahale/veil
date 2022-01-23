use std::convert::TryInto;

use rand::RngCore;
use unicode_normalization::UnicodeNormalization;

use crate::constants::{MAC_LEN, U32_LEN, U64_LEN};
use crate::strobe::Protocol;

/// The number of bytes encryption adds to a plaintext.
pub const OVERHEAD: usize = U32_LEN + U32_LEN + SALT_LEN + MAC_LEN;

/// Encrypt the given plaintext using the given passphrase.
#[must_use]
pub fn encrypt(passphrase: &str, time: u32, space: u32, plaintext: &[u8]) -> Vec<u8> {
    // Generate a random salt.
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase.nfkc().to_string().as_bytes(), &salt, time, space);

    // Allocate an output buffer.
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Encode the time and space parameters.
    out.extend(time.to_le_bytes());
    out.extend(space.to_le_bytes());

    // Copy the salt.
    out.extend(salt);

    // Encrypt the ciphertext.
    out.extend(pbenc.encrypt("ciphertext", plaintext));

    // Generate a MAC.
    out.extend(pbenc.mac::<MAC_LEN>("mac"));

    out
}

/// Decrypt the given ciphertext using the given passphrase.
#[must_use]
pub fn decrypt(passphrase: &str, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < U32_LEN + U32_LEN + SALT_LEN + MAC_LEN {
        return None;
    }

    // Split the input into parts.
    let mut time = Vec::from(ciphertext);
    let mut space = time.split_off(U32_LEN);
    let mut salt = space.split_off(U32_LEN);
    let mut ciphertext = salt.split_off(SALT_LEN);
    let mac = ciphertext.split_off(ciphertext.len() - MAC_LEN);

    // Decode the time and space parameters.
    let time = u32::from_le_bytes(time.try_into().ok()?);
    let space = u32::from_le_bytes(space.try_into().ok()?);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase.nfkc().to_string().as_bytes(), &salt, time, space);

    // Decrypt the ciphertext.
    let plaintext = pbenc.decrypt("ciphertext", &ciphertext);

    // Verify the MAC.
    pbenc.verify_mac("mac", &mac)?;

    Some(plaintext)
}

macro_rules! hash_counter {
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr, $out:expr) => {
        $ctr += 1;

        $pbenc.as_mut().meta_ad(b"counter", false);
        $pbenc.as_mut().meta_ad(&(U64_LEN as u32).to_le_bytes(), true);
        $pbenc.as_mut().ad(&$ctr.to_le_bytes(), false);

        $pbenc.as_mut().meta_ad(b"left", false);
        $pbenc.as_mut().meta_ad(&($left.len() as u32).to_le_bytes(), true);
        $pbenc.as_mut().ad(&$left, false);

        $pbenc.as_mut().meta_ad(b"right", false);
        $pbenc.as_mut().meta_ad(&($right.len() as u32).to_le_bytes(), true);
        $pbenc.as_mut().ad(&$right, false);

        $pbenc.as_mut().meta_ad(b"out", false);
        $pbenc.as_mut().meta_ad(&(N as u32).to_le_bytes(), true);
        $pbenc.as_mut().prf(&mut $out, false);
    };
}

fn init(passphrase: &[u8], salt: &[u8], time: u32, space: u32) -> Protocol {
    let mut pbenc = Protocol::new("veil.pbenc");

    // Key with the passphrase.
    pbenc.key("passphrase", passphrase);

    // Include the salt as associated data.
    pbenc.ad("salt", salt);

    // Allocate buffers.
    let mut ctr = 0u64;
    let mut idx = [0u8; N];
    let mut buf = vec![[0u8; N]; space as usize];

    // Step 1: Expand input into buffer.
    pbenc.as_mut().meta_ad(b"expand", false);
    hash_counter!(pbenc, ctr, passphrase, salt, buf[0]);
    for m in 1..space as usize {
        pbenc.as_mut().meta_ad(b"space", false);
        pbenc.as_mut().meta_ad(&(m as u32).to_le_bytes(), true);
        hash_counter!(pbenc, ctr, buf[m - 1], [0u8; 0], buf[m]);
    }

    // Step 2: Mix buffer contents.
    pbenc.as_mut().meta_ad(b"mix", false);
    for t in 0..time as usize {
        pbenc.as_mut().meta_ad(b"time", false);
        pbenc.as_mut().meta_ad(&(t as u32).to_le_bytes(), true);

        for m in 0..space as usize {
            pbenc.as_mut().meta_ad(b"space", false);
            pbenc.as_mut().meta_ad(&(m as u32).to_le_bytes(), true);

            // Step 2a: Hash last and current blocks.
            pbenc.as_mut().meta_ad(b"mix-a", false);
            let prev = (m as isize - 1).rem_euclid(space as isize) as usize; // wrap 0 to last block
            hash_counter!(pbenc, ctr, buf[prev], buf[m], buf[m]);

            // Step 2b: Hash in pseudo-randomly chosen blocks.
            pbenc.as_mut().meta_ad(b"mix-b", false);
            for i in 0..DELTA {
                pbenc.as_mut().meta_ad(b"delta", false);
                pbenc.as_mut().meta_ad(&(i as u32).to_le_bytes(), true);

                // Map indexes to a block and hash it and the salt.
                idx[..U64_LEN].copy_from_slice(&(t as u64).to_le_bytes());
                idx[U64_LEN..U64_LEN * 2].copy_from_slice(&(m as u64).to_le_bytes());
                idx[U64_LEN * 2..U64_LEN * 3].copy_from_slice(&(i as u64).to_le_bytes());
                hash_counter!(pbenc, ctr, salt, idx, idx);

                // Map the hashed index block back to an index and hash that block.
                let v = u64::from_le_bytes(idx[..U64_LEN].try_into().expect("invalid u64 len"));
                hash_counter!(pbenc, ctr, buf[(v % space as u64) as usize], [0u8; 0], buf[m]);
            }
        }
    }

    // Step 3: Extract output from buffer.
    pbenc.key("extract", &buf[space as usize - 1]);

    pbenc
}

const SALT_LEN: usize = 16;
const N: usize = 32;
const DELTA: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn round_trip() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let ciphertext = encrypt(passphrase, 5, 3, message);
        let plaintext = decrypt(passphrase, &ciphertext);

        assert_eq!(Some(message.to_vec()), plaintext);
    }

    #[test]
    pub fn bad_time() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[0] ^= 1;

        assert_eq!(None, decrypt(passphrase, &ciphertext));
    }

    #[test]
    pub fn bad_space() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[5] ^= 1;

        assert_eq!(None, decrypt(passphrase, &ciphertext));
    }

    #[test]
    pub fn bad_salt() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[12] ^= 1;

        assert_eq!(None, decrypt(passphrase, &ciphertext));
    }

    #[test]
    pub fn bad_ciphertext() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[37] ^= 1;

        assert_eq!(None, decrypt(passphrase, &ciphertext));
    }

    #[test]
    pub fn bad_mac() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[49] ^= 1;

        assert_eq!(None, decrypt(passphrase, &ciphertext));
    }
}
