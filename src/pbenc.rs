use rand::RngCore;
use std::convert::TryInto;

use unicode_normalization::UnicodeNormalization;

use crate::constants::{MAC_LEN, U32_LEN, U64_LEN};
use crate::strobe::Protocol;

/// Encrypt the given plaintext using the given passphrase.
#[must_use]
pub fn encrypt(passphrase: &str, time: u32, space: u32, plaintext: &[u8]) -> Vec<u8> {
    // Generate a random salt.
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase.nfkc().to_string().as_bytes(), &salt, time, space);

    // Allocate an output buffer.
    let mut out = vec![0u8; CT_OFFSET + plaintext.len() + MAC_LEN];

    // Encode the time and space parameters.
    out[TIME_OFFSET..SPACE_OFFSET].copy_from_slice(&time.to_le_bytes());
    out[SPACE_OFFSET..SALT_OFFSET].copy_from_slice(&space.to_le_bytes());

    // Copy the salt.
    out[SALT_OFFSET..CT_OFFSET].copy_from_slice(&salt);

    // Copy the plaintext and encrypt it.
    out[CT_OFFSET..CT_OFFSET + plaintext.len()].copy_from_slice(plaintext);
    pbenc.send_enc(&mut out[CT_OFFSET..CT_OFFSET + plaintext.len()], false);

    // Generate a MAC.
    pbenc.send_mac(&mut out[CT_OFFSET + plaintext.len()..], false);

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
    let mut mac = ciphertext.split_off(ciphertext.len() - MAC_LEN);

    // Decode the time and space parameters.
    let time = u32::from_le_bytes(time.try_into().ok()?);
    let space = u32::from_le_bytes(space.try_into().ok()?);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase.nfkc().to_string().as_bytes(), &salt, time, space);

    // Decrypt the ciphertext.
    pbenc.recv_enc(&mut ciphertext, false);
    let plaintext = ciphertext;

    // Verify the MAC.
    pbenc.recv_mac(&mut mac).ok()?;

    Some(plaintext)
}

macro_rules! hash_counter {
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr, $out:expr) => {
        $ctr += 1;

        $pbenc.ad(&$ctr.to_le_bytes(), false);
        $pbenc.ad(&$left, false);
        $pbenc.ad(&$right, false);

        $pbenc.prf(&mut $out, false);
    };
}

fn init(passphrase: &[u8], salt: &[u8], time: u32, space: u32) -> Protocol {
    let mut pbenc = Protocol::new("veil.pbenc");

    // Initialize protocol with metadata.
    pbenc.meta_ad_u32(DELTA as u32);
    pbenc.meta_ad_u32(N as u32);
    pbenc.meta_ad_u32(MAC_LEN as u32);
    pbenc.meta_ad_u32(time);
    pbenc.meta_ad_u32(space);

    // Key with the passphrase and include the salt as associated data.
    pbenc.key(passphrase, false);
    pbenc.ad(salt, false);

    // Allocate buffers.
    let mut ctr = 0u64;
    let mut idx = [0u8; N];
    let mut buf = vec![[0u8; N]; space as usize];

    // Step 1: Expand input into buffer.
    hash_counter!(pbenc, ctr, passphrase, salt, buf[0]);
    for m in 1..space as usize {
        hash_counter!(pbenc, ctr, buf[m - 1], [], buf[m]);
    }

    // Step 2: Mix buffer contents.
    for t in 0..time as usize {
        for m in 0..space as usize {
            // Step 2a: Hash last and current blocks.
            let prev = (m as isize - 1).rem_euclid(space as isize) as usize; // wrap 0 to last block
            hash_counter!(pbenc, ctr, buf[prev], buf[m], buf[m]);

            // Step 2b: Hash in pseudo-randomly chosen blocks.
            for i in 0..DELTA {
                // Map indexes to a block and hash it and the salt.
                idx[..U64_LEN].copy_from_slice(&(t as u64).to_le_bytes());
                idx[U64_LEN..U64_LEN * 2].copy_from_slice(&(m as u64).to_le_bytes());
                idx[U64_LEN * 2..U64_LEN * 3].copy_from_slice(&(i as u64).to_le_bytes());
                hash_counter!(pbenc, ctr, salt, idx, idx);

                // Map the hashed index block back to an index and hash that block.
                let v = u64::from_le_bytes(idx[..U64_LEN].try_into().expect("invalid u64 len"));
                hash_counter!(pbenc, ctr, buf[(v % space as u64) as usize], [], buf[m]);
            }
        }
    }

    // Step 3: Extract output from buffer.
    pbenc.key(&buf[space as usize - 1], false);

    pbenc
}

const SALT_LEN: usize = 16;
const TIME_OFFSET: usize = 0;
const SPACE_OFFSET: usize = U32_LEN;
const SALT_OFFSET: usize = SPACE_OFFSET + U32_LEN;
const CT_OFFSET: usize = SALT_OFFSET + SALT_LEN;
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
