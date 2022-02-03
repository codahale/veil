use std::convert::TryInto;

use rand::RngCore;
use secrecy::{ExposeSecret, Secret, Zeroize};
use unicode_normalization::UnicodeNormalization;

use crate::constants::{MAC_LEN, U32_LEN};
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
    let mut pbenc = init(passphrase, &salt, time, space);

    // Allocate an output buffer.
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);

    // Encode the time, space, and block size parameters.
    out.extend(time.to_le_bytes());
    out.extend(space.to_le_bytes());

    // Copy the salt.
    out.extend(salt);

    // Encrypt the ciphertext.
    out.extend(pbenc.encrypt("ciphertext", plaintext));

    // Generate a MAC.
    out.extend(pbenc.mac("mac"));

    out
}

/// Decrypt the given ciphertext using the given passphrase.
#[must_use]
pub fn decrypt(passphrase: &str, ciphertext: &[u8]) -> Option<Secret<Vec<u8>>> {
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
    let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - MAC_LEN);
    let plaintext = pbenc.decrypt("ciphertext", ciphertext);

    // Verify the MAC.
    pbenc.verify_mac("mac", mac)?;

    Some(plaintext)
}

macro_rules! hash_counter {
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr) => {
        $pbenc.ad("counter", &$ctr.to_le_bytes());
        $ctr += 1;

        $pbenc.ad("left", &$left);
        $pbenc.ad("right", &$right);
    };
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr, $out:expr) => {
        hash_counter!($pbenc, $ctr, $left, $right);
        $pbenc.prf_fill("out", &mut $out);
    };
}

fn init(passphrase: &str, salt: &[u8], time: u32, space: u32) -> Protocol {
    // Normalize the passphrase into NFKC form.
    let passphrase = Secret::new(passphrase.nfkc().to_string().bytes().collect::<Vec<u8>>());

    // Initialize the protocol.
    let mut pbenc = Protocol::new("veil.pbenc");

    // Key with the passphrase.
    pbenc.key("passphrase", passphrase.expose_secret());

    // Include the salt, time, space, block size, and delta parameters as associated data.
    pbenc.ad("salt", salt);
    pbenc.ad("time", &time.to_le_bytes());
    pbenc.ad("space", &space.to_le_bytes());
    pbenc.ad("block-size", &(N as u32).to_le_bytes());
    pbenc.ad("delta", &(DELTA as u32).to_le_bytes());

    // Convert params.
    let time = time as usize;
    let space = space as usize;

    // Allocate buffers.
    let mut ctr = 0u64;
    let mut buf = vec![[0u8; N]; space];

    // Step 1: Expand input into buffer.
    hash_counter!(pbenc, ctr, passphrase.expose_secret(), salt, buf[0]);
    for m in 1..space {
        hash_counter!(pbenc, ctr, buf[m - 1], [], buf[m]);
    }

    // Step 2: Mix buffer contents.
    for t in 0..time {
        for m in 0..space {
            // Step 2a: Hash last and current blocks.
            let prev = (m as isize - 1).rem_euclid(space as isize) as usize; // wrap 0 to last block
            hash_counter!(pbenc, ctr, buf[prev], buf[m], buf[m]);

            // Step 2b: Hash in pseudo-randomly chosen blocks.
            for i in 0..DELTA {
                // Map indexes to a block and hash it and the salt.
                let mut idx = Vec::with_capacity(N);
                idx.extend((t as u64).to_le_bytes());
                idx.extend((m as u64).to_le_bytes());
                idx.extend((i as u64).to_le_bytes());

                hash_counter!(pbenc, ctr, salt, idx);

                // Map the PRF output to a block index.
                let idx = u64::from_le_bytes(pbenc.prf("idx")) % space as u64;

                // Hash the pseudo-randomly selected block.
                hash_counter!(pbenc, ctr, buf[idx as usize], [], buf[m]);
            }
        }
    }

    // Step 3: Extract output from buffer.
    pbenc.key("extract", &buf[space - 1]);

    // Zeroize buffer.
    buf.zeroize();

    pbenc
}

const SALT_LEN: usize = 16;
const DELTA: usize = 3;
const N: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn round_trip() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let ciphertext = encrypt(passphrase, 5, 3, message);
        let plaintext = decrypt(passphrase, &ciphertext);

        assert_eq!(message.as_slice(), plaintext.unwrap().expose_secret());
    }

    #[test]
    pub fn bad_passphrase() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let ciphertext = encrypt(passphrase, 5, 3, message);

        assert!(decrypt("whoops", &ciphertext).is_none());
    }

    #[test]
    pub fn bad_time() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[0] ^= 1;

        assert!(decrypt(passphrase, &ciphertext).is_none());
    }

    #[test]
    pub fn bad_space() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[8] ^= 1;

        assert!(decrypt(passphrase, &ciphertext).is_none());
    }

    #[test]
    pub fn bad_salt() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[9] ^= 1;

        assert!(decrypt(passphrase, &ciphertext).is_none());
    }

    #[test]
    pub fn bad_ciphertext() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[OVERHEAD - MAC_LEN + 1] ^= 1;

        assert!(decrypt(passphrase, &ciphertext).is_none());
    }

    #[test]
    pub fn bad_mac() {
        let passphrase = "this is a secret";
        let message = b"this is too";
        let mut ciphertext = encrypt(passphrase, 5, 3, message);
        ciphertext[message.len() + OVERHEAD - 1] ^= 1;

        assert!(decrypt(passphrase, &ciphertext).is_none());
    }
}
