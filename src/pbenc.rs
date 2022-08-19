//! Passphrase-based encryption based on Balloon Hashing.

use std::mem;

use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex, TAG_LEN};

/// The number of bytes encryption adds to a plaintext.
pub const OVERHEAD: usize = mem::size_of::<u8>() + mem::size_of::<u8>() + SALT_LEN + TAG_LEN;

/// Encrypt the given plaintext using the given passphrase.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    passphrase: &[u8],
    time: u8,
    space: u8,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (out_time, out_space) = ciphertext.split_at_mut(mem::size_of::<u8>());
    let (out_space, out_salt) = out_space.split_at_mut(mem::size_of::<u8>());
    let (out_salt, out_ciphertext) = out_salt.split_at_mut(SALT_LEN);

    // Encode the time and space parameters.
    out_time[0] = time;
    out_space[0] = space;

    // Generate a random salt.
    rng.fill_bytes(out_salt);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase, out_salt, time, space);

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
    let (time, ciphertext) = in_out.split_at_mut(1);
    let time = time[0];
    let (space, ciphertext) = ciphertext.split_at_mut(1);
    let space = space[0];

    // Perform the balloon hashing.
    let (salt, ciphertext) = ciphertext.split_at_mut(SALT_LEN);
    let mut pbenc = init(passphrase, salt, time, space);

    // Decrypt the ciphertext.
    pbenc.unseal_mut(ciphertext)
}

macro_rules! hash_counter {
    ($pbenc:ident, $ctr:ident, $left:expr) => {
        $pbenc.absorb(&$ctr.to_le_bytes());
        $ctr += 1;

        $pbenc.absorb(&$left);
    };
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr) => {
        hash_counter!($pbenc, $ctr, $left);
        $pbenc.absorb(&$right);
    };
    ($pbenc:ident, $ctr:ident, $left:expr, $right:expr, $out:expr) => {
        hash_counter!($pbenc, $ctr, $left, $right);
        $pbenc.squeeze_mut(&mut $out);
    };
}

fn init(passphrase: &[u8], salt: &[u8], time: u8, space: u8) -> KeyedDuplex {
    // Initialize an unkeyed duplex.
    let mut pbenc = UnkeyedDuplex::new("veil.pbenc");

    // Absorb the passphrase.
    pbenc.absorb(passphrase);

    // Absorb the salt, time, space, block size, and delta parameters.
    pbenc.absorb(salt);
    pbenc.absorb(&[time]);
    pbenc.absorb(&[space]);
    pbenc.absorb(&[N.try_into().expect("unexpected overflow")]);
    pbenc.absorb(&[DELTA.try_into().expect("unexpected overflow")]);

    // Convert time and space params into linear terms.
    let time = 1usize << time;
    let space = 1usize << space;
    let space64 = u64::try_from(space).expect("unexpected overflow");

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
            let prev = (m + (space - 1)) % space; // wrap 0 to last block
            hash_counter!(pbenc, ctr, buf[prev], buf[m], buf[m]);

            // Step 2b: Hash in pseudo-randomly chosen blocks.
            for i in 0..DELTA {
                // Hash the salt and the indexes.
                hash_counter!(pbenc, ctr, salt);
                pbenc.absorb(&u64::try_from(t).expect("unexpected overflow").to_le_bytes());
                pbenc.absorb(&u64::try_from(m).expect("unexpected overflow").to_le_bytes());
                pbenc.absorb(&u64::try_from(i).expect("unexpected overflow").to_le_bytes());

                // Map the PRF output to a block index.
                let idx = usize::try_from(u64::from_le_bytes(pbenc.squeeze()) % space64)
                    .expect("unexpected overflow");

                // Hash the pseudo-randomly selected block.
                hash_counter!(pbenc, ctr, buf[idx], [], buf[m]);
            }
        }
    }

    // Step 3: Extract key from buffer.
    pbenc.absorb(&buf[buf.len() - 1]);

    // Convert the unkeyed duplex to a keyed duplex.
    pbenc.into_keyed()
}

const SALT_LEN: usize = 16;
const DELTA: usize = 3;
const N: usize = 32;

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
        encrypt(&mut rng, passphrase, 2, 6, message, &mut ciphertext);

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(Some(message.as_slice()), plaintext, "invalid plaintext");
    }

    #[test]
    fn wrong_passphrase() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 2, 6, message, &mut ciphertext);

        let plaintext = decrypt(b"whoops", &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_time() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let passphrase = b"this is a secret";
        let message = b"this is too";
        let mut ciphertext = vec![0u8; message.len() + OVERHEAD];
        encrypt(&mut rng, passphrase, 2, 6, message, &mut ciphertext);
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
        encrypt(&mut rng, passphrase, 2, 6, message, &mut ciphertext);
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
        encrypt(&mut rng, passphrase, 2, 6, message, &mut ciphertext);
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
        encrypt(&mut rng, passphrase, 2, 6, message, &mut ciphertext);
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
        encrypt(&mut rng, passphrase, 2, 6, message, &mut ciphertext);
        ciphertext[message.len() + OVERHEAD - 1] ^= 1;

        let plaintext = decrypt(passphrase, &mut ciphertext);
        assert_eq!(None, plaintext, "decrypted an invalid ciphertext");
    }
}
