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
    let (ct_time, ct_space) = ciphertext.split_at_mut(mem::size_of::<u8>());
    let (ct_space, salt) = ct_space.split_at_mut(mem::size_of::<u8>());
    let (salt, ciphertext) = salt.split_at_mut(SALT_LEN);

    // Encode the time and space parameters.
    ct_time[0] = time;
    ct_space[0] = space;

    // Generate a random salt.
    rng.fill_bytes(salt);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase, salt, time, space);

    // Encrypt the plaintext.
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    pbenc.seal_mut(ciphertext);
}

/// Decrypt the given ciphertext using the given passphrase.
#[must_use]
pub fn decrypt<'a>(passphrase: &[u8], in_out: &'a mut [u8]) -> Option<&'a [u8]> {
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Split up the input buffer.
    let (time, space) = in_out.split_at_mut(mem::size_of::<u8>());
    let (space, salt) = space.split_at_mut(mem::size_of::<u8>());
    let (salt, ciphertext) = salt.split_at_mut(SALT_LEN);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase, salt, time[0], space[0]);

    // Decrypt the ciphertext.
    pbenc.unseal_mut(ciphertext)
}

fn init(passphrase: &[u8], salt: &[u8], time: u8, space: u8) -> KeyedDuplex {
    // A macro for the common hash operations. This is a macro rather than a function so it can
    // accept both immutable references to blocks in the buffer as well as a mutable reference to a
    // block in the same buffer for output.
    macro_rules! hash {
        ($h:ident, $ctr:ident, $out:expr, $($block:expr),*) => {
            let mut h = $h.clone();
            h.absorb(&$ctr.to_le_bytes());
            $ctr = $ctr.wrapping_add(1);
            $(h.absorb($block);)*
            h.squeeze_mut($out);
        };
    }

    // Allocate buffer, initialize counter and default duplex state.
    let mut ctr = 0u64;
    let mut buf = vec![[0u8; N]; 1usize << space];
    let buf_len = u64::try_from(buf.len()).expect("unexpected overflow");
    let h = UnkeyedDuplex::new("veil.pbenc.iter");

    // Step 1: Expand input into buffer.
    hash!(h, ctr, &mut buf[0], passphrase, salt);
    for m in 1..buf.len() {
        hash!(h, ctr, &mut buf[m], &buf[m - 1]);
    }

    // Step 2: Mix buffer contents.
    for t in 0..1u64 << time {
        for m in 0..buf.len() {
            // Step 2a: Hash last and current blocks.
            let prev = (m + (buf.len() - 1)) % buf.len(); // wrap 0 to last block
            hash!(h, ctr, &mut buf[m], &buf[prev], &buf[m]);

            // Step 2b: Hash in pseudo-randomly chosen blocks.
            for i in 0..DELTA {
                // Hash the salt and the loop indexes as 64-bit integers.
                let mut idx_block = [0u8; mem::size_of::<u64>()];
                hash!(
                    h,
                    ctr,
                    &mut idx_block,
                    salt,
                    &t.to_le_bytes(),
                    &u64::try_from(m).expect("unexpected overflow").to_le_bytes(),
                    &i.to_le_bytes()
                );

                // Map the PRF output to a block index.
                let idx = u64::from_le_bytes(idx_block) % buf_len;
                let idx = usize::try_from(idx).expect("unexpected overflow");

                // Hash the pseudo-randomly selected block.
                hash!(h, ctr, &mut buf[m], &buf[idx]);
            }
        }
    }

    // Step 3: Extract key from buffer.
    let mut pbenc = UnkeyedDuplex::new("veil.pbenc");
    pbenc.absorb(&buf[buf.len() - 1]);
    pbenc.into_keyed()
}

const SALT_LEN: usize = 16;
const DELTA: u64 = 3;
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
