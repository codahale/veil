//! Passphrase-based encryption based on Balloon Hashing.

use std::mem;

use lockstitch::{Protocol, TAG_LEN};
use rand::{CryptoRng, Rng};

/// The number of bytes encryption adds to a plaintext.
pub const OVERHEAD: usize = mem::size_of::<u8>() + mem::size_of::<u8>() + SALT_LEN + TAG_LEN;

/// Encrypt the given plaintext using the given passphrase.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    passphrase: &[u8],
    time_cost: u8,
    memory_cost: u8,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (t, m) = ciphertext.split_at_mut(mem::size_of::<u8>());
    let (m, salt) = m.split_at_mut(mem::size_of::<u8>());
    let (salt, ciphertext) = salt.split_at_mut(SALT_LEN);

    // Encode the time and memory cost parameters.
    t[0] = time_cost;
    m[0] = memory_cost;

    // Generate a random salt.
    rng.fill_bytes(salt);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase, salt, time_cost, memory_cost);

    // Encrypt the plaintext.
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    pbenc.seal(ciphertext);
}

/// Decrypt the given ciphertext using the given passphrase.
#[must_use]
pub fn decrypt<'a>(passphrase: &[u8], in_out: &'a mut [u8]) -> Option<&'a [u8]> {
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Split up the input buffer.
    let (t, m) = in_out.split_at_mut(mem::size_of::<u8>());
    let (m, salt) = m.split_at_mut(mem::size_of::<u8>());
    let (salt, ciphertext) = salt.split_at_mut(SALT_LEN);

    // Perform the balloon hashing.
    let mut pbenc = init(passphrase, salt, t[0], m[0]);

    // Decrypt the ciphertext.
    pbenc.open(ciphertext)
}

fn init(passphrase: &[u8], salt: &[u8], time_cost: u8, memory_cost: u8) -> Protocol {
    // A macro for the common hash operations. This is a macro rather than a function so it can
    // accept both immutable references to blocks in the buffer as well as a mutable reference to a
    // block in the same buffer for output. Accepts a template protocol, a counter variable, an
    // output block, and a sequence of input blocks.

    macro_rules! hash {
        ($h:ident, $ctr:ident, $out:expr, $($block:expr),*) => {
            // Clone the template protocol's state, allowing us to avoid the cost of a single
            // permutation.
            let mut h = $h.clone();

            // Mix the counter as a Little Endian byte string into the protocol.
            h.mix(&$ctr.to_le_bytes());

            // Increment the counter by one.
            $ctr = $ctr.wrapping_add(1);

            // Mix each block in order into the protocol.
            $(
                h.mix($block);
            )*

            // Fill the output with derived data.
            h.derive($out);
        };
    }

    // Allocate buffer, initialize counter and default protocol state.
    let mut ctr = 0u64;
    let mut buf = vec![[0u8; N]; 1usize << memory_cost];
    let buf_len = u64::try_from(buf.len()).expect("usize should be <= u64");
    let h = Protocol::new("veil.pbenc.iter");

    // Step 1: Expand input into buffer.
    hash!(h, ctr, &mut buf[0], passphrase, salt);
    for m in 1..buf.len() {
        hash!(h, ctr, &mut buf[m], &buf[m - 1]);
    }

    // Step 2: Mix buffer contents.
    for t in 0..1u64 << time_cost {
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
                    &u64::try_from(m).expect("usize should be <= u64").to_le_bytes(),
                    &i.to_le_bytes()
                );

                // Map the derived output to a block index.
                let idx = u64::from_le_bytes(idx_block) % buf_len;
                let idx = usize::try_from(idx).expect("usize should be <= u64");

                // Hash the pseudo-randomly selected block.
                hash!(h, ctr, &mut buf[m], &buf[idx]);
            }
        }
    }

    // Step 3: Extract key from buffer.
    let mut pbenc = Protocol::new("veil.pbenc");
    pbenc.mix(&buf[buf.len() - 1]);
    pbenc
}

const SALT_LEN: usize = 16;
const DELTA: u64 = 3;
const N: usize = 1024;

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let (_, passphrase, plaintext, mut ciphertext) = setup();
        assert_eq!(
            Some(plaintext.as_slice()),
            decrypt(&passphrase, &mut ciphertext),
            "invalid plaintext"
        );
    }

    #[test]
    fn wrong_passphrase() {
        let (mut rng, _, _, mut ciphertext) = setup();
        let wrong_passphrase = rng.gen::<[u8; 32]>();
        assert_eq!(
            None,
            decrypt(&wrong_passphrase, &mut ciphertext),
            "decrypted an invalid ciphertext"
        );
    }

    #[test]
    fn modified_time_cost() {
        let (_, passphrase, _, mut ciphertext) = setup();
        ciphertext[0] ^= 1;
        assert_eq!(None, decrypt(&passphrase, &mut ciphertext), "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_memory_cost() {
        let (_, passphrase, _, mut ciphertext) = setup();
        ciphertext[1] ^= 1;
        assert_eq!(None, decrypt(&passphrase, &mut ciphertext), "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_salt() {
        let (_, passphrase, _, mut ciphertext) = setup();
        ciphertext[9] ^= 1;
        assert_eq!(None, decrypt(&passphrase, &mut ciphertext), "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_ciphertext() {
        let (_, passphrase, _, mut ciphertext) = setup();
        ciphertext[OVERHEAD - TAG_LEN + 1] ^= 1;
        assert_eq!(None, decrypt(&passphrase, &mut ciphertext), "decrypted an invalid ciphertext");
    }

    #[test]
    fn modified_tag() {
        let (_, passphrase, plaintext, mut ciphertext) = setup();
        ciphertext[plaintext.len() + OVERHEAD - 1] ^= 1;
        assert_eq!(None, decrypt(&passphrase, &mut ciphertext), "decrypted an invalid ciphertext");
    }

    fn setup() -> (ChaChaRng, [u8; 32], [u8; 64], Vec<u8>) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let passphrase = rng.gen::<[u8; 32]>();
        let plaintext = rng.gen::<[u8; 64]>();

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, &passphrase, 1, 6, &plaintext, &mut ciphertext);

        (rng, passphrase, plaintext, ciphertext)
    }
}
