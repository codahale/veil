//! pbenc implements memory-hard password-based encryption via STROBE using
//! [balloon hashing](https://eprint.iacr.org/2016/027.pdf).
//!
//! # Initialization
//!
//! The protocol is initialized as follows, given a passphrase `P`, salt `S`, delta constant `D`,
//! space parameter `N_space`, time parameter `N_time`, block size `N_block`, and MAC size `N_mac`:
//!
//! ```text
//! INIT('veil.kdf.balloon', level=256)
//! AD(LE_U32(D),            meta=true)
//! AD(LE_U32(N_block),      meta=true)
//! AD(LE_U32(N_mac),        meta=true)
//! AD(LE_U32(N_time),       meta=true)
//! AD(LE_U32(N_space),      meta=true)
//! KEY(P)
//! AD(S)
//! ```
//!
//! Then, for each iteration of the balloon hashing algorithm, given a counter `C`, a left block
//! `L`, and a right block `R`:
//!
//! ```text
//! AD(LE_U64(C))
//! AD(L)
//! AD(R)
//! PRF(N)
//! ```
//!
//! The final block `B_n` of the balloon hashing algorithm is then used to key the protocol:
//!
//! ```text
//! KEY(B_n)
//! ```
//!
//! # Encryption
//!
//! Encryption of a message `M` is as follows:
//!
//! ```text
//! SEND_ENC(M)
//! SEND_MAC(T)
//! ```
//!
//! The ciphertext `C` and MAC `T` are returned.
//!
//! # Decryption
//!
//! Decryption of a ciphertext `C` and MAC `T` is as follows:
//!
//! ```text
//! RECV_ENC(C)
//! RECV_MAC(T)
//! ```
//!
//! If the `RECV_MAC` call is successful, the plaintext is returned.
//!
//! It should be noted that there is no standard balloon hashing algorithm, so this protocol is in
//! the very, very tall grass of cryptography and should never be used.
//!

use byteorder::ByteOrder;
use rand::Rng;
use strobe_rs::{SecParam, Strobe};

use crate::common;

const SALT_LEN: usize = 16;

pub(crate) fn encrypt(passphrase: &[u8], plaintext: &[u8], time: u32, space: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt);

    let mut pbenc = init(passphrase, &salt, time, space);

    let mut out = Vec::with_capacity(SALT_LEN + plaintext.len() + common::MAC_LEN + 8);
    out.extend(&time.to_le_bytes());
    out.extend(&space.to_le_bytes());
    out.extend(&salt);

    out.extend(plaintext);
    pbenc.send_enc(&mut out[8 + SALT_LEN..], false);

    out.extend(&[0u8; common::MAC_LEN]);
    pbenc.send_mac(&mut out[8 + SALT_LEN + plaintext.len()..], false);

    out
}

pub(crate) fn decrypt(passphrase: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let time = byteorder::LE::read_u32(&ciphertext[..4]);
    let space = byteorder::LE::read_u32(&ciphertext[4..8]);

    let mut pbenc = init(passphrase, &ciphertext[8..SALT_LEN + 8], time, space);

    let pt_len = ciphertext.len() - common::MAC_LEN - SALT_LEN - 8;

    let mut out = Vec::with_capacity(ciphertext.len());
    out.extend(&ciphertext[8 + SALT_LEN..]);
    pbenc.recv_enc(&mut out[..pt_len], false);

    if pbenc.recv_mac(&mut out[pt_len..]).is_err() {
        return None;
    }

    Some(out[..pt_len].to_vec())
}

fn init(passphrase: &[u8], salt: &[u8], time: u32, space: u32) -> Strobe {
    let mut pbenc = Strobe::new(b"", SecParam::B256);

    // Initialize protocol with metadata.
    pbenc.meta_ad(&(DELTA as u32).to_le_bytes(), false);
    pbenc.meta_ad(&(N as u32).to_le_bytes(), false);
    pbenc.meta_ad(&(common::MAC_LEN as u32).to_le_bytes(), false);
    pbenc.meta_ad(&time.to_le_bytes(), false);
    pbenc.meta_ad(&space.to_le_bytes(), false);

    // Key with the passphrase and include the salt as associated data.
    pbenc.key(passphrase, false);
    pbenc.ad(salt, false);

    // Allocate buffers.
    let mut ctr = 0u64;
    let mut idx = [0u8; N];
    let mut buf: Vec<[u8; N]> = (0..space).map(|_| [0u8; N]).collect();

    // Step 1: Expand input into buffer.
    buf[0] = hash_counter(&mut pbenc, &mut ctr, passphrase, salt);
    for m in 1..space as usize {
        buf[m] = hash_counter(&mut pbenc, &mut ctr, &buf[m - 1], &[]);
    }

    // Step 2: Mix buffer contents.
    for t in 1..time as usize {
        for m in 1..space as usize {
            // Step 2a: Hash last and current blocks.
            let prev = (m - 1) % space as usize;
            buf[m] = hash_counter(&mut pbenc, &mut ctr, &buf[prev], &buf[m]);

            // Step 2b: Hash in pseudo-randomly chosen blocks.
            for i in 0..DELTA {
                // Map indexes to a block and hash it and the salt.
                byteorder::LE::write_u32(&mut idx[0..4], t as u32);
                byteorder::LE::write_u32(&mut idx[0..4], m as u32);
                byteorder::LE::write_u32(&mut idx[0..4], i as u32);
                idx = hash_counter(&mut pbenc, &mut ctr, salt, &idx);

                // Map the hashed index block back to an index and hash that block.
                let other = (byteorder::LE::read_u64(&idx) % space as u64) as usize;
                buf[m] = hash_counter(&mut pbenc, &mut ctr, &buf[other], &[]);
            }
        }
    }

    // Step 3: Extract output from buffer.
    pbenc.key(&buf[space as usize - 1], false);

    pbenc
}

fn hash_counter(pbenc: &mut Strobe, ctr: &mut u64, left: &[u8], right: &[u8]) -> [u8; N] {
    *ctr += 1;

    pbenc.ad(&ctr.to_le_bytes(), false);
    pbenc.ad(left, false);
    pbenc.ad(right, false);

    let mut out = [0u8; N];
    pbenc.prf(&mut out, false);
    out
}

const N: usize = 32;
const DELTA: usize = 3;

#[cfg(test)]
mod tests {
    use crate::pbenc::{decrypt, encrypt};

    #[test]
    pub fn round_trip() {
        let passphrase = b"this is a secret";
        let message = b"this is too";
        let ciphertext = encrypt(passphrase, message, 5, 3);
        let plaintext = decrypt(passphrase, &ciphertext);

        assert_eq!(Some(message.to_vec()), plaintext);
    }
}
