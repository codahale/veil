//! A multi-receiver, hybrid cryptosystem.

use std::io::{self, Read, Write};
use std::mem;

use rand::{CryptoRng, Rng};

use crate::blockio::ReadBlock;
use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex, TAG_LEN};
use crate::keys::{PrivKey, PubKey};
use crate::schnorr::SIGNATURE_LEN;
use crate::sres::NONCE_LEN;
use crate::{schnorr, sres, DecryptError, Signature};

/// Encrypt the contents of `reader` such that they can be decrypted and verified by all members of
/// `receivers` and write the ciphertext to `writer` with `padding` bytes of random data added.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    reader: impl Read,
    mut writer: impl Write,
    sender: &PrivKey,
    receivers: &[PubKey],
    padding: usize,
) -> io::Result<u64> {
    let padding = u64::try_from(padding).expect("unexpected overflow");

    // Initialize an unkeyed duplex and absorb the sender's public key.
    let mut mres = UnkeyedDuplex::new("veil.mres");
    mres.absorb(&sender.pub_key.encoded);

    // Generate ephemeral key pair, DEK, and nonce.
    let (ephemeral, dek, nonce) = mres.hedge(&mut rng, sender, |clone| {
        (clone.squeeze_private_key(), clone.squeeze(), clone.squeeze::<NONCE_LEN>())
    });

    // Absorb and write the nonce.
    mres.absorb(&nonce);
    writer.write_all(&nonce)?;
    let mut written = u64::try_from(NONCE_LEN).expect("unexpected overflow");

    // Encrypt a header for each receiver.
    written += encrypt_headers(
        &mut mres,
        &mut rng,
        sender,
        &ephemeral,
        receivers,
        &dek,
        padding,
        &mut writer,
    )?;

    // Add random padding to the end of the headers.
    written += mres.absorb_reader_into(RngRead(&mut rng).take(padding), &mut writer)?;

    // Absorb the DEK.
    mres.absorb(&dek);

    // Convert the unkeyed duplex to a keyed duplex.
    let mut mres = mres.into_keyed();

    // Encrypt the plaintext in blocks and write them.
    written += encrypt_message(&mut mres, reader, &mut writer)?;

    // Sign the duplex's final state with the ephemeral private key and append the signature.
    let sig = schnorr::sign_duplex(&mut mres, &mut rng, &ephemeral);
    writer.write_all(&sig.encode())?;

    Ok(written + u64::try_from(SIGNATURE_LEN).expect("unexpected overflow"))
}

/// The length of the data encryption key.
const DEK_LEN: usize = 32;

const HEADER_LEN: usize = DEK_LEN + mem::size_of::<u64>() + mem::size_of::<u64>();

/// Encode the DEK, header count, and padding size in a header.
#[inline]
#[must_use]
fn encode_header(dek: &[u8; DEK_LEN], recv_count: u64, padding: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let (hdr_dek, hdr_recv_count) = header.split_at_mut(DEK_LEN);
    let (hdr_recv_count, hdr_padding) = hdr_recv_count.split_at_mut(mem::size_of::<u64>());
    hdr_dek.copy_from_slice(dek);
    hdr_recv_count.copy_from_slice(&recv_count.to_le_bytes());
    hdr_padding.copy_from_slice(&padding.to_le_bytes());
    header
}

#[allow(clippy::too_many_arguments)]
fn encrypt_headers(
    mres: &mut UnkeyedDuplex,
    mut rng: impl Rng + CryptoRng,
    sender: &PrivKey,
    ephemeral: &PrivKey,
    receivers: &[PubKey],
    dek: &[u8; DEK_LEN],
    padding: u64,
    mut writer: impl Write,
) -> io::Result<u64> {
    let mut written = 0u64;
    let header =
        encode_header(dek, receivers.len().try_into().expect("unexpected overflow"), padding);
    let mut enc_header = [0u8; ENC_HEADER_LEN];

    // For each receiver, encrypt a copy of the header with veil.sres.
    for receiver in receivers {
        // Squeeze a nonce for each header.
        let nonce = mres.squeeze::<NONCE_LEN>();

        // Encrypt the header for the given receiver.
        sres::encrypt(&mut rng, sender, ephemeral, receiver, &nonce, &header, &mut enc_header);

        // Absorb the encrypted header.
        mres.absorb(&enc_header);

        // Write the encrypted header.
        writer.write_all(&enc_header)?;
        written += u64::try_from(ENC_HEADER_LEN).expect("unexpected overflow");
    }

    Ok(written)
}

/// The length of plaintext blocks which are encrypted.
const BLOCK_LEN: usize = 32 * 1024;

/// Given a duplex keyed with the DEK, read the entire contents of `reader` in blocks and write the
/// encrypted blocks and authentication tags to `writer`.
fn encrypt_message(
    mres: &mut KeyedDuplex,
    mut reader: impl Read,
    mut writer: impl Write,
) -> io::Result<u64> {
    let mut buf = [0u8; ENC_BLOCK_LEN];
    let mut written = 0;

    loop {
        // Read a block of data.
        let n = reader.read_block(&mut buf[..BLOCK_LEN])?;
        let block = &mut buf[..n + TAG_LEN];

        // Encrypt the block and write the ciphertext and a tag.
        mres.seal_mut(block);
        writer.write_all(block)?;
        written += u64::try_from(block.len()).expect("unexpected overflow");

        // If the block was undersized, we're at the end of the reader.
        if n < BLOCK_LEN {
            break;
        }
    }

    // Return the number of ciphertext bytes written.
    Ok(written)
}

/// Decrypt the contents of `reader` iff they were originally encrypted by `q_s` for `q_r` and write
/// the plaintext to `writer`.
pub fn decrypt(
    mut reader: impl Read,
    mut writer: impl Write,
    receiver: &PrivKey,
    sender: &PubKey,
) -> Result<u64, DecryptError> {
    // Initialize an unkeyed duplex and absorb the sender's public key.
    let mut mres = UnkeyedDuplex::new("veil.mres");
    mres.absorb(&sender.encoded);

    // Read and absorb the nonce.
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce)?;
    mres.absorb(&nonce);

    // Find a header, decrypt it, and write the entirety of the headers and padding to the duplex.
    let (ephemeral, dek) = decrypt_header(&mut mres, &mut reader, receiver, sender)?;

    // Absorb the DEK.
    mres.absorb(&dek);

    // Convert the duplex to a keyed duplex.
    let mut mres = mres.into_keyed();

    // Decrypt the message.
    let (written, sig) = decrypt_message(&mut mres, &mut reader, &mut writer)?;

    // Verify the signature and return the number of bytes written.
    schnorr::verify_duplex(&mut mres, &ephemeral, &sig)
        .and(Some(written))
        .ok_or(DecryptError::InvalidCiphertext)
}

/// The length of an encrypted block and authentication tag.
const ENC_BLOCK_LEN: usize = BLOCK_LEN + TAG_LEN;

/// Given a duplex keyed with the DEK, read the entire contents of `reader` in blocks and write the
/// decrypted blocks `writer`.
fn decrypt_message(
    mres: &mut KeyedDuplex,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(u64, Signature), DecryptError> {
    let mut buf = [0u8; ENC_BLOCK_LEN + SIGNATURE_LEN];
    let mut offset = 0;
    let mut written = 0;

    loop {
        // Read a block and a possible signature, keeping in mind the unused bit of the buffer from
        // the last iteration.
        let n = reader.read_block(&mut buf[offset..])?;

        // If we're at the end of the reader, we only have the signature left to process. Break out
        // of the read loop and go process the signature.
        if n == 0 {
            break;
        }

        // Pretend we don't see the possible signature at the end.
        let block_len = n - SIGNATURE_LEN + offset;
        let block = &mut buf[..block_len];

        // Decrypt the block and write the plaintext. If the block cannot be decrypted, return an
        // error.
        let plaintext = mres.unseal_mut(block).ok_or(DecryptError::InvalidCiphertext)?;
        writer.write_all(plaintext)?;
        written += u64::try_from(plaintext.len()).expect("unexpected overflow");

        // Copy the unused part to the beginning of the buffer and set the offset for the next loop.
        buf.copy_within(block_len.., 0);
        offset = buf.len() - block_len;
    }

    // Return the number of bytes and the signature.
    Ok((written, Signature::decode(&buf[..SIGNATURE_LEN]).expect("invalid signature len")))
}

/// The length of an encrypted header.
const ENC_HEADER_LEN: usize = HEADER_LEN + sres::OVERHEAD;

/// Iterate through the contents of `reader` looking for a header which was encrypted by the given
/// sender for the given receiver.
fn decrypt_header(
    mres: &mut UnkeyedDuplex,
    mut reader: impl Read,
    receiver: &PrivKey,
    sender: &PubKey,
) -> Result<(PubKey, [u8; DEK_LEN]), DecryptError> {
    let mut enc_header = [0u8; ENC_HEADER_LEN];
    let mut header = None;
    let mut i = 0u64;
    let mut recv_count = u64::MAX;

    // Iterate through blocks, looking for an encrypted header that can be decrypted.
    while i < recv_count {
        // Read a potential encrypted header. If the header is short, we're at the end of the
        // reader.
        reader.read_exact(&mut enc_header).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                DecryptError::InvalidCiphertext
            } else {
                e.into()
            }
        })?;

        // Squeeze a nonce regardless of whether we need to in order to keep the duplex state
        // consistent.
        let nonce = mres.squeeze::<NONCE_LEN>();

        // Absorb the encrypted header with the duplex.
        mres.absorb(&enc_header);

        // If a header hasn't been decrypted yet, try to decrypt this one.
        if header.is_none() {
            if let Some((ephemeral, d, c, p)) =
                sres::decrypt(receiver, sender, &nonce, &mut enc_header).map(decode_header)
            {
                // If the header was successfully decrypted, keep the ephemeral public key, DEK, and
                // padding and update the loop variable to not be effectively infinite.
                header = Some((ephemeral, p, d));
                recv_count = c;
            }
        }

        i += 1;
    }

    // Unpack the header values, if any.
    let (ephemeral, padding, dek) = header.ok_or(DecryptError::InvalidCiphertext)?;

    // Read the padding and absorb it with the duplex.
    mres.absorb_reader(&mut reader.take(padding))?;

    // Return the ephemeral public key and DEK.
    Ok((ephemeral, dek))
}

/// Decode an ephemeral public key and header into an ephemeral public key, DEK, header count, and
/// padding size.
#[inline]
#[must_use]
fn decode_header((ephemeral, header): (PubKey, &[u8])) -> (PubKey, [u8; DEK_LEN], u64, u64) {
    // Split header into components.
    let (dek, hdr_count) = header.split_at(DEK_LEN);
    let (hdr_count, padding) = hdr_count.split_at(mem::size_of::<u64>());

    // Decode components.
    let dek = dek.try_into().expect("invalid DEK len");
    let hdr_count = u64::from_le_bytes(hdr_count.try_into().expect("invalid u64 len"));
    let padding = u64::from_le_bytes(padding.try_into().expect("invalid u64 len"));

    (ephemeral, dek, hdr_count, padding)
}

struct RngRead<R>(R)
where
    R: Rng + CryptoRng;

impl<R> Read for RngRead<R>
where
    R: Rng + CryptoRng,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.try_fill_bytes(buf)?;
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let message = b"this is a thingy";

        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let receivers = &[sender.pub_key, receiver.pub_key];
        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, &sender, receivers, 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len =
            decrypt(&mut src, &mut dst, &receiver, &sender.pub_key).expect("error decrypting");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let message = b"this is a thingy";

        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(
            &mut rng,
            &mut src,
            &mut dst,
            &sender,
            &[sender.pub_key, receiver.pub_key],
            123,
        )
        .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let wrong_sender = PubKey::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert!(matches!(
            decrypt(&mut src, &mut dst, &receiver, &wrong_sender),
            Err(DecryptError::InvalidCiphertext)
        ));
    }

    #[test]
    fn wrong_receiver() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(
            &mut rng,
            &mut src,
            &mut dst,
            &sender,
            &[sender.pub_key, receiver.pub_key],
            123,
        )
        .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let wrong_receiver = PrivKey::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert!(matches!(
            decrypt(&mut src, &mut dst, &wrong_receiver, &sender.pub_key),
            Err(DecryptError::InvalidCiphertext)
        ));
    }

    #[test]
    fn multi_block_message() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let message = [69u8; 65 * 1024];

        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let receivers = &[sender.pub_key, receiver.pub_key];
        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, &sender, receivers, 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len =
            decrypt(&mut src, &mut dst, &receiver, &sender.pub_key).expect("error decrypting");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn split_sig() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let message = [69u8; 32 * 1024 - 37];

        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let receivers = &[sender.pub_key, receiver.pub_key];
        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, &sender, receivers, 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len =
            decrypt(&mut src, &mut dst, &receiver, &sender.pub_key).expect("error decrypting");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn flip_every_bit() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let message = b"this is a thingy";

        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        encrypt(&mut rng, &mut src, &mut dst, &sender, &[sender.pub_key, receiver.pub_key], 123)
            .expect("error encrypting");

        let ciphertext = dst.into_inner();

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                let mut src = Cursor::new(ciphertext);

                match decrypt(&mut src, &mut io::sink(), &receiver, &sender.pub_key) {
                    Err(DecryptError::InvalidCiphertext) => {}
                    Ok(_) => panic!("bit flip at byte {i}, bit {j} produced a valid message"),
                    Err(e) => panic!("unknown error: {:?}", e),
                };
            }
        }
    }
}
