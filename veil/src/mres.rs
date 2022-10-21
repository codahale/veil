//! A multi-receiver, hybrid cryptosystem.

use std::io::{self, Read, Write};
use std::mem;

use lockstitch::{Protocol, TAG_LEN};
use rand::{CryptoRng, Rng};

use crate::blockio::ReadBlock;
use crate::keys::{PrivKey, PubKey};
use crate::schnorr::SIGNATURE_LEN;
use crate::sres::NONCE_LEN;
use crate::{schnorr, sres, DecryptError, EncryptError, Signature};

/// The length of plaintext blocks which are encrypted.
const BLOCK_LEN: usize = 32 * 1024;

/// The length of an encrypted block and authentication tag.
const ENC_BLOCK_LEN: usize = BLOCK_LEN + TAG_LEN;

/// The length of the data encryption key.
const DEK_LEN: usize = 32;

/// The length of an encoded header.
const HEADER_LEN: usize = DEK_LEN + mem::size_of::<u64>() + mem::size_of::<u64>();

/// The length of an encrypted header.
const ENC_HEADER_LEN: usize = HEADER_LEN + sres::OVERHEAD;

/// Encrypt the contents of `reader` such that they can be decrypted and verified by all members of
/// `receivers` and write the ciphertext to `writer` with `padding` bytes of random data added.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    reader: impl Read,
    mut writer: impl Write,
    sender: &PrivKey,
    receivers: &[PubKey],
    padding: usize,
) -> Result<u64, EncryptError> {
    let padding = u64::try_from(padding).expect("unexpected overflow");

    // Initialize a protocol and mix the sender's public key into it.
    let mut mres = Protocol::new("veil.mres");
    mres.mix(&sender.pub_key.encoded);

    // Generate ephemeral key pair, DEK, and nonce.
    let (ephemeral, dek, nonce) = mres.hedge(&mut rng, &[&sender.d.encode()], |clone| {
        PrivKey::decode_reduce(clone.derive_array::<32>())
            .map(|k| (k, clone.derive_array(), clone.derive_array::<NONCE_LEN>()))
    });

    // Write the nonce and mix it into the protocol.
    writer.write_all(&nonce).map_err(EncryptError::WriteIo)?;
    let mut written = u64::try_from(NONCE_LEN).expect("unexpected overflow");
    mres.mix(&nonce);

    // Encode a header with the DEK, receiver count, and padding.
    let header = Header::new(dek, receivers.len(), padding).encode();

    // For each receiver, encrypt a copy of the header with veil.sres.
    let mut enc_header = [0u8; ENC_HEADER_LEN];
    for receiver in receivers {
        // Derive a nonce for each header.
        let nonce = mres.derive_array::<NONCE_LEN>();

        // Encrypt the header for the given receiver.
        sres::encrypt(&mut rng, sender, &ephemeral, receiver, &nonce, &header, &mut enc_header);

        // Mix the encrypted header into the protocol.
        mres.mix(&enc_header);

        // Write the encrypted header.
        writer.write_all(&enc_header).map_err(EncryptError::WriteIo)?;
        written += u64::try_from(ENC_HEADER_LEN).expect("unexpected overflow");
    }

    // Add random padding to the end of the headers, mixing it into the protocol.
    written += mres
        .copy_stream(RngRead(&mut rng).take(padding), &mut writer)
        .map_err(EncryptError::WriteIo)?;

    // Mix the DEK into the protocol.
    mres.mix(&dek);

    // Encrypt the plaintext in blocks and write them.
    written += encrypt_message(&mut mres, reader, &mut writer)?;

    // Sign the protocol's final state with the ephemeral private key and append the signature.
    let sig = schnorr::sign_protocol(&mut mres, &mut rng, &ephemeral);
    writer.write_all(&sig.encode()).map_err(EncryptError::WriteIo)?;

    Ok(written + u64::try_from(SIGNATURE_LEN).expect("unexpected overflow"))
}

/// Given a protocol keyed with the DEK, read the entire contents of `reader` in blocks and write
/// the encrypted blocks and authentication tags to `writer`.
fn encrypt_message(
    mres: &mut Protocol,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<u64, EncryptError> {
    let mut buf = [0u8; ENC_BLOCK_LEN];
    let mut written = 0;

    loop {
        // Read a block of data.
        let n = reader.read_block(&mut buf[..BLOCK_LEN]).map_err(EncryptError::ReadIo)?;
        let block = &mut buf[..n + TAG_LEN];

        // Seal the block and write it.
        mres.seal(block);
        writer.write_all(block).map_err(EncryptError::WriteIo)?;
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
    // Initialize a protocol and mix the sender's public key into it.
    let mut mres = Protocol::new("veil.mres");
    mres.mix(&sender.encoded);

    // Read the nonce and mix it into the protocol.
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce).map_err(DecryptError::ReadIo)?;
    mres.mix(&nonce);

    // Find a header, decrypt it, and mix the entirety of the headers and padding into the protocol.
    let (ephemeral, dek) = decrypt_header(&mut mres, &mut reader, receiver, sender)?;

    // Mix the DEK into the protocol.
    mres.mix(&dek);

    // Decrypt the message.
    let (written, sig) = decrypt_message(&mut mres, &mut reader, &mut writer)?;

    // Verify the signature and return the number of bytes written.
    schnorr::verify_protocol(&mut mres, &ephemeral, &sig)
        .and(Some(written))
        .ok_or(DecryptError::InvalidCiphertext)
}

/// Given a protocol keyed with the DEK, read the entire contents of `reader` in blocks and write
/// the decrypted blocks `writer`.
fn decrypt_message(
    mres: &mut Protocol,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(u64, Signature), DecryptError> {
    let mut buf = [0u8; ENC_BLOCK_LEN + SIGNATURE_LEN];
    let mut offset = 0;
    let mut written = 0;

    loop {
        // Read a block and a possible signature, keeping in mind the unused bit of the buffer from
        // the last iteration.
        let n = reader.read_block(&mut buf[offset..]).map_err(DecryptError::ReadIo)?;

        // If we're at the end of the reader, we only have the signature left to process. Break out
        // of the read loop and go process the signature.
        if n == 0 {
            break;
        }

        // Pretend we don't see the possible signature at the end.
        let block_len = n - SIGNATURE_LEN + offset;
        let block = &mut buf[..block_len];

        // Open the block and write the plaintext. If the block cannot be decrypted, return an
        // error.
        let plaintext = mres.open(block).ok_or(DecryptError::InvalidCiphertext)?;
        writer.write_all(plaintext).map_err(DecryptError::WriteIo)?;
        written += u64::try_from(plaintext.len()).expect("unexpected overflow");

        // Copy the unused part to the beginning of the buffer and set the offset for the next loop.
        buf.copy_within(block_len.., 0);
        offset = buf.len() - block_len;
    }

    // Return the number of bytes and the signature.
    Ok((written, Signature::decode(&buf[..SIGNATURE_LEN]).expect("invalid signature len")))
}

/// Iterate through the contents of `reader` looking for a header which was encrypted by the given
/// sender for the given receiver.
fn decrypt_header(
    mres: &mut Protocol,
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
                DecryptError::ReadIo(e)
            }
        })?;

        // Derive a nonce regardless of whether we need to in order to keep the protocol state
        // consistent.
        let nonce = mres.derive_array::<NONCE_LEN>();

        // Mix the encrypted header into the protocol.
        mres.mix(&enc_header);

        // If a header hasn't been decrypted yet, try to decrypt this one.
        if header.is_none() {
            if let Some((ephemeral, hdr)) = sres::decrypt(receiver, sender, &nonce, &mut enc_header)
            {
                // If the header was successfully decrypted, keep the ephemeral public key, DEK, and
                // padding and update the loop variable to not be effectively infinite.
                let hdr = Header::decode(hdr);
                recv_count = hdr.recv_count;
                header = Some((ephemeral, hdr));
            }
        }

        i += 1;
    }

    // Unpack the header values, if any.
    let (ephemeral, header) = header.ok_or(DecryptError::InvalidCiphertext)?;

    // Read the padding and mix it into the protocol.
    mres.mix_stream(&mut reader.take(header.padding)).map_err(DecryptError::ReadIo)?;

    // Return the ephemeral public key and DEK.
    Ok((ephemeral, header.dek))
}

struct Header {
    dek: [u8; DEK_LEN],
    recv_count: u64,
    padding: u64,
}

impl Header {
    fn new(dek: [u8; DEK_LEN], recv_count: usize, padding: u64) -> Header {
        Header { dek, recv_count: recv_count.try_into().expect("unexpected overflow"), padding }
    }

    #[inline]
    #[must_use]
    fn decode(header: &[u8]) -> Header {
        // Split header into components.
        let (dek, recv_count) = header.split_at(DEK_LEN);
        let (recv_count, padding) = recv_count.split_at(mem::size_of::<u64>());

        // Decode components.
        let dek = dek.try_into().expect("invalid DEK len");
        let recv_count = u64::from_le_bytes(recv_count.try_into().expect("invalid u64 len"));
        let padding = u64::from_le_bytes(padding.try_into().expect("invalid u64 len"));

        Header { dek, recv_count, padding }
    }

    #[inline]
    #[must_use]
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        let (hdr_dek, hdr_recv_count) = header.split_at_mut(DEK_LEN);
        let (hdr_recv_count, hdr_padding) = hdr_recv_count.split_at_mut(mem::size_of::<u64>());
        hdr_dek.copy_from_slice(&self.dek);
        hdr_recv_count.copy_from_slice(&self.recv_count.to_le_bytes());
        hdr_padding.copy_from_slice(&self.padding.to_le_bytes());
        header
    }
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

    use assert_matches::assert_matches;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let (_, sender, receiver, plaintext, ciphertext) = setup(64);

        let mut writer = Cursor::new(Vec::new());

        let ptx_len = decrypt(Cursor::new(ciphertext), &mut writer, &receiver, &sender.pub_key)
            .expect("error decrypting");

        assert_eq!(writer.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(plaintext.to_vec(), writer.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn wrong_sender() {
        let (mut rng, _, receiver, _, ciphertext) = setup(64);

        let wrong_sender = PubKey::random(&mut rng);

        assert_matches!(
            decrypt(Cursor::new(ciphertext), Cursor::new(Vec::new()), &receiver, &wrong_sender),
            Err(DecryptError::InvalidCiphertext)
        );
    }

    #[test]
    fn wrong_receiver() {
        let (mut rng, sender, _, _, ciphertext) = setup(64);

        let wrong_receiver = PrivKey::random(&mut rng);

        assert_matches!(
            decrypt(
                Cursor::new(ciphertext),
                Cursor::new(Vec::new()),
                &wrong_receiver,
                &sender.pub_key
            ),
            Err(DecryptError::InvalidCiphertext)
        );
    }

    #[test]
    fn multi_block_message() {
        let (_, sender, receiver, plaintext, ciphertext) = setup(65 * 1024);

        let mut writer = Cursor::new(Vec::new());
        let ptx_len = decrypt(Cursor::new(ciphertext), &mut writer, &receiver, &sender.pub_key)
            .expect("error decrypting");

        assert_eq!(writer.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(plaintext.to_vec(), writer.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn split_sig() {
        let (_, sender, receiver, plaintext, ciphertext) = setup(32 * 1024 - 37);

        let mut writer = Cursor::new(Vec::new());
        let ptx_len = decrypt(Cursor::new(ciphertext), &mut writer, &receiver, &sender.pub_key)
            .expect("error decrypting");

        assert_eq!(writer.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(plaintext.to_vec(), writer.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn flip_every_bit() {
        let (_, sender, receiver, _, ciphertext) = setup(16);

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

    fn setup(n: usize) -> (ChaChaRng, PrivKey, PrivKey, Vec<u8>, Vec<u8>) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = PrivKey::random(&mut rng);
        let receiver = PrivKey::random(&mut rng);
        let mut plaintext = vec![0u8; n];
        rng.fill_bytes(&mut plaintext);
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        let ctx_len = encrypt(
            &mut rng,
            Cursor::new(&plaintext),
            Cursor::new(&mut ciphertext),
            &sender,
            &[sender.pub_key, receiver.pub_key],
            123,
        )
        .expect("error encrypting");

        assert_eq!(
            u64::try_from(ciphertext.len()).expect("unexpected overflow"),
            ctx_len,
            "returned/observed ciphertext length mismatch"
        );

        (rng, sender, receiver, plaintext, ciphertext)
    }
}
