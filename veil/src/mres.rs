//! A multi-receiver, hybrid cryptosystem.

use std::{
    io::{self, Read, Write},
    mem,
};

use lockstitch::{Protocol, TAG_LEN};
use rand::{CryptoRng, Rng};

use crate::{
    blockio::ReadBlock,
    keys::{PrivKey, PubKey},
    schnorr::{self, DET_SIGNATURE_LEN},
    sres::{self, NONCE_LEN},
    DecryptError, EncryptError,
};

/// The length of a plaintext block header. The first byte signifies the block type, the next three
/// are the following block length in bytes, encoded as a 24-bit unsigned little-endian integer.
const BLOCK_HEADER_LEN: usize = 4;

/// The length of an encrypted block header and authentication tag.
const ENC_BLOCK_HEADER_LEN: usize = BLOCK_HEADER_LEN + TAG_LEN;

/// A block of message data.
const DATA_BLOCK: u8 = 0;

/// A block of random padding.
const PADDING_BLOCK: u8 = 1;

/// The length of a plaintext block.
const BLOCK_LEN: usize = 64 * 1024;

/// The length of an encrypted block and authentication tag.
const ENC_BLOCK_LEN: usize = BLOCK_LEN + TAG_LEN;

/// The length of the data encryption key.
const DEK_LEN: usize = 32;

/// The length of an encoded header.
const HEADER_LEN: usize = DEK_LEN + mem::size_of::<u64>();

/// The length of an encrypted header.
const ENC_HEADER_LEN: usize = HEADER_LEN + sres::OVERHEAD;

/// Encrypt the contents of `reader` such that they can be decrypted and verified by all members of
/// `receivers` and write the ciphertext to `writer` with some padding bytes of random data added.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    reader: impl Read,
    mut writer: impl Write,
    sender: &PrivKey,
    receivers: &[PubKey],
) -> Result<u64, EncryptError> {
    // Initialize a protocol and mix the sender's public key into it.
    let mut mres = Protocol::new("veil.mres");
    mres.mix("sender", &sender.pub_key.encoded);

    // Generate a random ephemeral key pair, DEK, and nonce.
    let ephemeral = PrivKey::random(&mut rng);
    let dek = rng.gen::<[u8; DEK_LEN]>();
    let nonce = rng.gen::<[u8; NONCE_LEN]>();

    // Write the nonce and mix it into the protocol.
    writer.write_all(&nonce).map_err(EncryptError::WriteIo)?;
    let mut written = u64::try_from(NONCE_LEN).expect("usize should be <= u64");
    mres.mix("nonce", &nonce);

    // Encode a header with the DEK and receiver count.
    let header = Header::new(dek, receivers.len()).encode();

    // For each receiver, encrypt a copy of the header with veil.sres.
    let mut enc_header = [0u8; ENC_HEADER_LEN];
    for receiver in receivers {
        // Derive a nonce for each header.
        let nonce = mres.derive_array::<NONCE_LEN>("header-nonce");

        // Encrypt the header for the given receiver.
        sres::encrypt(sender, &ephemeral, receiver, &nonce, &header, &mut enc_header);

        // Mix the encrypted header into the protocol.
        mres.mix("header", &enc_header);

        // Write the encrypted header.
        writer.write_all(&enc_header).map_err(EncryptError::WriteIo)?;
        written += u64::try_from(ENC_HEADER_LEN).expect("usize should be <= u64");
    }

    // Mix the DEK into the protocol.
    mres.mix("dek", &dek);

    // Encrypt the plaintext in blocks and write them, then sign the message.
    written += encrypt_message(&mut rng, mres, reader, writer, ephemeral)?;

    Ok(written)
}

/// Given a protocol keyed with the DEK, read the entire contents of `reader` in blocks and write
/// the encrypted blocks and authentication tags to `writer`.
fn encrypt_message(
    mut rng: impl Rng + CryptoRng,
    mut mres: Protocol,
    mut reader: impl Read,
    mut writer: impl Write,
    ephemeral: PrivKey,
) -> Result<u64, EncryptError> {
    let mut buf = [0u8; ENC_BLOCK_LEN];
    let mut block_header = [0u8; ENC_BLOCK_HEADER_LEN];
    let mut read = 0;
    let mut written = 0;

    loop {
        // Read a block of data.
        let n = reader.read_block(&mut buf[..BLOCK_LEN]).map_err(EncryptError::ReadIo)?;
        read += u64::try_from(n).expect("usize should be <= u64");
        let block = &mut buf[..n + TAG_LEN];

        // Encode, seal, and write a data block header.
        block_header[0] = DATA_BLOCK;
        block_header[1..4].copy_from_slice(&(n as u32).to_le_bytes()[..3]);
        mres.seal("block-header", &mut block_header);
        writer.write_all(&block_header).map_err(EncryptError::WriteIo)?;
        written += u64::try_from(block_header.len()).expect("usize should be <= u64");

        // Seal the block and write it.
        mres.seal("block", block);
        writer.write_all(block).map_err(EncryptError::WriteIo)?;
        written += u64::try_from(block.len()).expect("usize should be <= u64");

        // If the block was undersized, we're at the end of the reader.
        if n < BLOCK_LEN {
            break;
        }
    }

    // Calculate the number of bytes to automatically pad the message with.
    let padding_len = padding_len(read);

    // Encode, seal, and write a padding block header.
    block_header[0] = PADDING_BLOCK;
    block_header[1..4].copy_from_slice(&(padding_len as u32).to_le_bytes()[..3]);
    mres.seal("block-header", &mut block_header);
    writer.write_all(&block_header).map_err(EncryptError::WriteIo)?;
    written += u64::try_from(block_header.len()).expect("usize should be <= u64");

    // Seal and write the padding block.
    let mut padding = vec![0u8; padding_len + TAG_LEN];
    rng.fill_bytes(&mut padding[..padding_len]);
    mres.seal("block", &mut padding);
    writer.write_all(&padding).map_err(EncryptError::WriteIo)?;
    written += u64::try_from(padding.len()).expect("usize should be <= u64");

    // Deterministically sign the protocol's final state with the ephemeral private key and append
    // the signature. The protocol's state is randomized with both the nonce and the ephemeral key,
    // so the risk of e.g. fault attacks is minimal.
    let sig = schnorr::det_sign(&mut mres, &ephemeral);
    writer.write_all(&sig).map_err(EncryptError::WriteIo)?;
    written += u64::try_from(sig.len()).expect("usize should be <= u64");

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
    mres.mix("sender", &sender.encoded);

    // Read the nonce and mix it into the protocol.
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce).map_err(DecryptError::ReadIo)?;
    mres.mix("nonce", &nonce);

    // Find a header, decrypt it, and mix the entirety of the headers and padding into the protocol.
    let (mut mres, ephemeral, dek) = decrypt_header(mres, &mut reader, receiver, sender)?;

    // Mix the DEK into the protocol.
    mres.mix("dek", &dek);

    // Decrypt the message.
    let (written, sig) = decrypt_message(&mut mres, &mut reader, &mut writer)?;

    // Verify the signature and return the number of bytes written.
    schnorr::det_verify(&mut mres, &ephemeral, sig.try_into().expect("should be signature sized"))
        .and(Some(written))
        .ok_or(DecryptError::InvalidCiphertext)
}

/// Given a protocol keyed with the DEK, read the entire contents of `reader` in blocks and write
/// the decrypted blocks `writer`.
fn decrypt_message(
    mres: &mut Protocol,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(u64, Vec<u8>), DecryptError> {
    let mut header = [0u8; ENC_BLOCK_HEADER_LEN];
    let mut buf = vec![0u8; ENC_BLOCK_LEN + DET_SIGNATURE_LEN];
    let mut written = 0;

    loop {
        // Read and open a block header.
        reader.read_exact(&mut header).map_err(DecryptError::ReadIo)?;
        let header =
            mres.open("block-header", &mut header).ok_or(DecryptError::InvalidCiphertext)?;
        let block_len = (header[1] as usize)
            + ((header[2] as usize) << 8)
            + ((header[3] as usize) << 16)
            + TAG_LEN;

        // Read and open the block.
        reader.read_exact(&mut buf[..block_len]).map_err(DecryptError::ReadIo)?;
        let plaintext =
            mres.open("block", &mut buf[..block_len]).ok_or(DecryptError::InvalidCiphertext)?;
        if header[0] == DATA_BLOCK {
            // Write the plaintext.
            writer.write_all(plaintext).map_err(DecryptError::WriteIo)?;
            written += u64::try_from(plaintext.len()).expect("usize should be <= u64");
        } else {
            // Ignore the padding and read the final signature.
            buf.truncate(0);
            reader.read_to_end(&mut buf).map_err(DecryptError::ReadIo)?;
            buf.shrink_to_fit();

            // Return the number of written bytes and the signature.
            return Ok((written, buf));
        }
    }
}

/// Iterate through the contents of `reader` looking for a header which was encrypted by the given
/// sender for the given receiver.
fn decrypt_header(
    mut mres: Protocol,
    mut reader: impl Read,
    receiver: &PrivKey,
    sender: &PubKey,
) -> Result<(Protocol, PubKey, [u8; DEK_LEN]), DecryptError> {
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
        let nonce = mres.derive_array::<NONCE_LEN>("header-nonce");

        // Mix the encrypted header into the protocol.
        mres.mix("header", &enc_header);

        // If a header hasn't been decrypted yet, try to decrypt this one.
        if header.is_none() {
            if let Some((ephemeral, hdr)) = sres::decrypt(receiver, sender, &nonce, &mut enc_header)
            {
                // If the header was successfully decrypted, keep the ephemeral public key and DEK
                // and update the loop variable to not be effectively infinite.
                let hdr = Header::decode(hdr);
                recv_count = hdr.recv_count;
                header = Some((ephemeral, hdr));
            }
        }

        i += 1;
    }

    // Unpack the header values, if any.
    let (ephemeral, header) = header.ok_or(DecryptError::InvalidCiphertext)?;

    // Return the ephemeral public key and DEK.
    Ok((mres, ephemeral, header.dek))
}

struct Header {
    dek: [u8; DEK_LEN],
    recv_count: u64,
}

impl Header {
    fn new(dek: [u8; DEK_LEN], recv_count: usize) -> Header {
        Header { dek, recv_count: recv_count.try_into().expect("usize should be <= u64") }
    }

    #[inline]
    #[must_use]
    fn decode(header: &[u8]) -> Header {
        // Split header into components.
        let (dek, recv_count) = header.split_at(DEK_LEN);

        // Decode components.
        let dek = dek.try_into().expect("should be DEK-sized");
        let recv_count = u64::from_le_bytes(recv_count.try_into().expect("should be 8 bytes"));

        Header { dek, recv_count }
    }

    #[inline]
    #[must_use]
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        let (hdr_dek, hdr_recv_count) = header.split_at_mut(DEK_LEN);
        hdr_dek.copy_from_slice(&self.dek);
        hdr_recv_count.copy_from_slice(&self.recv_count.to_le_bytes());
        header
    }
}

/// Returns the number of bytes with which to pad a message of the given size.
///
/// Uses the PADMÉ algorithm from
/// [Reducing Metadata Leakage from Encrypted Files and Communication with PURBs](https://bford.info/pub/sec/purb.pdf).
#[inline]
fn padding_len(len: u64) -> usize {
    let e = 63u64.saturating_sub(len.leading_zeros() as u64);
    let s = 64 - e.leading_zeros() as u64;
    let z = e - s;
    let mask = (1u64 << z) - 1;
    usize::try_from(((len + mask) & !mask) - len).expect("should be <= usize")
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
            .expect("decryption should be ok");

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
            .expect("decryption should be ok");

        assert_eq!(writer.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(plaintext.to_vec(), writer.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn split_sig() {
        let (_, sender, receiver, plaintext, ciphertext) = setup(32 * 1024 - 37);

        let mut writer = Cursor::new(Vec::new());
        let ptx_len = decrypt(Cursor::new(ciphertext), &mut writer, &receiver, &sender.pub_key)
            .expect("decryption should be ok");

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
                    Err(e) => panic!("unknown error: {e:?}"),
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
        )
        .expect("encryption should be ok");

        assert_eq!(
            u64::try_from(ciphertext.len()).expect("usize should be <= u64"),
            ctx_len,
            "returned/observed ciphertext length mismatch"
        );

        (rng, sender, receiver, plaintext, ciphertext)
    }
}
