//! A multi-receiver cryptosystem.

use std::io::{self, Read, Write};

use lockstitch::{Protocol, TAG_LEN};
use rand::{CryptoRng, Rng, RngCore};

use crate::{
    kemeleon::{self, ENC_CT_LEN},
    keys::{PubKey, SecKey},
    sig, DecryptError, EncryptError,
};

/// The length of a plaintext block header. The first byte signifies the block type, the next three
/// are the following block length in bytes, encoded as a 24-bit unsigned little-endian integer.
const BLOCK_HEADER_LEN: usize = 4;

/// The length of an encrypted block header and authentication tag.
const ENC_BLOCK_HEADER_LEN: usize = BLOCK_HEADER_LEN + TAG_LEN;

/// The length of a plaintext block.
const BLOCK_LEN: usize = 64 * 1024;

/// The length of the data encryption key.
const DEK_LEN: usize = 32;

/// The length of an encoded header.
const HEADER_LEN: usize = DEK_LEN + size_of::<u64>();

/// The length of an encrypted header.
const ENC_HEADER_LEN: usize = ENC_CT_LEN + HEADER_LEN + TAG_LEN;

/// Encrypt the contents of `reader` such that they can be decrypted and verified by all members of
/// `receivers` and write the ciphertext to `writer` with some padding bytes of random data added.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    reader: impl Read,
    mut writer: impl Write,
    sender: &SecKey,
    receivers: &[Option<&PubKey>],
) -> Result<u64, EncryptError> {
    // Initialize a protocol and mix the sender's public key into it.
    let mut message = Protocol::new("veil.message");
    message.mix("sender", &sender.pub_key.encoded);

    // Generate a random DEK.
    let dek = rng.gen::<[u8; DEK_LEN]>();

    // Encode a header with the DEK and receiver count.
    let header = Header::new(dek, receivers.len()).encode();

    // For each receiver, encrypt a copy of the header.
    let mut written = 0;
    let mut enc_header = [0u8; ENC_HEADER_LEN];
    for receiver in receivers {
        // Encrypt the header for the given receiver, if any, or use random data to create a fake
        // recipient.
        if let Some(receiver) = receiver {
            encrypt_header(message.clone(), &mut rng, receiver, &header, &mut enc_header);
        } else {
            rng.fill_bytes(&mut enc_header);
        }

        // Mix the encrypted header into the protocol.
        message.mix("header", &enc_header);

        // Write the encrypted header.
        writer.write_all(&enc_header).map_err(EncryptError::WriteIo)?;
        written += u64::try_from(ENC_HEADER_LEN).expect("usize should be <= u64");
    }

    // Mix the DEK into the protocol.
    message.mix("dek", &dek);

    // Encrypt the plaintext in blocks and write them, then sign the message.
    written += encrypt_message(&mut rng, message, reader, writer, sender)?;

    Ok(written)
}

/// Given an initialized protocol, the receiver's public key and a plaintext header, encrypts the
/// given header and returns the ciphertext.
fn encrypt_header(
    mut protocol: Protocol,
    mut rng: impl RngCore + CryptoRng,
    receiver: &PubKey,
    plaintext: &[u8; HEADER_LEN],
    ciphertext: &mut [u8; ENC_HEADER_LEN],
) {
    // Split up the output buffer.
    let (out_kem, out_ciphertext) = ciphertext.split_at_mut(ENC_CT_LEN);

    // Mix the receiver's public key into the protocol.
    protocol.mix("receiver", &receiver.encoded);

    // Encapsulate a shared secret with ML-KEM and mix it into the protocol's state.
    let (kem_ect, kem_ss) = kemeleon::encapsulate(&receiver.ek, &mut rng);
    out_kem.copy_from_slice(&kem_ect);
    protocol.mix("ml-kem-768-ect", out_kem);

    // Mix the ML-KEM shared secret into the protocol.
    protocol.mix("ml-kem-768-ss", &kem_ss);

    // Seal the plaintext.
    out_ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    protocol.seal("header", out_ciphertext);
}

/// Given a protocol keyed with the DEK, read the entire contents of `reader` in blocks and write
/// the encrypted blocks and authentication tags to `writer`, then add a signature of the protocol's
/// final state.
fn encrypt_message(
    mut rng: impl Rng + CryptoRng,
    mut message: Protocol,
    mut reader: impl Read,
    mut writer: impl Write,
    sender: &SecKey,
) -> Result<u64, EncryptError> {
    let mut block = Vec::with_capacity(BLOCK_LEN + TAG_LEN);
    let mut block_header = [0u8; ENC_BLOCK_HEADER_LEN];
    let mut read = 0;
    let mut written = 0;

    loop {
        // Read a block of data.
        let n = (&mut reader)
            .take(BLOCK_LEN as u64)
            .read_to_end(&mut block)
            .map_err(EncryptError::ReadIo)?;
        read += u64::try_from(n).expect("usize should be <= u64");

        // Break if we're at the end of the reader.
        if n == 0 {
            break;
        }

        // Encode, seal, and write a data block header.
        block_header[0] = BlockType::Data as u8;
        block_header[1..4].copy_from_slice(&(n as u32).to_le_bytes()[..3]);
        message.seal("block-header", &mut block_header);
        writer.write_all(&block_header).map_err(EncryptError::WriteIo)?;
        written += u64::try_from(block_header.len()).expect("usize should be <= u64");

        // Seal the block and write it.
        block.resize(n + TAG_LEN, 0);
        message.seal("block", &mut block);
        writer.write_all(&block).map_err(EncryptError::WriteIo)?;
        written += u64::try_from(block.len()).expect("usize should be <= u64");

        // If the block was undersized, we're at the end of the reader.
        if n < BLOCK_LEN {
            break;
        }

        // Reset the block buffer for the next read.
        block.truncate(0);
    }

    // Calculate the number of bytes to automatically pad the message with.
    let padding_len = padding_len(read);

    // Encode, seal, and write a padding block header.
    block_header[0] = BlockType::Padding as u8;
    block_header[1..4].copy_from_slice(&(padding_len as u32).to_le_bytes()[..3]);
    message.seal("block-header", &mut block_header);
    writer.write_all(&block_header).map_err(EncryptError::WriteIo)?;
    written += u64::try_from(block_header.len()).expect("usize should be <= u64");

    // Seal and write the padding block.
    let mut padding = vec![0u8; padding_len + TAG_LEN];
    rng.fill_bytes(&mut padding[..padding_len]);
    message.seal("block", &mut padding);
    writer.write_all(&padding).map_err(EncryptError::WriteIo)?;
    written += u64::try_from(padding.len()).expect("usize should be <= u64");

    // Sign the protocol's final state with the sender's secret key and append the signature.
    let sig = sig::sign_protocol(&mut rng, &mut message, sender);
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
    receiver: &SecKey,
    sender: &PubKey,
) -> Result<u64, DecryptError> {
    // Initialize a protocol and mix the sender's public key into it.
    let mut message = Protocol::new("veil.message");
    message.mix("sender", &sender.encoded);

    // Find a header, decrypt it, and mix the entirety of the headers and padding into the protocol.
    let (mut message, dek) = decrypt_headers(message, &mut reader, receiver)?;

    // Mix the DEK into the protocol.
    message.mix("dek", &dek);

    // Decrypt the message.
    let (written, sig) = decrypt_message(&mut message, &mut reader, &mut writer)?;

    // Verify the signature and return the number of bytes written.
    sig::verify_protocol(&mut message, sender, sig.try_into().expect("should be signature sized"))
        .and(Some(written))
        .ok_or(DecryptError::InvalidCiphertext)
}

/// Given a protocol keyed with the DEK, read the entire contents of `reader` in blocks and write
/// the decrypted blocks `writer`.
fn decrypt_message(
    message: &mut Protocol,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(u64, Vec<u8>), DecryptError> {
    let mut header = [0u8; ENC_BLOCK_HEADER_LEN];
    let mut buf = Vec::with_capacity(BLOCK_LEN + TAG_LEN);
    let mut written = 0;

    loop {
        // Read and open a block header.
        reader.read_exact(&mut header).map_err(DecryptError::ReadIo)?;
        let header =
            message.open("block-header", &mut header).ok_or(DecryptError::InvalidCiphertext)?;
        let block_len = (header[1] as usize)
            + ((header[2] as usize) << 8)
            + ((header[3] as usize) << 16)
            + TAG_LEN;
        buf.resize(block_len, 0);

        // Read and open the block.
        reader.read_exact(&mut buf[..block_len]).map_err(DecryptError::ReadIo)?;
        let plaintext =
            message.open("block", &mut buf[..block_len]).ok_or(DecryptError::InvalidCiphertext)?;
        match BlockType::try_from(header[0]) {
            Ok(BlockType::Data) => {
                // Write the plaintext.
                writer.write_all(plaintext).map_err(DecryptError::WriteIo)?;
                written += u64::try_from(plaintext.len()).expect("usize should be <= u64");
            }
            Ok(BlockType::Padding) => {
                // Ignore the padding and read the final signature.
                buf.truncate(0);
                reader.read_to_end(&mut buf).map_err(DecryptError::ReadIo)?;
                buf.shrink_to_fit();

                // Return the number of written bytes and the signature.
                return Ok((written, buf));
            }
            Err(b) => return Err(DecryptError::InvalidBlockType(b)),
        }
    }
}

/// Iterate through the contents of `reader` looking for a header which was encrypted by the given
/// sender for the given receiver.
fn decrypt_headers(
    mut message: Protocol,
    mut reader: impl Read,
    receiver: &SecKey,
) -> Result<(Protocol, [u8; DEK_LEN]), DecryptError> {
    let mut enc_header = [0u8; ENC_HEADER_LEN];
    let mut dek = None;
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

        // Clone the protocol at its state before this header is processed.
        let clone = message.clone();

        // Mix the encrypted header into the protocol.
        message.mix("header", &enc_header);

        // If a header hasn't been decrypted yet, try to decrypt this one.
        if dek.is_none() {
            if let Some(hdr) = decrypt_header(clone, receiver, &mut enc_header) {
                // If the header was successfully decrypted, keep the DEK and update the loop
                // variable to not be effectively infinite.
                let hdr = Header::decode(hdr);
                recv_count = hdr.recv_count;
                dek = Some(hdr.dek);
            }
        }

        i += 1;
    }

    // Return the protocol and DEK.
    Ok((message, dek.ok_or(DecryptError::InvalidCiphertext)?))
}

/// Given the receiver's key pair and an encrypted header, decrypts the ciphertext and returns the
/// plaintext iff the ciphertext was encrypted for the receiver.
#[must_use]
fn decrypt_header<'a>(
    mut message: Protocol,
    receiver: &SecKey,
    in_out: &'a mut [u8; ENC_HEADER_LEN],
) -> Option<&'a [u8]> {
    // Split the ciphertext into its components.
    let (kem_ect, ciphertext) = in_out.split_at_mut(ENC_CT_LEN);

    // Mix the receiver's public key into the protocol.
    message.mix("receiver", &receiver.pub_key.encoded);

    // Mix the ML-KEM ciphertext into the protocol, decapsulate the ML-KEM shared secret, then mix
    // the shared secret into the protocol.
    message.mix("ml-kem-768-ect", kem_ect);
    let kem_ss =
        kemeleon::decapsulate(&receiver.dk, kem_ect.try_into().expect("should be 1252 bytes"));
    message.mix("ml-kem-768-ss", &kem_ss);

    // Open the plaintext.
    message.open("header", ciphertext)
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

#[derive(Debug)]
#[repr(u8)]
enum BlockType {
    Data = 0x00,
    Padding = 0x01,
}

impl TryFrom<u8> for BlockType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // inline when inline_const_pat lands
        const DATA: u8 = BlockType::Data as u8;
        const PADDING: u8 = BlockType::Padding as u8;
        match value {
            DATA => Ok(BlockType::Data),
            PADDING => Ok(BlockType::Padding),
            _ => Err(value),
        }
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
            .expect("decryption should be ok");

        assert_eq!(writer.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(plaintext.to_vec(), writer.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn wrong_sender() {
        let (mut rng, _, receiver, _, ciphertext) = setup(64);

        let wrong_sender = SecKey::random(&mut rng);

        assert_matches!(
            decrypt(
                Cursor::new(ciphertext),
                Cursor::new(Vec::new()),
                &receiver,
                &wrong_sender.pub_key
            ),
            Err(DecryptError::InvalidCiphertext)
        );
    }

    #[test]
    fn wrong_receiver() {
        let (mut rng, sender, _, _, ciphertext) = setup(64);

        let wrong_receiver = SecKey::random(&mut rng);

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
        let (_, sender, receiver, plaintext, ciphertext) = setup(BLOCK_LEN * 5 + 102);

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

    fn setup(n: usize) -> (ChaChaRng, Box<SecKey>, Box<SecKey>, Vec<u8>, Vec<u8>) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let sender = SecKey::random(&mut rng);
        let receiver = SecKey::random(&mut rng);
        let mut plaintext = vec![0u8; n];
        rng.fill_bytes(&mut plaintext);
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        let ctx_len = encrypt(
            &mut rng,
            Cursor::new(&plaintext),
            Cursor::new(&mut ciphertext),
            &sender,
            &[Some(&sender.pub_key), Some(&receiver.pub_key), None],
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
