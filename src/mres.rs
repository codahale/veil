//! A multi-receiver, hybrid cryptosystem.

use std::io::{self, Read, Write};
use std::mem;

use rand::{CryptoRng, Rng};

use crate::blockio::ReadBlock;
use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex, TAG_LEN};
use crate::ecc::{CanonicallyEncoded, Point, Scalar};
use crate::schnorr::SIGNATURE_LEN;
use crate::sres::NONCE_LEN;
use crate::{schnorr, sres, AsciiEncoded, DecryptError, Signature};

/// Encrypt the contents of `reader` such that they can be decrypted and verified by all members of
/// `q_rs` and write the ciphertext to `writer` with `padding` bytes of random data added.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    reader: impl Read,
    mut writer: impl Write,
    (d_s, q_s): (&Scalar, &Point),
    q_rs: &[Point],
    padding: usize,
) -> io::Result<u64> {
    let padding = u64::try_from(padding).expect("unexpected overflow");

    // Initialize an unkeyed duplex and absorb the sender's public key.
    let mut mres = UnkeyedDuplex::new("veil.mres");
    mres.absorb_point(q_s);

    // Generate ephemeral key pair, DEK, and nonce.
    let (d_e, dek, nonce) = mres.hedge(&mut rng, &d_s.as_canonical_bytes(), |clone| {
        (clone.squeeze_scalar(), clone.squeeze::<DEK_LEN>(), clone.squeeze::<NONCE_LEN>())
    });
    let q_e = Point::mulgen(&d_e);

    // Absorb and write the nonce.
    mres.absorb(&nonce);
    writer.write_all(&nonce)?;
    let mut written = u64::try_from(NONCE_LEN).expect("unexpected overflow");

    // Encrypt a header for each receiver.
    written += encrypt_headers(
        &mut mres,
        &mut rng,
        (d_s, q_s),
        (&d_e, &q_e),
        q_rs,
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
    let sig = schnorr::sign_duplex(&mut mres, &mut rng, &d_e);
    writer.write_all(&sig.to_bytes())?;

    Ok(written + u64::try_from(SIGNATURE_LEN).expect("unexpected overflow"))
}

/// The length of the data encryption key.
const DEK_LEN: usize = 32;

const INT_LEN: usize = mem::size_of::<u64>();
const HEADER_LEN: usize = DEK_LEN + INT_LEN + INT_LEN;

/// Encode the DEK, header count, and padding size in a header.
#[inline]
fn encode_header(dek: &[u8; DEK_LEN], recv_count: u64, padding: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let (hdr_dek, hdr_recv_count) = header.split_at_mut(DEK_LEN);
    let (hdr_recv_count, hdr_padding) = hdr_recv_count.split_at_mut(INT_LEN);
    hdr_dek.copy_from_slice(dek);
    hdr_recv_count.copy_from_slice(&recv_count.to_le_bytes());
    hdr_padding.copy_from_slice(&padding.to_le_bytes());
    header
}

#[allow(clippy::too_many_arguments)]
fn encrypt_headers(
    mres: &mut UnkeyedDuplex,
    mut rng: impl Rng + CryptoRng,
    (d_s, q_s): (&Scalar, &Point),
    (d_e, q_e): (&Scalar, &Point),
    q_rs: &[Point],
    dek: &[u8; DEK_LEN],
    padding: u64,
    mut writer: impl Write,
) -> io::Result<u64> {
    let mut written = 0u64;
    let header = encode_header(dek, q_rs.len().try_into().expect("unexpected overflow"), padding);
    let mut enc_header = [0u8; ENC_HEADER_LEN];

    // For each receiver, encrypt a copy of the header with veil.sres.
    for q_r in q_rs {
        // Squeeze a nonce for each header.
        let nonce = mres.squeeze::<NONCE_LEN>();

        // Encrypt the header for the given receiver.
        sres::encrypt(&mut rng, (d_s, q_s), (d_e, q_e), q_r, &nonce, &header, &mut enc_header);

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
    (d_r, q_r): (&Scalar, &Point),
    q_s: &Point,
) -> Result<u64, DecryptError> {
    // Initialize an unkeyed duplex and absorb the sender's public key.
    let mut mres = UnkeyedDuplex::new("veil.mres");
    mres.absorb_point(q_s);

    // Read and absorb the nonce.
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce)?;
    mres.absorb(&nonce);

    // Find a header, decrypt it, and write the entirety of the headers and padding to the duplex.
    let (mut mres, q_e, dek) = decrypt_header(mres, &mut reader, d_r, q_r, q_s)?;

    // Absorb the DEK.
    mres.absorb(&dek);

    // Convert the duplex to a keyed duplex.
    let mut mres = mres.into_keyed();

    // Decrypt the message.
    let (written, sig) = decrypt_message(&mut mres, &mut reader, &mut writer)?;

    // Verify the signature and return the number of bytes written.
    schnorr::verify_duplex(&mut mres, &q_e, &sig)
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
    Ok((written, Signature::from_bytes(&buf[..SIGNATURE_LEN]).expect("invalid signature len")))
}

/// The length of an encrypted header.
const ENC_HEADER_LEN: usize = HEADER_LEN + sres::OVERHEAD;

/// Iterate through the contents of `reader` looking for a header which was encrypted by the given
/// sender for the given receiver.
fn decrypt_header(
    mut mres: UnkeyedDuplex,
    mut reader: impl Read,
    d_r: &Scalar,
    q_r: &Point,
    q_s: &Point,
) -> Result<(UnkeyedDuplex, Point, [u8; DEK_LEN]), DecryptError> {
    let mut header = [0u8; ENC_HEADER_LEN];
    let mut i = 0u64;
    let mut recv_count = u64::MAX;

    let mut header_values: Option<(Point, u64, [u8; DEK_LEN])> = None;

    // Iterate through blocks, looking for an encrypted header that can be decrypted.
    while i < recv_count {
        // Read a potential encrypted header.
        let n = reader.read_block(&mut header)?;

        // If the header is short, we're at the end of the reader.
        if n < ENC_HEADER_LEN {
            return Err(DecryptError::InvalidCiphertext);
        }

        // Squeeze a nonce regardless of whether we need to in order to keep the duplex state
        // consistent.
        let nonce = mres.squeeze::<NONCE_LEN>();

        // Absorb the encrypted header with the duplex.
        mres.absorb(&header);

        // If a header hasn't been decrypted yet, try to decrypt this one.
        if header_values.is_none() {
            if let Some((q_e, d, c, p)) =
                sres::decrypt((d_r, q_r), q_s, &nonce, &mut header).map(decode_header)
            {
                // If the header was successfully decrypted, keep the ephemeral public key, DEK, and
                // padding and update the loop variable to not be effectively infinite.
                header_values = Some((q_e, p, d));
                recv_count = c;
            }
        }

        i += 1;
    }

    if let Some((q_e, padding, dek)) = header_values {
        // Read the padding and absorb it with the duplex.
        mres.absorb_reader(&mut reader.take(padding))?;

        // Return the duplex, ephemeral public key, and DEK.
        Ok((mres, q_e, dek))
    } else {
        Err(DecryptError::InvalidCiphertext)
    }
}

/// Decode an ephemeral public key and header into an ephemeral public key, DEK, header count, and
/// padding size.
#[inline]
fn decode_header((q_e, header): (Point, &[u8])) -> (Point, [u8; DEK_LEN], u64, u64) {
    // Split header into components.
    let (dek, hdr_count) = header.split_at(DEK_LEN);
    let (hdr_count, padding) = hdr_count.split_at(mem::size_of::<u64>());

    // Decode components.
    let dek = dek.try_into().expect("invalid DEK len");
    let hdr_count = u64::from_le_bytes(hdr_count.try_into().expect("invalid u64 len"));
    let padding = u64::from_le_bytes(padding.try_into().expect("invalid u64 len"));

    (q_e, dek, hdr_count, padding)
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
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let q_rs = &[q_s, q_r, q_s, q_s, q_s];
        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), q_rs, 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s).expect("error decrypting");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn wrong_sender_public_key() {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let q_s = Point::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_eq!(
            "invalid ciphertext",
            decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s)
                .expect_err("should not have decrypted")
                .to_string()
        );
    }

    #[test]
    fn wrong_receiver_public_key() {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let q_r = Point::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_eq!(
            "invalid ciphertext",
            decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s)
                .expect_err("should not have decrypted")
                .to_string()
        );
    }

    #[test]
    fn wrong_receiver_private_key() {
        let (mut rng, d_s, q_s, _, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let d_r = Scalar::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_eq!(
            "invalid ciphertext",
            decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s)
                .expect_err("should not have decrypted")
                .to_string()
        );
    }

    #[test]
    fn multi_block_message() {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = [69u8; 65 * 1024];
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s).expect("error decrypting");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn split_sig() {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = [69u8; 32 * 1024 - 37];
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 0)
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s).expect("error decrypting");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn flip_every_bit() {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)
            .expect("error encrypting");

        let ciphertext = dst.into_inner();

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                let mut src = Cursor::new(ciphertext);

                match decrypt(&mut src, &mut io::sink(), (&d_r, &q_r), &q_s) {
                    Err(DecryptError::InvalidCiphertext) => {}
                    Ok(_) => panic!("bit flip at byte {i}, bit {j} produced a valid message"),
                    Err(e) => panic!("unknown error: {:?}", e),
                };
            }
        }
    }

    fn setup() -> (ChaChaRng, Scalar, Point, Scalar, Point) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d_s = Scalar::random(&mut rng);
        let q_s = Point::mulgen(&d_s);

        let d_r = Scalar::random(&mut rng);
        let q_r = Point::mulgen(&d_r);

        (rng, d_s, q_s, d_r, q_r)
    }
}
