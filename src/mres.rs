//! A multi-receiver, hybrid cryptosystem.

use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::mem;

use p256::{NonZeroScalar, ProjectivePoint};
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex, TAG_LEN};
use crate::schnorr::SIGNATURE_LEN;
use crate::sres::NONCE_LEN;
use crate::{schnorr, sres, DecryptError};

/// Encrypt the contents of `reader` such that they can be decrypted and verified by all members of
/// `q_rs` and write the ciphertext to `writer` with `padding` bytes of random data added.
pub fn encrypt(
    mut rng: impl Rng + CryptoRng,
    reader: &mut impl Read,
    writer: &mut impl Write,
    (d_s, q_s): (&NonZeroScalar, &ProjectivePoint),
    q_rs: &[ProjectivePoint],
    padding: usize,
) -> io::Result<u64> {
    // Initialize an unkeyed duplex and absorb the sender's public key.
    let mut mres = UnkeyedDuplex::new("veil.mres");
    mres.absorb_point(q_s);

    // Generate ephemeral key pair, DEK, and nonce.
    let (d_e, dek, nonce) = mres.hedge(&mut rng, &d_s.to_bytes(), |clone| {
        (clone.squeeze_scalar(), clone.squeeze::<DEK_LEN>(), clone.squeeze::<NONCE_LEN>())
    });
    let q_e = &ProjectivePoint::GENERATOR * &d_e;

    // Absorb and write the random nonce.
    mres.absorb(&nonce);
    writer.write_all(&nonce)?;
    let mut written = NONCE_LEN as u64;

    // Encrypt a header for each receiver.
    written += encrypt_headers(
        &mut mres,
        &mut rng,
        (d_s, q_s),
        (&d_e, &q_e),
        q_rs,
        &dek,
        padding as u64,
        writer,
    )?;

    // Add random padding to the end of the headers.
    let mut padding_block = vec![0u8; padding];
    rng.fill_bytes(&mut padding_block);
    mres.absorb(&padding_block);
    writer.write_all(&padding_block)?;

    // Absorb the DEK.
    mres.absorb(&dek);

    // Convert the unkeyed duplex to a keyed duplex.
    let mut mres = mres.into_keyed();

    // Encrypt the plaintext in blocks and write them.
    written += encrypt_message(&mut mres, reader, writer)?;

    // Sign the duplex's final state with the ephemeral private key.
    let (i, s) = schnorr::sign_duplex(&mut mres, &mut rng, &d_e);

    // Encrypt the proof scalar.
    let s = mres.encrypt(&s.to_bytes());

    // Write the signature components.
    writer.write_all(&i)?;
    writer.write_all(&s)?;

    Ok(written + padding as u64 + i.len() as u64 + s.len() as u64)
}

/// The length of the data encryption key.
const DEK_LEN: usize = 32;

const HEADER_LEN: usize = DEK_LEN + mem::size_of::<u64>() + mem::size_of::<u64>();

/// Encode the DEK, header count, and padding size in a header.
#[inline]
fn encode_header(dek: &[u8], hdr_count: u64, padding: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend(dek);
    header.extend(hdr_count.to_le_bytes());
    header.extend(padding.to_le_bytes());
    header
}

#[allow(clippy::too_many_arguments)]
fn encrypt_headers(
    mres: &mut UnkeyedDuplex,
    mut rng: impl Rng + CryptoRng,
    (d_s, q_s): (&NonZeroScalar, &ProjectivePoint),
    (d_e, q_e): (&NonZeroScalar, &ProjectivePoint),
    q_rs: &[ProjectivePoint],
    dek: &[u8],
    padding: u64,
    writer: &mut impl Write,
) -> io::Result<u64> {
    let mut written = 0u64;

    let header = encode_header(dek, q_rs.len() as u64, padding);

    // For each receiver, encrypt a copy of the header with veil.sres.
    for q_r in q_rs {
        // Squeeze a nonce for each header.
        let nonce = mres.squeeze::<NONCE_LEN>();

        // Encrypt the header for the given receiver.
        let ciphertext = sres::encrypt(&mut rng, (d_s, q_s), (d_e, q_e), q_r, &nonce, &header);

        // Absorb the encrypted header.
        mres.absorb(&ciphertext);

        // Write the encrypted header.
        writer.write_all(&ciphertext)?;
        written += ciphertext.len() as u64;
    }

    Ok(written)
}

/// The length of plaintext blocks which are encrypted.
const BLOCK_LEN: usize = 32 * 1024;

/// Given a duplex keyed with the DEK, read the entire contents of `reader` in blocks and write the
/// encrypted blocks and authentication tags to `writer`.
fn encrypt_message(
    mres: &mut KeyedDuplex,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> io::Result<u64> {
    let mut buf = Vec::with_capacity(BLOCK_LEN);
    let mut written = 0;

    loop {
        // Read a block of data.
        let n = reader.take(BLOCK_LEN as u64).read_to_end(&mut buf)?;
        let block = &buf[..n];

        // Encrypt the block and write the ciphertext and a tag.
        writer.write_all(&mres.seal(block))?;
        written += (n + TAG_LEN) as u64;

        // If the block was undersized, we're at the end of the reader.
        if n < BLOCK_LEN {
            break;
        }

        // Reset the buffer.
        buf.clear();
    }

    // Return the number of ciphertext bytes written.
    Ok(written)
}

/// Decrypt the contents of `reader` iff they were originally encrypted by `q_s` for `q_r` and write
/// the plaintext to `writer`.
pub fn decrypt(
    reader: &mut impl Read,
    writer: &mut impl Write,
    (d_r, q_r): (&NonZeroScalar, &ProjectivePoint),
    q_s: &ProjectivePoint,
) -> Result<u64, DecryptError> {
    // Initialize an unkeyed duplex and absorb the sender's public key.
    let mut mres = UnkeyedDuplex::new("veil.mres");
    mres.absorb_point(q_s);

    // Read and absorb the nonce.
    let mut nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce)?;
    mres.absorb(&nonce);

    // Find a header, decrypt it, and write the entirety of the headers and padding to the duplex.
    let (mut mres, q_e, dek) = decrypt_header(mres, reader, d_r, q_r, q_s)?;

    // Absorb the DEK.
    mres.absorb(&dek);

    // Convert the duplex to a keyed duplex.
    let mut mres = mres.into_keyed();

    // Decrypt the message.
    let (written, sig) = decrypt_message(&mut mres, reader, writer)?;

    // Verify the signature.
    schnorr::verify_duplex(&mut mres, &q_e, &sig).map_err(|_| DecryptError::InvalidCiphertext)?;

    // Return the number of plaintext bytes written.
    Ok(written)
}

/// The length of an encrypted block and authentication tag.
const ENC_BLOCK_LEN: usize = BLOCK_LEN + TAG_LEN;

/// Given a duplex keyed with the DEK, read the entire contents of `reader` in blocks and write the
/// decrypted blocks `writer`.
fn decrypt_message(
    mres: &mut KeyedDuplex,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(u64, Vec<u8>), DecryptError> {
    let mut buf = Vec::with_capacity(ENC_BLOCK_LEN + SIGNATURE_LEN);
    let mut written = 0;

    loop {
        // Read a block and a possible signature, keeping in mind the unused bit of the buffer from
        // the last iteration.
        let n = reader
            .take((ENC_BLOCK_LEN + SIGNATURE_LEN - buf.len()) as u64)
            .read_to_end(&mut buf)?;

        // If we're at the end of the reader, we only have the signature left to process. Break out
        // of the read loop and go process the signature.
        if n == 0 {
            break;
        }

        // Pretend we don't see the possible signature at the end.
        let n = buf.len() - SIGNATURE_LEN;
        let block = &buf[..n];

        // Decrypt the block and write the plaintext. If the block cannot be decrypted, return an
        // error.
        let plaintext = mres.unseal(block).ok_or(DecryptError::InvalidCiphertext)?;
        writer.write_all(&plaintext)?;
        written += plaintext.len() as u64;

        // Clear the part of the buffer we used.
        buf.drain(0..n);
    }

    // Return the number of bytes and the signature.
    Ok((written, buf))
}

/// The length of an encrypted header.
const ENC_HEADER_LEN: usize = HEADER_LEN + sres::OVERHEAD;

/// Iterate through the contents of `reader` looking for a header which was encrypted by the given
/// sender for the given receiver.
fn decrypt_header(
    mut mres: UnkeyedDuplex,
    reader: &mut impl Read,
    d_r: &NonZeroScalar,
    q_r: &ProjectivePoint,
    q_s: &ProjectivePoint,
) -> Result<(UnkeyedDuplex, ProjectivePoint, Vec<u8>), DecryptError> {
    let mut buf = Vec::with_capacity(ENC_HEADER_LEN);
    let mut i = 0u64;
    let mut hdr_count = u64::MAX;

    let mut padding: Option<u64> = None;
    let mut dek: Option<Vec<u8>> = None;
    let mut q_e: Option<ProjectivePoint> = None;

    // Iterate through blocks, looking for an encrypted header that can be decrypted.
    while i < hdr_count {
        // Read a potential encrypted header.
        let n = reader.take(ENC_HEADER_LEN as u64).read_to_end(&mut buf)?;
        let header = &buf[..n];

        // If the header is short, we're at the end of the reader.
        if header.len() < ENC_HEADER_LEN {
            return Err(DecryptError::InvalidCiphertext);
        }

        // Squeeze a nonce regardless of whether we need to in order to keep the duplex state
        // consistent.
        let nonce = mres.squeeze::<NONCE_LEN>();

        // If a header hasn't been decrypted yet, try to decrypt this one.
        if dek.is_none() {
            if let Some((d, q, c, p)) =
                sres::decrypt((d_r, q_r), q_s, &nonce, header).and_then(decode_header)
            {
                // If the header was successfully decrypted, keep the DEK and padding and update the
                // loop variable to not be effectively infinite.
                dek = Some(d);
                q_e = Some(q);
                hdr_count = c;
                padding = Some(p);
            }
        }

        // Absorb the encrypted header with the duplex.
        mres.absorb(header);
        i += 1;

        buf.clear();
    }

    if let Some(((dek, q_e), padding)) = dek.zip(q_e).zip(padding) {
        // Read the remainder of the padding and absorb it with the duplex.
        let mut padding_block = vec![0u8; padding as usize];
        reader.read_exact(&mut padding_block)?;
        mres.absorb(&padding_block);

        // Return the duplex and DEK.
        Ok((mres, q_e, dek))
    } else {
        Err(DecryptError::InvalidCiphertext)
    }
}

/// Decode a header into a DEK, header count, and padding size.
#[inline]
fn decode_header(
    (q_e, header): (ProjectivePoint, Vec<u8>),
) -> Option<(Vec<u8>, ProjectivePoint, u64, u64)> {
    // Check header for proper length.
    if header.len() != HEADER_LEN {
        return None;
    }

    // Split header into components.
    let (dek, hdr_count) = header.split_at(DEK_LEN);
    let (hdr_count, padding) = hdr_count.split_at(mem::size_of::<u64>());

    // Decode components.
    let dek = dek.to_vec();
    let hdr_count = u64::from_le_bytes(hdr_count.try_into().expect("invalid u64 len"));
    let padding = u64::from_le_bytes(padding.try_into().expect("invalid u64 len"));

    Some((dek, q_e, hdr_count, padding))
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

    use crate::Group;

    use super::*;

    macro_rules! assert_failed {
        ($action: expr) => {
            match $action {
                Ok(_) => panic!("decrypted but shouldn't have"),
                Err(DecryptError::InvalidCiphertext) => Ok(()),
                Err(e) => Err(e),
            }
        };
    }

    #[test]
    fn round_trip() -> Result<(), DecryptError> {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let q_rs = &[q_s, q_r, q_s, q_s, q_s];
        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), q_rs, 123)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s)?;
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");

        Ok(())
    }

    #[test]
    fn wrong_sender_public_key() -> Result<(), DecryptError> {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let q_s = ProjectivePoint::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_failed!(decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s))
    }

    #[test]
    fn wrong_receiver_public_key() -> Result<(), DecryptError> {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let q_r = ProjectivePoint::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_failed!(decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s))
    }

    #[test]
    fn wrong_receiver_private_key() -> Result<(), DecryptError> {
        let (mut rng, d_s, q_s, _, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let d_r = NonZeroScalar::random(&mut rng);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_failed!(decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s))
    }

    #[test]
    fn multi_block_message() -> Result<(), DecryptError> {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = [69u8; 65 * 1024];
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s)?;
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");

        Ok(())
    }

    #[test]
    fn split_sig() -> Result<(), DecryptError> {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = [69u8; 32 * 1024 - 37];
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 0)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, (&d_r, &q_r), &q_s)?;
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");

        Ok(())
    }

    #[test]
    fn flip_every_bit() -> Result<(), DecryptError> {
        let (mut rng, d_s, q_s, d_r, q_r) = setup();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        encrypt(&mut rng, &mut src, &mut dst, (&d_s, &q_s), &[q_s, q_r], 123)?;

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

        Ok(())
    }

    fn setup() -> (ChaChaRng, NonZeroScalar, ProjectivePoint, NonZeroScalar, ProjectivePoint) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d_s = NonZeroScalar::random(&mut rng);
        let q_s = &ProjectivePoint::GENERATOR * &d_s;

        let d_r = NonZeroScalar::random(&mut rng);
        let q_r = &ProjectivePoint::GENERATOR * &d_r;

        (rng, d_s, q_s, d_r, q_r)
    }
}
