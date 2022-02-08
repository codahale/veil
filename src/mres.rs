//! A multi-recipient, hybrid cryptosystem.

use std::convert::TryInto;
use std::io::{self, Read, Result, Write};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::prelude::ThreadRng;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret, SecretVec, Zeroize};

use crate::constants::{MAC_LEN, POINT_LEN, U64_LEN};
use crate::schnorr::{Signer, Verifier, SIGNATURE_LEN};
use crate::sres;
use crate::strobe::Protocol;

/// Encrypt the contents of `reader` such that they can be decrypted and verified by all members of
/// `q_rs` and write the ciphertext to `writer` with `padding` bytes of random data added.
pub fn encrypt<R, W>(
    reader: &mut R,
    writer: &mut W,
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    q_rs: &[RistrettoPoint],
    padding: u64,
) -> Result<u64>
where
    R: Read,
    W: Write,
{
    // Initialize a protocol and send the sender's public key as cleartext.
    let mut mres = Protocol::new("veil.mres");
    mres.send("sender", q_s.compress().as_bytes());

    // Derive a random ephemeral key pair from the protocol's current state, the sender's private
    // key, and a random nonce.
    let d_e = mres.hedge(d_s.as_bytes(), |clone| clone.prf_scalar("ephemeral-private-key"));
    let q_e = &G * d_e.expose_secret();

    // Derive a random DEK from the protocol's current state, the sender's private key, and a random
    // nonce.
    let dek = mres.hedge(d_s.as_bytes(), |clone| clone.prf_vec("data-encryption-key", DEK_LEN));

    // Encode the DEK, the ephemeral public key, and the message offset in a header.
    let msg_offset = ((q_rs.len() as u64) * ENC_HEADER_LEN as u64) + padding;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend(dek.expose_secret());
    header.extend(q_e.compress().as_bytes());
    header.extend(&msg_offset.to_le_bytes());

    // Count and sign all of the bytes written to `writer`.
    let signer = Signer::new(writer);

    // Include all encrypted headers and padding as sent cleartext.
    let mut send_clr = mres.send_clr_writer("headers", signer);

    // For each recipient, encrypt a copy of the header with veil.sres.
    for q_r in q_rs {
        let ciphertext = sres::encrypt(d_s, q_s, q_r, &header);
        send_clr.write_all(&ciphertext)?;
    }

    // Add random padding to the end of the headers.
    io::copy(&mut RngReader(rand::thread_rng()).take(padding), &mut send_clr)?;

    // Unwrap the sent cleartext writer.
    let (mut mres, mut signer, header_len) = send_clr.into_inner();

    // Key the protocol with the DEK.
    mres.key("data-encryption-key", dek.expose_secret());

    // Encrypt the plaintext, pass it through the signer, and write it.
    let ciphertext_len = encrypt_message(&mut mres, reader, &mut signer)?;

    // Sign the encrypted headers and ciphertext with the ephemeral key pair.
    let (sig, writer) = signer.sign(d_e.expose_secret(), &q_e);

    // Encrypt the signature.
    let sig = mres.encrypt("signature", &sig);

    // Write the encrypted signature.
    writer.write_all(&sig)?;

    Ok(header_len + ciphertext_len + sig.len() as u64)
}

fn encrypt_message<R, W>(mres: &mut Protocol, reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: Read,
    W: Write,
{
    let mut buf = SecBuf(Vec::with_capacity(BLOCK_LEN));
    let mut written = 0;

    loop {
        // Read a block of data.
        let n = reader.take(BLOCK_LEN as u64).read_to_end(&mut buf.0)?;
        let block = &buf.0[..n];

        // Encrypt the block and write the ciphertext.
        writer.write_all(&mres.encrypt("block", block))?;
        written += n as u64;

        // Generate a MAC and write it.
        writer.write_all(&mres.mac("mac"))?;
        written += MAC_LEN as u64;

        // If the block is undersized, we're at the end of the reader.
        if n < BLOCK_LEN {
            break;
        }

        // Reset the buffer.
        buf.0.clear();
    }

    Ok(written)
}

/// Decrypt the contents of `reader` iff they were originally encrypted by `q_s` for `q_r` and write
/// the plaintext to `writer`.
pub fn decrypt<R, W>(
    reader: &mut R,
    writer: &mut W,
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
) -> Result<(bool, u64)>
where
    R: Read,
    W: Write,
{
    // Initialize a protocol and receive the sender's public key as cleartext.
    let mut mres = Protocol::new("veil.mres");
    mres.receive("sender", q_s.compress().as_bytes());

    // Initialize a verifier for the entire ciphertext.
    let verifier = Verifier::new();

    // Include all encrypted headers and padding as received cleartext.
    let mut mres_writer = mres.recv_clr_writer("headers", verifier);

    // Find a header, decrypt it, and write the entirety of the headers and padding to the verifier.
    let (dek, q_e) = match decrypt_header(reader, &mut mres_writer, d_r, q_r, q_s)? {
        Some((dek, q_e)) => (dek, q_e),
        None => return Ok((false, 0)),
    };

    // Unwrap the received cleartext writer.
    let (mut mres, mut verifier, _) = mres_writer.into_inner();

    // Key the protocol with the recovered DEK.
    mres.key("data-encryption-key", dek.expose_secret());

    // Decrypt the message and get the signature.
    let (written, sig) = decrypt_message(&mut mres, reader, writer, &mut verifier)?;

    // Return the signature's validity and the number of bytes of plaintext written.
    Ok((verifier.verify(&q_e, &sig), written))
}

fn decrypt_message<R, W>(
    mres: &mut Protocol,
    reader: &mut R,
    writer: &mut W,
    verifier: &mut Verifier,
) -> Result<(u64, [u8; SIGNATURE_LEN])>
where
    R: Read,
    W: Write,
{
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

        // Add the block to the verifier.
        verifier.write_all(block)?;

        // Split the block into ciphertext and MAC.
        let (ciphertext, mac) = block.split_at(n - MAC_LEN);

        // Decrypt the block and write the plaintext.
        writer.write_all(mres.decrypt("block", ciphertext).expose_secret())?;
        written += ciphertext.len() as u64;

        // Verify the MAC.
        if mres.verify_mac("mac", mac).is_none() {
            return Ok((written, [0u8; SIGNATURE_LEN]));
        }

        // Clear the part of the buffer we used.
        buf.drain(0..n);
    }

    // Decrypt the signature.
    let sig = mres.decrypt("signature", &buf);

    Ok((written, sig.expose_secret().as_slice().try_into().expect("invalid sig len")))
}

fn decrypt_header<R, W>(
    reader: &mut R,
    verifier: &mut W,
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
) -> Result<Option<(SecretVec<u8>, RistrettoPoint)>>
where
    R: Read,
    W: Write,
{
    let mut buf = Vec::with_capacity(ENC_HEADER_LEN);
    let mut hdr_offset = 0u64;

    // Iterate through blocks, looking for an encrypted header that can be decrypted.
    loop {
        // Read a potential encrypted header.
        let n = reader.take(ENC_HEADER_LEN as u64).read_to_end(&mut buf)?;
        let header = &buf[..n];

        // If the header is short, we're at the end of the reader.
        if header.len() < ENC_HEADER_LEN {
            return Ok(None);
        }

        // Pass the block to the verifier.
        verifier.write_all(header)?;
        hdr_offset += ENC_HEADER_LEN as u64;

        // Try to decrypt the encrypted header.
        if let Some((dek, q_e, msg_offset)) =
            sres::decrypt(d_r, q_r, q_s, header).and_then(decode_header)
        {
            // Read the remainder of the headers and padding and write them to the verifier.
            let mut remainder = reader.take(msg_offset - hdr_offset);
            io::copy(&mut remainder, verifier)?;

            // Return the DEK and ephemeral public key.
            return Ok(Some((dek, q_e)));
        }

        buf.clear();
    }
}

#[inline]
fn decode_header(header: Secret<Vec<u8>>) -> Option<(SecretVec<u8>, RistrettoPoint, u64)> {
    // Check header for proper length.
    let header = header.expose_secret();
    if header.len() != HEADER_LEN {
        return None;
    }

    // Split header into components.
    let (dek, header) = header.split_at(DEK_LEN);
    let (q_e, msg_offset) = header.split_at(POINT_LEN);

    // Decode components.
    let dek = dek.to_vec().into();
    let q_e = CompressedRistretto::from_slice(q_e).decompress()?;
    let msg_offset = u64::from_le_bytes(msg_offset.try_into().expect("invalid u64 len"));

    Some((dek, q_e, msg_offset))
}

const DEK_LEN: usize = 32;
const HEADER_LEN: usize = DEK_LEN + POINT_LEN + U64_LEN;
const ENC_HEADER_LEN: usize = HEADER_LEN + sres::OVERHEAD;
const BLOCK_LEN: usize = 32 * 1024;
const ENC_BLOCK_LEN: usize = BLOCK_LEN + MAC_LEN;

struct SecBuf(Vec<u8>);

impl Drop for SecBuf {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct RngReader(ThreadRng);

impl Read for RngReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.fill_bytes(buf);
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn round_trip() -> Result<()> {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut src, &mut dst, &d_s, &q_s, &[q_s, q_r], 123)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let (verified, ptx_len) = decrypt(&mut src, &mut dst, &d_r, &q_r, &q_s)?;
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
        assert!(verified, "valid message not verified");

        Ok(())
    }

    #[test]
    fn multi_block_message() -> Result<()> {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        let message = [69u8; 65 * 1024];
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut src, &mut dst, &d_s, &q_s, &[q_s, q_r], 123)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let (verified, ptx_len) = decrypt(&mut src, &mut dst, &d_r, &q_r, &q_s)?;
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
        assert!(verified, "valid message not verified");

        Ok(())
    }

    #[test]
    fn split_sig() -> Result<()> {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        let message = [69u8; 32 * 1024 - 37];
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut src, &mut dst, &d_s, &q_s, &[q_s, q_r], 0)?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let (verified, ptx_len) = decrypt(&mut src, &mut dst, &d_r, &q_r, &q_s)?;
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
        assert!(verified, "valid message not verified");

        Ok(())
    }

    #[test]
    fn flip_every_bit() -> Result<()> {
        let d_s = Scalar::random(&mut rand::thread_rng());
        let q_s = &G * &d_s;

        let d_r = Scalar::random(&mut rand::thread_rng());
        let q_r = &G * &d_r;

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        encrypt(&mut src, &mut dst, &d_s, &q_s, &[q_s, q_r], 123)?;

        let ciphertext = dst.into_inner();

        for i in 0..ciphertext.len() {
            for j in 0u8..8 {
                let mut ciphertext = ciphertext.clone();
                ciphertext[i] ^= 1 << j;
                let mut src = Cursor::new(ciphertext);

                let (verified, _) = decrypt(&mut src, &mut io::sink(), &d_r, &q_r, &q_s)?;
                assert!(!verified, "bit flip at byte {}, bit {} produced a valid message", i, j);
            }
        }

        Ok(())
    }
}
