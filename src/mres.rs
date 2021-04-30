use std::io;
use std::io::Read;
use std::io::Write;

use byteorder::ByteOrder;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};
use strobe_rs::{SecParam, Strobe};

use crate::{common, hpke, schnorr};

// TODO padding
// TODO shuffling
// TODO fakes

pub fn encrypt<W, R>(
    dst: &mut W,
    src: &mut R,
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    q_rs: Vec<&RistrettoPoint>,
) -> io::Result<u64>
where
    W: io::Write,
    R: io::Read,
{
    let mut written = 0u64;
    let mut rng = OsRng::default();
    let mut signer = schnorr::Signer::new();

    // Generate an ephemeral key pair.
    let d_e = Scalar::random(&mut rng);
    let q_e = RISTRETTO_BASEPOINT_POINT * d_e;

    // Generate a data encryption key.
    let mut dek = [0u8; DEK_LEN];
    rng.fill_bytes(&mut dek);

    // Encode the DEK and message offset in a header.
    let header = encode_header(&dek, q_rs.len());

    // For each recipient, encrypt a copy of the header.
    for q_r in q_rs {
        let ciphertext = hpke::encrypt(d_s, q_s, &d_e, &q_e, q_r, &header);
        written += dst.write(&ciphertext)? as u64;

        // Include encrypted headers in the signature.
        signer.write(&ciphertext)?;
    }

    // Initialize a protocol and key it with the DEK.
    let mut mres = Strobe::new(b"veil.mres", SecParam::B256);
    mres.key(&dek, false);

    // Prep for streaming encryption.
    mres.send_enc(&mut [], false);

    // Read through src in 32KiB chunks.
    let mut buf = [0u8; 32 * 1024];
    while let Ok(n) = src.read(&mut buf) {
        if n == 0 {
            break;
        }

        // Encrypt the block.
        mres.send_enc(&mut buf[0..n], true);

        // Sign the ciphertext.
        signer.write(&buf[0..n])?;

        // Write the ciphertext.
        written += dst.write(&buf[0..n])? as u64;
    }

    // Sign the encrypted headers and ciphertext with the ephemeral key pair.
    let mut sig = signer.sign(&d_e, &q_e);

    // Encrypt the signature.
    mres.send_enc(&mut sig, false);

    // Write the encrypted signature.
    written += dst.write(&sig)? as u64;

    Ok(written)
}

pub fn decrypt<W, R>(
    dst: &mut W,
    src: &mut R,
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
) -> io::Result<u64>
where
    W: io::Write,
    R: io::Read,
{
    let mut written = 0u64;
    let mut verifier = schnorr::Verifier::new();

    let mut buf = [0u8; ENC_HEADER_LEN];
    let mut dek = [0u8; DEK_LEN];
    let mut msg_offset = 0u64;
    let mut hdr_offset = 0u64;
    let mut q_e = RISTRETTO_BASEPOINT_POINT;

    while let Ok(()) = src.read_exact(&mut buf) {
        hdr_offset += verifier.write(&buf)? as u64;

        match hpke::decrypt(d_r, q_r, q_s, &buf) {
            Some((p, header)) => {
                q_e = p;
                dek.copy_from_slice(&header[..32]);
                msg_offset = byteorder::LE::read_u64(&header[header.len() - 8..]);
            }
            None => continue,
        }
    }

    if msg_offset == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ciphertext",
        ));
    }

    let mut remainder = src.take(msg_offset - hdr_offset);
    io::copy(&mut remainder, &mut verifier)?;

    // Initialize a protocol and key it with the DEK.
    let mut mres = Strobe::new(b"veil.mres", SecParam::B256);
    mres.key(&dek, false);

    // Prep for streaming decryption.
    mres.recv_enc(&mut [], false);

    // Read through src in 32KiB chunks, keeping the last 64 bytes as the signature.
    let mut buf = [0u8; 32 * 1024];
    let mut sig = [0u8; 64];
    while let Ok(mut n) = src.read(&mut buf) {
        if n < 64 {
            break;
        }
        sig.copy_from_slice(&buf[n - 64..n]);
        n -= 64;

        verifier.write(&buf[0..n])?;
        mres.recv_enc(&mut buf[0..n], true);
        written += dst.write(&buf[0..n])? as u64;
    }

    mres.recv_enc(&mut sig, false);
    if !verifier.verify(&q_e, &sig) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad sig"));
    }

    Ok(written)
}

const DEK_LEN: usize = 32;
const HEADER_LEN: usize = DEK_LEN + 8;
const ENC_HEADER_LEN: usize = HEADER_LEN + 32 + common::MAC_LEN;

fn encode_header(dek: &[u8; DEK_LEN], r_len: usize) -> Vec<u8> {
    let msg_offset = (r_len as u64) * ENC_HEADER_LEN as u64;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(dek);
    header.extend_from_slice(&msg_offset.to_le_bytes());

    header.to_vec()
}

#[cfg(test)]
mod tests {
    use std::io;

    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    use crate::mres::{decrypt, encrypt};

    #[test]
    pub fn round_trip() {
        let mut rng = OsRng::default();

        let d_s = Scalar::random(&mut rng);
        let q_s = RISTRETTO_BASEPOINT_POINT * d_s;

        let d_r = Scalar::random(&mut rng);
        let q_r = RISTRETTO_BASEPOINT_POINT * d_r;

        let mut src = io::Cursor::new(b"this is a thingy");
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut dst, &mut src, &d_s, &q_s, vec![&q_s, &q_r]).expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut src = io::Cursor::new(dst.into_inner());
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut dst, &mut src, &d_r, &q_r, &q_s).expect("decrypt");
        assert_eq!(dst.position(), ptx_len);
        assert_eq!(b"this is a thingy".to_vec(), dst.into_inner());
    }
}
