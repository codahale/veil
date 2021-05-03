//! mres implements Veil's multi-recipient encryption system.
//!
//! # Encryption
//!
//! Encrypting a message begins as follows, given the sender's key pair, `d_s` and `Q_s`, a
//! plaintext message in blocks `P_0`…`P_n`, a list of recipient public keys, `Q_r0`…`Q_rm`, and a
//! DEK size `N_dek`:
//!
//! ```text
//! INIT('veil.mres', level=256)
//! AD(LE_32(N_dek),  meta=true)
//! AD(Q_s)
//! ```
//!
//! The protocol context is cloned and keyed with the sender's private key and a random nonce and
//! used to derive a data encryption key, `K_dek`, and an ephemeral private key, `d_e`:
//!
//! ```text
//! KEY(d_s)
//! KEY(rand())
//! PRF(32) -> K_dek
//! PRF(64) -> d_e
//! ```
//!
//! The ephemeral public key is computed and the cloned context is discarded:
//!
//! ```text
//! Q_e = G^d_e
//! ```
//!
//! The data encryption key and the message offset are encoded into a fixed-length header and copies
//! of it are encrypted with `veil.akem` for each recipient using `d_e` and `Q_e`. Optional random
//! padding is added to the end, and the resulting block `H` is written:
//
//! ```text
//! SEND_CLR(H)
//! ```
//!
//! The protocol is keyed with the DEK and the encrypted message is written:
//!
//! ```text
//! KEY(K_dek)
//! SEND_ENC('')
//! SEND_ENC(P_0,     more=true)
//! …
//! SEND_ENC(P_n,     more=true)
//! ```
//!
//! Finally, a Schnorr signature `S` of the entire ciphertext (headers, padding, and DEM ciphertext)
//! is created with `d_e` and encrypted:
//!
//! ```text
//! SEND_ENC(S)
//! ```
//!
//! The resulting ciphertext then contains, in order: the `veil.akem`-encrypted headers, random
//! padding, message ciphertext, and a Schnorr signature of the headers, padding, and ciphertext.
//!
//! # Decryption
//!
//! Decryption begins as follows, given the recipient's key pair, `d_r` and `Q_r`, the sender's
//! public key, `Q_s`:
//!
//! ```text
//! INIT('veil.mres', level=256)
//! AD(LE_32(N_dek),  meta=true)
//! AD(Q_s)
//! ```
//!
//! The recipient reads through the ciphertext in header-sized blocks, looking for one which is
//! decryptable given their key pair and the sender's public key. Having found one, they recover the
//! data encryption key `K_dek`, the message offset, and the ephemeral public key `Q_e`. They then
//! read the remainder of the block of encrypted headers and padding `H`:
//!
//! ```text
//! RECV_CLR(H)
//! ```
//!
//! The protocol is keyed with the DEK and the plaintext decrypted:
//!
//! ```text
//! KEY(K_dek)
//! RECV_ENC('')
//! RECV_ENC(C_0,     more=true)
//! …
//! RECV_ENC(C_n,     more=true)
//! ```
//!
//! Finally, the signature `S` is decrypted and verified against the entire ciphertext:
//!
//! ```text
//! RECV_ENC(S)
//! ```
//!
//! # Multi-Recipient Confidentiality
//!
//! To evaluate the confidentiality of this construction, consider an attacker provided with an
//! encryption oracle for the sender's private key and a decryption oracle for each recipient,
//! engaged in an IND-CCA2 game with the goal of gaining an advantage against any individual
//! recipient. The elements available for them to analyze and manipulate are the encrypted headers,
//! the random padding, the message ciphertext, and the signature.
//!
//! Each recipient's header is an IND-CCA2-secure ciphertext, so an attacker can gain no advantage
//! there. Further, the attacker cannot modify the copy of the DEK, the ephemeral public key, or the
//! header length each recipient receives.
//!
//! The encrypted headers and/or padding for other recipients are not IND-CCA2-secure for all
//! recipients, so the attacker may modify those without producing invalid headers. Similarly, the
//! encrypted message is only IND-CPA-secure. Any attacker attempting to modify any of those,
//! however, will have to forge a valid signature for the overall message to be valid. As
//! `veil.schnorr` is SUF-CMA-secure, this is not possible.
//!
//! # Multi-Recipient Authenticity
//!
//! Similarly, an attacker engaged in parallel CMA games with recipients has negligible advantage in
//! forging messages. The `veil.schnorr` signature covers the entirety of the ciphertext.
//!
//! The standard KEM/DEM hybrid construction (i.e. Construction 12.20 from Modern Cryptography 3e)
//! provides strong confidentiality (per Theorem 12.14), but no authenticity. A compromised
//! recipient can replace the DEM component of the ciphertext with an arbitrary message encrypted
//! with the same DEK. Even if the KEM provides strong authenticity against insider attacks, the
//! KEM/DEM construction does not. [Alwen et al.](https://eprint.iacr.org/2020/1499.pdf) detail this
//! attack against the proposed HPKE standard.
//!
//! In the single-recipient setting, the practical advantages of this attack are limited: the
//! attacker can forge messages which appear to be from a sender but are only decryptable by the
//! attacker. In the multi-recipient setting, however, the practical advantage is much greater: the
//! attacker can present forged messages which appear to be from a sender to other, honest
//! recipients.
//!
//! `veil.mres` eliminates this attack by using the ephemeral key pair to sign the entire ciphertext
//! and including only the public key in the KEM ciphertext. Re-using the KEM ciphertexts with a new
//! message requires forging a new signature for a SUF-CMA-secure scheme. The use of an
//! authenticated KEM serves to authenticate the ephemeral public key and thus the message: only the
//! possessor of the sender's private key can calculate the static shared secret used to encrypt the
//! ephemeral public key, and the recipient can only forge KEM ciphertexts with themselves as the
//! intended recipient.
//!
//! # Repudiability
//!
//! Because the sender's private key is only used to calculate shared secrets, a `veil.mres`
//! ciphertext is entirely repudiable unless a recipient reveals their public key. The
//! `veil.schnorr` keys are randomly generated for each message and all other forms of sender
//! identity which are transmitted are only binding on public information.
//!
//! # Randomness Re-Use
//!
//! The ephemeral key pair, `d_e` and `Q_e`, are used multiple times: once for each `veil.akem`
//! header and finally once for the end signature. This improves the efficiency of the scheme
//! without reducing its security, per [Bellare et al.'s treatment of Randomness Reusing
//! Multi-Recipient Encryption Schemes](http://cseweb.ucsd.edu/~Mihir/papers/bbs.pdf).
//!
//! # Ephemeral Scalar Hedging
//!
//! In deriving the DEK and ephemeral scalar from a cloned context, `veil.mres` uses [Aranha et
//! al.'s "hedged signature" technique](https://eprint.iacr.org/2019/956.pdf) to mitigate against
//! both catastrophic randomness failures and differential fault attacks against purely
//! deterministic encryption schemes.
//!

use std::io;
use std::io::Read;
use std::io::Write;

use byteorder::ByteOrder;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use strobe_rs::{SecParam, Strobe};

use crate::{akem, schnorr, MAC_LEN};

pub(crate) fn encrypt<R, W>(
    reader: &mut R,
    writer: &mut W,
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    q_rs: Vec<RistrettoPoint>,
    padding: u64,
) -> io::Result<u64>
where
    R: io::Read,
    W: io::Write,
{
    let mut written = 0u64;
    let mut rng = rand::thread_rng();
    let mut signer = schnorr::Signer::new(writer);

    // Generate an ephemeral key pair.
    let d_e = Scalar::random(&mut rng);
    let q_e = RISTRETTO_BASEPOINT_POINT * d_e;

    // Generate a data encryption key.
    let mut dek = [0u8; DEK_LEN];
    rng.fill(dek.as_mut());

    // Encode the DEK and message offset in a header.
    let header = encode_header(&dek, q_rs.len(), padding);

    // For each recipient, encrypt a copy of the header.
    for q_r in q_rs {
        let ciphertext = akem::encapsulate(d_s, q_s, &d_e, &q_e, &q_r, &header);
        signer.write_all(&ciphertext)?;
        written += ciphertext.len() as u64;
    }

    // Add random padding to the end of the headers.
    written += io::copy(
        &mut RngReader(rand::thread_rng()).take(padding),
        &mut signer,
    )?;

    // Initialize a protocol and key it with the DEK.
    let mut mres = Strobe::new(b"veil.mres", SecParam::B256);
    mres.key(&dek, false);

    // Prep for streaming encryption.
    mres.send_enc(&mut [], false);

    // Read through src in 32KiB chunks.
    let mut buf = [0u8; 32 * 1024];
    while let Ok(n) = reader.read(&mut buf) {
        if n == 0 {
            break;
        }

        // Encrypt the block.
        mres.send_enc(&mut buf[0..n], true);

        // Write the ciphertext and sign it.
        signer.write_all(&buf[0..n])?;
        written += n as u64;
    }

    // Sign the encrypted headers and ciphertext with the ephemeral key pair.
    let mut sig = signer.sign(&d_e, &q_e);

    // Encrypt the signature.
    mres.send_enc(&mut sig, false);

    // Write the encrypted signature.
    signer.direct_write_all(&sig)?;
    written += sig.len() as u64;

    Ok(written)
}

pub(crate) fn decrypt<R, W>(
    reader: &mut R,
    writer: &mut W,
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
) -> io::Result<u64>
where
    R: io::Read,
    W: io::Write,
{
    let mut written = 0u64;
    let mut verifier = schnorr::Verifier::new();

    let mut buf = [0u8; ENC_HEADER_LEN];
    let mut dek = [0u8; DEK_LEN];
    let mut msg_offset = 0u64;
    let mut hdr_offset = 0u64;
    let mut q_e = RISTRETTO_BASEPOINT_POINT;

    // Iterate through blocks, looking for an encrypted header that can be decrypted.
    while let Ok(()) = reader.read_exact(&mut buf) {
        verifier.write_all(&buf)?;
        hdr_offset += buf.len() as u64;

        match akem::decapsulate(d_r, q_r, q_s, &buf) {
            Some((p, header)) => {
                // Recover the ephemeral public key, the DEK, and the message offset.
                q_e = p;
                dek.copy_from_slice(&header[..32]);
                msg_offset = byteorder::LE::read_u64(&header[header.len() - 8..]);

                break;
            }
            None => continue,
        }
    }

    // If no header was found, return an error.
    if msg_offset == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ciphertext",
        ));
    }

    // Read the remainder of the headers and padding and write them to the verifier.
    let mut remainder = reader.take(msg_offset - hdr_offset);
    io::copy(&mut remainder, &mut verifier)?;

    // Initialize a protocol and key it with the DEK.
    let mut mres = Strobe::new(b"veil.mres", SecParam::B256);
    mres.key(&dek, false);

    // Prep for streaming decryption.
    mres.recv_enc(&mut [], false);

    // Read through src in 32KiB chunks, keeping the last 64 bytes as the signature.
    const BUF_SIZE: usize = 32 * 1024;
    let mut input = [0u8; BUF_SIZE];
    let mut buf = Vec::with_capacity(BUF_SIZE + 64);
    loop {
        let n = reader.read(&mut input)?;
        buf.extend_from_slice(&input[..n]);

        // Process the data if we have at least a signature's worth.
        if buf.len() > 64 {
            // Pop the first N-64 bytes off the buffer.
            let n = buf.len();
            let mut block: Vec<u8> = buf.drain(..n - 64).collect();

            // Verify the ciphertext, decrypt it, and write the plaintext.
            verifier.write_all(&block)?;
            mres.recv_enc(&mut block, true);
            writer.write_all(&block)?;
            written += block.len() as u64;
        }

        // If our last read returned zero bytes, we're at the end of the ciphertext.
        if n == 0 {
            break;
        }
    }

    // Use the last 64 bytes as a signature.
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&buf);

    // Decrypt and verify the signature.
    mres.recv_enc(&mut sig, false);
    if !verifier.verify(&q_e, &sig) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ciphertext",
        ));
    }

    Ok(written)
}

const DEK_LEN: usize = 32;
const HEADER_LEN: usize = DEK_LEN + 8;
const ENC_HEADER_LEN: usize = HEADER_LEN + 32 + MAC_LEN;

fn encode_header(dek: &[u8; DEK_LEN], r_len: usize, padding: u64) -> Vec<u8> {
    let msg_offset = ((r_len as u64) * ENC_HEADER_LEN as u64) + padding;
    vec![dek.to_vec(), (&msg_offset.to_le_bytes()).to_vec()].concat()
}

struct RngReader<R: rand::Rng>(R);

impl<R: rand::Rng> io::Read for RngReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.fill(buf);

        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    use crate::mres::{decrypt, encrypt};

    #[test]
    pub fn round_trip() {
        let mut rng = rand::thread_rng();

        let d_s = Scalar::random(&mut rng);
        let q_s = RISTRETTO_BASEPOINT_POINT * d_s;

        let d_r = Scalar::random(&mut rng);
        let q_r = RISTRETTO_BASEPOINT_POINT * d_r;

        let message = b"this is a thingy";
        let mut src = io::Cursor::new(message);
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len =
            encrypt(&mut src, &mut dst, &d_s, &q_s, vec![q_s, q_r], 123).expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut src = io::Cursor::new(dst.into_inner());
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, &d_r, &q_r, &q_s).expect("decrypt");
        assert_eq!(dst.position(), ptx_len);
        assert_eq!(message.to_vec(), dst.into_inner());
    }

    #[test]
    pub fn multi_block_message() {
        let mut rng = rand::thread_rng();

        let d_s = Scalar::random(&mut rng);
        let q_s = RISTRETTO_BASEPOINT_POINT * d_s;

        let d_r = Scalar::random(&mut rng);
        let q_r = RISTRETTO_BASEPOINT_POINT * d_r;

        let message = [69u8; 65 * 1024];
        let mut src = io::Cursor::new(message);
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len =
            encrypt(&mut src, &mut dst, &d_s, &q_s, vec![q_s, q_r], 123).expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut src = io::Cursor::new(dst.into_inner());
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, &d_r, &q_r, &q_s).expect("decrypt");
        assert_eq!(dst.position(), ptx_len);
        assert_eq!(message.to_vec(), dst.into_inner());
    }

    #[test]
    pub fn split_sig() {
        let mut rng = rand::thread_rng();

        let d_s = Scalar::random(&mut rng);
        let q_s = RISTRETTO_BASEPOINT_POINT * d_s;

        let d_r = Scalar::random(&mut rng);
        let q_r = RISTRETTO_BASEPOINT_POINT * d_r;

        let message = [69u8; 32 * 1024 - 37];
        let mut src = io::Cursor::new(message);
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len = encrypt(&mut src, &mut dst, &d_s, &q_s, vec![q_s, q_r], 0).expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut src = io::Cursor::new(dst.into_inner());
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = decrypt(&mut src, &mut dst, &d_r, &q_r, &q_s).expect("decrypt");
        assert_eq!(dst.position(), ptx_len);
        assert_eq!(message.to_vec(), dst.into_inner());
    }
}
