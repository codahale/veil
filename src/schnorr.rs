//! Schnorr-variant digital signatures.

use std::convert::TryInto;
use std::io;
use std::io::{Result, Write};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use secrecy::ExposeSecret;

use crate::constants::{POINT_LEN, SCALAR_LEN};
use crate::strobe::{Protocol, RecvClrWriter, SendClrWriter};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = POINT_LEN + SCALAR_LEN;

/// A writer which accumulates message contents for signing before passing them along to an inner
/// writer.
pub struct Signer<W: Write> {
    writer: SendClrWriter<W>,
}

impl<W> Signer<W>
where
    W: Write,
{
    /// Create a new signer which passes writes through to the given writer.
    pub fn new(writer: W) -> Signer<W> {
        let schnorr = Protocol::new("veil.schnorr");
        Signer { writer: schnorr.send_clr_writer("message", writer) }
    }

    /// Create a signature of the previously-written message contents using the given key pair.
    #[allow(clippy::many_single_char_names)]
    pub fn sign(self, d: &Scalar, q: &RistrettoPoint) -> ([u8; SIGNATURE_LEN], W) {
        // Unwrap the SEND_CLR writer.
        let (mut schnorr, writer, _) = self.writer.into_inner();

        // Allocate an output buffer.
        let mut sig = Vec::with_capacity(SIGNATURE_LEN);

        // Send the signer's public key as cleartext.
        schnorr.send("signer", q.compress().as_bytes());

        // Derive a commitment scalar from the protocol's current state, the signer's private key,
        // and a random nonce.
        let k = schnorr.hedge(d.as_bytes(), |clone| clone.prf_scalar("commitment-scalar"));

        // Calculate and encrypt the commitment point.
        let i = &G * k.expose_secret();
        sig.extend(schnorr.encrypt("commitment-point", i.compress().as_bytes()));

        // Derive a challenge scalar from PRF output.
        let r = schnorr.prf_scalar("challenge-scalar");

        // Calculate and encrypt the proof scalar.
        let s = d * r + k.expose_secret();
        sig.extend(schnorr.encrypt("proof-scalar", s.as_bytes()));

        // Return the encrypted commitment point and proof scalar, plus the underlying writer.
        (sig.try_into().expect("invalid sig len"), writer)
    }
}

impl<W> Write for Signer<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

/// A writer which accumulates message contents for verifying.
pub struct Verifier {
    writer: RecvClrWriter<io::Sink>,
}

impl Verifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Verifier {
        let schnorr = Protocol::new("veil.schnorr");
        Verifier { writer: schnorr.recv_clr_writer("message", io::sink()) }
    }

    /// Verify the previously-written message contents using the given public key and signature.
    #[must_use]
    pub fn verify(self, q: &RistrettoPoint, sig: &[u8; SIGNATURE_LEN]) -> bool {
        let (mut schnorr, _, _) = self.writer.into_inner();

        // Receive the signer's public key as cleartext.
        schnorr.receive("signer", q.compress().as_bytes());

        // Split the signature into parts.
        let (i, s) = sig.split_at(POINT_LEN);

        // Decrypt and decode the commitment point.
        let i = schnorr.decrypt("commitment-point", i);
        let i = CompressedRistretto::from_slice(i.expose_secret()).decompress();

        // Re-derive the challenge scalar.
        let r = schnorr.prf_scalar("challenge-scalar");

        // Decrypt and decode the proof scalar.
        let s = schnorr.decrypt("proof-scalar", s);
        let s = s.expose_secret().as_slice().try_into().expect("invalid scalar len");
        let s = Scalar::from_canonical_bytes(s);

        // Early exit if either commitment point or proof scalar are malformed.
        let (i, s) = match (i, s) {
            (Some(i), Some(s)) => (i, s),
            _ => return false,
        };

        // Return true iff I == rG - sQ. Use the variable-time implementation here because the
        // verifier has no secret data.
        i == RistrettoPoint::vartime_double_scalar_mul_basepoint(&r, &-q, &s)
    }
}

impl Write for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;

    use super::*;

    #[test]
    fn sign_and_verify() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        assert_eq!(22, signer.write(b"this is a message that")?);
        assert_eq!(30, signer.write(b" is written in multiple pieces")?);
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        assert_eq!(22, verifier.write(b"this is a message that")?);
        assert_eq!(23, verifier.write(b" is written in multiple")?);
        assert_eq!(7, verifier.write(b" pieces")?);
        verifier.flush()?;

        assert!(verifier.verify(&q, &sig));

        Ok(())
    }

    #[test]
    fn bad_message() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        assert_eq!(22, signer.write(b"this is a message that")?);
        assert_eq!(30, signer.write(b" is written in multiple pieces")?);
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        assert_eq!(26, verifier.write(b"this NOT is a message that")?);
        assert_eq!(23, verifier.write(b" is written in multiple")?);
        assert_eq!(7, verifier.write(b" pieces")?);
        verifier.flush()?;

        assert!(!verifier.verify(&q, &sig));

        Ok(())
    }

    #[test]
    fn bad_key() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        assert_eq!(22, signer.write(b"this is a message that")?);
        assert_eq!(30, signer.write(b" is written in multiple pieces")?);
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        assert_eq!(22, verifier.write(b"this is a message that")?);
        assert_eq!(23, verifier.write(b" is written in multiple")?);
        assert_eq!(7, verifier.write(b" pieces")?);
        verifier.flush()?;

        assert!(!verifier.verify(&G.basepoint(), &sig));

        Ok(())
    }

    #[test]
    fn bad_sig() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        assert_eq!(22, signer.write(b"this is a message that")?);
        assert_eq!(30, signer.write(b" is written in multiple pieces")?);
        signer.flush()?;

        let (mut sig, _) = signer.sign(&d, &q);
        sig[22] ^= 1;

        let mut verifier = Verifier::new();
        assert_eq!(22, verifier.write(b"this is a message that")?);
        assert_eq!(23, verifier.write(b" is written in multiple")?);
        assert_eq!(7, verifier.write(b" pieces")?);
        verifier.flush()?;

        assert!(!verifier.verify(&q, &sig));

        Ok(())
    }
}
