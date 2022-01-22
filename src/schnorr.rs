use std::convert::TryInto;
use std::io::{Result, Write};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::constants::{POINT_LEN, SCALAR_LEN};
use crate::strobe::{SendClrWriter, StrobeExt};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = SCALAR_LEN * 2;

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
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B128);
        schnorr.meta_ad(b"message", false);
        Signer { writer: schnorr.send_clr_writer(writer) }
    }

    /// Create a signature of the previously-written message contents using the given key pair.
    #[allow(clippy::many_single_char_names)]
    pub fn sign(self, d: &Scalar, q: &RistrettoPoint) -> ([u8; SIGNATURE_LEN], W) {
        let (mut schnorr, writer) = self.writer.into_inner();

        // Send the signer's public key as cleartext.
        schnorr.metadata("signer", &(POINT_LEN as u32));
        schnorr.send_clr(q.compress().as_bytes(), false);

        // Derive a commitment scalar from the protocol's current state, the signer's private key,
        // and a random nonce.
        let r = schnorr.hedge(d.as_bytes(), |clone| clone.prf_scalar("commitment-scalar"));

        // Add the commitment point as associated data.
        let r_g = &G * &r;
        schnorr.metadata("commitment-point", &(POINT_LEN as u32));
        schnorr.ad(r_g.compress().as_bytes(), false);

        // Derive a challenge scalar from PRF output.
        let c = schnorr.prf_scalar("challenge-scalar");

        // Calculate the signature scalar.
        let s = d * c + r;

        // Return the challenge and signature scalars, plus the underlying writer.
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..SCALAR_LEN].copy_from_slice(c.as_bytes());
        sig[SCALAR_LEN..].copy_from_slice(s.as_bytes());
        (sig, writer)
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
    schnorr: Strobe,
}

impl Verifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Verifier {
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B128);
        schnorr.meta_ad(b"message", false);
        schnorr.recv_clr(&[], false);
        Verifier { schnorr }
    }

    /// Verify the previously-written message contents using the given public key and signature.
    #[must_use]
    pub fn verify(self, q: &RistrettoPoint, sig: &[u8; SIGNATURE_LEN]) -> bool {
        let mut schnorr = self.schnorr;

        // Add the signer's public key as associated data.
        schnorr.metadata("signer", &(POINT_LEN as u32));
        schnorr.recv_clr(q.compress().as_bytes(), false);

        // Split the signature into parts.
        let c = sig[..SCALAR_LEN].try_into().expect("invalid scalar len");
        let s = sig[SCALAR_LEN..].try_into().expect("invalid scalar len");

        // Decode the challenge and signature scalars.
        let (c, s) = match (Scalar::from_canonical_bytes(c), Scalar::from_canonical_bytes(s)) {
            (Some(c), Some(s)) => (c, s),
            _ => return false,
        };

        // Re-calculate the commitment point and add it as associated data.
        let r_g = (&G * &s) + (-c * q);
        schnorr.metadata("commitment-point", &(POINT_LEN as u32));
        schnorr.ad(r_g.compress().as_bytes(), false);

        // Re-derive the challenge scalar.
        let c_p = schnorr.prf_scalar("challenge-scalar");

        // Return true iff c' == c.
        c_p == c
    }
}

impl Write for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.schnorr.recv_clr(buf, true);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;

    use super::*;

    #[test]
    pub fn sign_and_verify() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(true, verifier.verify(&q, &sig));

        Ok(())
    }

    #[test]
    pub fn bad_message() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is NOT a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(false, verifier.verify(&q, &sig));

        Ok(())
    }

    #[test]
    pub fn bad_key() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(false, verifier.verify(&G.basepoint(), &sig));

        Ok(())
    }

    #[test]
    pub fn bad_sig() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let (mut sig, _) = signer.sign(&d, &q);
        sig[22] ^= 1;

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(false, verifier.verify(&q, &sig));

        Ok(())
    }
}
