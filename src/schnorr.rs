use std::convert::TryInto;
use std::io;
use std::io::{Result, Write};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use secrecy::ExposeSecret;

use crate::constants::SCALAR_LEN;
use crate::strobe::{Protocol, RecvClrWriter, SendClrWriter};

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
        let schnorr = Protocol::new("veil.schnorr");
        Signer { writer: schnorr.send_clr_writer("message", writer) }
    }

    /// Create a signature of the previously-written message contents using the given key pair.
    #[allow(clippy::many_single_char_names)]
    pub fn sign(self, d: &Scalar, q: &RistrettoPoint) -> ([u8; SIGNATURE_LEN], W) {
        let (mut schnorr, writer, _) = self.writer.into_inner();

        // Send the signer's public key as cleartext.
        schnorr.send("signer", q.compress().as_bytes());

        // Derive a commitment scalar from the protocol's current state, the signer's private key,
        // and a random nonce.
        let k = schnorr.hedge(d.as_bytes(), |clone| clone.prf_scalar("commitment-scalar"));

        // Add the commitment point as associated data.
        let i = &G * k.expose_secret();
        schnorr.ad("commitment-point", i.compress().as_bytes());

        // Derive a challenge scalar from PRF output.
        let r = schnorr.prf_scalar("challenge-scalar");

        // Calculate the proof scalar.
        let s = d * r + k.expose_secret();

        // Return the challenge and proof scalars, plus the underlying writer.
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..SCALAR_LEN].copy_from_slice(r.as_bytes());
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
        let r = sig[..SCALAR_LEN].try_into().expect("invalid scalar len");
        let s = sig[SCALAR_LEN..].try_into().expect("invalid scalar len");

        // Decode the challenge and proof scalars.
        let (r, s) = match (Scalar::from_canonical_bytes(r), Scalar::from_canonical_bytes(s)) {
            (Some(r), Some(s)) => (r, s),
            _ => return false,
        };

        // Re-calculate the commitment point and add it as associated data.
        let i = (&G * &s) + (q * -r);
        schnorr.ad("commitment-point", i.compress().as_bytes());

        // Re-derive the challenge scalar.
        let r_p = schnorr.prf_scalar("challenge-scalar");

        // Return true iff r' == r.
        r_p == r
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
    pub fn sign_and_verify() -> Result<()> {
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
    pub fn bad_message() -> Result<()> {
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
    pub fn bad_key() -> Result<()> {
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
    pub fn bad_sig() -> Result<()> {
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
