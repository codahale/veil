use std::convert::TryInto;
use std::io::{Result, Write};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::util::{StrobeExt, G};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = SCALAR_LEN * 2;

/// A writer which accumulates message contents for signing before passing them along to an inner
/// writer.
pub struct Signer<W: Write> {
    schnorr: Strobe,
    writer: W,
}

impl<W> Signer<W>
where
    W: Write,
{
    /// Create a new signer which passes writes through to the given writer.
    pub fn new(writer: W) -> Signer<W> {
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B128);
        schnorr.send_clr(&[], false);
        Signer { schnorr, writer }
    }

    /// Create a signature of the previously-written message contents using the given key pair.
    #[allow(clippy::many_single_char_names)]
    pub fn sign(&mut self, d: &Scalar, q: &RistrettoPoint) -> [u8; SIGNATURE_LEN] {
        // Add the signer's public key as associated data.
        self.schnorr.ad_point(q);

        // Derive an ephemeral scalar from the protocol's current state, the signer's private key,
        // and a random nonce.
        let r = self.schnorr.hedge(d.as_bytes(), StrobeExt::prf_scalar);

        // Add the ephemeral public key as associated data.
        let r_g = G * &r;
        self.schnorr.ad_point(&r_g);

        // Derive a challenge scalar from PRF output.
        let c = self.schnorr.prf_scalar();

        // Calculate the signature scalar.
        let s = d * c + r;

        // Return the challenge and signature scalars.
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..SCALAR_LEN].copy_from_slice(c.as_bytes());
        sig[SCALAR_LEN..].copy_from_slice(s.as_bytes());
        sig
    }

    /// Unwrap the signer, returning the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W> Write for Signer<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.schnorr.send_clr(buf, true);
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
    pub fn new() -> Verifier {
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B128);
        schnorr.recv_clr(&[], false);
        Verifier { schnorr }
    }

    /// Verify the previously-written message contents using the given public key and signature.
    pub fn verify(mut self, q: &RistrettoPoint, sig: &[u8; SIGNATURE_LEN]) -> bool {
        // Add the signer's public key as associated data.
        self.schnorr.ad_point(q);

        // Split the signature into parts.
        let c = sig[..SCALAR_LEN].try_into().expect("invalid scalar len");
        let s = sig[SCALAR_LEN..].try_into().expect("invalid scalar len");

        // Decode the challenge and signature scalars.
        let c = if let Some(c) = Scalar::from_canonical_bytes(c) {
            c
        } else {
            return false;
        };
        let s = if let Some(s) = Scalar::from_canonical_bytes(s) {
            s
        } else {
            return false;
        };

        // Re-calculate the ephemeral public key and add it as associated data.
        let r_g = (G * &s) + (-c * q);
        self.schnorr.ad_point(&r_g);

        // Re-derive the challenge scalar.
        let c_p = self.schnorr.prf_scalar();

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

const SCALAR_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;

    use super::*;

    #[test]
    pub fn sign_and_verify() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let sig = signer.sign(&d, &q);

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
        let q = G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let sig = signer.sign(&d, &q);

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
        let q = G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let sig = signer.sign(&d, &q);

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
        let q = G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let mut sig = signer.sign(&d, &q);
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
