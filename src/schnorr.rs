//! Schnorr-variant digital signatures.

use std::convert::TryInto;
use std::io;
use std::io::{Result, Write};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::constants::{POINT_LEN, SCALAR_LEN};
use crate::duplex::{AbsorbWriter, Duplex};
use crate::ristretto::CanonicallyEncoded;

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = POINT_LEN + SCALAR_LEN;

/// A writer which accumulates message contents for signing before passing them along to an inner
/// writer.
pub struct Signer<W: Write> {
    writer: AbsorbWriter<W>,
}

impl<W> Signer<W>
where
    W: Write,
{
    /// Create a new signer which passes writes through to the given writer.
    pub fn new(writer: W) -> Signer<W> {
        // Initialize a duplex.
        let schnorr = Duplex::new("veil.schnorr");

        Signer { writer: schnorr.absorb_stream(writer) }
    }

    /// Create a signature of the previously-written message contents using the given key pair.
    #[allow(clippy::many_single_char_names)]
    pub fn sign(self, d: &Scalar, q: &RistrettoPoint) -> Result<([u8; SIGNATURE_LEN], W)> {
        // Unwrap the duplex and writer.
        let (mut schnorr, writer, _) = self.writer.into_inner()?;

        // Allocate an output buffer.
        let mut sig = Vec::with_capacity(SIGNATURE_LEN);

        // Absorb the signer's public key.
        schnorr.absorb(&q.to_canonical_encoding());

        // Derive a commitment scalar from the protocol's current state, the signer's private key,
        // and a random nonce.
        let k = schnorr.hedge(d, Duplex::squeeze_scalar);

        // Calculate and encrypt the commitment point.
        let i = &G * &k;
        sig.extend(schnorr.encrypt(&i.to_canonical_encoding()));

        // Squeeze a challenge scalar.
        let r = schnorr.squeeze_scalar();

        // Calculate and encrypt the proof scalar.
        let s = d * r + k;
        sig.extend(schnorr.encrypt(&s.to_canonical_encoding()));

        // Return the encrypted commitment point and proof scalar, plus the underlying writer.
        Ok((sig.try_into().expect("invalid sig len"), writer))
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
    writer: AbsorbWriter<io::Sink>,
}

impl Verifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Verifier {
        // Initialize a duplex.
        let schnorr = Duplex::new("veil.schnorr");

        Verifier { writer: schnorr.absorb_stream(io::sink()) }
    }

    /// Verify the previously-written message contents using the given public key and signature.
    pub fn verify(self, q: &RistrettoPoint, sig: &[u8; SIGNATURE_LEN]) -> Result<bool> {
        // Unwrap duplex.
        let (mut schnorr, _, _) = self.writer.into_inner()?;

        // Absorb the signer's public key.
        schnorr.absorb(&q.to_canonical_encoding());

        // Split the signature into parts.
        let (i, s) = sig.split_at(POINT_LEN);

        // Decrypt and decode the commitment point.
        let i = schnorr.decrypt(i).trust();
        let i = RistrettoPoint::from_canonical_encoding(&i);

        // Re-derive the challenge scalar.
        let r = schnorr.squeeze_scalar();

        // Decrypt and decode the proof scalar.
        let s = schnorr.decrypt(s).trust();
        let s = Scalar::from_canonical_encoding(&s);

        // Early exit if either commitment point or proof scalar are malformed.
        let (i, s) = match (i, s) {
            (Some(i), Some(s)) => (i, s),
            _ => return Ok(false),
        };

        // Return true iff I == sG - rQ. Use the variable-time implementation here because the
        // verifier has no secret data.
        Ok(i == RistrettoPoint::vartime_double_scalar_mul_basepoint(&r, &-q, &s))
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
        assert_eq!(22, signer.write(b"this is a message that")?, "invalid write count");
        assert_eq!(30, signer.write(b" is written in multiple pieces")?, "invalid write count");
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q).expect("error signing");

        let mut verifier = Verifier::new();
        assert_eq!(22, verifier.write(b"this is a message that")?, "invalid write count");
        assert_eq!(23, verifier.write(b" is written in multiple")?, "invalid write count");
        assert_eq!(7, verifier.write(b" pieces")?, "invalid write count");
        verifier.flush()?;

        assert!(
            verifier.verify(&q, &sig).expect("error verifying"),
            "should have verified a valid signature"
        );

        Ok(())
    }

    #[test]
    fn bad_message() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write_all(b"this is a message that")?;
        signer.write_all(b" is written in multiple pieces")?;
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q).expect("error signing");

        let mut verifier = Verifier::new();
        verifier.write_all(b"this NOT is a message that")?;
        verifier.write_all(b" is written in multiple")?;
        verifier.write_all(b" pieces")?;
        verifier.flush()?;

        assert!(
            !verifier.verify(&q, &sig).expect("error verifying"),
            "verified an invalid signature"
        );

        Ok(())
    }

    #[test]
    fn bad_key() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write_all(b"this is a message that")?;
        signer.write_all(b" is written in multiple pieces")?;
        signer.flush()?;

        let (sig, _) = signer.sign(&d, &q).expect("error signing");

        let mut verifier = Verifier::new();
        verifier.write_all(b"this is a message that")?;
        verifier.write_all(b" is written in multiple")?;
        verifier.write_all(b" pieces")?;
        verifier.flush()?;

        assert!(
            !verifier.verify(&G.basepoint(), &sig).expect("error verifying"),
            "verified an invalid signature"
        );

        Ok(())
    }

    #[test]
    fn bad_sig() -> Result<()> {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = &G * &d;

        let mut signer = Signer::new(io::sink());
        signer.write_all(b"this is a message that")?;
        signer.write_all(b" is written in multiple pieces")?;
        signer.flush()?;

        let (mut sig, _) = signer.sign(&d, &q).expect("error signing");
        sig[22] ^= 1;

        let mut verifier = Verifier::new();
        verifier.write_all(b"this is a message that")?;
        verifier.write_all(b" is written in multiple")?;
        verifier.write_all(b" pieces")?;
        verifier.flush()?;

        assert!(
            !verifier.verify(&q, &sig).expect("error verifying"),
            "verified an invalid signature"
        );

        Ok(())
    }
}
