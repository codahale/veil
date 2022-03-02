//! Schnorr-variant digital signatures.

use std::convert::TryInto;
use std::fmt::Formatter;
use std::io::{Result, Write};
use std::str::FromStr;
use std::{fmt, io, result};

use rand::{CryptoRng, Rng};

use crate::duplex::{AbsorbWriter, Duplex};
use crate::ristretto::{CanonicallyEncoded, G, POINT_LEN, SCALAR_LEN};
use crate::ristretto::{Point, Scalar};
use crate::{ParseSignatureError, VerifyError};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = POINT_LEN + SCALAR_LEN;

/// A Schnorr signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LEN]);

impl FromStr for Signature {
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        bs58::decode(s)
            .into_vec()
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(Signature)
            .ok_or(ParseSignatureError)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

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
    pub fn sign(self, rng: impl Rng + CryptoRng, d: &Scalar, q: &Point) -> Result<(Signature, W)> {
        // Unwrap the duplex and writer.
        let (mut schnorr, writer, _) = self.writer.into_inner()?;

        // Allocate an output buffer.
        let mut out = Vec::with_capacity(SIGNATURE_LEN);

        // Absorb the signer's public key.
        schnorr.absorb(&q.to_canonical_encoding());

        // Derive a commitment scalar from the protocol's current state, the signer's private key,
        // and a random nonce.
        let k = schnorr.hedge(rng, d, Duplex::squeeze_scalar);

        // Calculate and encrypt the commitment point.
        let i = &k * &G;
        out.extend(schnorr.encrypt(&i.to_canonical_encoding()));

        // Squeeze a challenge scalar.
        let r = schnorr.squeeze_scalar();

        // Calculate and encrypt the proof scalar.
        let s = d * r + k;
        out.extend(schnorr.encrypt(&s.to_canonical_encoding()));

        // Return the encrypted commitment point and proof scalar, plus the underlying writer.
        Ok((Signature(out.try_into().expect("invalid sig len")), writer))
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
    pub fn verify(self, q: &Point, sig: &Signature) -> result::Result<(), VerifyError> {
        // Unwrap duplex.
        let (mut schnorr, _, _) = self.writer.into_inner()?;

        // Absorb the signer's public key.
        schnorr.absorb(&q.to_canonical_encoding());

        // Split the signature into parts.
        let (i, s) = sig.0.split_at(POINT_LEN);

        // Decrypt and decode the commitment point. Return an error if it's the identity point.
        let i = schnorr.decrypt(i);
        let i = Point::from_canonical_encoding(&i);
        let i = i.ok_or(VerifyError::InvalidSignature)?;

        // Re-derive the challenge scalar.
        let r = schnorr.squeeze_scalar();

        // Decrypt and decode the proof scalar. Return an error if it's zero.
        let s = schnorr.decrypt(s);
        let s = Scalar::from_canonical_encoding(&s);
        let s = s.ok_or(VerifyError::InvalidSignature)?;

        // Return true iff I and s are well-formed and I == [s]G - [r]Q. Use the variable-time
        // implementation here because the verifier has no secret data.
        //    I == [r](-Q) + [s]G == [s]G - [r]Q
        if i == Point::vartime_double_scalar_mul_basepoint(&r, &-q, &s /*G*/) {
            Ok(())
        } else {
            Err(VerifyError::InvalidSignature)
        }
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
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::io;
    use std::io::Write;

    use super::*;

    #[test]
    fn sign_and_verify() -> Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &d * &G;

        let mut signer = Signer::new(io::sink());
        assert_eq!(22, signer.write(b"this is a message that")?, "invalid write count");
        assert_eq!(30, signer.write(b" is written in multiple pieces")?, "invalid write count");
        signer.flush()?;

        let (sig, _) = signer.sign(&mut rng, &d, &q).expect("error signing");

        let mut verifier = Verifier::new();
        assert_eq!(22, verifier.write(b"this is a message that")?, "invalid write count");
        assert_eq!(23, verifier.write(b" is written in multiple")?, "invalid write count");
        assert_eq!(7, verifier.write(b" pieces")?, "invalid write count");
        verifier.flush()?;

        assert!(verifier.verify(&q, &sig).is_ok(), "should have verified a valid signature");

        Ok(())
    }

    macro_rules! assert_failed {
        ($action: expr) => {
            match $action {
                Ok(_) => panic!("verified but shouldn't have"),
                Err(VerifyError::InvalidSignature) => Ok(()),
                Err(e) => Err(e),
            }
        };
    }

    #[test]
    fn bad_message() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &d * &G;

        let mut signer = Signer::new(io::sink());
        signer.write_all(b"this is a message that")?;
        signer.write_all(b" is written in multiple pieces")?;
        signer.flush()?;

        let (sig, _) = signer.sign(&mut rng, &d, &q).expect("error signing");

        let mut verifier = Verifier::new();
        verifier.write_all(b"this NOT is a message that")?;
        verifier.write_all(b" is written in multiple")?;
        verifier.write_all(b" pieces")?;
        verifier.flush()?;

        assert_failed!(verifier.verify(&q, &sig))
    }

    #[test]
    fn bad_key() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &d * &G;

        let mut signer = Signer::new(io::sink());
        signer.write_all(b"this is a message that")?;
        signer.write_all(b" is written in multiple pieces")?;
        signer.flush()?;

        let (sig, _) = signer.sign(&mut rng, &d, &q).expect("error signing");

        let mut verifier = Verifier::new();
        verifier.write_all(b"this is a message that")?;
        verifier.write_all(b" is written in multiple")?;
        verifier.write_all(b" pieces")?;
        verifier.flush()?;

        let q = Point::random(&mut rng);
        assert_failed!(verifier.verify(&q, &sig))
    }

    #[test]
    fn bad_sig() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &d * &G;

        let mut signer = Signer::new(io::sink());
        signer.write_all(b"this is a message that")?;
        signer.write_all(b" is written in multiple pieces")?;
        signer.flush()?;

        let (mut sig, _) = signer.sign(&mut rng, &d, &q).expect("error signing");
        sig.0[22] ^= 1;

        let mut verifier = Verifier::new();
        verifier.write_all(b"this is a message that")?;
        verifier.write_all(b" is written in multiple")?;
        verifier.write_all(b" pieces")?;
        verifier.flush()?;

        assert_failed!(verifier.verify(&q, &sig))
    }

    #[test]
    fn signature_encoding() {
        let sig = Signature([69u8; SIGNATURE_LEN]);
        assert_eq!(
            "2PKwbVQ1YMFEexCmUDyxy8cuwb69VWcvoeodZCLegqof62ro8siurvh9QCnFzdsdTixDC94tCMzH7dMuqL5Gi2CC",
            sig.to_string(),
            "invalid encoded signature"
        );

        let decoded = "2PKwbVQ1YMFEexCmUDyxy8cuwb69VWcvoeodZCLegqof62ro8siurvh9QCnFzdsdTixDC94tCMzH7dMuqL5Gi2CC".parse::<Signature>();
        assert_eq!(Ok(sig), decoded, "error parsing signature");

        assert_eq!(
            Err(ParseSignatureError),
            "woot woot".parse::<Signature>(),
            "parsed invalid signature"
        );
    }
}
