//! Schnorr-variant digital signatures.

use std::convert::TryInto;
use std::fmt::Formatter;
use std::io::{Read, Result};
use std::str::FromStr;
use std::{fmt, io, result};

use rand::{CryptoRng, Rng};

use crate::duplex::Duplex;
use crate::ristretto::{CanonicallyEncoded, G, POINT_LEN, SCALAR_LEN};
use crate::ristretto::{Point, Scalar};
use crate::{AsciiEncoded, ParseSignatureError, VerifyError};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = POINT_LEN + SCALAR_LEN;

/// A Schnorr signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LEN]);

impl AsciiEncoded for Signature {
    type Err = ParseSignatureError;

    fn from_bytes(b: &[u8]) -> result::Result<Self, <Self as AsciiEncoded>::Err> {
        Ok(Signature(b.try_into().map_err(|_| ParseSignatureError::InvalidLength)?))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl FromStr for Signature {
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        Signature::from_ascii(s)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii())
    }
}

/// Create a Schnorr signature of the given message using the given key pair.
pub fn sign(
    rng: impl Rng + CryptoRng,
    (d, q): (&Scalar, &Point),
    mut message: impl Read,
) -> Result<Signature> {
    // Initialize a duplex.
    let mut schnorr = Duplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb(&q.to_canonical_encoding());

    // Absorb the message in blocks.
    let mut schnorr = schnorr.absorb_stream(io::sink());
    io::copy(&mut message, &mut schnorr)?;

    // Unwrap the duplex and writer.
    let (mut schnorr, _, _) = schnorr.into_inner()?;

    // Derive a commitment scalar from the duplex's current state, the signer's private key,
    // and a random nonce.
    let k = schnorr.hedge(rng, d, Duplex::squeeze_scalar);

    // Calculate the encrypted commitment point and proof scalar.
    let (i, s) = sign_duplex(&mut schnorr, d, k);

    // Allocate an output buffer.
    let mut out = Vec::with_capacity(SIGNATURE_LEN);

    // Encrypt the proof scalar.
    out.extend(i);
    out.extend(schnorr.encrypt(&s.to_canonical_encoding()));

    // Return the encrypted commitment point and proof scalar.
    Ok(Signature(out.try_into().expect("invalid sig len")))
}

/// Verify a Schnorr signature of the given message using the given public key.
pub fn verify(
    q: &Point,
    mut message: impl Read,
    sig: &Signature,
) -> result::Result<(), VerifyError> {
    // Initialize a duplex.
    let mut schnorr = Duplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb(&q.to_canonical_encoding());

    // Absorb the message in blocks.
    let mut schnorr = schnorr.absorb_stream(io::sink());
    io::copy(&mut message, &mut schnorr)?;

    // Unwrap the duplex and writer.
    let (mut schnorr, _, _) = schnorr.into_inner()?;

    // Verify the signature.
    verify_duplex(&mut schnorr, q, &sig.0)
}

/// Create a Schnorr signature of the given duplex's state using the given private key. Returns
/// the encrypted commitment point and the proof scalar.
pub fn sign_duplex(duplex: &mut Duplex, d: &Scalar, k: Scalar) -> (Vec<u8>, Scalar) {
    // Calculate and encrypt the commitment point.
    let i = &k * &G;
    let i = duplex.encrypt(&i.to_canonical_encoding());

    // Squeeze a challenge scalar.
    let r = duplex.squeeze_scalar();

    // Calculate the proof scalar.
    let s = d * r + k;

    // Return the encrypted commitment point and the proof scalar.
    (i, s)
}

/// Verify a Schnorr signature of the given duplex's state using the given public key.
pub fn verify_duplex(
    duplex: &mut Duplex,
    q: &Point,
    sig: &[u8],
) -> result::Result<(), VerifyError> {
    // Split the signature into parts.
    let (i, s) = sig.split_at(POINT_LEN);

    // Decrypt and decode the commitment point. Return an error if it's the identity point.
    let i = duplex.decrypt(i);
    let i = Point::from_canonical_encoding(&i);
    let i = i.ok_or(VerifyError::InvalidSignature)?;

    // Re-derive the challenge scalar.
    let r = duplex.squeeze_scalar();

    // Decrypt and decode the proof scalar. Return an error if it's zero.
    let s = duplex.decrypt(s);
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn sign_and_verify() -> Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &d * &G;
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message))?;

        assert!(
            verify(&q, Cursor::new(message), &sig).is_ok(),
            "should have verified a valid signature"
        );

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
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message))?;

        let message = b"this is NOT a message";
        assert_failed!(verify(&q, Cursor::new(message), &sig))
    }

    #[test]
    fn bad_key() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &d * &G;
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message))?;

        let q = Point::random(&mut rng);

        assert_failed!(verify(&q, Cursor::new(message), &sig))
    }

    #[test]
    fn bad_sig() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &d * &G;
        let message = b"this is a message";
        let mut sig = sign(&mut rng, (&d, &q), Cursor::new(message))?;

        sig.0[22] ^= 1;

        assert_failed!(verify(&q, Cursor::new(message), &sig))
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
            Err(ParseSignatureError::BadEncoding(bs58::decode::Error::InvalidCharacter {
                character: ' ',
                index: 4
            })),
            "woot woot".parse::<Signature>(),
            "parsed invalid signature"
        );
    }
}
