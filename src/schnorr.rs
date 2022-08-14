//! Schnorr-variant digital signatures.

use std::convert::TryInto;
use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};

use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex};
use crate::ecc::{CanonicallyEncoded, Point, Scalar, POINT_LEN, SCALAR_LEN};
use crate::{AsciiEncoded, ParseSignatureError, VerifyError};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = POINT_LEN + SCALAR_LEN;

/// A Schnorr signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LEN]);

impl AsciiEncoded<SIGNATURE_LEN> for Signature {
    type Err = ParseSignatureError;

    fn from_bytes(b: &[u8]) -> Result<Self, <Self as AsciiEncoded<SIGNATURE_LEN>>::Err> {
        Ok(Signature(b.try_into().map_err(|_| ParseSignatureError::InvalidLength)?))
    }

    fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl FromStr for Signature {
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Signature::from_ascii(s)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii())
    }
}

/// Create a Schnorr signature of the given message using the given key pair.
pub fn sign(
    rng: impl Rng + CryptoRng,
    (d, q): (&Scalar, &Point),
    message: impl Read,
) -> io::Result<Signature> {
    // Initialize an unkeyed duplex.
    let mut schnorr = UnkeyedDuplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb_point(q);

    // Absorb the message.
    schnorr.absorb_reader(message)?;

    // Convert the unkeyed duplex to a keyed duplex.
    let mut schnorr = schnorr.into_keyed();

    // Calculate and return the encrypted commitment point and proof scalar.
    Ok(sign_duplex(&mut schnorr, rng, d))
}

/// Verify a Schnorr signature of the given message using the given public key.
pub fn verify(q: &Point, message: impl Read, sig: &Signature) -> Result<(), VerifyError> {
    // Initialize an unkeyed duplex.
    let mut schnorr = UnkeyedDuplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb_point(q);

    // Absorb the message.
    schnorr.absorb_reader(message)?;

    // Convert the unkeyed duplex to a keyed duplex.
    let mut schnorr = schnorr.into_keyed();

    // Verify the signature.
    verify_duplex(&mut schnorr, q, sig).ok_or(VerifyError::InvalidSignature)
}

/// Create a Schnorr signature of the given duplex's state using the given private key.
/// Returns the full signature.
#[must_use]
pub fn sign_duplex(
    duplex: &mut KeyedDuplex,
    mut rng: impl CryptoRng + Rng,
    d: &Scalar,
) -> Signature {
    // Allocate an output buffer.
    let mut sig = [0u8; SIGNATURE_LEN];
    let (sig_i, sig_s) = sig.split_at_mut(POINT_LEN);

    // Derive a commitment scalar from the duplex's current state, the signer's private key,
    // and a random nonce.
    let k = duplex.hedge(&mut rng, &d.as_canonical_bytes(), Squeeze::squeeze_scalar);

    // Calculate and encrypt the commitment point.
    sig_i.copy_from_slice(&duplex.encrypt(&Point::mulgen(&k).as_canonical_bytes()));

    // Squeeze a challenge scalar.
    let r = duplex.squeeze_scalar();

    // Calculate the proof scalar.
    let s = (d * r) + k;

    // Encode and encrypt the proof scalar.
    sig_s.copy_from_slice(&duplex.encrypt(&s.as_canonical_bytes()));

    // Return the full signature.
    Signature(sig)
}

/// Verify a Schnorr signature of the given duplex's state using the given public key.
pub fn verify_duplex(duplex: &mut KeyedDuplex, q: &Point, sig: &Signature) -> Option<()> {
    // Split signature into components.
    let (i, s) = sig.0.split_at(POINT_LEN);

    // Decrypt the commitment point.
    let i = &duplex.decrypt(i);

    // Re-derive the challenge scalar.
    let r_p = duplex.squeeze_scalar();

    // Decrypt and decode the proof scalar.
    let s = Scalar::from_canonical_bytes(&duplex.decrypt(s))?;

    // Return true iff I and s are well-formed and I == [s]G - [r']Q.
    ((-q).mul_add_mulgen_vartime(&r_p, &s).encode().as_slice() == i.as_slice()).then_some(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn sign_and_verify() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = Point::mulgen(&d);
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message)).expect("error signing message");

        assert!(
            verify(&q, Cursor::new(message), &sig).is_ok(),
            "should have verified a valid signature"
        );
    }

    macro_rules! assert_failed {
        ($action: expr) => {
            match $action {
                Ok(_) => panic!("verified but shouldn't have"),
                Err(VerifyError::InvalidSignature) => {}
                Err(e) => panic!("unknown error: {}", e),
            }
        };
    }

    #[test]
    fn modified_message() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = Point::mulgen(&d);
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message)).expect("error signing");

        let message = b"this is NOT a message";
        assert_failed!(verify(&q, Cursor::new(message), &sig));
    }

    #[test]
    fn wrong_public_key() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = Point::mulgen(&d);
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message)).expect("error signing");

        let q = Point::random(&mut rng);

        assert_failed!(verify(&q, Cursor::new(message), &sig));
    }

    #[test]
    fn modified_sig() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = Point::mulgen(&d);
        let message = b"this is a message";
        let mut sig = sign(&mut rng, (&d, &q), Cursor::new(message)).expect("error signing");

        sig.0[22] ^= 1;

        assert_failed!(verify(&q, Cursor::new(message), &sig));
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
            Err(ParseSignatureError::InvalidEncoding(bs58::decode::Error::InvalidCharacter {
                character: ' ',
                index: 4,
            })),
            "woot woot".parse::<Signature>(),
            "parsed invalid signature"
        );
    }
}
