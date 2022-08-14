//! Schnorr-variant digital signatures.

use std::convert::TryInto;
use std::fmt::Formatter;
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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
    Ok(sign_duplex(&mut schnorr, rng, d, None))
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
    if verify_duplex(&mut schnorr, q, None, sig) {
        Ok(())
    } else {
        Err(VerifyError::InvalidSignature)
    }
}

/// Create a Schnorr signature of the given duplex's state using the given private key and an
/// optional designated verifier public key. Returns the full signature.
#[must_use]
pub fn sign_duplex(
    duplex: &mut KeyedDuplex,
    mut rng: impl CryptoRng + Rng,
    d: &Scalar,
    q_v: Option<&Point>,
) -> Signature {
    loop {
        // Clone the duplex's state in case we need to re-generate the commitment scalar.
        let mut clone = duplex.clone();

        // Derive a commitment scalar from the duplex's current state, the signer's private key,
        // and a random nonce.
        let k = clone.hedge(&mut rng, &d.as_canonical_bytes(), Squeeze::squeeze_scalar);

        // Allocate an output buffer.
        let mut sig = [0u8; SIGNATURE_LEN];
        let (sig_i, sig_s_or_x) = sig.split_at_mut(POINT_LEN);

        // Calculate and encrypt the commitment point.
        let i = Point::mulgen(&k);
        sig_i.copy_from_slice(&clone.encrypt(&i.as_canonical_bytes()));

        // Squeeze a challenge scalar.
        let r = clone.squeeze_scalar();

        // Calculate the proof scalar.
        let s = (d * r) + k;

        // Ensure the proof scalar isn't zero. This would only happen if d * r == -k, which is
        // astronomically rare but not impossible.
        if s.iszero() == 0 {
            // If a designated verifier is specified, calculate a designated proof point and encode
            // it. Otherwise, encode the proof scalar.
            sig_s_or_x.copy_from_slice(&clone.encrypt(&if let Some(q_v) = q_v {
                (q_v * s).as_canonical_bytes()
            } else {
                s.as_canonical_bytes()
            }));

            // Set the duplex's state to the current clone.
            *duplex = clone;

            // Return the full signature.
            return Signature(sig);
        }
    }
}

/// Verify a Schnorr signature of the given duplex's state using the given public key and optional
/// designated verifier's private key.
#[must_use]
pub fn verify_duplex(
    duplex: &mut KeyedDuplex,
    q: &Point,
    d_v: Option<&Scalar>,
    sig: &Signature,
) -> bool {
    // Split signature into components.
    let (i, s_or_x) = sig.0.split_at(POINT_LEN);

    // Decrypt and decode the commitment point.
    let i = if let Some(i) = Point::from_canonical_bytes(&duplex.decrypt(i)) {
        i
    } else {
        return false;
    };

    // Re-derive the challenge scalar.
    let r_p = duplex.squeeze_scalar();

    // Decrypt either the proof scalar or the designated proof point.
    let s_or_x = duplex.decrypt(s_or_x);

    if let Some(d) = d_v {
        // If the signature has a designated verifier, re-calculate the proof point.
        let x_p = (i + (q * r_p)) * d;

        // Return true iff the canonical encoding of the re-calculated proof point matches the
        // encoding of the decrypted proof point.
        s_or_x == x_p.as_canonical_bytes().as_slice()
    } else {
        // If the signature is publicly verifiable, decrypt and decode the proof scalar.
        let s = if let Some(s) = Scalar::from_canonical_bytes(&s_or_x) {
            s
        } else {
            return false;
        };

        // Return true iff I and s are well-formed and I == [s]G - [r']Q.
        unsafe {
            // crrl doesn't yet support using Pornin's EdDSA verification optimizations for
            // Ristretto, so we resort to some unsafe trickery here. A Ristretto point is internally
            // just a newtype wrapper around an Ed25519 point. We transmute the pointers to
            // Ristretto points to pointers to Ed25519 points and use them to verify the signature.
            let q_raw = std::mem::transmute::<_, &crrl::ed25519::Point>(q);
            let i_raw = std::mem::transmute::<_, &crrl::ed25519::Point>(&i);
            q_raw.verify_helper_vartime(i_raw, &s, &r_p)
        }
    }
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
