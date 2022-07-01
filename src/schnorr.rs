//! Schnorr-variant digital signatures.

use std::convert::TryInto;
use std::fmt::Formatter;
use std::io::{Read, Result};
use std::str::FromStr;
use std::{fmt, result};

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::ops::LinearCombination;
use elliptic_curve::Field;
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex};
use crate::ecc::{decode_point, decode_scalar, Point, Scalar, POINT_LEN, SCALAR_LEN};
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
    message: impl Read,
) -> Result<Signature> {
    // Initialize an unkeyed duplex.
    let mut schnorr = UnkeyedDuplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb_point(q);

    // Absorb the message in 32KiB blocks.
    schnorr.absorb_reader(message)?;

    // Convert the unkeyed duplex to a keyed duplex.
    let mut schnorr = schnorr.into_keyed();

    // Calculate the encrypted commitment point and proof scalar.
    let (i, s) = sign_duplex(&mut schnorr, rng, d);

    // Allocate an output buffer.
    let mut out = Vec::with_capacity(SIGNATURE_LEN);

    // Encrypt the proof scalar.
    out.extend(i);
    out.extend(schnorr.encrypt(&s.to_bytes()));

    // Return the encrypted commitment point and proof scalar.
    Ok(Signature(out.try_into().expect("invalid sig len")))
}

/// Verify a Schnorr signature of the given message using the given public key.
pub fn verify(q: &Point, message: impl Read, sig: &Signature) -> result::Result<(), VerifyError> {
    // Initialize an unkeyed duplex.
    let mut schnorr = UnkeyedDuplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb_point(q);

    // Absorb the message in 32KiB blocks.
    schnorr.absorb_reader(message)?;

    // Convert the unkeyed duplex to a keyed duplex.
    let mut schnorr = schnorr.into_keyed();

    // Verify the signature.
    verify_duplex(&mut schnorr, q, &sig.0)
}

/// Create a Schnorr signature of the given duplex's state using the given private key. Returns
/// the encrypted commitment point and the proof scalar.
pub fn sign_duplex(
    duplex: &mut KeyedDuplex,
    mut rng: impl CryptoRng + Rng,
    d: &Scalar,
) -> (Vec<u8>, Scalar) {
    loop {
        // Clone the duplex's state in case we need to re-generate the commitment scalar.
        let mut clone = duplex.clone();

        // Derive a commitment scalar from the duplex's current state, the signer's private key,
        // and a random nonce.
        let k = clone.hedge(&mut rng, &d.to_bytes(), Squeeze::squeeze_scalar);

        // Calculate and encrypt the commitment point.
        let i = &Point::GENERATOR * &k;
        let i = clone.encrypt(&i.to_bytes());

        // Squeeze a challenge scalar.
        let r = clone.squeeze_scalar();

        // Calculate the proof scalar.
        let s = (*d * r).as_ref() + &k;

        // Ensure the proof scalar isn't zero. This would only happen if d * r == -k, which is
        // astronomically rare but not impossible.
        if !s.is_zero_vartime() {
            // If the proof scalar is non-zero, set the duplex's state to the current clone.
            *duplex = clone;

            // Return the encrypted commitment point and the proof scalar.
            return (i, Scalar::new(s).unwrap());
        }
    }
}

/// Verify a Schnorr signature of the given duplex's state using the given public key.
pub fn verify_duplex(
    duplex: &mut KeyedDuplex,
    q: &Point,
    sig: &[u8],
) -> result::Result<(), VerifyError> {
    // Split the signature into parts.
    let (i, s) = sig.split_at(POINT_LEN);

    // Decrypt and decode the commitment point.
    let i = duplex.decrypt(i);
    let i = decode_point(&i).ok_or(VerifyError::InvalidSignature)?;

    // Re-derive the challenge scalar.
    let r_p = duplex.squeeze_scalar();

    // Decrypt and decode the proof scalar.
    let s = duplex.decrypt(s);
    let s = decode_scalar(&s).ok_or(VerifyError::InvalidSignature)?;

    // Return true iff I and s are well-formed and I == [s]G - [r']Q.
    //    I == [r'](-Q) + [s]G == [s]G - [r']Q
    if i == Point::lincomb(&-q, &r_p, &Point::GENERATOR, &s) {
        Ok(())
    } else {
        Err(VerifyError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use elliptic_curve::Group;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn sign_and_verify() -> Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &Point::GENERATOR * &d;
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
    fn modified_message() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &Point::GENERATOR * &d;
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message))?;

        let message = b"this is NOT a message";
        assert_failed!(verify(&q, Cursor::new(message), &sig))
    }

    #[test]
    fn wrong_public_key() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &Point::GENERATOR * &d;
        let message = b"this is a message";
        let sig = sign(&mut rng, (&d, &q), Cursor::new(message))?;

        let q = Point::random(&mut rng);

        assert_failed!(verify(&q, Cursor::new(message), &sig))
    }

    #[test]
    fn modified_sig() -> result::Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let d = Scalar::random(&mut rng);
        let q = &Point::GENERATOR * &d;
        let message = b"this is a message";
        let mut sig = sign(&mut rng, (&d, &q), Cursor::new(message))?;

        sig.0[22] ^= 1;

        assert_failed!(verify(&q, Cursor::new(message), &sig))
    }

    #[test]
    fn signature_encoding() {
        let sig = Signature([69u8; SIGNATURE_LEN]);
        assert_eq!(
            "77YbyELZPNMqGWewHAJS2kdWfwTiUqjaUurpM73jLrQw7DCndkszKMzC5QzmBPkTvxAgpAc8y9dp8FVJCKBrL4GQk",
            sig.to_string(),
            "invalid encoded signature"
        );

        let decoded = "77YbyELZPNMqGWewHAJS2kdWfwTiUqjaUurpM73jLrQw7DCndkszKMzC5QzmBPkTvxAgpAc8y9dp8FVJCKBrL4GQk".parse::<Signature>();
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
