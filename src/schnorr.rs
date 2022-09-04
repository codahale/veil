//! Schnorr-variant digital signatures.

use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};

use crrl::jq255e::{Point, Scalar};
use rand::{CryptoRng, Rng};

use crate::duplex::{Absorb, KeyedDuplex, Squeeze, UnkeyedDuplex};
use crate::keys::{PrivKey, PubKey, POINT_LEN, SCALAR_LEN};
use crate::{ParseSignatureError, VerifyError};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = POINT_LEN + SCALAR_LEN;

/// A Schnorr signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Create a signature from a 64-byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<Signature> {
        Some(Signature(b.as_ref().try_into().ok()?))
    }

    /// Encode the signature as a 64-byte array.
    #[must_use]
    pub const fn encode(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl FromStr for Signature {
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Signature::decode(bs58::decode(s).into_vec()?.as_slice())
            .ok_or(ParseSignatureError::InvalidLength)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

/// Create a Schnorr signature of the given message using the given key pair.
pub fn sign(
    rng: impl Rng + CryptoRng,
    signer: &PrivKey,
    message: impl Read,
) -> io::Result<Signature> {
    // Initialize an unkeyed duplex.
    let mut schnorr = UnkeyedDuplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb(&signer.pub_key.encoded);

    // Absorb the message.
    schnorr.absorb_reader(message)?;

    // Convert the unkeyed duplex to a keyed duplex.
    let mut schnorr = schnorr.into_keyed();

    // Calculate and return the encrypted commitment point and proof scalar.
    Ok(sign_duplex(&mut schnorr, rng, signer))
}

/// Verify a Schnorr signature of the given message using the given public key.
pub fn verify(signer: &PubKey, message: impl Read, sig: &Signature) -> Result<(), VerifyError> {
    // Initialize an unkeyed duplex.
    let mut schnorr = UnkeyedDuplex::new("veil.schnorr");

    // Absorb the signer's public key.
    schnorr.absorb(&signer.encoded);

    // Absorb the message.
    schnorr.absorb_reader(message)?;

    // Convert the unkeyed duplex to a keyed duplex.
    let mut schnorr = schnorr.into_keyed();

    // Verify the signature.
    verify_duplex(&mut schnorr, signer, sig).ok_or(VerifyError::InvalidSignature)
}

/// Create a Schnorr signature of the given duplex's state using the given private key.
/// Returns the full signature.
#[must_use]
pub fn sign_duplex(
    duplex: &mut KeyedDuplex,
    mut rng: impl CryptoRng + Rng,
    signer: &PrivKey,
) -> Signature {
    // Allocate an output buffer.
    let mut sig = [0u8; SIGNATURE_LEN];
    let (sig_i, sig_s) = sig.split_at_mut(POINT_LEN);

    // Derive a commitment scalar from the duplex's current state, the signer's private key,
    // and a random nonce, and calculate the commitment point.
    let k = duplex.hedge(&mut rng, signer, Squeeze::squeeze_scalar);
    let i = Point::mulgen(&k);

    // Calculate, encode, and encrypt the commitment point.
    sig_i.copy_from_slice(&i.encode());
    duplex.encrypt_mut(sig_i);

    // Squeeze a challenge scalar.
    let r = Scalar::from_u128(u128::from_le_bytes(duplex.squeeze()));

    // Calculate, encode, and encrypt the proof scalar.
    let s = (signer.d * r) + k;
    sig_s.copy_from_slice(&s.encode32());
    duplex.encrypt_mut(sig_s);

    // Return the full signature.
    Signature(sig)
}

/// Verify a Schnorr signature of the given duplex's state using the given public key.
#[must_use]
pub fn verify_duplex(duplex: &mut KeyedDuplex, signer: &PubKey, sig: &Signature) -> Option<()> {
    // Split signature into components.
    let mut sig = sig.0;
    let (i, s) = sig.split_at_mut(POINT_LEN);

    // Decrypt the commitment point but don't decode it.
    duplex.decrypt_mut(i);

    // Re-derive the challenge scalar.
    let r_p = u128::from_le_bytes(duplex.squeeze());

    // Decrypt and decode the proof scalar.
    duplex.decrypt_mut(s);
    let (s, ok) = Scalar::decode32(s);
    if ok == 0 {
        return None;
    }

    // Return true iff I and s are well-formed and I == [s]G - [r']Q. Here we compare the encoded
    // form of I' with the encoded form of I from the signature. This is faster, as encoding a point
    // is faster than decoding a point.
    ((-signer.q).mul128_add_mulgen_vartime(r_p, &s).encode().as_slice() == i).then_some(())
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
        let signer = PrivKey::random(&mut rng);

        let message = b"this is a message";
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("error signing message");

        assert!(
            verify(&signer.pub_key, Cursor::new(message), &sig).is_ok(),
            "should have verified a valid signature"
        );
    }

    #[test]
    fn modified_message() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = PrivKey::random(&mut rng);
        let message = b"this is a message";
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("error signing");

        let message = b"this is NOT a message";
        assert!(matches!(
            verify(&signer.pub_key, Cursor::new(message), &sig),
            Err(VerifyError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_signer() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = PrivKey::random(&mut rng);
        let wrong_signer = PubKey::random(&mut rng);
        let message = b"this is a message";
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("error signing");

        assert!(matches!(
            verify(&wrong_signer, Cursor::new(message), &sig),
            Err(VerifyError::InvalidSignature)
        ));
    }

    #[test]
    fn modified_sig() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = PrivKey::random(&mut rng);
        let message = b"this is a message";
        let mut sig = sign(&mut rng, &signer, Cursor::new(message)).expect("error signing");

        sig.0[22] ^= 1;

        assert!(matches!(
            verify(&signer.pub_key, Cursor::new(message), &sig),
            Err(VerifyError::InvalidSignature)
        ));
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
