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
    sig_s.copy_from_slice(&s.encode());
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
    let s = Scalar::decode(s)?;

    // Return true iff I and s are well-formed and I == [s]G - [r']Q. Here we compare the encoded
    // form of I' with the encoded form of I from the signature. This is faster, as encoding a point
    // is faster than decoding a point.
    ((-signer.q).mul128_add_mulgen_vartime(r_p, &s).encode().as_slice() == i).then_some(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use assert_matches::assert_matches;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn sign_and_verify() {
        let (_, signer, message, sig) = setup();
        assert_matches!(
            verify(&signer.pub_key, Cursor::new(message), &sig),
            Ok(()),
            "should have verified a valid signature"
        );
    }

    #[test]
    fn modified_message() {
        let (mut rng, signer, _, sig) = setup();
        let wrong_message = rng.gen::<[u8; 64]>();
        assert_matches!(
            verify(&signer.pub_key, Cursor::new(wrong_message), &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_signer() {
        let (mut rng, _, message, sig) = setup();
        let wrong_signer = PubKey::random(&mut rng);
        assert_matches!(
            verify(&wrong_signer, Cursor::new(message), &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn modified_sig() {
        let (_, signer, message, mut sig) = setup();
        sig.0[22] ^= 1;
        assert_matches!(
            verify(&signer.pub_key, Cursor::new(message), &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn signature_encoding() {
        let (_, _, _, sig) = setup();
        assert_eq!(
            "5rcaoLjdV6BsgX1X7QzDHXALJVjae8pvFhLu3YbPZL8RspFe1jbhwYhfKNLBvjbsj4gtiinm8oQZc67w2MUKfFLm",
            sig.to_string(),
            "invalid encoded signature"
        );
    }

    #[test]
    fn signature_decoding() {
        let (_, _, _, sig) = setup();
        let decoded = "5rcaoLjdV6BsgX1X7QzDHXALJVjae8pvFhLu3YbPZL8RspFe1jbhwYhfKNLBvjbsj4gtiinm8oQZc67w2MUKfFLm".parse::<Signature>();
        assert_eq!(Ok(sig), decoded, "error parsing signature");

        assert_eq!(
            Err(ParseSignatureError::InvalidEncoding(bs58::decode::Error::InvalidCharacter {
                character: 'l',
                index: 4,
            })),
            "invalid signature".parse::<Signature>(),
            "parsed invalid signature"
        );
    }

    fn setup() -> (ChaChaRng, PrivKey, Vec<u8>, Signature) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = PrivKey::random(&mut rng);
        let message = rng.gen::<[u8; 64]>();
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("error signing");
        (rng, signer, message.to_vec(), sig)
    }
}
