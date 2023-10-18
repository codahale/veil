//! Schnorr-variant digital signatures.

use std::io::Read;
use std::str::FromStr;
use std::{fmt, io};

use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

use crate::ecc::{Point, Scalar};
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
    mut message: impl Read,
) -> io::Result<Signature> {
    // Initialize a protocol.
    let mut schnorr = Protocol::new("veil.schnorr");

    // Mix the signer's public key into the protocol.
    schnorr.mix(&signer.pub_key.encoded);

    // Mix the message into the protocol.
    let mut writer = schnorr.mix_writer(io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut schnorr, _) = writer.into_inner();

    // Calculate and return the encrypted commitment point and proof scalar.
    Ok(sign_protocol(&mut schnorr, rng, signer))
}

/// Verify a Schnorr signature of the given message using the given public key.
pub fn verify(signer: &PubKey, mut message: impl Read, sig: &Signature) -> Result<(), VerifyError> {
    // Initialize a protocol.
    let mut schnorr = Protocol::new("veil.schnorr");

    // Mix the signer's public key into the protocol.
    schnorr.mix(&signer.encoded);

    // Mix the message into the protocol.
    let mut writer = schnorr.mix_writer(io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut schnorr, _) = writer.into_inner();

    // Verify the signature.
    verify_protocol(&mut schnorr, signer, sig).ok_or(VerifyError::InvalidSignature)
}

/// Create a Schnorr signature of the given protocol's state using the given private key.
/// Returns the full signature.
#[must_use]
pub fn sign_protocol(
    protocol: &mut Protocol,
    mut rng: impl CryptoRng + Rng,
    signer: &PrivKey,
) -> Signature {
    // Allocate an output buffer.
    let mut sig = [0u8; SIGNATURE_LEN];
    let (sig_i, sig_s) = sig.split_at_mut(POINT_LEN);

    // Derive a commitment scalar from the protocol's current state, the signer's private key,
    // and a random nonce, and calculate the commitment point.
    let k = protocol
        .hedge(&mut rng, &[signer.nonce], |clone| Some(Scalar::reduce(clone.derive_array())));
    let i = Point::mul_gen(&k);

    // Calculate, encode, and encrypt the commitment point.
    sig_i.copy_from_slice(&i.to_bytes());
    protocol.encrypt(sig_i);

    // Derive a challenge scalar.
    let r = Scalar::reduce(protocol.derive_array());

    // Calculate, encode, and encrypt the proof scalar.
    let s = (signer.d * r) + k;
    sig_s.copy_from_slice(&s.to_bytes());
    protocol.encrypt(sig_s);

    // Return the full signature.
    Signature(sig)
}

/// Verify a Schnorr signature of the given protocol's state using the given public key.
#[must_use]
pub fn verify_protocol(protocol: &mut Protocol, signer: &PubKey, sig: &Signature) -> Option<()> {
    // Split signature into components.
    let mut sig = sig.0;
    let (i, s) = sig.split_at_mut(POINT_LEN);

    // Decrypt the commitment point but don't decode it.
    protocol.decrypt(i);

    // Re-derive the challenge scalar.
    let r_p = Scalar::reduce(protocol.derive_array());

    // Decrypt and decode the proof scalar.
    protocol.decrypt(s);
    let s = Scalar::from_bytes(s.try_into().ok()?)?;

    // Return true iff I and s are well-formed and I == [s]G - [r']Q. Here we compare the encoded
    // form of I' with the encoded form of I from the signature. This is faster, as encoding a point
    // is faster than decoding a point.
    let i_p = Point::lincomb(&s, &-signer.q, &r_p);
    (i == i_p.to_bytes()).then_some(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use assert_matches::assert_matches;
    use expect_test::expect;
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
    fn signature_kat() {
        let (_, _, _, sig) = setup();
        let expected = expect!["AvSrUBL7upTZsrjYihynuNKhE4AyG5kLaYiEYeCLyfjnoNANQ76fcPEXgjFWLv5K9FbwJv5XD3M3385yzUi3ru2wt"];
        expected.assert_eq(&sig.to_string());
    }

    #[test]
    fn signature_decoding() {
        let (_, _, _, sig) = setup();
        let decoded = sig.to_string().parse::<Signature>();
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
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("signing should be ok");
        (rng, signer, message.to_vec(), sig)
    }
}
