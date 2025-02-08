//! Encrypted ML-DSA-65 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use fips204::{
    ml_dsa_65,
    traits::{Signer as _, Verifier as _},
};
use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

use crate::{
    keys::{PubKey, SecKey},
    ParseSignatureError, VerifyError, DIGEST_LEN,
};

/// The length of a signature, in bytes.
pub const SIG_LEN: usize = ml_dsa_65::SIG_LEN;

/// An encrypted ML-DSA-65 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIG_LEN]);

impl Signature {
    /// Create a signature from a byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<Signature> {
        Some(Signature(b.as_ref().try_into().ok()?))
    }

    /// Encode the signature as a byte array.
    #[must_use]
    pub const fn encode(&self) -> [u8; SIG_LEN] {
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

/// Create an encrypted ML-DSA-65 signature of the given message using the given key pair.
pub fn sign(
    rng: impl Rng + CryptoRng,
    signer: &SecKey,
    mut message: impl Read,
) -> io::Result<Signature> {
    // Initialize a protocol.
    let mut sig = Protocol::new("veil.sig");

    // Mix the signer's public key into the protocol.
    sig.mix("signer", &signer.pub_key.encoded);

    // Mix the message into the protocol.
    let mut writer = sig.mix_writer("message", io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut sig, _) = writer.into_inner();

    // Create a ML-DSA-65 signature of the protocol state.
    Ok(Signature(sign_protocol(rng, &mut sig, signer)))
}

/// Verify a ML-DSA-65 signature of the given message using the given public key.
pub fn verify(
    signer: &PubKey,
    mut message: impl Read,
    signature: &Signature,
) -> Result<(), VerifyError> {
    // Initialize a protocol.
    let mut sig = Protocol::new("veil.sig");

    // Mix the signer's public key into the protocol.
    sig.mix("signer", &signer.encoded);

    // Mix the message into the protocol.
    let mut writer = sig.mix_writer("message", io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut sig, _) = writer.into_inner();

    // Verify the signature.
    verify_protocol(&mut sig, signer, signature.0).ok_or(VerifyError::InvalidSignature)
}

/// Create an encrypted ML-DSA-65 signature of the given protocol's state using the given signing
/// key.
pub fn sign_protocol(
    mut rng: impl Rng + CryptoRng,
    protocol: &mut Protocol,
    signer: &SecKey,
) -> [u8; SIG_LEN] {
    // Derive a 256-bit digest.
    let h = protocol.derive_array::<DIGEST_LEN>("digest");

    // Sign the digest with ML-DSA-65.
    let mut sig = signer.sk.try_sign_with_rng(&mut rng, &h, b"veil").expect("should sign");

    // Encrypt the signature.
    protocol.encrypt("signature", &mut sig);

    // Return the encrypted signature.
    sig
}

/// Verify a ML-DSA-65 signature of the given protocol's state using the given public key.
#[must_use]
pub fn verify_protocol(
    protocol: &mut Protocol,
    signer: &PubKey,
    mut sig: [u8; SIG_LEN],
) -> Option<()> {
    // Derive a counterfactual digest from the protocol state.
    let h_p = protocol.derive_array::<DIGEST_LEN>("digest");

    // Decrypt the signature.
    protocol.decrypt("signature", &mut sig);

    // Verify the ML-DSA-65 signature.
    signer.vk.verify(&h_p, &sig, b"veil").then_some(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use assert_matches::assert_matches;
    use expect_test::expect;
    use rand::{Rng as _, SeedableRng};
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
        let wrong_signer = SecKey::random(&mut rng);
        assert_matches!(
            verify(&wrong_signer.pub_key, Cursor::new(message), &sig),
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
        let expected = expect!["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"];
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

    fn setup() -> (ChaChaRng, SecKey, Vec<u8>, Signature) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = SecKey::random(&mut rng);
        let message = rng.gen::<[u8; 64]>();
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("signing should be ok");
        (rng, signer, message.to_vec(), sig)
    }
}
