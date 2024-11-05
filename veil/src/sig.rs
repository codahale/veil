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
