//! Encrypted ML-DSA-65 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use fips204::{
    ml_dsa_65,
    traits::{Signer as _, Verifier as _},
    Ph,
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
    let mut sig = signer
        .sk
        .try_hash_sign_with_rng(&mut rng, &h, b"veil", &Ph::SHAKE128)
        .expect("should sign");

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
    signer.vk.hash_verify(&h_p, &sig, b"veil", &Ph::SHAKE128).then_some(())
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
