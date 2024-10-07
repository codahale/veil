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
