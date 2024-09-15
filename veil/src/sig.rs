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
    let mut sig = signer.sk.try_sign_with_rng(&mut rng, &h).expect("should sign");

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
    signer.vk.verify(&h_p, &sig).then_some(())
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
