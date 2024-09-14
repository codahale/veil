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
