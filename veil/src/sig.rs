//! ML-DSA-65 digital signatures.

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
    keys::{MlDsa65SigningKey, MlDsa65VerifyingKey, StaticPublicKey, StaticSecretKey},
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
    signer: &StaticSecretKey,
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

    // Create an encrypted ML-DSA-65 signature of the protocol state.
    Ok(Signature(sign_protocol(rng, &mut sig, &signer.sk)))
}

/// Verify an encrypted ML-DSA-65 signature of the given message using the given public key.
pub fn verify(
    signer: &StaticPublicKey,
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
    verify_protocol(&mut sig, &signer.vk, signature.0).ok_or(VerifyError::InvalidSignature)
}

/// Create an encrypted ML-DSA-65 signature of the given protocol's state using the given secret
/// key.
pub fn sign_protocol(
    mut rng: impl Rng + CryptoRng,
    protocol: &mut Protocol,
    signer: &MlDsa65SigningKey,
) -> [u8; SIG_LEN] {
    // Derive a 256-bit digest from the protocol state.
    let h = protocol.derive_array::<DIGEST_LEN>("signature-digest");

    // Sign the digest with ML-DSA-65.
    let mut sig = signer.try_sign_with_rng_ct(&mut rng, &h).expect("should sign");

    // Encrypt the signature.
    protocol.encrypt("ml-dsa-65-signature", &mut sig);

    // Return the encrypted ML-DSA-65 signature.
    sig
}

/// Verify an encrypted ML-DSA-65 signature of the given protocol's state using the given public
/// key.
#[must_use]
pub fn verify_protocol(
    protocol: &mut Protocol,
    signer: &MlDsa65VerifyingKey,
    mut sig: [u8; SIG_LEN],
) -> Option<()> {
    // Derive a 256-bit digest from the protocol state.
    let d = protocol.derive_array::<DIGEST_LEN>("signature-digest");

    // Decrypt the signature.
    protocol.decrypt("ml-dsa-65-signature", &mut sig);

    signer.try_verify_vt(&d, &sig).is_ok().then_some(())
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
        let wrong_signer = StaticSecretKey::random(&mut rng);
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

    fn setup() -> (ChaChaRng, StaticSecretKey, Vec<u8>, Signature) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = StaticSecretKey::random(&mut rng);
        let message = rng.gen::<[u8; 64]>();
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("signing should be ok");
        (rng, signer, message.to_vec(), sig)
    }
}
