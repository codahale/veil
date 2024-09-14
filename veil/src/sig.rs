//! Encrypted ML-DSA-65 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use arrayref::{array_refs, mut_array_refs};
use fips204::{
    ml_dsa_65,
    traits::{Signer as _, Verifier as _},
};
use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

use crate::{
    keys::{PubKey, SecKey},
    sres::NONCE_LEN,
    ParseSignatureError, VerifyError, DIGEST_LEN,
};

/// The length of a signature, in bytes.
pub const SIG_LEN: usize = NONCE_LEN + DIGEST_LEN + ml_dsa_65::SIG_LEN;

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
    let mut sig = [0u8; SIG_LEN];

    // Generate a random nonce and a message digest.
    {
        let (r, h, _) = mut_array_refs![&mut sig, NONCE_LEN, DIGEST_LEN, ml_dsa_65::SIG_LEN];

        // Generate a random nonce and mix it into the protocol.
        rng.fill(r);
        protocol.mix("nonce", r);

        // Derive a 256-bit digest from the protocol state.
        protocol.derive("digest", h);
    }

    // Create a ML-DSA-65 signature of the nonce and the digest.
    {
        let (signed, sig) = mut_array_refs![&mut sig, NONCE_LEN + DIGEST_LEN, ml_dsa_65::SIG_LEN];
        sig.copy_from_slice(&signer.sk.try_sign_with_rng(&mut rng, signed).expect("should sign"));

        // Encrypt the signature.
        protocol.encrypt("signature", sig);
    }

    // Return the nonce, the digest, and the encrypted signature.
    sig
}

/// Verify a ML-DSA-65 signature of the given protocol's state using the given public key.
#[must_use]
pub fn verify_protocol(
    protocol: &mut Protocol,
    signer: &PubKey,
    mut sig: [u8; SIG_LEN],
) -> Option<()> {
    // Mix the nonce into the protocol, check the digest, and decrypt the signature.
    {
        let (r, h, sig) = mut_array_refs![&mut sig, NONCE_LEN, DIGEST_LEN, ml_dsa_65::SIG_LEN];

        // Mix the nonce into the protocol.
        protocol.mix("nonce", r);

        // Check the signature's digest.
        if h != &protocol.derive_array::<DIGEST_LEN>("digest") {
            return None;
        }

        protocol.decrypt("signature", sig);
    }

    // Verify the ML-DSA-65 signature.
    {
        let (signed, sig) = array_refs![&sig, NONCE_LEN + DIGEST_LEN, ml_dsa_65::SIG_LEN];
        if !signer.vk.verify(signed, sig) {
            return None;
        }
    }

    Some(())
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
