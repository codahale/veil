//! Ed25519 digital signatures.

use std::{fmt, io, io::Read, str::FromStr};

use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

use crate::{
    keys::{StaticPrivKey, StaticPubKey},
    sres::NONCE_LEN,
    ParseSignatureError, VerifyError,
};

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = NONCE_LEN + ed25519_zebra::Signature::BYTE_SIZE;

/// A Schnorr signature.
///
/// Consists of a 16-byte nonce, an encrypted commitment point, and an encrypted proof scalar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Create a signature from a 80-byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<Signature> {
        Some(Signature(b.as_ref().try_into().ok()?))
    }

    /// Encode the signature as a 80-byte array.
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

/// Create a randomized Schnorr signature of the given message using the given key pair.
pub fn sign(
    mut rng: impl Rng + CryptoRng,
    signer: &StaticPrivKey,
    mut message: impl Read,
) -> io::Result<Signature> {
    // Allocate an output buffer.
    let mut sig = [0u8; SIGNATURE_LEN];

    // Initialize a protocol.
    let mut schnorr = Protocol::new("veil.schnorr");

    // Mix the signer's public key into the protocol.
    schnorr.mix("signer", &signer.pub_key.encoded);

    // Generate a random nonce and mix it into the protocol.
    rng.fill_bytes(&mut sig[..NONCE_LEN]);
    schnorr.mix("nonce", &sig[..NONCE_LEN]);

    // Mix the message into the protocol.
    let mut writer = schnorr.mix_writer("message", io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut schnorr, _) = writer.into_inner();

    // Calculate the encrypted commitment point and proof scalar.
    sig[NONCE_LEN..].copy_from_slice(&det_sign(&mut schnorr, &signer.sk_c));
    Ok(Signature(sig))
}

/// Verify a randomized Schnorr signature of the given message using the given public key.
pub fn verify(
    signer: &StaticPubKey,
    mut message: impl Read,
    sig: &Signature,
) -> Result<(), VerifyError> {
    // Initialize a protocol.
    let mut schnorr = Protocol::new("veil.schnorr");

    // Mix the signer's public key into the protocol.
    schnorr.mix("signer", &signer.encoded);

    // Mix the nonce into the protocol.
    schnorr.mix("nonce", &sig.0[..NONCE_LEN]);

    // Mix the message into the protocol.
    let mut writer = schnorr.mix_writer("message", io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut schnorr, _) = writer.into_inner();

    // Verify the signature.
    det_verify(
        &mut schnorr,
        &signer.vk_c,
        sig.0[NONCE_LEN..].try_into().expect("should be 64 bytes"),
    )
    .ok_or(VerifyError::InvalidSignature)
}

/// Create a deterministic Ed25519 signature of the given protocol's state using the given private
/// key. The protocol's state must be randomized to mitigate fault attacks.
pub fn det_sign(
    protocol: &mut Protocol,
    signer: &ed25519_zebra::SigningKey,
) -> [u8; ed25519_zebra::Signature::BYTE_SIZE] {
    // Derive a 256-bit commitment value.
    let k = protocol.derive_array::<32>("commitment");

    // Create an Ed25519 signature of it.
    let mut sig = signer.sign(&k).to_bytes();

    // Encrypt the signature.
    protocol.encrypt("signature", &mut sig);

    sig
}

/// Verify a deterministic Schnorr signature of the given protocol's state using the given public
/// key.
#[must_use]
pub fn det_verify(
    protocol: &mut Protocol,
    signer: &ed25519_zebra::VerificationKey,
    mut sig: [u8; ed25519_zebra::Signature::BYTE_SIZE],
) -> Option<()> {
    // Derive a 256-bit commitment value.
    let k = protocol.derive_array::<32>("commitment");

    // Decrypt the signature.
    protocol.decrypt("signature", &mut sig);
    let sig = ed25519_zebra::Signature::from_bytes(&sig);

    // Verify the signature.
    signer.verify(&sig, &k).ok()
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
        let wrong_signer = StaticPrivKey::random(&mut rng);
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
        let expected = expect!["2Hjs2aUcr3g3QcfaUhs4WuKZqSseAqvgHihioT3cEPVwrnTpv3cWb57MrAiRMeNiNDwj1nxLjMki9H2frfTdwcVqTrJUXeinKTuY1gGrzvQ72h"];
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

    fn setup() -> (ChaChaRng, StaticPrivKey, Vec<u8>, Signature) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = StaticPrivKey::random(&mut rng);
        let message = rng.gen::<[u8; 64]>();
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("signing should be ok");
        (rng, signer, message.to_vec(), sig)
    }
}
