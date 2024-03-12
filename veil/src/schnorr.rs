//! Ed25519 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use fips204::{
    ml_dsa_65,
    traits::{Signer, Verifier},
};
use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

use crate::{
    keys::{StaticPrivKey, StaticPubKey},
    sres::NONCE_LEN,
    ParseSignatureError, VerifyError,
};

/// The length of a deterministic signature, in bytes.
pub const DET_SIGNATURE_LEN: usize = ed25519_zebra::Signature::BYTE_SIZE + ml_dsa_65::SIG_LEN;

/// The length of a signature, in bytes.
pub const SIGNATURE_LEN: usize = NONCE_LEN + DET_SIGNATURE_LEN;

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
    mut rng: impl RngCore + CryptoRng,
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
    sig[NONCE_LEN..].copy_from_slice(&det_sign(
        &mut schnorr,
        &mut rng,
        (&signer.sk_pq, &signer.sk_c),
    ));
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
        (&signer.vk_pq, &signer.vk_c),
        sig.0[NONCE_LEN..].try_into().expect("should be signature-sized"),
    )
    .ok_or(VerifyError::InvalidSignature)
}

/// Create a deterministic Ed25519 signature of the given protocol's state using the given private
/// key. The protocol's state must be randomized to mitigate fault attacks.
pub fn det_sign(
    protocol: &mut Protocol,
    mut rng: impl RngCore + CryptoRng,
    (sk_pq, sk_c): (&ml_dsa_65::PrivateKey, &ed25519_zebra::SigningKey),
) -> [u8; DET_SIGNATURE_LEN] {
    // Allocate a signature buffer.
    let mut sig = [0u8; DET_SIGNATURE_LEN];
    let (sig_c, sig_pq) = sig.split_at_mut(ed25519_zebra::Signature::BYTE_SIZE);

    // Derive a 256-bit commitment value.
    let k = protocol.derive_array::<32>("commitment");

    // Create an Ed25519 signature of the commitment value.
    sig_c.copy_from_slice(&sk_c.sign(&k).to_bytes());

    // Create an ML-DSA-65 signature of the Ed25519 signature.
    sig_pq.copy_from_slice(&sk_pq.try_sign_with_rng_ct(&mut rng, sig_c).expect("should sign"));

    // Encrypt the signature.
    protocol.encrypt("signature", &mut sig);

    sig
}

/// Verify a deterministic Schnorr signature of the given protocol's state using the given public
/// key.
#[must_use]
pub fn det_verify(
    protocol: &mut Protocol,
    (vk_pq, vk_c): (&ml_dsa_65::PublicKey, &ed25519_zebra::VerificationKey),
    mut sig: [u8; DET_SIGNATURE_LEN],
) -> Option<()> {
    // Derive a 256-bit commitment value.
    let k = protocol.derive_array::<32>("commitment");

    // Decrypt the signature.
    protocol.decrypt("signature", &mut sig);

    // Split the signature up.
    let (sig_c, sig_pq) = sig.split_at(ed25519_zebra::Signature::BYTE_SIZE);

    // Verify the signatures and ensure the padding bytes are unmodified.
    vk_c.verify(
        &ed25519_zebra::Signature::from_bytes(&sig_c.try_into().expect("should be 64 bytes")),
        &k,
    )
    .ok()?;
    vk_pq
        .try_verify_vt(sig_c, sig_pq.try_into().expect("should be ML-DSA-65 signature sized"))
        .ok()?
        .then_some(())
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

    fn setup() -> (ChaChaRng, StaticPrivKey, Vec<u8>, Signature) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let signer = StaticPrivKey::random(&mut rng);
        let message = rng.gen::<[u8; 64]>();
        let sig = sign(&mut rng, &signer, Cursor::new(message)).expect("signing should be ok");
        (rng, signer, message.to_vec(), sig)
    }
}
