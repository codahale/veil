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
    sig[NONCE_LEN..].copy_from_slice(&det_sign(&mut schnorr, (&signer.sk_pq, &signer.sk_c)));
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
    (sk_pq, sk_c): (&ml_dsa_65::PrivateKey, &ed25519_zebra::SigningKey),
) -> [u8; DET_SIGNATURE_LEN] {
    // Allocate a signature buffer.
    let mut sig = [0u8; DET_SIGNATURE_LEN];
    let (sig_c, sig_pq) = sig.split_at_mut(ed25519_zebra::Signature::BYTE_SIZE);

    // Derive a 256-bit commitment value.
    let k = protocol.derive_array::<32>("commitment");

    // Create an Ed25519 signature of the commitment value.
    sig_c.copy_from_slice(&sk_c.sign(&k).to_bytes());

    /// An all-zero RNG which we need to ensure the ML-KEM-65 signature is actually deterministic. The
    /// API in 0.1.1, at least, doesn't allow for not using the probabilistic version.
    struct ZeroRng;

    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            dest.fill(0);
            Ok(())
        }
    }

    impl CryptoRng for ZeroRng {}

    // Create an ML-DSA-65 signature of the Ed25519 signature.
    sig_pq.copy_from_slice(&sk_pq.try_sign_with_rng_ct(&mut ZeroRng, sig_c).expect("should sign"));

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
