//! Hybrid Ed25519/ML-DSA-65 digital signatures.

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

/// A hybrid Ed25519/ML-DSA-65 signature.
///
/// Consists of a 16-byte nonce,and an encrypted Ed25519 signature, and an encrypted ML-DSA-65
/// signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Create a signature from a byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<Signature> {
        Some(Signature(b.as_ref().try_into().ok()?))
    }

    /// Encode the signature as a byte array.
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

/// Create a randomized hybrid Ed25519/ML-DSA-65 signature of the given message using the given key
/// pair.
pub fn sign(
    mut rng: impl RngCore + CryptoRng,
    signer: &StaticPrivKey,
    mut message: impl Read,
) -> io::Result<Signature> {
    // Allocate an output buffer.
    let mut out = [0u8; SIGNATURE_LEN];
    let (out_nonce, out_sig) = out.split_at_mut(NONCE_LEN);

    // Initialize a protocol.
    let mut sig = Protocol::new("veil.sig");

    // Mix the signer's public key into the protocol.
    sig.mix("signer", &signer.pub_key.encoded);

    // Generate a random nonce and mix it into the protocol.
    rng.fill_bytes(out_nonce);
    sig.mix("nonce", out_nonce);

    // Mix the message into the protocol.
    let mut writer = sig.mix_writer("message", io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut schnorr, _) = writer.into_inner();

    // Create a deterministic hybrid Ed25519/ML-DSA-65 signature of the randomized protocol state.
    out_sig.copy_from_slice(&det_sign(&mut schnorr, (&signer.sk_pq, &signer.sk_c)));

    Ok(Signature(out))
}

/// Verify a randomized hybrid Ed25519/ML-DSA-65 signature of the given message using the given
/// public key.
pub fn verify(
    signer: &StaticPubKey,
    mut message: impl Read,
    signature: &Signature,
) -> Result<(), VerifyError> {
    // Split the signature into its nonce and signature.
    let (nonce, signature) = signature.0.split_at(NONCE_LEN);

    // Initialize a protocol.
    let mut sig = Protocol::new("veil.sig");

    // Mix the signer's public key into the protocol.
    sig.mix("signer", &signer.encoded);

    // Mix the nonce into the protocol.
    sig.mix("nonce", nonce);

    // Mix the message into the protocol.
    let mut writer = sig.mix_writer("message", io::sink());
    io::copy(&mut message, &mut writer)?;
    let (mut schnorr, _) = writer.into_inner();

    // Verify the signature.
    det_verify(
        &mut schnorr,
        (&signer.vk_pq, &signer.vk_c),
        signature.try_into().expect("should be signature-sized"),
    )
    .ok_or(VerifyError::InvalidSignature)
}

/// Create a deterministic hybrid Ed25519/ML-DSA-65 signature of the given protocol's state using
/// the given private key. The protocol's state must be randomized to mitigate fault attacks.
pub fn det_sign(
    protocol: &mut Protocol,
    (sk_pq, sk_c): (&ml_dsa_65::PrivateKey, &ed25519_zebra::SigningKey),
) -> [u8; DET_SIGNATURE_LEN] {
    // Allocate a signature buffer.
    let mut sig = [0u8; DET_SIGNATURE_LEN];
    let (sig_c, sig_pq) = sig.split_at_mut(ed25519_zebra::Signature::BYTE_SIZE);

    // Derive a 256-bit commitment value from the protocol state.
    let k0 = protocol.derive_array::<32>("ed25519-commitment");

    // Create an Ed25519 signature of the commitment value and encrypt it.
    sig_c.copy_from_slice(&sk_c.sign(&k0).to_bytes());
    protocol.encrypt("ed25519-signature", sig_c);

    // Derive a second 256-bit commitment value from the protocol state.
    let k1 = protocol.derive_array::<32>("ml-dsa-65-commitment");

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

    // Create an ML-DSA-65 signature of the second commitment value.
    sig_pq.copy_from_slice(&sk_pq.try_sign_with_rng_ct(&mut ZeroRng, &k1).expect("should sign"));

    // Encrypt the ML-DSA-65 signature.
    protocol.encrypt("ml-dsa-65-signature", sig_pq);

    sig
}

/// Verify a deterministic hybrid Ed25519/ML-DSA-65 signature of the given protocol's state using
/// the given public key.
#[must_use]
pub fn det_verify(
    protocol: &mut Protocol,
    (vk_pq, vk_c): (&ml_dsa_65::PublicKey, &ed25519_zebra::VerificationKey),
    mut sig: [u8; DET_SIGNATURE_LEN],
) -> Option<()> {
    // Split the signature up.
    let (sig_c, sig_pq) = sig.split_at_mut(ed25519_zebra::Signature::BYTE_SIZE);

    // Derive a 256-bit commitment value from the protocol's state.
    let k0 = protocol.derive_array::<32>("ed25519-commitment");

    // Decrypt the Ed25519 signature.
    protocol.decrypt("ed25519-signature", sig_c);

    // Verify the Ed25519 signature.
    vk_c.verify(
        &ed25519_zebra::Signature::from_bytes(&sig_c.try_into().expect("should be 64 bytes")),
        &k0,
    )
    .ok()?;

    // Derive a second 256-bit commitment value from the protocol state.
    let k1 = protocol.derive_array::<32>("ml-dsa-65-commitment");

    // Decrypt the ML-DSA-65 signature.
    protocol.decrypt("ml-dsa-65-signature", sig_pq);

    // Verify the ML-DSA-65 signature.
    vk_pq
        .try_verify_vt(
            &k1,
            sig_pq.as_ref().try_into().expect("should be ML-DSA-65 signature sized"),
        )
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
