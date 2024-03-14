//! Hybrid Ed25519/ML-DSA-65 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use ed25519_dalek::ed25519::signature::Signer as _;
use fips204::{
    ml_dsa_65,
    traits::{Signer as _, Verifier as _},
};
use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

use crate::{
    keys::{
        Ed25519SigningKey, Ed25519VerifyingKey, MlDsa65SigningKey, MlDsa65VerifyingKey,
        StaticPublicKey, StaticSecretKey,
    },
    sres::NONCE_LEN,
    ParseSignatureError, VerifyError,
};

/// The length of a deterministic signature, in bytes.
pub const DET_SIG_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH + ml_dsa_65::SIG_LEN;

/// The length of a signature, in bytes.
pub const SIG_LEN: usize = NONCE_LEN + DET_SIG_LEN;

/// A hybrid Ed25519/ML-DSA-65 signature.
///
/// Consists of a 16-byte nonce,and an encrypted Ed25519 signature, and an encrypted ML-DSA-65
/// signature.
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

/// Create a randomized hybrid Ed25519/ML-DSA-65 signature of the given message using the given key
/// pair.
pub fn sign(
    mut rng: impl RngCore + CryptoRng,
    signer: &StaticSecretKey,
    mut message: impl Read,
) -> io::Result<Signature> {
    // Allocate an output buffer.
    let mut out = [0u8; SIG_LEN];
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
    out_sig.copy_from_slice(&sign_protocol(&mut schnorr, signer));

    Ok(Signature(out))
}

/// Verify a randomized hybrid Ed25519/ML-DSA-65 signature of the given message using the given
/// public key.
pub fn verify(
    signer: &StaticPublicKey,
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
    verify_protocol(&mut schnorr, signer, signature.try_into().expect("should be signature-sized"))
        .ok_or(VerifyError::InvalidSignature)
}

/// Create a deterministic hybrid Ed25519/ML-DSA-65 signature of the given protocol's state using
/// the given secret key. The protocol's state must be randomized to mitigate fault attacks.
pub fn sign_protocol(
    protocol: &mut Protocol,
    signer: impl AsRef<Ed25519SigningKey> + AsRef<MlDsa65SigningKey>,
) -> [u8; DET_SIG_LEN] {
    // Allocate a signature buffer.
    let mut sig = [0u8; DET_SIG_LEN];
    let (sig_c, sig_pq) = sig.split_at_mut(ed25519_dalek::SIGNATURE_LENGTH);

    // Derive a 512-bit digest from the protocol state.
    let d = protocol.derive_array::<64>("signature-digest");

    // Create an Ed25519 signature of the commitment value and encrypt it.
    sig_c.copy_from_slice(&AsRef::<Ed25519SigningKey>::as_ref(&signer).sign(&d).to_bytes());
    protocol.encrypt("ed25519-signature", sig_c);

    /// An all-zero RNG which we need to ensure the ML-KEM-65 signature is actually deterministic.
    /// The API in 0.1.1, at least, doesn't allow for not using the probabilistic version.
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
    sig_pq.copy_from_slice(
        &AsRef::<MlDsa65SigningKey>::as_ref(&signer)
            .try_sign_with_rng_ct(&mut ZeroRng, &d)
            .expect("should sign"),
    );

    // Encrypt the ML-DSA-65 signature.
    protocol.encrypt("ml-dsa-65-signature", sig_pq);

    sig
}

/// Verify a deterministic hybrid Ed25519/ML-DSA-65 signature of the given protocol's state using
/// the given public key.
#[must_use]
pub fn verify_protocol(
    protocol: &mut Protocol,
    signer: impl AsRef<Ed25519VerifyingKey> + AsRef<MlDsa65VerifyingKey>,
    mut sig: [u8; DET_SIG_LEN],
) -> Option<()> {
    // Split the signature up.
    let (sig_c, sig_pq) = sig.split_at_mut(ed25519_dalek::SIGNATURE_LENGTH);

    // Derive a 512-bit digest from the protocol state.
    let d = protocol.derive_array::<64>("signature-digest");

    // Decrypt and decode the Ed25519 signature.
    protocol.decrypt("ed25519-signature", sig_c);
    let sig_c = sig_c.try_into().expect("should be 64 bytes");
    let sig_c = ed25519_dalek::Signature::from_bytes(&sig_c);

    // Decrypt and decode the ML-DSA-65 signature.
    protocol.decrypt("ml-dsa-65-signature", sig_pq);
    let sig_pq = sig_pq.as_ref().try_into().expect("should be ML-DSA-65 signature sized");

    // The signature is valid iff both Ed25519 and ML-DSA-65 signatures are valid.
    (AsRef::<Ed25519VerifyingKey>::as_ref(&signer).verify_strict(&d, &sig_c).is_ok()
        && AsRef::<MlDsa65VerifyingKey>::as_ref(&signer).try_verify_vt(&d, sig_pq).is_ok())
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
