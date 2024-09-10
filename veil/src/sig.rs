//! Hybrid Ed25519/ML-DSA-65 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use arrayref::{array_refs, mut_array_refs};
use ed25519_dalek::ed25519::signature::Signer;
use fips204::{
    ml_dsa_65,
    traits::{Signer as _, Verifier as _},
};
use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

use crate::{
    keys::{
        Ed25519SigningKey, Ed25519VerifyingKey, MlDsa65SigningKey, MlDsa65VerifyingKey,
        StaticPublicKey, StaticSecretKey,
    },
    sres::NONCE_LEN,
    ParseSignatureError, VerifyError, DIGEST_LEN,
};

/// The length of a signature, in bytes.
pub const SIG_LEN: usize =
    NONCE_LEN + DIGEST_LEN + ed25519_dalek::SIGNATURE_LENGTH + ml_dsa_65::SIG_LEN;

/// A hybrid Ed25519/ML-DSA-65 signature.
///
/// Consists of an encrypted Ed25519 signature and an encrypted ML-DSA-65 signature.
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

/// Create a hybrid Ed25519/ML-DSA-65 signature of the given message using the given key pair.
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

    // Create a hybrid Ed25519/ML-DSA-65 signature of the protocol state.
    Ok(Signature(sign_protocol(rng, &mut sig, signer)))
}

/// Verify a hybrid Ed25519/ML-DSA-65 signature of the given message using the given public key.
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
    verify_protocol(&mut sig, signer, signature.0).ok_or(VerifyError::InvalidSignature)
}

/// Create a hybrid Ed25519/ML-DSA-65 signature of the given protocol's state using the given secret
/// key.
pub fn sign_protocol(
    mut rng: impl Rng + CryptoRng,
    protocol: &mut Protocol,
    signer: impl AsRef<Ed25519SigningKey> + AsRef<MlDsa65SigningKey>,
) -> [u8; SIG_LEN] {
    let mut sig = [0u8; SIG_LEN];

    // Generate a random nonce and a digest.
    {
        let (r, h, _) = mut_array_refs![
            &mut sig,
            NONCE_LEN,
            DIGEST_LEN,
            ed25519_dalek::SIGNATURE_LENGTH + ml_dsa_65::SIG_LEN
        ];

        // Generate a random nonce and mix it into the protocol.
        rng.fill(r);
        protocol.mix("signature-nonce", r);

        // Derive a 256-bit digest from the protocol state.
        protocol.derive("signature-digest", h);
    }

    // Create a Ed25519 signature of the nonce and the digest.
    {
        let (signed, sig_c, _) = mut_array_refs![
            &mut sig,
            NONCE_LEN + DIGEST_LEN,
            ed25519_dalek::SIGNATURE_LENGTH,
            ml_dsa_65::SIG_LEN
        ];

        sig_c.copy_from_slice(&AsRef::<Ed25519SigningKey>::as_ref(&signer).sign(signed).to_bytes());
    }

    // Create a ML-DSA-65 signature of the nonce, the digest, and the Ed255919 signature.
    {
        let (signed, sig_pq) = mut_array_refs![
            &mut sig,
            NONCE_LEN + DIGEST_LEN + ed25519_dalek::SIGNATURE_LENGTH,
            ml_dsa_65::SIG_LEN
        ];
        sig_pq.copy_from_slice(
            &AsRef::<MlDsa65SigningKey>::as_ref(&signer)
                .try_sign_with_rng(&mut rng, signed)
                .expect("should sign"),
        );
    }

    // Encrypt the two signatures.
    let (_, sig_c, sig_pq) = mut_array_refs![
        &mut sig,
        NONCE_LEN + DIGEST_LEN,
        ed25519_dalek::SIGNATURE_LENGTH,
        ml_dsa_65::SIG_LEN
    ];
    protocol.encrypt("ed25519-signature", sig_c);
    protocol.encrypt("ml-dsa-65-signature", sig_pq);

    // Return the nonce, the digest, the encrypted Ed25519 signature, and the encrypted ML-DSA-65
    // signature.
    sig
}

/// Verify a hybrid Ed25519/ML-DSA-65 signature of the given protocol's state using the given public
/// key.
#[must_use]
pub fn verify_protocol(
    protocol: &mut Protocol,
    signer: impl AsRef<Ed25519VerifyingKey> + AsRef<MlDsa65VerifyingKey>,
    mut sig: [u8; SIG_LEN],
) -> Option<()> {
    // Mix the nonce into the protocol, check the digest, and decrypt the signatures.
    {
        let (r, h, sig_c, sig_pq) = mut_array_refs![
            &mut sig,
            NONCE_LEN,
            DIGEST_LEN,
            ed25519_dalek::SIGNATURE_LENGTH,
            ml_dsa_65::SIG_LEN
        ];

        // Mix the nonce into the protocol.
        protocol.mix("signature-nonce", r);

        // Check the signature's digest.
        if h != &protocol.derive_array::<DIGEST_LEN>("signature-digest") {
            return None;
        }

        protocol.decrypt("ed25519-signature", sig_c);
        protocol.decrypt("ml-dsa-65-signature", sig_pq);
    }

    // Verify the Ed25519 signature.
    {
        let (signed, sig_c, _) = array_refs![
            &sig,
            NONCE_LEN + DIGEST_LEN,
            ed25519_dalek::SIGNATURE_LENGTH,
            ml_dsa_65::SIG_LEN
        ];
        let sig_c = ed25519_dalek::Signature::from_bytes(sig_c);
        if AsRef::<Ed25519VerifyingKey>::as_ref(&signer).verify_strict(signed, &sig_c).is_err() {
            return None;
        }
    }

    // Verify the ML-DSA-65 signature.
    {
        let (signed, sig_pq) = array_refs![
            &sig,
            NONCE_LEN + DIGEST_LEN + ed25519_dalek::SIGNATURE_LENGTH,
            ml_dsa_65::SIG_LEN
        ];
        if !AsRef::<MlDsa65VerifyingKey>::as_ref(&signer).verify(signed, sig_pq) {
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
