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
