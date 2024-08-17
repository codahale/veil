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
