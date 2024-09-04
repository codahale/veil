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
