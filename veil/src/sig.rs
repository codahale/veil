//! Hybrid Ed25519/ML-DSA-65 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use arrayref::mut_array_refs;
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
                .try_sign_with_rng_ct(&mut rng, signed)
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
        let (signed, sig_c, _) = mut_array_refs![
            &mut sig,
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
        let (signed, sig_pq) = mut_array_refs![
            &mut sig,
            NONCE_LEN + DIGEST_LEN + ed25519_dalek::SIGNATURE_LENGTH,
            ml_dsa_65::SIG_LEN
        ];
        if AsRef::<MlDsa65VerifyingKey>::as_ref(&signer).try_verify_vt(signed, sig_pq).is_err() {
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
