//! Hybrid Ed25519/ML-DSA-65 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    str::FromStr,
};

use ed25519_dalek::{hazmat as ed25519, Digest, Sha512};
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
    ParseSignatureError, VerifyError,
};

/// The length of a signature, in bytes.
pub const SIG_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH + ml_dsa_65::SIG_LEN;

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
    // Allocate a signature buffer.
    let mut sig = [0u8; SIG_LEN];
    let (sig_c, sig_pq) = sig.split_at_mut(ed25519_dalek::SIGNATURE_LENGTH);

    // Derive a 512-bit digest from the protocol state.
    let d = protocol.derive_array::<64>("signature-digest");

    // Create a hedged Ed25519 signature of the commitment value. Here, we replace the deterministic
    // nonce of the Ed25519 secret key with the first 32 bytes of the SHA-512 hash of the nonce and
    // a random 32-byte value.
    let sk_c = AsRef::<Ed25519SigningKey>::as_ref(&signer);
    let mut esk_c = ed25519::ExpandedSecretKey::from(sk_c.as_bytes());
    let h = Sha512::default()
        .chain_update(esk_c.hash_prefix)
        .chain_update(rng.gen::<[u8; 32]>())
        .finalize();
    esk_c.hash_prefix.copy_from_slice(&h[..32]);
    sig_c.copy_from_slice(
        &ed25519::raw_sign::<Sha512>(&esk_c, &d, &sk_c.verifying_key()).to_bytes(),
    );

    // Create a hedged ML-DSA-65 signature of the commitment value.
    sig_pq.copy_from_slice(
        &AsRef::<MlDsa65SigningKey>::as_ref(&signer)
            .try_sign_with_rng_ct(&mut rng, &d)
            .expect("should sign"),
    );

    // Encrypt the two signatures.
    protocol.encrypt("ed25519-signature", sig_c);
    protocol.encrypt("ml-dsa-65-signature", sig_pq);

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
    let sig_pq = sig_pq.as_ref().try_into().expect("should be 3309 bytes");

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
