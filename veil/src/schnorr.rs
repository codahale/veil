//! Ed25519 digital signatures.

use std::{
    fmt,
    io::{self, Read},
    mem,
    str::FromStr,
};

use dilithium_raw::{
    dilithium3, ffi::dilithium3::SIGNATUREBYTES as DILITHIUM3_SIG_LEN, util::ByteArrayVec,
};
use lockstitch::Protocol;
use rand::{CryptoRng, Rng};

use crate::{
    keys::{StaticPrivKey, StaticPubKey},
    sres::NONCE_LEN,
    ParseSignatureError, VerifyError,
};

/// The length of a deterministic signature, in bytes.
pub const DET_SIGNATURE_LEN: usize =
    ed25519_zebra::Signature::BYTE_SIZE + mem::size_of::<u16>() + DILITHIUM3_SIG_LEN;

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
    mut rng: impl Rng + CryptoRng,
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
    (sk_pq, sk_c): (&dilithium3::SecretKey, &ed25519_zebra::SigningKey),
) -> [u8; DET_SIGNATURE_LEN] {
    // Allocate a signature buffer.
    let mut sig = [0u8; DET_SIGNATURE_LEN];
    let (sig_c, sig_pq_len) = sig.split_at_mut(ed25519_zebra::Signature::BYTE_SIZE);
    let (sig_pq_len, sig_pq) = sig_pq_len.split_at_mut(mem::size_of::<u16>());

    // Derive a 256-bit commitment value.
    let k = protocol.derive_array::<32>("commitment");

    // Create an Ed25519 signature of the commitment value.
    sig_c.copy_from_slice(&sk_c.sign(&k).to_bytes());

    // Create a Dilithium3 signature of the Ed25519 signature.
    let s = dilithium3::sign(sig_c, sk_pq);
    let s_len = <dilithium3::Signature as AsRef<[u8]>>::as_ref(&s).len();
    sig_pq_len.copy_from_slice(&(s_len as u16).to_le_bytes());
    sig_pq[..s_len].copy_from_slice(s.as_ref());

    // Encrypt the signature.
    protocol.encrypt("signature", &mut sig);

    sig
}

/// Verify a deterministic Schnorr signature of the given protocol's state using the given public
/// key.
#[must_use]
pub fn det_verify(
    protocol: &mut Protocol,
    (vk_pq, vk_c): (&dilithium3::PublicKey, &ed25519_zebra::VerificationKey),
    mut sig: [u8; DET_SIGNATURE_LEN],
) -> Option<()> {
    // Derive a 256-bit commitment value.
    let k = protocol.derive_array::<32>("commitment");

    // Decrypt the signature.
    protocol.decrypt("signature", &mut sig);

    // Split the signature up.
    let (sig_c, sig_pq_len) = sig.split_at(ed25519_zebra::Signature::BYTE_SIZE);
    let (sig_pq_len, sig_pq_raw) = sig_pq_len.split_at(mem::size_of::<u16>());
    let sig_c =
        ed25519_zebra::Signature::from_bytes(&sig_c.try_into().expect("should be 64 bytes"));
    let sig_pq_len = u16::from_le_bytes(sig_pq_len.try_into().expect("should be 2 bytes")) as usize;
    let sig_pq = dilithium3::Signature::from(ByteArrayVec::new(
        sig_pq_raw.try_into().expect("should be signature sized"),
        sig_pq_len,
    ));

    // Verify the signatures and ensure the padding bytes are unmodified.
    vk_c.verify(&sig_c, &k).ok()?;
    dilithium3::verify(sig_c.to_bytes(), &sig_pq, vk_pq).ok()?;
    sig_pq_raw[sig_pq_len..].iter().all(|&b| b == 0).then_some(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use assert_matches::assert_matches;
    use expect_test::expect;
    use rand::SeedableRng;
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
