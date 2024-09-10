//! An insider-secure hybrid signcryption implementation.

use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

use crate::{
    kemeleon::{self, ENC_CT_LEN},
    keys::{StaticPublicKey, StaticSecretKey},
    sig::{self, SIG_LEN},
};

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = ENC_CT_LEN + SIG_LEN;

/// Given the sender's key pair, the ephemeral key pair, the receiver's public key, a nonce, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    mut rng: impl RngCore + CryptoRng,
    sender: &StaticSecretKey,
    receiver: &StaticPublicKey,
    nonce: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (out_kem, out_ciphertext) = ciphertext.split_at_mut(ENC_CT_LEN);
    let (out_ciphertext, out_sig) = out_ciphertext.split_at_mut(plaintext.len());

    // Initialize a protocol.
    let mut sres = Protocol::new("veil.sres");

    // Mix the sender's public key into the protocol. This binds all following outputs to the
    // sender's identity, preventing unknown key-share attacks with respect to the sender.
    sres.mix("sender", &sender.pub_key.encoded);

    // Mix the receiver's public key into the protocol. This binds all following outputs to the
    // receiver's identity, preventing unknown key-share attacks with respect to the receiver.
    sres.mix("receiver", &receiver.encoded);

    // Mix the nonce into the protocol. This makes all following outputs probabilistic with respect
    // to the nonce.
    sres.mix("nonce", nonce);

    // Encapsulate a shared secret with ML-KEM and mix it into the protocol's state. Because the
    // ML-KEM-768 ciphertext is encoded with Kemeleon, it is indistinguishable from random noise.
    let (kem_ect, kem_ss) = kemeleon::encapsulate(&receiver.ek, &mut rng);
    out_kem.copy_from_slice(&kem_ect);
    sres.mix("ml-kem-768-ect", out_kem);

    // Mix the ML-KEM shared secret into the protocol. This makes all following output confidential
    // against quantum passive insider adversaries (i.e. in possession of the sender's secret key
    // and the receiver's public key) but not active insider adversaries.
    sres.mix("ml-kem-768-ss", &kem_ss);

    // Encrypt the plaintext. By itself, this is confidential against passive insider adversaries
    // and implicitly authenticated as being from either the sender or the receiver but vulnerable
    // to key compromise impersonation (i.e. authenticated against outsider but not insider
    // adversaries).
    out_ciphertext.copy_from_slice(plaintext);
    sres.encrypt("message", out_ciphertext);

    // Sign the protocol's state. The protocol's state is randomized with both the nonce and the
    // ephemeral key, so the risk of e.g. fault attacks is minimal.
    let sig = sig::sign_protocol(&mut rng, &mut sres, sender);
    out_sig.copy_from_slice(&sig);
}

/// Given the receiver's key pair, the sender's public key, a nonce, and a ciphertext, decrypts the
/// given ciphertext and returns the plaintext iff the ciphertext was encrypted for the receiver by
/// the sender.
#[must_use]
pub fn decrypt<'a>(
    receiver: &StaticSecretKey,
    sender: &StaticPublicKey,
    nonce: &[u8],
    in_out: &'a mut [u8],
) -> Option<&'a [u8]> {
    // Check for too-small ciphertexts.
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (kem_ect, ciphertext) = in_out.split_at_mut(ENC_CT_LEN);
    let (ciphertext, sig) = ciphertext.split_at_mut(ciphertext.len() - SIG_LEN);

    // Initialize a protocol.
    let mut sres = Protocol::new("veil.sres");

    // Mix the sender's public key into the protocol.
    sres.mix("sender", &sender.encoded);

    // Mix the receiver's public key into the protocol.
    sres.mix("receiver", &receiver.pub_key.encoded);

    // Mix the nonce into the protocol.
    sres.mix("nonce", nonce);

    // Mix the ML-KEM ciphertext into the protocol, decapsulate the ML-KEM shared secret, then mix
    // the shared secret into the protocol.
    sres.mix("ml-kem-768-ect", kem_ect);
    let kem_ss =
        kemeleon::decapsulate(&receiver.dk, kem_ect.try_into().expect("should be 1252 bytes"));
    sres.mix("ml-kem-768-ss", &kem_ss);

    // Decrypt the plaintext.
    sres.decrypt("message", ciphertext);

    // Verify the signature.
    sig::verify_protocol(&mut sres, sender, sig.try_into().expect("should be 3373 bytes"))
        .is_some()
        .then_some(ciphertext)
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let (_, sender, receiver, plaintext, nonce, mut ciphertext) = setup();

        assert_eq!(
            Some(plaintext.as_slice()),
            decrypt(&receiver, &sender.pub_key, &nonce, &mut ciphertext)
        );
    }

    #[test]
    fn wrong_receiver() {
        let (mut rng, sender, _, _, nonce, mut ciphertext) = setup();

        let wrong_receiver = StaticSecretKey::random(&mut rng);
        assert_eq!(None, decrypt(&wrong_receiver, &sender.pub_key, &nonce, &mut ciphertext));
    }

    #[test]
    fn wrong_sender() {
        let (mut rng, _, receiver, _, nonce, mut ciphertext) = setup();

        let wrong_sender = StaticSecretKey::random(&mut rng);
        assert_eq!(None, decrypt(&receiver, &wrong_sender.pub_key, &nonce, &mut ciphertext));
    }

    #[test]
    fn wrong_nonce() {
        let (mut rng, sender, receiver, _, _, mut ciphertext) = setup();

        let wrong_nonce = rng.gen::<[u8; NONCE_LEN]>();
        assert_eq!(None, decrypt(&receiver, &sender.pub_key, &wrong_nonce, &mut ciphertext));
    }

    fn setup() -> (ChaChaRng, StaticSecretKey, StaticSecretKey, [u8; 64], [u8; NONCE_LEN], Vec<u8>)
    {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sender = StaticSecretKey::random(&mut rng);
        let receiver = StaticSecretKey::random(&mut rng);
        let plaintext = rng.gen::<[u8; 64]>();
        let nonce = rng.gen::<[u8; NONCE_LEN]>();

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(&mut rng, &sender, &receiver.pub_key, &nonce, &plaintext, &mut ciphertext);

        (rng, sender, receiver, plaintext, nonce, ciphertext)
    }
}
