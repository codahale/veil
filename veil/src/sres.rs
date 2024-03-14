//! An insider-secure hybrid signcryption implementation.

use lockstitch::Protocol;
use ml_kem::{Decapsulate, Encapsulate};
use rand::{CryptoRng, RngCore};

use crate::{
    keys::{
        EphemeralPublicKey, EphemeralSecretKey, StaticPublicKey, StaticSecretKey, EPHEMERAL_PK_LEN,
    },
    sig::{self, DET_SIGNATURE_LEN},
};

/// The recommended size of the nonce passed to [encrypt].
pub const NONCE_LEN: usize = 16;

/// The number of bytes added to plaintext by [encrypt].
pub const OVERHEAD: usize = EPHEMERAL_PK_LEN + 1088 + DET_SIGNATURE_LEN;

/// Given the sender's key pair, the ephemeral key pair, the receiver's public key, a nonce, and a
/// plaintext, encrypts the given plaintext and returns the ciphertext.
pub fn encrypt(
    mut rng: impl RngCore + CryptoRng,
    sender: &StaticSecretKey,
    ephemeral: &EphemeralSecretKey,
    receiver: &StaticPublicKey,
    nonce: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert_eq!(ciphertext.len(), plaintext.len() + OVERHEAD);

    // Split up the output buffer.
    let (out_kem, out_ephemeral) = ciphertext.split_at_mut(1088);
    let (out_ephemeral, out_ciphertext) = out_ephemeral.split_at_mut(EPHEMERAL_PK_LEN);
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

    // Mix the static ECDH shared secret `[d_S]Q_R` into the protocol. This makes all following
    // outputs confidential against passive outsider adversaries (i.e. in possession of the sender
    // and receiver's public keys but no secret keys) but not active outsider adversaries.
    sres.mix("static-ecdh", sender.dk_c.diffie_hellman(&receiver.ek_c).as_bytes());

    // Encapsulate a shared secret with ML-KEM and encrypt it.
    let (ct, ss) = receiver.ek_pq.encapsulate(&mut rng).expect("should encapsulate");
    out_kem.copy_from_slice(&ct);
    sres.encrypt("kem-ct", out_kem);

    // Mix the KEM shared secret into the protocol.
    sres.mix("kem-ss", &ss);

    // Encrypt the ephemeral public key. An insider adversary (i.e. in possession of either the
    // sender or the receiver's secret key) can recover this value. While this does represent a
    // distinguishing attack, ~12% of random 32-byte values successfully decode to GLS254 points,
    // which reduces the utility somewhat.
    out_ephemeral.copy_from_slice(&ephemeral.pub_key.encoded);
    sres.encrypt("ephemeral-key", out_ephemeral);

    // Mix the ephemeral ECDH shared secret `[d_E]Q_R` into the protocol. This makes all following
    // outputs confidential against passive insider adversaries (i.e. an adversary in possession of
    // the sender's secret key) a.k.a sender forward-secure.
    sres.mix("ephemeral-ecdh", ephemeral.dk_c.diffie_hellman(&receiver.ek_c).as_bytes());

    // Encrypt the plaintext. By itself, this is confidential against passive insider adversaries
    // and implicitly authenticated as being from either the sender or the receiver but vulnerable
    // to key compromise impersonation (i.e. authenticated against outsider but not insider
    // adversaries).
    out_ciphertext.copy_from_slice(plaintext);
    sres.encrypt("message", out_ciphertext);

    // Deterministically sign the protocol's state. The protocol's state is randomized with both
    // the nonce and the ephemeral key, so the risk of e.g. fault attacks is minimal.
    let sig = sig::det_sign(&mut sres, (&sender.sk_pq, &sender.sk_c));
    out_sig.copy_from_slice(&sig);
}

/// Given the receiver's key pair, the sender's public key, a nonce, and a ciphertext, decrypts the
/// given ciphertext and returns the ephemeral public key and plaintext iff the ciphertext was
/// encrypted for the receiver by the sender.
#[must_use]
pub fn decrypt<'a>(
    receiver: &StaticSecretKey,
    sender: &StaticPublicKey,
    nonce: &[u8],
    in_out: &'a mut [u8],
) -> Option<(EphemeralPublicKey, &'a [u8])> {
    // Check for too-small ciphertexts.
    if in_out.len() < OVERHEAD {
        return None;
    }

    // Split the ciphertext into its components.
    let (kem, ephemeral) = in_out.split_at_mut(1088);
    let (ephemeral, ciphertext) = ephemeral.split_at_mut(EPHEMERAL_PK_LEN);
    let (ciphertext, sig) = ciphertext.split_at_mut(ciphertext.len() - DET_SIGNATURE_LEN);

    // Initialize a protocol.
    let mut sres = Protocol::new("veil.sres");

    // Mix the sender's public key into the protocol.
    sres.mix("sender", &sender.encoded);

    // Mix the receiver's public key into the protocol.
    sres.mix("receiver", &receiver.pub_key.encoded);

    // Mix the nonce into the protocol.
    sres.mix("nonce", nonce);

    // Mix the static ECDH shared secret into the protocol: [d_R]Q_S
    sres.mix("static-ecdh", receiver.dk_c.diffie_hellman(&sender.ek_c).as_bytes());

    // Decrypt and decapsulate the ML-KEM shared secret, then mix it into the protocol.
    sres.decrypt("kem-ct", kem);
    let kem = ml_kem::Ciphertext::<ml_kem::MlKem768>::clone_from_slice(kem);
    let ss = receiver.dk_pq.decapsulate(&kem).ok()?;
    sres.mix("kem-ss", &ss);

    // Decrypt and decode the ephemeral public key.
    sres.decrypt("ephemeral-key", ephemeral);
    let ephemeral = EphemeralPublicKey::from_canonical_bytes(ephemeral)?;

    // Mix the ephemeral ECDH shared secret into the protocol: [d_R]Q_E
    sres.mix("ephemeral-ecdh", receiver.dk_c.diffie_hellman(&ephemeral.ek_c).as_bytes());

    // Decrypt the plaintext.
    sres.decrypt("message", ciphertext);

    // Verify the signature.
    sig::det_verify(
        &mut sres,
        (&sender.vk_pq, &sender.vk_c),
        sig.try_into().expect("should be signature sized"),
    )
    .is_some()
    .then_some((ephemeral, ciphertext))
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let (_, sender, receiver, ephemeral, plaintext, nonce, mut ciphertext) = setup();

        assert_eq!(
            Some((ephemeral.pub_key, plaintext.as_slice())),
            decrypt(&receiver, &sender.pub_key, &nonce, &mut ciphertext)
        );
    }

    #[test]
    fn wrong_receiver() {
        let (mut rng, sender, _, _, _, nonce, mut ciphertext) = setup();

        let wrong_receiver = StaticSecretKey::random(&mut rng);
        assert_eq!(None, decrypt(&wrong_receiver, &sender.pub_key, &nonce, &mut ciphertext));
    }

    #[test]
    fn wrong_sender() {
        let (mut rng, _, receiver, _, _, nonce, mut ciphertext) = setup();

        let wrong_sender = StaticSecretKey::random(&mut rng);
        assert_eq!(None, decrypt(&receiver, &wrong_sender.pub_key, &nonce, &mut ciphertext));
    }

    #[test]
    fn wrong_nonce() {
        let (mut rng, sender, receiver, _, _, _, mut ciphertext) = setup();

        let wrong_nonce = rng.gen::<[u8; NONCE_LEN]>();
        assert_eq!(None, decrypt(&receiver, &sender.pub_key, &wrong_nonce, &mut ciphertext));
    }

    fn setup() -> (
        ChaChaRng,
        StaticSecretKey,
        StaticSecretKey,
        EphemeralSecretKey,
        [u8; 64],
        [u8; NONCE_LEN],
        Vec<u8>,
    ) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sender = StaticSecretKey::random(&mut rng);
        let receiver = StaticSecretKey::random(&mut rng);
        let ephemeral = EphemeralSecretKey::random(&mut rng);
        let plaintext = rng.gen::<[u8; 64]>();
        let nonce = rng.gen::<[u8; NONCE_LEN]>();

        let mut ciphertext = vec![0u8; plaintext.len() + OVERHEAD];
        encrypt(
            &mut rng,
            &sender,
            &ephemeral,
            &receiver.pub_key,
            &nonce,
            &plaintext,
            &mut ciphertext,
        );

        (rng, sender, receiver, ephemeral, plaintext, nonce, ciphertext)
    }
}
