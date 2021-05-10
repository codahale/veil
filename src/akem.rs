//! akem implements Veil's authenticated key encapsulation mechanism.
//!
//! # Encapsulation
//!
//! Encapsulation is as follows, given the sender's key pair, `d_s` and `Q_s`, an ephemeral key
//! pair, `d_e` and `Q_e`, the receiver's public key, `Q_r`, a plaintext message `P`, and MAC size
//! `N_mac`:
//!
//! ```text
//! INIT('veil.akem', level=256)
//! AD(LE_U32(N_mac), meta=true)
//! AD(Q_r)
//! AD(Q_s)
//! ZZ_s = Q_r^d_s
//! KEY(ZZ_s)
//! SEND_ENC(Q_e) -> E
//! ZZ_e = Q_r^d_e
//! KEY(ZZ_e)
//! ```
//!
//! This is effectively an authenticated ECDH KEM, but instead of returning KDF output for use in a
//! DEM, we use the keyed protocol to directly encrypt the ciphertext and create a MAC:
//!
//! ```text
//! SEND_ENC(P)     -> C
//! SEND_MAC(N_mac) -> M
//! ```
//!
//! The resulting ciphertext is the concatenation of `E`, `C`, and `M`.
//!
//! # Decapsulation
//!
//! Decapsulation is then the inverse of encryption, given the recipient's key pair, `d_r` and
//! `Q_r`, and the sender's public key `Q_s`:
//!
//! ```text
//! INIT('veil.akem', level=256)
//! AD(LE_U32(N_max), meta=true)
//! AD(Q_r)
//! AD(Q_s)
//! ZZ_s = Q_s^d_r
//! KEY(ZZ_s)
//! RECV_ENC(E) -> Q_e
//! ZZ_e = Q_e^d_r
//! KEY(ZZ_e)
//! RECV_ENC(C) -> P
//! RECV_MAC(M)
//! ```
//!
//! If the `RECV_MAC` call is successful, the ephemeral public key `E` and the plaintext message
//! `P` are returned.
//!
//! # IND-CCA2 Security
//!
//! This construction combines two overlapping KEM/DEM constructions: a "El Gamal-like" KEM combined
//! with a STROBE-based AEAD, and an ephemeral ECIES-style KEM combined with a STROBE-based AEAD.
//!
//! The STROBE-based AEAD is equivalent to Construction 5.6 of Modern Cryptography 3e and is
//! CCA-secure per Theorem 5.7, provided STROBE's encryption is CPA-secure. STROBE's SEND_ENC is
//! equivalent to Construction 3.31 and is CPA-secure per Theorem 3.29, provided STROBE is a
//! sufficiently strong pseudorandom function.
//!
//! The first KEM/DEM construction is equivalent to Construction 12.19 of Modern Cryptography 3e,
//! and is CCA-secure per Theorem 12.22, provided the gap-CDH problem is hard relative to
//! ristretto255 and STROBE is modeled as a random oracle.
//!
//! The second KEM/DEM construction is equivalent to Construction 12.23 of Modern Cryptography 3e,
//! and is CCA-secure per Corollary 12.24, again provided that the gap-CDH problem is hard relative
//! to ristretto255 and STROBE is modeled as a random oracle.
//!
//! # IK-CCA Security
//!
//! `veil.akem` is IK-CCA (per [Bellare](https://iacr.org/archive/asiacrypt2001/22480568.pdf)), in
//! that it is impossible for an attacker in possession of two public keys to determine which of the
//! two keys a given ciphertext was encrypted with in either chosen-plaintext or chosen-ciphertext
//! attacks. Informally, veil.akem ciphertexts consist exclusively of STROBE ciphertext and PRF
//! output; an attacker being able to distinguish between ciphertexts based on keying material would
//! imply STROBE's AEAD construction is not IND-CCA2.
//!
//! Consequently, a passive adversary scanning for encoded elements would first need the parties'
//! static Diffie-Hellman secret in order to distinguish messages from random noise.
//!
//! # Forward Sender Security
//!
//! Because the ephemeral private key is discarded after encryption, a compromise of the sender's
//! private key will not compromise previously-created ciphertexts. If the sender's private key is
//! compromised, the most an attacker can discover about previously sent messages is the ephemeral
//! public key, not the message itself.
//!
//! # Insider Authenticity
//!
//! This construction is not secure against insider attacks on authenticity, nor is it intended to
//! be. A recipient can forge ciphertexts which appear to be from a sender by re-using the ephemeral
//! public key and encrypting an alternate plaintext, but the forgeries will only be decryptable by
//! the forger. Because this type of forgery is possible, `veil.akem` ciphertexts are therefore
//! repudiable.
//!
//! # Randomness Re-Use
//!
//! The ephemeral key pair, `d_e` and `Q_e`, are generated outside of this construction and can be
//! used multiple times for multiple recipients. This improves the efficiency of the scheme without
//! reducing its security, per Bellare et al.'s treatment of
//! [Randomness Reusing Multi-Recipient Encryption Schemes](http://cseweb.ucsd.edu/~Mihir/papers/bbs.pdf).
//!

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::util::{StrobeExt, MAC_LEN, POINT_LEN};

pub(crate) const OVERHEAD: usize = POINT_LEN + MAC_LEN;

pub(crate) fn encapsulate(
    d_s: &Scalar,
    q_s: &RistrettoPoint,
    d_e: &Scalar,
    q_e: &RistrettoPoint,
    q_r: &RistrettoPoint,
    plaintext: &[u8],
) -> Vec<u8> {
    // Allocate a buffer for output and fill it with plaintext.
    let mut out = vec![0u8; POINT_LEN + plaintext.len() + MAC_LEN];
    out[..POINT_LEN].copy_from_slice(q_e.compress().as_bytes());
    out[POINT_LEN..POINT_LEN + plaintext.len()].copy_from_slice(plaintext);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B256);
    akem.meta_ad_u32(MAC_LEN as u32);

    // Include the sender and receiver as associated data.
    akem.ad_point(q_s);
    akem.ad_point(q_r);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key_point(d_s * q_r);

    // Encrypt the ephemeral public key.
    akem.send_enc(&mut out[..POINT_LEN], false);

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.key_point(d_e * q_r);

    // Encrypt the plaintext.
    akem.send_enc(&mut out[POINT_LEN..POINT_LEN + plaintext.len()], false);

    // Calculate a MAC of the entire operation transcript.
    akem.send_mac(&mut out[POINT_LEN + plaintext.len()..], false);

    // Return the encrypted ephemeral public key, the ciphertext, and the MAC.
    out
}

pub(crate) fn decapsulate(
    d_r: &Scalar,
    q_r: &RistrettoPoint,
    q_s: &RistrettoPoint,
    ciphertext: &[u8],
) -> Option<(RistrettoPoint, Vec<u8>)> {
    if ciphertext.len() < POINT_LEN + MAC_LEN {
        return None;
    }

    // Copy the input for modification.
    let mut out = Vec::from(ciphertext);

    // Initialize the protocol.
    let mut akem = Strobe::new(b"veil.akem", SecParam::B256);
    akem.meta_ad_u32(MAC_LEN as u32);

    // Include the sender and receiver as associated data.
    akem.ad_point(q_s);
    akem.ad_point(q_r);

    // Calculate the static Diffie-Hellman shared secret and key the protocol with it.
    akem.key_point(d_r * q_s);

    // Decrypt the ephemeral public key.
    akem.recv_enc(&mut out[..POINT_LEN], false);

    // Decode the ephemeral public key.
    let q_e = CompressedRistretto::from_slice(&out[..POINT_LEN]).decompress()?;

    // Calculate the ephemeral Diffie-Hellman shared secret and key the protocol with it.
    akem.key_point(d_r * q_e);

    // Decrypt the plaintext.
    akem.recv_enc(&mut out[POINT_LEN..ciphertext.len() - MAC_LEN], false);

    // Verify the MAC.
    akem.recv_mac(&mut out[ciphertext.len() - MAC_LEN..]).ok()?;

    // Return the ephemeral public key and the plaintext.
    Some((q_e, out[POINT_LEN..ciphertext.len() - MAC_LEN].to_vec()))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    use crate::util;

    use super::*;

    #[test]
    fn round_trip() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        let (pk, plaintext) = decapsulate(&d_r, &q_r, &q_s, &ciphertext).expect("decapsulate");

        assert_eq!(q_e, pk);
        assert_eq!(b"this is an example".to_vec(), plaintext);
    }

    #[test]
    fn bad_ephemeral_public_key() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[0] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_ciphertext() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[36] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    #[test]
    fn bad_mac() {
        let (d_s, q_s, d_e, q_e, d_r, q_r) = setup();
        let mut ciphertext = encapsulate(&d_s, &q_s, &d_e, &q_e, &q_r, b"this is an example");
        ciphertext[64] ^= 1;

        assert_eq!(None, decapsulate(&d_r, &q_r, &q_s, &ciphertext));
    }

    fn setup() -> (Scalar, RistrettoPoint, Scalar, RistrettoPoint, Scalar, RistrettoPoint) {
        let d_s = Scalar::from_bytes_mod_order_wide(&util::rand_array());
        let q_s = RISTRETTO_BASEPOINT_POINT * d_s;

        let d_e = Scalar::from_bytes_mod_order_wide(&util::rand_array());
        let q_e = RISTRETTO_BASEPOINT_POINT * d_e;

        let d_r = Scalar::from_bytes_mod_order_wide(&util::rand_array());
        let q_r = RISTRETTO_BASEPOINT_POINT * d_r;

        (d_s, q_s, d_e, q_e, d_r, q_r)
    }
}
