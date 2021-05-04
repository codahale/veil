#![warn(missing_docs)]

//! The Veil hybrid cryptosystem.
//!
//! Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
//! authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
//! Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
//! encrypted. As a result, a global passive adversary would be unable to gain any information from
//! a Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise
//! their true length, and fake recipients can be added to disguise their true number from other
//! recipients.
//!
//! You should not use this.
//!
//!
//! ```
//! use std::{io, str};
//! use veil_lib::SecretKey;
//!
//! // Alice creates a secret key.
//! let alice_sk = SecretKey::new();
//!
//! // Bea creates a secret key.
//! let bea_sk = SecretKey::new();
//!
//! // Alice derives a private key for messaging with Bea and shares the corresponding public key.
//! let alice_priv = alice_sk.private_key("/friends/bea");
//! let alice_pub = alice_priv.public_key();
//!
//! // Bea derives a private key for messaging with Alice and shares the corresponding public key.
//! let bea_priv = bea_sk.private_key("/buddies/cool-ones/alice");
//! let bea_pub = bea_priv.public_key();
//!
//! // Alice encrypts a secret message for Bea.
//! let mut ciphertext = io::Cursor::new(Vec::new());
//! alice_priv.encrypt(
//!   &mut io::Cursor::new("this is a secret message"),
//!   &mut ciphertext,
//!   vec![bea_pub],
//!   20,
//!   1234,
//! ).expect("encryption failed");
//!
//! // Bea decrypts the message.
//! let mut plaintext = io::Cursor::new(Vec::new());
//! bea_priv.decrypt(
//!   &mut io::Cursor::new(ciphertext.into_inner()),
//!   &mut plaintext,
//!   &alice_pub,
//! ).expect("decryption failed");
//!
//! // Having decrypted the message, Bea can read the plaintext.
//! assert_eq!(
//!   "this is a secret message",
//!   str::from_utf8(&plaintext.into_inner()).expect("invalid UTF-8"),
//! );
//! ```

use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;
use std::{cmp, error, fmt, io, iter};

use base58::{FromBase58, ToBase58};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::Rng;
use zeroize::Zeroize;

pub mod akem;
pub mod mres;
pub mod pbenc;
pub mod scaldf;
pub mod schnorr;

/// Veil's custom result type.
pub type Result<T> = std::result::Result<T, VeilError>;

/// The full set of Veil errors.
#[derive(Debug)]
pub enum VeilError {
    /// Returned when a ciphertext can't be decrypted.
    InvalidCiphertext(),
    /// Returned when a signature is invalid.
    InvalidSignature(),
    /// Returned when a public key is invalid.
    InvalidPublicKey(),
    /// Returned when an underlying IO error occured.
    IoError(io::Error),
}

impl fmt::Display for VeilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VeilError::InvalidCiphertext() => f.write_str("invalid ciphertext"),
            VeilError::InvalidSignature() => f.write_str("invalid signature"),
            VeilError::InvalidPublicKey() => f.write_str("invalid public key"),
            VeilError::IoError(e) => std::fmt::Display::fmt(&e, f),
        }
    }
}

impl error::Error for VeilError {}

/// A 512-bit secret from which multiple private keys can be derived.
pub struct SecretKey([u8; 64]);

impl SecretKey {
    /// Returns a randomly generated secret key.
    pub fn new() -> SecretKey {
        let mut seed = [0u8; 64];
        rand::thread_rng().fill(&mut seed);

        SecretKey(seed)
    }

    /// Encrypts the secret key with the given passphrase and pbenc parameters.
    pub fn encrypt(&self, passphrase: &[u8], time: u32, space: u32) -> Vec<u8> {
        pbenc::encrypt(passphrase, &self.0, time, space)
    }

    /// Decrypts the secret key with the given passphrase and pbenc parameters.
    pub fn decrypt(passphrase: &[u8], ciphertext: &[u8]) -> Result<SecretKey> {
        pbenc::decrypt(passphrase, ciphertext)
            .ok_or(VeilError::InvalidCiphertext())
            .and_then(|plaintext| {
                let seed: Option<[u8; 64]> = plaintext.try_into().ok();
                seed.ok_or(VeilError::InvalidCiphertext())
            })
            .map(SecretKey)
    }

    /// Derives a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn private_key(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_root(&self.0);
        let q = RISTRETTO_BASEPOINT_POINT * d;
        PrivateKey(d, PublicKey(q)).derive(key_id)
    }

    /// Derives a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn public_key(&self, key_id: &str) -> PublicKey {
        self.private_key(key_id).1
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A derived private key, used to encrypt, decrypt, and sign messages.
pub struct PrivateKey(Scalar, PublicKey);

impl PrivateKey {
    /// Returns the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        self.1
    }

    /// Encrypts the contents of the reader such that any of the recipients will be able to decrypt
    /// it with authenticity and writes the ciphertext to the writer.
    ///
    /// Optionally adds a number of fake recipients and random padding to disguise the number of
    /// true recipients and message length.
    pub fn encrypt<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        recipients: Vec<PublicKey>,
        fakes: usize,
        padding: u64,
    ) -> Result<u64>
    where
        R: io::Read,
        W: io::Write,
    {
        // Add any fakes and shuffle the recipients list.
        let mut rng = rand::thread_rng();
        let mut q_rs: Vec<RistrettoPoint> = recipients
            .into_iter()
            .map(|pk| pk.0)
            .chain(iter::from_fn(|| Some(RistrettoPoint::random(&mut rng))).take(fakes))
            .collect();
        q_rs.shuffle(&mut rng);

        // Finally, encrypt.
        mres::encrypt(
            &mut io::BufReader::new(reader),
            &mut io::BufWriter::new(writer),
            &self.0,
            &self.1 .0,
            q_rs,
            padding,
        )
        .map_err(VeilError::IoError)
    }

    /// Decrypts the contents of the reader, if possible, and writes the plaintext to the writer.
    ///
    /// If the ciphertext has been modified, was not sent by the sender, or was not encrypted for
    /// this private key, will return an error.
    pub fn decrypt<R, W>(&self, reader: &mut R, writer: &mut W, sender: &PublicKey) -> Result<u64>
    where
        R: io::Read,
        W: io::Write,
    {
        mres::decrypt(
            &mut io::BufReader::new(reader),
            &mut io::BufWriter::new(writer),
            &self.0,
            &self.1 .0,
            &sender.0,
        )
        .map_err(VeilError::IoError)
        .and_then(|o| o.ok_or(VeilError::InvalidCiphertext()))
    }

    /// Reads the contents of the reader and returns a Schnorr signature.
    pub fn sign<R: io::Read>(&self, reader: &mut R) -> Result<Signature> {
        let mut signer = schnorr::Signer::new(io::sink());
        io::copy(reader, &mut signer).map_err(VeilError::IoError)?;
        Ok(Signature(signer.sign(&self.0, &self.1 .0)))
    }

    /// Derives a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn derive(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_scalar(&self.0, key_id);
        let q = RISTRETTO_BASEPOINT_POINT * d;
        PrivateKey(d, PublicKey(q))
    }
}

impl cmp::PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.1 == other.1
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.1.fmt(f)
    }
}

/// A Schnorr signature.
pub struct Signature([u8; 64]);

impl Signature {
    /// Converts the signature to a base58 string.
    pub fn to_ascii(&self) -> String {
        self.0.to_base58()
    }

    /// Parses the given base58 string and returns a signature.
    pub fn from_ascii(s: &str) -> Option<Signature> {
        let sig: [u8; 64] = s.from_base58().ok()?.try_into().ok()?;
        Some(Signature(sig))
    }
}

impl TryFrom<&str> for Signature {
    type Error = VeilError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Signature::from_ascii(value).ok_or(VeilError::InvalidSignature())
    }
}

/// A derived public key, used to verify messages.
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    /// Converts the public key to a base58 string.
    pub fn to_ascii(&self) -> String {
        self.0.compress().to_bytes().to_base58()
    }

    /// Parses the given base58 string and returns a public key.
    pub fn from_ascii(s: &str) -> Option<PublicKey> {
        let b = s.from_base58().ok()?;
        let q = CompressedRistretto::from_slice(&b).decompress()?;
        Some(PublicKey(q))
    }

    /// Reads the contents of the reader returns () iff the given signature was created by this
    /// public key of the exact contents.
    pub fn verify<R: io::Read>(&self, reader: &mut R, sig: &Signature) -> Result<()> {
        let mut verifier = schnorr::Verifier::new();
        io::copy(reader, &mut verifier).map_err(VeilError::IoError)?;
        if verifier.verify(&self.0, &sig.0) {
            Ok(())
        } else {
            Err(VeilError::InvalidSignature())
        }
    }

    /// Derives a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn derive(&self, key_id: &str) -> PublicKey {
        PublicKey(scaldf::derive_point(&self.0, key_id))
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = VeilError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        PublicKey::from_ascii(value).ok_or(VeilError::InvalidPublicKey())
    }
}

pub(crate) const MAC_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use std::io;

    use crate::SecretKey;

    #[test]
    pub fn private_keys() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c");
        let abc_p = sk.private_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }

    #[test]
    pub fn public_keys() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c").public_key();
        let abc_p = sk.public_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }

    #[test]
    pub fn round_trip() {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = io::Cursor::new(message);
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut src, &mut dst, vec![priv_b.public_key()], 20, 123)
            .expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut src = io::Cursor::new(dst.into_inner());
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = priv_b
            .decrypt(&mut src, &mut dst, &priv_a.public_key())
            .expect("decrypt");
        assert_eq!(dst.position(), ptx_len);
        assert_eq!(message.to_vec(), dst.into_inner());
    }

    #[test]
    pub fn bad_sender_key() {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = io::Cursor::new(message);
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut src, &mut dst, vec![priv_b.public_key()], 20, 123)
            .expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut src = io::Cursor::new(dst.into_inner());
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = priv_b.decrypt(&mut src, &mut dst, &priv_b.public_key());
        assert_eq!(true, ptx_len.is_err());
    }

    #[test]
    pub fn bad_recipient() {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = io::Cursor::new(message);
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut src, &mut dst, vec![priv_a.public_key()], 20, 123)
            .expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut src = io::Cursor::new(dst.into_inner());
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key());
        assert_eq!(true, ptx_len.is_err());
    }

    #[test]
    pub fn bad_ciphertext() {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = io::Cursor::new(message);
        let mut dst = io::Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut src, &mut dst, vec![priv_b.public_key()], 20, 123)
            .expect("encrypt");
        assert_eq!(dst.position(), ctx_len);

        let mut ciphertext = dst.into_inner();
        ciphertext[200] ^= 1;

        let mut src = io::Cursor::new(ciphertext);
        let mut dst = io::Cursor::new(Vec::new());

        let ptx_len = priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key());
        assert_eq!(true, ptx_len.is_err());
    }
}
