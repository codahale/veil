use std::convert::TryInto;
use std::fmt::{Debug, Formatter};
use std::io::{BufWriter, Read, Write};
use std::str::FromStr;
use std::{fmt, io, iter};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::prelude::SliceRandom;
use rand::RngCore;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

use crate::constants::POINT_LEN;
use crate::schnorr::{Signer, Verifier, SIGNATURE_LEN};
use crate::{mres, pbenc, scaldf};

/// Error due to invalid public key format.
#[derive(Error, Debug, Eq, PartialEq, Copy, Clone)]
#[error("invalid public key")]
pub struct PublicKeyError;

/// Error due to invalid signature format.
#[derive(Error, Debug, Eq, PartialEq, Copy, Clone)]
#[error("invalid signature")]
pub struct SignatureError;

/// The error type for message decryption.
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// Error due to message/private key/public key mismatch.
    ///
    /// The ciphertext may have been altered, the message may not have been encrypted by the given
    /// sender, or the message may not have been encrypted for the given recipient.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// An error returned when there was an underlying IO error during decryption.
    #[error("error decrypting: {0}")]
    IoError(#[from] io::Error),
}

/// The error type for message verification.
#[derive(Error, Debug)]
pub enum VerificationError {
    /// Error due to signature/message/public key mismatch.
    ///
    /// The message or signature may have been altered, or the message may not have been signed with
    /// the given key.
    #[error("invalid signature")]
    InvalidSignature,

    /// The reader containing the message returned an IO error.
    #[error("error verifying: {0}")]
    IoError(#[from] io::Error),
}

/// A 512-bit secret from which multiple private keys can be derived.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    r: [u8; 64],
}

impl SecretKey {
    /// Return a randomly generated secret key.
    #[must_use]
    pub fn new() -> SecretKey {
        let mut r = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut r);
        SecretKey { r }
    }

    /// Encrypt the secret key with the given passphrase and pbenc parameters.
    #[must_use]
    pub fn encrypt(&self, passphrase: &str, time: u32, space: u32, block_size: u32) -> Vec<u8> {
        pbenc::encrypt(passphrase, time, space, block_size, &self.r)
    }

    /// Decrypt the secret key with the given passphrase and pbenc parameters.
    pub fn decrypt(passphrase: &str, ciphertext: &[u8]) -> Result<SecretKey, DecryptionError> {
        pbenc::decrypt(passphrase, ciphertext)
            .and_then(|b| b.try_into().ok())
            .map(|r| SecretKey { r })
            .ok_or(DecryptionError::InvalidCiphertext)
    }

    /// Derive a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. `/` -> `one` -> `two` -> `three`).
    #[must_use]
    pub fn private_key(&self, key_id: &str) -> PrivateKey {
        self.root().derive(key_id)
    }

    /// Derive a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. `/` -> `one` -> `two` -> `three`).
    #[must_use]
    pub fn public_key(&self, key_id: &str) -> PublicKey {
        self.private_key(key_id).public_key()
    }

    #[must_use]
    fn root(&self) -> PrivateKey {
        let d = scaldf::derive_root(&self.r);
        PrivateKey { d, pk: PublicKey { q: &G * &d } }
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.root().fmt(f)
    }
}

/// A derived private key, used to encrypt, decrypt, and sign messages.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    d: Scalar,
    #[zeroize(skip)]
    pk: PublicKey,
}

impl PrivateKey {
    /// Return the corresponding public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.pk
    }

    /// Encrypt the contents of the reader such that any of the recipients will be able to decrypt
    /// it with authenticity and writes the ciphertext to the writer.
    ///
    /// Optionally add a number of fake recipients to disguise the number of true recipients and/or
    /// random padding to disguise the message length.
    pub fn encrypt<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        recipients: Vec<PublicKey>,
        fakes: usize,
        padding: u64,
    ) -> io::Result<u64>
    where
        R: Read,
        W: Write,
    {
        // Add fakes.
        let mut q_rs = recipients
            .into_iter()
            .map(|pk| pk.q)
            .chain(
                iter::repeat_with(|| RistrettoPoint::random(&mut rand::thread_rng())).take(fakes),
            )
            .collect::<Vec<RistrettoPoint>>();

        // Shuffle the recipients list.
        q_rs.shuffle(&mut rand::thread_rng());

        // Finally, encrypt.
        mres::encrypt(reader, &mut BufWriter::new(writer), &self.d, &self.pk.q, q_rs, padding)
    }

    /// Decrypt the contents of the reader, if possible, and writes the plaintext to the writer.
    ///
    /// If the ciphertext has been modified, was not sent by the sender, or was not encrypted for
    /// this private key, will return [DecryptionError::InvalidCiphertext].
    pub fn decrypt<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        sender: &PublicKey,
    ) -> Result<u64, DecryptionError>
    where
        R: Read,
        W: Write,
    {
        let (verified, written) =
            mres::decrypt(reader, &mut BufWriter::new(writer), &self.d, &self.pk.q, &sender.q)?;

        if verified {
            Ok(written)
        } else {
            Err(DecryptionError::InvalidCiphertext)
        }
    }

    /// Read the contents of the reader and returns a digital signature.
    pub fn sign<R>(&self, reader: &mut R) -> io::Result<Signature>
    where
        R: Read,
    {
        let mut signer = Signer::new(io::sink());
        io::copy(reader, &mut signer)?;
        let (sig, _) = signer.sign(&self.d, &self.pk.q);
        Ok(Signature { sig: (sig) })
    }

    /// Derive a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    #[must_use]
    pub fn derive(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_scalar(self.d, key_id);
        PrivateKey { d, pk: PublicKey { q: &G * &d } }
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.pk.fmt(f)
    }
}

/// A Schnorr signature.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Signature {
    sig: [u8; SIGNATURE_LEN],
}

impl FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bs58::decode(s)
            .into_vec()
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|sig| Signature { sig })
            .ok_or(SignatureError)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.sig).into_string())
    }
}

/// A derived public key, used to verify messages.
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub struct PublicKey {
    q: RistrettoPoint,
}

impl PublicKey {
    /// Read the contents of the reader and return `Ok(())` iff the given signature was created by
    /// this public key of the exact contents. Otherwise, returns
    /// [VerificationError::InvalidSignature].
    pub fn verify<R>(&self, reader: &mut R, sig: &Signature) -> Result<(), VerificationError>
    where
        R: Read,
    {
        let mut verifier = Verifier::new();
        io::copy(reader, &mut verifier)?;
        verifier.verify(&self.q, &sig.sig).then(|| ()).ok_or(VerificationError::InvalidSignature)
    }

    /// Derive a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    #[must_use]
    pub fn derive(&self, key_id: &str) -> PublicKey {
        PublicKey { q: scaldf::derive_point(&self.q, key_id) }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.q.compress().as_bytes()).into_string())
    }
}

impl FromStr for PublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bs58::decode(s)
            .into_vec()
            .ok()
            .filter(|b| b.len() == POINT_LEN)
            .map(|b| CompressedRistretto::from_slice(&b))
            .and_then(|p| p.decompress())
            .map(|q| PublicKey { q })
            .ok_or(PublicKeyError)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    pub fn private_key_derivation() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c");
        let abc_p = sk.private_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }

    #[test]
    pub fn public_key_derivation() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c").public_key();
        let abc_p = sk.public_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }

    #[test]
    pub fn public_key_encoding() {
        let base = PublicKey { q: G.basepoint() };

        assert_eq!("GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3", base.to_string());

        let decoded = "GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3".parse::<PublicKey>();
        assert_eq!(Ok(base), decoded);

        assert_eq!(Err(PublicKeyError), "woot woot".parse::<PublicKey>());
    }

    #[test]
    pub fn signature_encoding() {
        let sig = Signature { sig: [69u8; SIGNATURE_LEN] };

        assert_eq!("2PKwbVQ1YMFEexCmUDyxy8cuwb69VWcvoeodZCLegqof62ro8siurvh9QCnFzdsdTixDC94tCMzH7dMuqL5Gi2CC", sig.to_string());

        let decoded = "2PKwbVQ1YMFEexCmUDyxy8cuwb69VWcvoeodZCLegqof62ro8siurvh9QCnFzdsdTixDC94tCMzH7dMuqL5Gi2CC".parse::<Signature>();
        assert_eq!(Ok(sig), decoded);

        assert_eq!(Err(SignatureError), "woot woot".parse::<Signature>());
    }

    #[test]
    pub fn round_trip() -> Result<(), DecryptionError> {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(&mut src, &mut dst, vec![priv_b.public_key()], 20, 123)?;
        assert_eq!(dst.position(), ctx_len);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key())?;
        assert_eq!(dst.position(), ptx_len);
        assert_eq!(message.to_vec(), dst.into_inner());

        Ok(())
    }

    #[test]
    pub fn bad_sender_key() -> Result<(), DecryptionError> {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(&mut src, &mut dst, vec![priv_b.public_key()], 20, 123)?;
        assert_eq!(dst.position(), ctx_len);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_failed_decryption(priv_b.decrypt(&mut src, &mut dst, &priv_b.public_key()))
    }

    #[test]
    pub fn bad_recipient() -> Result<(), DecryptionError> {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(&mut src, &mut dst, vec![priv_a.public_key()], 20, 123)?;
        assert_eq!(dst.position(), ctx_len);

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_failed_decryption(priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key()))
    }

    #[test]
    pub fn bad_ciphertext() -> Result<(), DecryptionError> {
        let sk_a = SecretKey::new();
        let priv_a = sk_a.private_key("/one/two");

        let sk_b = SecretKey::new();
        let priv_b = sk_b.private_key("/a/b");

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(&mut src, &mut dst, vec![priv_b.public_key()], 20, 123)?;
        assert_eq!(dst.position(), ctx_len);

        let mut ciphertext = dst.into_inner();
        ciphertext[200] ^= 1;

        let mut src = Cursor::new(ciphertext);
        let mut dst = Cursor::new(Vec::new());

        assert_failed_decryption(priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key()))
    }

    #[test]
    pub fn sign_and_verify() -> Result<(), VerificationError> {
        let sk = SecretKey::new();
        let priv_a = sk.private_key("/one/two");
        let pub_a = priv_a.public_key();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);

        let sig = priv_a.sign(&mut src)?;

        let mut src = Cursor::new(message);
        pub_a.verify(&mut src, &sig)
    }

    fn assert_failed_decryption(
        result: Result<u64, DecryptionError>,
    ) -> Result<(), DecryptionError> {
        match result {
            Ok(_) => panic!("decrypted but shouldn't have"),
            Err(DecryptionError::InvalidCiphertext) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
