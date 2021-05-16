use std::convert::TryInto;
use std::fmt::{Debug, Formatter};
use std::io::{BufReader, BufWriter, Read, Write};
use std::{fmt, io, iter, str};

use base58::{FromBase58, ToBase58};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::schnorr::{Signer, Verifier, SIGNATURE_LEN};
use crate::util::POINT_LEN;
use crate::{
    mres, pbenc, scaldf, util, DecryptionError, PublicKeyError, SignatureError, VerificationError,
};

/// A 512-bit secret from which multiple private keys can be derived.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    r: [u8; 64],
}

impl SecretKey {
    /// Return a randomly generated secret key.
    pub fn new() -> SecretKey {
        SecretKey { r: util::rand_array() }
    }

    /// Encrypt the secret key with the given passphrase and pbenc parameters.
    pub fn encrypt(&self, passphrase: &[u8], time: u32, space: u32) -> Vec<u8> {
        pbenc::encrypt(passphrase, time, space, &self.r)
    }

    /// Decrypt the secret key with the given passphrase and pbenc parameters.
    pub fn decrypt(passphrase: &[u8], ciphertext: &[u8]) -> Result<SecretKey, DecryptionError> {
        pbenc::decrypt(passphrase, ciphertext)
            .and_then(|b| b.try_into().ok())
            .map(|r| SecretKey { r })
            .ok_or(DecryptionError::InvalidCiphertext)
    }

    /// Derive a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. `/` -> `one` -> `two` -> `three`).
    pub fn private_key(&self, key_id: &str) -> PrivateKey {
        self.root().derive(key_id)
    }

    /// Derive a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. `/` -> `one` -> `two` -> `three`).
    pub fn public_key(&self, key_id: &str) -> PublicKey {
        self.private_key(key_id).public_key()
    }

    fn root(&self) -> PrivateKey {
        let d = scaldf::derive_root(&self.r);
        PrivateKey { d, pk: PublicKey { q: RISTRETTO_BASEPOINT_POINT * d } }
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
#[derive(Copy, Clone)]
pub struct PrivateKey {
    d: Scalar,
    pk: PublicKey,
}

impl PrivateKey {
    /// Return the corresponding public key.
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
            .chain(iter::repeat_with(util::rand_point).take(fakes))
            .collect();

        // Shuffle the recipients list.
        shuffle(&mut q_rs);

        // Finally, encrypt.
        mres::encrypt(
            &mut BufReader::new(reader),
            &mut BufWriter::new(writer),
            &self.d,
            &self.pk.q,
            q_rs,
            padding,
        )
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
        let (verified, written) = mres::decrypt(
            &mut BufReader::new(reader),
            &mut BufWriter::new(writer),
            &self.d,
            &self.pk.q,
            &sender.q,
        )?;
        verified.then(|| written).ok_or(DecryptionError::InvalidCiphertext)
    }

    /// Read the contents of the reader and returns a digital signature.
    pub fn sign<R>(&self, reader: &mut R) -> io::Result<Signature>
    where
        R: Read,
    {
        let mut signer = Signer::new(io::sink());
        io::copy(reader, &mut signer)?;
        Ok(Signature { sig: signer.sign(&self.d, &self.pk.q) })
    }

    /// Derive a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn derive(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_scalar(self.d, key_id);
        PrivateKey { d, pk: PublicKey { q: RISTRETTO_BASEPOINT_POINT * d } }
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

impl str::FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.from_base58()
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|sig| Signature { sig })
            .ok_or(SignatureError)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sig.to_base58())
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
    pub fn derive(&self, key_id: &str) -> PublicKey {
        PublicKey { q: scaldf::derive_point(&self.q, key_id) }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.q.compress().as_bytes().to_base58())
    }
}

impl str::FromStr for PublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.from_base58()
            .ok()
            .filter(|b| b.len() == POINT_LEN)
            .map(|b| CompressedRistretto::from_slice(&b))
            .and_then(|p| p.decompress())
            .map(|q| PublicKey { q })
            .ok_or(PublicKeyError)
    }
}

/// Fisher-Yates shuffle with cryptographically generated random numbers.
fn shuffle(pks: &mut Vec<RistrettoPoint>) {
    for i in (1..pks.len()).rev() {
        pks.swap(i, rand_usize(i + 1));
    }
}

/// Generate a random `usize` in `[0..n)` using rejection sampling.
#[inline]
fn rand_usize(n: usize) -> usize {
    let max = (usize::MAX - 1 - (usize::MAX % n)) as u64;
    let mut v = max;
    while v > max {
        v = u64::from_le_bytes(util::rand_array());
    }
    (v % n as u64) as usize
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

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
        let base = PublicKey { q: RISTRETTO_BASEPOINT_POINT };

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
