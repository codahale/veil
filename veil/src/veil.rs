use std::convert::TryInto;
use std::fmt::{Debug, Formatter};
use std::str;
use std::{cmp, fmt, io, iter, result};

use base58::{FromBase58, ToBase58};
use byteorder::ByteOrder;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use thiserror::Error;
use zeroize::Zeroize;

use crate::VeilError::IoError;
use crate::{mres, pbenc, scaldf, schnorr};

/// Veil's custom result type.
pub type Result<T> = result::Result<T, VeilError>;

/// The full set of Veil errors.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum VeilError {
    /// Returned when a ciphertext can't be decrypted.
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    /// Returned when a signature is invalid.
    #[error("invalid signature")]
    InvalidSignature,
    /// Returned when a public key is invalid.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Returned when a secret key can't be decrypted.
    #[error("invalid secret key/passphrase")]
    InvalidSecretKey,
    /// Returned when an underlying IO error occured.
    #[error("io error: {source:?}")]
    IoError {
        /// The source of the IO error.
        #[from]
        source: io::Error,
    },
}

pub(crate) fn io_error(source: io::Error) -> VeilError {
    IoError { source }
}

/// A 512-bit secret from which multiple private keys can be derived.
pub struct SecretKey {
    r: [u8; 64],
}

impl SecretKey {
    /// Returns a randomly generated secret key.
    pub fn new() -> SecretKey {
        let mut r = [0u8; 64];
        getrandom::getrandom(&mut r).expect("rng failure");

        SecretKey { r }
    }

    /// Encrypts the secret key with the given passphrase and pbenc parameters.
    pub fn encrypt(&self, passphrase: &[u8], time: u32, space: u32) -> Vec<u8> {
        pbenc::encrypt(passphrase, &self.r, time, space)
    }

    /// Decrypts the secret key with the given passphrase and pbenc parameters.
    pub fn decrypt(passphrase: &[u8], ciphertext: &[u8]) -> Result<SecretKey> {
        pbenc::decrypt(passphrase, ciphertext)
            .ok_or(VeilError::InvalidSecretKey)
            .and_then(|plaintext| {
                plaintext
                    .try_into()
                    .map_err(|_| VeilError::InvalidSecretKey)
            })
            .map(|r| SecretKey { r })
    }

    /// Derives a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn private_key(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_root(&self.r);
        PrivateKey {
            d,
            pk: PublicKey {
                q: RISTRETTO_BASEPOINT_POINT * d,
            },
        }
        .derive(key_id)
    }

    /// Derives a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn public_key(&self, key_id: &str) -> PublicKey {
        self.private_key(key_id).pk
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.r.zeroize();
    }
}

/// A derived private key, used to encrypt, decrypt, and sign messages.
pub struct PrivateKey {
    d: Scalar,
    pk: PublicKey,
}

impl PrivateKey {
    /// Returns the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        self.pk
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
        // Add fakes.
        let mut q_rs = recipients
            .into_iter()
            .map(|pk| pk.q)
            .chain(iter::repeat_with(rand_point).take(fakes))
            .collect();

        // Shuffle the recipients list.
        shuffle(&mut q_rs);

        // Finally, encrypt.
        mres::encrypt(
            &mut io::BufReader::new(reader),
            &mut io::BufWriter::new(writer),
            &self.d,
            &self.pk.q,
            q_rs,
            padding,
        )
        .map_err(io_error)
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
            &self.d,
            &self.pk.q,
            &sender.q,
        )
    }

    /// Reads the contents of the reader and returns a Schnorr signature.
    pub fn sign<R: io::Read>(&self, reader: &mut R) -> Result<Signature> {
        let mut signer = schnorr::Signer::new(io::sink());
        io::copy(reader, &mut signer).map_err(io_error)?;
        Ok(Signature {
            sig: signer.sign(&self.d, &self.pk.q),
        })
    }

    /// Derives a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn derive(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_scalar(&self.d, key_id);
        PrivateKey {
            d,
            pk: PublicKey {
                q: RISTRETTO_BASEPOINT_POINT * d,
            },
        }
    }
}

impl cmp::PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pk.fmt(f)
    }
}

/// A Schnorr signature.
pub struct Signature {
    sig: [u8; 64],
}

impl str::FromStr for Signature {
    type Err = VeilError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        s.from_base58()
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|sig| Signature { sig })
            .ok_or(VeilError::InvalidSignature)
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
    /// Reads the contents of the reader returns () iff the given signature was created by this
    /// public key of the exact contents.
    pub fn verify<R: io::Read>(&self, reader: &mut R, sig: &Signature) -> Result<()> {
        let mut verifier = schnorr::Verifier::new();
        io::copy(reader, &mut verifier).map_err(io_error)?;
        if verifier.verify(&self.q, &sig.sig) {
            Ok(())
        } else {
            Err(VeilError::InvalidSignature)
        }
    }

    /// Derives a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn derive(&self, key_id: &str) -> PublicKey {
        PublicKey {
            q: scaldf::derive_point(&self.q, key_id),
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.q.compress().as_bytes().to_base58())
    }
}

impl str::FromStr for PublicKey {
    type Err = VeilError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let b = s.from_base58().map_err(|_| VeilError::InvalidPublicKey)?;
        if b.len() != 32 {
            return Err(VeilError::InvalidPublicKey);
        }

        let cp = CompressedRistretto::from_slice(&b);
        cp.decompress()
            .map(|q| PublicKey { q })
            .ok_or(VeilError::InvalidPublicKey)
    }
}

pub(crate) const MAC_LEN: usize = 16;

fn rand_point() -> RistrettoPoint {
    let mut seed = [0u8; 64];
    getrandom::getrandom(&mut seed).expect("rng failure");

    RistrettoPoint::from_uniform_bytes(&seed)
}

fn shuffle(pks: &mut Vec<RistrettoPoint>) {
    // Fisher-Yates shuffle with cryptographically generated numbers
    assert!(pks.len() < u32::MAX as usize);
    let mut buf = [0u8; 4];
    for i in (1..pks.len()).rev() {
        let max = ((1 << 31) - 1 - (1 << 31) % (i + 1)) as usize;
        loop {
            getrandom::getrandom(&mut buf).expect("rng failure");
            let n = byteorder::LE::read_u32(&buf) as usize;
            if n > max {
                continue;
            }

            pks.swap(i, n % (i + 1));
            break;
        }
    }
}

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
