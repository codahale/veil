//! The Veil hybrid cryptosystem.

use std::fmt::{Debug, Formatter};
use std::io::{BufWriter, Read, Write};
use std::str::FromStr;
use std::{fmt, io, iter};

use rand::prelude::SliceRandom;
use rand::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ristretto::{CanonicallyEncoded, Point, Scalar, G};
use crate::schnorr::{Signer, Verifier};
use crate::{hkd, mres, pbenc, DecryptError, ParsePublicKeyError, Signature, VerifyError};

/// A 512-bit secret from which multiple private keys can be derived.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    r: Vec<u8>,
}

impl SecretKey {
    /// Create a randomly generated secret key.
    #[must_use]
    pub fn random(mut rng: impl Rng + CryptoRng) -> SecretKey {
        SecretKey { r: rng.gen::<[u8; SECRET_KEY_LEN]>().to_vec() }
    }

    /// Encrypt the secret key with the given passphrase and `veil.pbenc` parameters.
    #[must_use]
    pub fn encrypt(
        &self,
        rng: impl Rng + CryptoRng,
        passphrase: &str,
        time: u32,
        space: u32,
    ) -> Vec<u8> {
        pbenc::encrypt(rng, passphrase, time, space, &self.r)
    }

    /// Decrypt the secret key with the given passphrase.
    ///
    /// # Errors
    ///
    /// If the passphrase is incorrect and/or the ciphertext has been modified, a
    /// [DecryptError::InvalidCiphertext] error will be returned.
    pub fn decrypt(passphrase: &str, ciphertext: &[u8]) -> Result<SecretKey, DecryptError> {
        // Decrypt the ciphertext and use the plaintext as the secret key.
        pbenc::decrypt(passphrase, ciphertext)
            .filter(|r| r.len() == SECRET_KEY_LEN)
            .map(|r| SecretKey { r })
            .ok_or(DecryptError::InvalidCiphertext)
    }

    /// Returns the root private key.
    #[must_use]
    pub fn private_key(&self) -> PrivateKey {
        let d = hkd::root_key(&self.r);
        PrivateKey { d, pk: PublicKey { q: &d * &G } }
    }

    /// Returns the root public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.private_key().public_key()
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.public_key().fmt(f)
    }
}

const SECRET_KEY_LEN: usize = 64;

/// A derived private key, used to encrypt, decrypt, and sign messages.
#[derive(ZeroizeOnDrop)]
pub struct PrivateKey {
    d: Scalar,
    pk: PublicKey,
}

impl PrivateKey {
    /// Return the corresponding public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.pk
    }

    /// Encrypt the contents of the reader and write the ciphertext to the writer.
    ///
    /// Optionally add a number of fake recipients to disguise the number of true recipients and/or
    /// random padding to disguise the message length.
    pub fn encrypt(
        &self,
        mut rng: impl Rng + CryptoRng,
        reader: &mut impl Read,
        writer: &mut impl Write,
        recipients: &[PublicKey],
        fakes: Option<usize>,
        padding: Option<u64>,
    ) -> io::Result<u64> {
        // Add fakes.
        let mut q_rs = recipients
            .iter()
            .map(|pk| pk.q)
            .chain(iter::repeat_with(|| Point::random(&mut rng)).take(fakes.unwrap_or_default()))
            .collect::<Vec<Point>>();

        // Shuffle the recipients list.
        q_rs.shuffle(&mut rng);

        // Finally, encrypt.
        mres::encrypt(
            &mut rng,
            reader,
            &mut BufWriter::new(writer),
            &self.d,
            &self.pk.q,
            &q_rs,
            padding.unwrap_or_default(),
        )
    }

    /// Decrypt the contents of the reader, if possible, and write the plaintext to the writer.
    ///
    /// If the ciphertext has been modified, was not sent by the sender, or was not encrypted for
    /// this private key, returns [DecryptError::InvalidCiphertext].
    pub fn decrypt(
        &self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        sender: &PublicKey,
    ) -> Result<u64, DecryptError> {
        mres::decrypt(reader, &mut BufWriter::new(writer), &self.d, &self.pk.q, &sender.q)
    }

    /// Read the contents of the reader and return a digital signature.
    pub fn sign(&self, rng: impl Rng + CryptoRng, reader: &mut impl Read) -> io::Result<Signature> {
        let mut signer = Signer::new(io::sink());
        io::copy(reader, &mut signer)?;
        let (sig, _) = signer.sign(rng, &self.d, &self.pk.q)?;
        Ok(sig)
    }

    /// Derive a private key with the given key path.
    #[must_use]
    pub fn derive<T>(&self, key_path: &[T]) -> PrivateKey
    where
        T: AsRef<[u8]>,
    {
        let (d, q) = key_path.iter().fold((self.d, self.pk.q), |(d, q), l| {
            let d = d + hkd::label_scalar(&q, l);
            (d, &d * &G)
        });
        PrivateKey { d, pk: PublicKey { q } }
    }
}

impl Eq for PrivateKey {}

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

/// A derived public key, used to verify messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct PublicKey {
    q: Point,
}

impl PublicKey {
    /// Read the contents of the reader and return `Ok(())` iff the given signature was created by
    /// this public key of the exact contents. Otherwise, returns [VerifyError::InvalidSignature].
    pub fn verify(&self, reader: &mut impl Read, sig: &Signature) -> Result<(), VerifyError> {
        let mut verifier = Verifier::new();
        io::copy(reader, &mut verifier)?;

        verifier.verify(&self.q, sig)
    }

    /// Derive a public key with the given key path.
    #[must_use]
    pub fn derive<T>(&self, key_path: &[T]) -> PublicKey
    where
        T: AsRef<[u8]>,
    {
        PublicKey { q: key_path.iter().fold(self.q, |q, l| q + &hkd::label_scalar(&q, l) * &G) }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.q.to_canonical_encoding()).into_string())
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bs58::decode(s)
            .into_vec()
            .ok()
            .and_then(|b| Point::from_canonical_encoding(&b))
            .map(|q| PublicKey { q })
            .ok_or(ParsePublicKeyError)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn hierarchical_key_derivation() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sk = SecretKey::random(&mut rng);

        let abc = sk.private_key().derive(&["a", "b", "c"]).public_key();
        let abc_p = sk.public_key().derive(&["a", "b", "c"]);
        assert_eq!(abc, abc_p, "invalid hierarchical derivation");

        let abc = sk.private_key().derive(&["a", "b", "c"]);
        let cba = sk.private_key().derive(&["c", "b", "a"]);
        assert_ne!(abc, cba, "invalid hierarchical derivation");

        let abc = sk.private_key().derive(&["a"]).derive(&["b"]).derive(&["c"]).public_key();
        let abc_p = sk.private_key().derive(&["a", "b", "c"]).public_key();
        assert_eq!(abc, abc_p, "invalid hierarchical derivation");
    }

    #[test]
    fn public_key_encoding() {
        let base = PublicKey { q: G.basepoint() };
        assert_eq!(
            "GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3",
            base.to_string(),
            "invalid encoded public key"
        );

        let decoded = "GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3".parse::<PublicKey>();
        assert_eq!(Ok(base), decoded, "error parsing public key");

        assert_eq!(
            Err(ParsePublicKeyError),
            "woot woot".parse::<PublicKey>(),
            "decoded invalid public key"
        );
    }

    #[test]
    fn round_trip() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sk_a = SecretKey::random(&mut rng);
        let priv_a = sk_a.private_key();

        let sk_b = SecretKey::random(&mut rng);
        let priv_b = sk_b.private_key();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(
            &mut rng,
            &mut src,
            &mut dst,
            &[priv_b.public_key()],
            Some(20),
            Some(123),
        )?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len = priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key())?;
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");

        Ok(())
    }

    macro_rules! assert_failed {
        ($action: expr) => {
            match $action {
                Ok(_) => panic!("decrypted but shouldn't have"),
                Err(DecryptError::InvalidCiphertext) => Ok(()),
                Err(e) => Err(e),
            }
        };
    }

    #[test]
    fn bad_sender_key() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sk_a = SecretKey::random(&mut rng);
        let priv_a = sk_a.private_key();

        let sk_b = SecretKey::random(&mut rng);
        let priv_b = sk_b.private_key();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(
            &mut rng,
            &mut src,
            &mut dst,
            &[priv_b.public_key()],
            Some(20),
            Some(123),
        )?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_failed!(priv_b.decrypt(&mut src, &mut dst, &priv_b.public_key()))
    }

    #[test]
    fn bad_recipient() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sk_a = SecretKey::random(&mut rng);
        let priv_a = sk_a.private_key();

        let sk_b = SecretKey::random(&mut rng);
        let priv_b = sk_b.private_key();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(
            &mut rng,
            &mut src,
            &mut dst,
            &[priv_a.public_key()],
            Some(20),
            Some(123),
        )?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_failed!(priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key()))
    }

    #[test]
    fn bad_ciphertext() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sk_a = SecretKey::random(&mut rng);
        let priv_a = sk_a.private_key();

        let sk_b = SecretKey::random(&mut rng);
        let priv_b = sk_b.private_key();

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a.encrypt(
            &mut rng,
            &mut src,
            &mut dst,
            &[priv_b.public_key()],
            Some(20),
            Some(123),
        )?;
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut ciphertext = dst.into_inner();
        ciphertext[200] ^= 1;

        let mut src = Cursor::new(ciphertext);
        let mut dst = Cursor::new(Vec::new());

        assert_failed!(priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key()))
    }

    #[test]
    fn sign_and_verify() -> Result<(), VerifyError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let sk = SecretKey::random(&mut rng);
        let message = b"this is a thingy";
        let mut src = Cursor::new(message);

        let sig = sk.private_key().sign(&mut rng, &mut src)?;

        let mut src = Cursor::new(message);
        sk.public_key().verify(&mut src, &sig)
    }
}
