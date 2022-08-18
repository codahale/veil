//! The Veil hybrid cryptosystem.

use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::str::FromStr;
use std::{fmt, io, iter};

use rand::prelude::SliceRandom;
use rand::{CryptoRng, Rng};

use crate::ecc::{CanonicallyEncoded, Point, Scalar, POINT_LEN, SCALAR_LEN};
use crate::{
    mres, pbenc, schnorr, AsciiEncoded, DecryptError, ParsePublicKeyError, Signature, VerifyError,
};

/// A private key, used to encrypt, decrypt, and sign messages.
pub struct PrivateKey {
    d: Scalar,
    pk: PublicKey,
}

impl PrivateKey {
    #[must_use]
    fn from_scalar(d: Scalar) -> PrivateKey {
        let q = Point::mulgen(&d);
        PrivateKey { d, pk: PublicKey { q } }
    }

    /// Creates a randomly generated private key.
    #[must_use]
    pub fn random(mut rng: impl Rng + CryptoRng) -> PrivateKey {
        PrivateKey::from_scalar(Scalar::random(&mut rng))
    }

    /// Returns the corresponding public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.pk
    }

    /// Encrypts the private key with the given passphrase and `veil.pbenc` parameters and writes it
    /// to the given writer.
    ///
    /// # Errors
    ///
    /// Returns any error returned by operations on `writer`.
    pub fn store(
        &self,
        mut writer: impl Write,
        rng: impl Rng + CryptoRng,
        passphrase: &[u8],
        time: u8,
        space: u8,
    ) -> io::Result<usize> {
        let mut enc_key = [0u8; SCALAR_LEN + pbenc::OVERHEAD];
        pbenc::encrypt(rng, passphrase, time, space, &self.d.as_canonical_bytes(), &mut enc_key);
        writer.write_all(&enc_key)?;
        Ok(enc_key.len())
    }

    /// Loads and decrypts the private key from the given reader with the given passphrase.
    ///
    /// # Errors
    ///
    /// If the passphrase is incorrect and/or the ciphertext has been modified, a
    /// [`DecryptError::InvalidCiphertext`] error will be returned. If an error occurred while
    /// reading, a [`DecryptError::IoError`] error will be returned.
    pub fn load(mut reader: impl Read, passphrase: &[u8]) -> Result<PrivateKey, DecryptError> {
        let mut b = Vec::with_capacity(SCALAR_LEN + pbenc::OVERHEAD);
        reader.read_to_end(&mut b)?;

        // Decrypt the ciphertext and use the plaintext as the private key.
        pbenc::decrypt(passphrase, &mut b)
            .and_then(Scalar::from_canonical_bytes)
            .map(PrivateKey::from_scalar)
            .ok_or(DecryptError::InvalidCiphertext)
    }

    /// Encrypts the contents of the reader and write the ciphertext to the writer.
    ///
    /// Optionally add a number of fake receivers to disguise the number of true receivers and/or
    /// random padding to disguise the message length.
    ///
    /// Returns the number of bytes of ciphertext written to `writer`.
    ///
    /// # Errors
    ///
    /// If there is an error while reading from `reader` or writing to `writer`, an [`io::Error`]
    /// will be returned.
    pub fn encrypt(
        &self,
        mut rng: impl Rng + CryptoRng,
        reader: impl Read,
        writer: impl Write,
        receivers: &[PublicKey],
        fakes: Option<usize>,
        padding: Option<usize>,
    ) -> io::Result<u64> {
        // Add fakes.
        let mut q_rs = receivers
            .iter()
            .map(|pk| pk.q)
            .chain(iter::repeat_with(|| Point::random(&mut rng)).take(fakes.unwrap_or_default()))
            .collect::<Vec<Point>>();

        // Shuffle the receivers list.
        q_rs.shuffle(&mut rng);

        // Finally, encrypt.
        mres::encrypt(
            &mut rng,
            reader,
            writer,
            (&self.d, &self.pk.q),
            &q_rs,
            padding.unwrap_or_default(),
        )
    }

    /// Decrypts the contents of `reader`, if possible, and writes the plaintext to `writer`.
    ///
    /// Returns the number of bytes of plaintext written to `writer`.
    ///
    /// # Errors
    ///
    /// If the ciphertext has been modified, was not sent by the sender, or was not encrypted for
    /// this private key, returns [`DecryptError::InvalidCiphertext`]. If there was an error reading
    /// from `reader` or writing to `writer`, returns [`DecryptError::IoError`].
    pub fn decrypt(
        &self,
        reader: impl Read,
        writer: impl Write,
        sender: &PublicKey,
    ) -> Result<u64, DecryptError> {
        mres::decrypt(reader, writer, (&self.d, &self.pk.q), &sender.q)
    }

    /// Reads the contents of the reader and returns a digital signature.
    ///
    /// # Errors
    ///
    /// If there is an error while reading from `message`, an [`io::Error`] will be returned.
    pub fn sign(&self, rng: impl Rng + CryptoRng, message: impl Read) -> io::Result<Signature> {
        schnorr::sign(rng, (&self.d, &self.pk.q), message)
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

/// A public key, used to verify messages.
#[derive(Clone, Copy)]
pub struct PublicKey {
    q: Point,
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.q.equals(other.q) != 0
    }
}

impl PublicKey {
    /// Verifies that the given signature was created by the owner of this public key for the exact
    /// contents of `message`. Returns `Ok(())` if successful.
    ///
    /// # Errors
    ///
    /// If the message has been modified or was not signed by the owner of this public key, returns
    /// [`VerifyError::InvalidSignature`]. If there was an error reading from `message` or writing
    /// to `writer`, returns [`VerifyError::IoError`].
    pub fn verify(&self, message: impl Read, sig: &Signature) -> Result<(), VerifyError> {
        schnorr::verify(&self.q, message, sig)
    }
}

impl AsciiEncoded<POINT_LEN> for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_bytes(b: &[u8]) -> Result<Self, <Self as AsciiEncoded<POINT_LEN>>::Err> {
        let q = Point::from_canonical_bytes(b).ok_or(ParsePublicKeyError::InvalidPublicKey)?;
        Ok(PublicKey { q })
    }

    fn to_bytes(&self) -> [u8; POINT_LEN] {
        self.q.as_canonical_bytes()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_ascii())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii())
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_ascii(s)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn public_key_encoding() {
        let base = PublicKey { q: Point::BASE };
        assert_eq!(
            "3ULQeLqAKMjxy7rTod4VHF9cXxBgJPGhNwhaKwcSzpcW",
            base.to_string(),
            "invalid encoded public key"
        );

        let decoded = "3ULQeLqAKMjxy7rTod4VHF9cXxBgJPGhNwhaKwcSzpcW".parse::<PublicKey>();
        assert_eq!(Ok(base), decoded, "error parsing public key");

        assert_eq!(
            Err(ParsePublicKeyError::InvalidEncoding(bs58::decode::Error::InvalidCharacter {
                character: ' ',
                index: 4,
            })),
            "woot woot".parse::<PublicKey>(),
            "decoded invalid public key"
        );
    }

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut rng, &mut src, &mut dst, &[priv_b.public_key()], Some(20), Some(123))
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        let ptx_len =
            priv_b.decrypt(&mut src, &mut dst, &priv_a.public_key()).expect("error decrypting");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(message.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn wrong_sender_key() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut rng, &mut src, &mut dst, &[priv_b.public_key()], Some(20), Some(123))
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_eq!(
            "invalid ciphertext",
            priv_b
                .decrypt(&mut src, &mut dst, &priv_b.public_key())
                .expect_err("should not have decrypted")
                .to_string()
        );
    }

    #[test]
    fn wrong_receiver() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut rng, &mut src, &mut dst, &[priv_a.public_key()], Some(20), Some(123))
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut src = Cursor::new(dst.into_inner());
        let mut dst = Cursor::new(Vec::new());

        assert_eq!(
            "invalid ciphertext",
            priv_b
                .decrypt(&mut src, &mut dst, &priv_a.public_key())
                .expect_err("should not have decrypted")
                .to_string()
        );
    }

    #[test]
    fn modified_ciphertext() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

        let message = b"this is a thingy";
        let mut src = Cursor::new(message);
        let mut dst = Cursor::new(Vec::new());

        let ctx_len = priv_a
            .encrypt(&mut rng, &mut src, &mut dst, &[priv_b.public_key()], Some(20), Some(123))
            .expect("error encrypting");
        assert_eq!(dst.position(), ctx_len, "returned/observed ciphertext length mismatch");

        let mut ciphertext = dst.into_inner();
        ciphertext[200] ^= 1;

        let mut src = Cursor::new(ciphertext);
        let mut dst = Cursor::new(Vec::new());

        assert_eq!(
            "invalid ciphertext",
            priv_b
                .decrypt(&mut src, &mut dst, &priv_a.public_key())
                .expect_err("should not have decrypted")
                .to_string()
        );
    }

    #[test]
    fn sign_and_verify() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let priv_key = PrivateKey::random(&mut rng);
        let message = b"this is a thingy";
        let mut src = Cursor::new(message);

        let sig = priv_key.sign(&mut rng, &mut src).expect("error signing");

        let mut src = Cursor::new(message);
        priv_key.public_key().verify(&mut src, &sig).expect("error verifying");
    }
}
