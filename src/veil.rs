//! The Veil hybrid cryptosystem.

use std::fmt::{Debug, Formatter};
use std::io::{BufWriter, Read, Write};
use std::str::FromStr;
use std::{fmt, io, iter};

use qdsa::hazmat::{Point, Scalar, G};
use rand::prelude::SliceRandom;
use rand::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    mres, pbenc, schnorr, AsciiEncoded, DecryptError, ParsePublicKeyError, Signature, VerifyError,
    POINT_LEN,
};

/// A private key, used to encrypt, decrypt, and sign messages.
#[derive(ZeroizeOnDrop)]
pub struct PrivateKey {
    d: Scalar,
    pk: PublicKey,
}

impl PrivateKey {
    fn from_scalar(d: Scalar) -> PrivateKey {
        let q = &G * &d;
        PrivateKey { d, pk: PublicKey { q } }
    }

    /// Creates a randomly generated private key.
    #[must_use]
    pub fn random(mut rng: impl Rng + CryptoRng) -> PrivateKey {
        let d = Scalar::clamp(&rng.gen());
        let q = &G * &d;
        PrivateKey { d, pk: PublicKey { q } }
    }

    /// Returns the corresponding public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.pk
    }

    /// Encrypts the private key with the given passphrase and `veil.pbenc` parameters and writes it
    /// to the given writer.
    pub fn store(
        &self,
        mut writer: impl Write,
        rng: impl Rng + CryptoRng,
        passphrase: &str,
        time: u8,
        space: u8,
    ) -> io::Result<usize> {
        let b = pbenc::encrypt(rng, passphrase, time, space, &self.d.as_bytes());
        writer.write_all(&b)?;
        Ok(b.len())
    }

    /// Loads and decrypts the private key from the given reader with the given passphrase.
    ///
    /// # Errors
    ///
    /// If the passphrase is incorrect and/or the ciphertext has been modified, a
    /// [DecryptError::InvalidCiphertext] error will be returned. If an error occurred while
    /// reading, a [DecryptError::IoError] error will be returned.
    pub fn load(mut reader: impl Read, passphrase: &str) -> Result<PrivateKey, DecryptError> {
        let mut b = Vec::with_capacity(POINT_LEN);
        reader.read_to_end(&mut b)?;

        // Decrypt the ciphertext and use the plaintext as the private key.
        pbenc::decrypt(passphrase, &b)
            .and_then(|b| b.try_into().ok())
            .map(|b| Scalar::clamp(&b))
            .filter(|d| d != &Scalar::ZERO)
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
    /// If there is an error while reading from `reader` or writing to `writer`, an [io::Error] will
    /// be returned.
    pub fn encrypt(
        &self,
        mut rng: impl Rng + CryptoRng,
        reader: &mut impl Read,
        writer: &mut impl Write,
        receivers: &[PublicKey],
        fakes: Option<usize>,
        padding: Option<usize>,
    ) -> io::Result<u64> {
        // Add fakes.
        let mut q_rs = receivers
            .iter()
            .map(|pk| pk.q)
            .chain(
                iter::repeat_with(|| Point::from_elligator(&rng.gen()))
                    .take(fakes.unwrap_or_default()),
            )
            .collect::<Vec<Point>>();

        // Shuffle the receivers list.
        q_rs.shuffle(&mut rng);

        // Finally, encrypt.
        mres::encrypt(
            &mut rng,
            reader,
            &mut BufWriter::new(writer),
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
    /// this private key, returns [DecryptError::InvalidCiphertext]. If there was an error reading
    /// from `reader` or writing to `writer`, returns [DecryptError::IoError].
    pub fn decrypt(
        &self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        sender: &PublicKey,
    ) -> Result<u64, DecryptError> {
        mres::decrypt(reader, &mut BufWriter::new(writer), (&self.d, &self.pk.q), &sender.q)
    }

    /// Reads the contents of the reader and returns a digital signature.
    ///
    /// # Errors
    ///
    /// If there is an error while reading from `message`, an [io::Error] will be returned.
    pub fn sign(
        &self,
        rng: impl Rng + CryptoRng,
        message: &mut impl Read,
    ) -> io::Result<Signature> {
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
#[derive(Clone, Copy, Eq, PartialEq, Zeroize)]
pub struct PublicKey {
    q: Point,
}

impl PublicKey {
    /// Verifies that the given signature was created by the owner of this public key for the exact
    /// contents of `message`. Returns `Ok(())` if successful.
    ///
    /// # Errors
    ///
    /// If the message has been modified or was not signed by the owner of this public key, returns
    /// [VerifyError::InvalidSignature]. If there was an error reading from `message` or writing to
    /// `writer`, returns [VerifyError::IoError].
    pub fn verify(&self, message: &mut impl Read, sig: &Signature) -> Result<(), VerifyError> {
        schnorr::verify(&self.q, message, sig)
    }
}

impl AsciiEncoded for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_bytes(b: &[u8]) -> Result<Self, <Self as AsciiEncoded>::Err> {
        let b = b.try_into().or(Err(ParsePublicKeyError::InvalidPublicKey))?;
        let q = Point::from_bytes(&b);
        if q.is_zero().into() {
            return Err(ParsePublicKeyError::InvalidPublicKey);
        }

        Ok(PublicKey { q })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.q.as_bytes().to_vec()
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
        let base = PublicKey { q: G };
        assert_eq!(
            "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7",
            base.to_string(),
            "invalid encoded public key"
        );

        let decoded = "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7".parse::<PublicKey>();
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
    fn round_trip() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

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
    fn wrong_sender_key() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

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
    fn wrong_receiver() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

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
    fn modified_ciphertext() -> Result<(), DecryptError> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let priv_a = PrivateKey::random(&mut rng);
        let priv_b = PrivateKey::random(&mut rng);

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

        let priv_key = PrivateKey::random(&mut rng);
        let message = b"this is a thingy";
        let mut src = Cursor::new(message);

        let sig = priv_key.sign(&mut rng, &mut src)?;

        let mut src = Cursor::new(message);
        priv_key.public_key().verify(&mut src, &sig)
    }
}
