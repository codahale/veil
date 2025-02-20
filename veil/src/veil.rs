//! The Veil cryptosystem.

use std::{
    fmt,
    fmt::{Debug, Formatter},
    io,
    io::{Read, Write},
    iter,
    str::FromStr,
};

use rand::{CryptoRng, Rng, prelude::SliceRandom};

use crate::{
    DecryptError, EncryptError, ParsePublicKeyError, Signature, VerifyError,
    keys::{PK_LEN, PubKey, SK_LEN, SecKey},
    message, pbenc, sig,
};

/// A secret key, used to encrypt, decrypt, and sign messages.
#[derive(PartialEq, Eq)]
pub struct SecretKey(SecKey);

impl SecretKey {
    /// Creates a randomly generated secret key.
    #[must_use]
    pub fn random(rng: impl Rng + CryptoRng) -> SecretKey {
        SecretKey(SecKey::random(rng))
    }

    /// Returns the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.pub_key.clone())
    }

    /// Encrypts the secret key with the given passphrase and `veil.pbenc` parameters and writes it
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
        time_cost: u8,
        memory_cost: u8,
        parallelism: u8,
    ) -> io::Result<usize> {
        let mut enc_key = [0u8; SK_LEN + pbenc::OVERHEAD];
        pbenc::encrypt(
            rng,
            passphrase,
            time_cost,
            memory_cost,
            parallelism,
            &self.0.seed,
            &mut enc_key,
        );
        writer.write_all(&enc_key)?;
        Ok(enc_key.len())
    }

    /// Loads and decrypts the secret key from the given reader with the given passphrase.
    ///
    /// # Errors
    ///
    /// If the passphrase is incorrect and/or the ciphertext has been modified, a
    /// [`DecryptError::InvalidCiphertext`] error will be returned. If an error occurred while
    /// reading, a [`DecryptError::ReadIo`] error will be returned.
    pub fn load(mut reader: impl Read, passphrase: &[u8]) -> Result<SecretKey, DecryptError> {
        let mut b = Vec::with_capacity(SK_LEN + pbenc::OVERHEAD);
        reader.read_to_end(&mut b).map_err(DecryptError::ReadIo)?;

        // Decrypt the ciphertext and use the plaintext as the secret key.
        pbenc::decrypt(passphrase, &mut b)
            .and_then(SecKey::from_canonical_bytes)
            .map(SecretKey)
            .ok_or(DecryptError::InvalidCiphertext)
    }

    /// Encrypts the contents of the reader and write the ciphertext to the writer.
    ///
    /// Optionally add a number of fake receivers to disguise the number of true receivers.
    ///
    /// Returns the number of bytes of ciphertext written to `writer`.
    ///
    /// # Errors
    ///
    /// If there is an error while reading from `reader` or writing to `writer`, an [`EncryptError`]
    /// will be returned.
    pub fn encrypt(
        &self,
        mut rng: impl Rng + CryptoRng,
        reader: impl Read,
        writer: impl Write,
        receivers: &[PublicKey],
        fakes: Option<usize>,
    ) -> Result<u64, EncryptError> {
        let mut receivers = receivers
            .iter()
            .map(|pk| Some(pk.0.clone()))
            .chain(iter::repeat(None).take(fakes.unwrap_or_default()))
            .collect::<Vec<_>>();

        // Shuffle the receivers list.
        receivers.shuffle(&mut rng);

        // Finally, encrypt.
        message::encrypt(&mut rng, reader, writer, &self.0, &receivers)
    }

    /// Decrypts the contents of `reader`, if possible, and writes the plaintext to `writer`.
    ///
    /// Returns the number of bytes of plaintext written to `writer`.
    ///
    /// # Errors
    ///
    /// If the ciphertext has been modified, was not sent by the sender, or was not encrypted for
    /// this secret key, returns [`DecryptError::InvalidCiphertext`]. If there was an error reading
    /// from `reader` or writing to `writer`, returns [`DecryptError::ReadIo`] or
    /// [`DecryptError::WriteIo`].
    pub fn decrypt(
        &self,
        reader: impl Read,
        writer: impl Write,
        sender: &PublicKey,
    ) -> Result<u64, DecryptError> {
        message::decrypt(reader, writer, &self.0, &sender.0)
    }

    /// Reads the contents of the reader and returns a digital signature.
    ///
    /// # Errors
    ///
    /// If there is an error while reading from `message`, an [`io::Error`] will be returned.
    pub fn sign(&self, rng: impl Rng + CryptoRng, message: impl Read) -> io::Result<Signature> {
        sig::sign(rng, &self.0, message)
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.public_key().fmt(f)
    }
}

/// A public key, used to verify messages.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(PubKey);

impl PublicKey {
    /// Decode a public key from a byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PublicKey> {
        PubKey::from_canonical_bytes(b).map(PublicKey)
    }

    /// Encode the public key as a byte array.
    #[must_use]
    pub const fn encode(&self) -> [u8; PK_LEN] {
        self.0.encoded
    }

    /// Verifies that the given signature was created by the owner of this public key for the exact
    /// contents of `message`. Returns `Ok(())` if successful.
    ///
    /// # Errors
    ///
    /// If the message has been modified or was not signed by the owner of this public key, returns
    /// [`VerifyError::InvalidSignature`]. If there was an error reading from `message`, returns
    /// [`VerifyError::ReadIo`].
    pub fn verify(&self, message: impl Read, sig: &Signature) -> Result<(), VerifyError> {
        sig::verify(&self.0, message, sig)
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.encode()).into_string())
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::decode(bs58::decode(s).into_vec()?.as_slice())
            .ok_or(ParsePublicKeyError::InvalidPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use assert_matches::assert_matches;
    use expect_test::expect;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn public_key_encoding() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let pk = SecretKey::random(rng).public_key();

        expect!["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"].assert_eq(&pk.to_string());

        let decoded = pk.to_string().parse::<PublicKey>();
        assert_eq!(Ok(pk), decoded, "error parsing public key");

        assert_eq!(
            Err(ParsePublicKeyError::InvalidEncoding(bs58::decode::Error::InvalidCharacter {
                character: 'l',
                index: 4,
            })),
            "invalid key".parse::<PublicKey>(),
            "decoded invalid public key"
        );
    }

    #[test]
    fn secret_key_round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let k = SecretKey::random(&mut rng);

        let mut ciphertext = Vec::new();
        k.store(&mut ciphertext, &mut rng, b"hello world", 1, 1, 1)
            .expect("should store successfully");

        let k_p = SecretKey::load(Cursor::new(&ciphertext), b"hello world")
            .expect("should load successfully");

        assert_eq!(k, k_p);
    }

    #[test]
    fn round_trip() {
        let (_, a, b, plaintext, ciphertext) = setup(64);
        let mut dst = Cursor::new(Vec::new());
        let ptx_len = b
            .decrypt(Cursor::new(ciphertext), &mut dst, &a.public_key())
            .expect("decryption should be ok");
        assert_eq!(dst.position(), ptx_len, "returned/observed plaintext length mismatch");
        assert_eq!(plaintext.to_vec(), dst.into_inner(), "incorrect plaintext");
    }

    #[test]
    fn wrong_sender() {
        let (rng, _, b, _, ciphertext) = setup(64);
        let c = SecretKey::random(rng);
        assert_matches!(
            b.decrypt(Cursor::new(ciphertext), io::sink(), &c.public_key()),
            Err(DecryptError::InvalidCiphertext)
        );
    }

    #[test]
    fn wrong_receiver() {
        let (rng, a, _, _, ciphertext) = setup(64);
        let c = SecretKey::random(rng);

        assert_matches!(
            c.decrypt(Cursor::new(ciphertext), io::sink(), &a.public_key()),
            Err(DecryptError::InvalidCiphertext)
        );
    }

    #[test]
    fn modified_ciphertext() {
        let (_, a, b, _, mut ciphertext) = setup(64);
        ciphertext[200] ^= 1;
        assert_matches!(
            b.decrypt(Cursor::new(ciphertext), io::sink(), &a.public_key()),
            Err(DecryptError::InvalidCiphertext)
        );
    }

    #[test]
    fn sign_and_verify() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let key = SecretKey::random(&mut rng);
        let message = rng.r#gen::<[u8; 64]>();

        let sig = key.sign(&mut rng, Cursor::new(message)).expect("signing should be ok");

        key.public_key().verify(Cursor::new(message), &sig).expect("verification should be ok");
    }

    fn setup(n: usize) -> (rand_chacha::ChaCha20Rng, SecretKey, SecretKey, Vec<u8>, Vec<u8>) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let a = SecretKey::random(&mut rng);
        let b = SecretKey::random(&mut rng);

        let mut plaintext = vec![0u8; n];
        rng.fill_bytes(&mut plaintext);

        let mut ciphertext = Vec::with_capacity(plaintext.len());

        let ctx_len = a
            .encrypt(
                &mut rng,
                Cursor::new(&plaintext),
                Cursor::new(&mut ciphertext),
                &[b.public_key()],
                Some(20),
            )
            .expect("encryption should be ok");
        assert_eq!(
            u64::try_from(ciphertext.len()).expect("usize should be <= u64"),
            ctx_len,
            "returned/observed ciphertext length mismatch"
        );

        (rng, a, b, plaintext, ciphertext)
    }
}
