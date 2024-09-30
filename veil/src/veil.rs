//! The Veil cryptosystem.

use std::{
    fmt,
    fmt::{Debug, Formatter},
    io,
    io::{Read, Write},
    iter,
    str::FromStr,
};

use rand::{prelude::SliceRandom, CryptoRng, Rng};

use crate::{
    keys::{PubKey, SecKey, PK_LEN, SK_LEN},
    message, pbenc, sig, DecryptError, EncryptError, ParsePublicKeyError, Signature, VerifyError,
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
    /// If any of the `m_cost`, `t_cost`, or `p_cost` parameters are invalid, returns an error with
    /// more details. Returns any error returned by operations on `writer`.
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
    /// reading, a [`DecryptError::IoError`] error will be returned.
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
    /// If there is an error while reading from `reader` or writing to `writer`, an [`io::Error`]
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
    /// from `reader` or writing to `writer`, returns [`DecryptError::IoError`].
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
    /// Decode a public key from a 32-byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PublicKey> {
        PubKey::from_canonical_bytes(b).map(PublicKey)
    }

    /// Encode the public key as a 32-byte array.
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
    /// [`VerifyError::InvalidSignature`]. If there was an error reading from `message` or writing
    /// to `writer`, returns [`VerifyError::IoError`].
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
        let message = rng.gen::<[u8; 64]>();

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
