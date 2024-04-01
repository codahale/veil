//! The Veil hybrid cryptosystem.

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
    keys::{StaticPublicKey, StaticSecretKey, STATIC_PK_LEN, STATIC_SK_LEN},
    mres, pbenc, sig, DecryptError, EncryptError, ParsePublicKeyError, Signature, VerifyError,
};

/// A secret key, used to encrypt, decrypt, and sign messages.
#[derive(PartialEq, Eq)]
pub struct SecretKey(StaticSecretKey);

impl SecretKey {
    /// Creates a randomly generated secret key.
    #[must_use]
    pub fn random(rng: impl Rng + CryptoRng) -> SecretKey {
        SecretKey(StaticSecretKey::random(rng))
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
        let mut enc_key = [0u8; STATIC_SK_LEN + pbenc::OVERHEAD];
        pbenc::encrypt(
            rng,
            passphrase,
            time_cost,
            memory_cost,
            parallelism,
            &self.0.encoded,
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
        let mut b = Vec::with_capacity(STATIC_SK_LEN + pbenc::OVERHEAD);
        reader.read_to_end(&mut b).map_err(DecryptError::ReadIo)?;

        // Decrypt the ciphertext and use the plaintext as the secret key.
        pbenc::decrypt(passphrase, &mut b)
            .and_then(StaticSecretKey::from_canonical_bytes)
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
            .collect::<Vec<Option<StaticPublicKey>>>();

        // Shuffle the receivers list.
        receivers.shuffle(&mut rng);

        // Finally, encrypt.
        mres::encrypt(&mut rng, reader, writer, &self.0, &receivers)
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
        mres::decrypt(reader, writer, &self.0, &sender.0)
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
pub struct PublicKey(StaticPublicKey);

impl PublicKey {
    /// Decode a public key from a 32-byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PublicKey> {
        StaticPublicKey::from_canonical_bytes(b).map(PublicKey)
    }

    /// Encode the public key as a 32-byte array.
    #[must_use]
    pub const fn encode(&self) -> [u8; STATIC_PK_LEN] {
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
