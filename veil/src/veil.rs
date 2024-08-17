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
            .collect::<Vec<_>>();

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
