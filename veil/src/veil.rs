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
