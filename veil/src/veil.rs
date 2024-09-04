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
