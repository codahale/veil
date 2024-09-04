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
