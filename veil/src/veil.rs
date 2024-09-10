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
