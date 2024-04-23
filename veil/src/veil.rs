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
