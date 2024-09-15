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
    mres, pbenc, sig, DecryptError, EncryptError, ParsePublicKeyError, Signature, VerifyError,
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
