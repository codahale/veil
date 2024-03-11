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
    keys::{StaticPrivKey, StaticPubKey, STATIC_PRIV_KEY_LEN, STATIC_PUB_KEY_LEN},
    mres, pbenc, schnorr, DecryptError, EncryptError, ParsePublicKeyError, Signature, VerifyError,
};

/// A private key, used to encrypt, decrypt, and sign messages.
#[derive(PartialEq, Eq)]
pub struct PrivateKey(StaticPrivKey);

impl PrivateKey {
    /// Creates a randomly generated private key.
    #[must_use]
    pub fn random(rng: impl Rng + CryptoRng) -> PrivateKey {
        PrivateKey(StaticPrivKey::random(rng))
    }

    /// Returns the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.pub_key.clone())
    }

    /// Encrypts the private key with the given passphrase and `veil.pbenc` parameters and writes it
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
    ) -> io::Result<usize> {
        let mut enc_key = [0u8; STATIC_PRIV_KEY_LEN + pbenc::OVERHEAD];
        pbenc::encrypt(rng, passphrase, time_cost, memory_cost, &self.0.encoded, &mut enc_key);
        writer.write_all(&enc_key)?;
        Ok(enc_key.len())
    }

    /// Loads and decrypts the private key from the given reader with the given passphrase.
    ///
    /// # Errors
    ///
    /// If the passphrase is incorrect and/or the ciphertext has been modified, a
    /// [`DecryptError::InvalidCiphertext`] error will be returned. If an error occurred while
    /// reading, a [`DecryptError::IoError`] error will be returned.
    pub fn load(mut reader: impl Read, passphrase: &[u8]) -> Result<PrivateKey, DecryptError> {
        let mut b = Vec::with_capacity(STATIC_PRIV_KEY_LEN + pbenc::OVERHEAD);
        reader.read_to_end(&mut b).map_err(DecryptError::ReadIo)?;

        // Decrypt the ciphertext and use the plaintext as the private key.
        pbenc::decrypt(passphrase, &mut b)
            .and_then(StaticPrivKey::from_canonical_bytes)
            .map(PrivateKey)
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
            .collect::<Vec<Option<StaticPubKey>>>();

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
    /// this private key, returns [`DecryptError::InvalidCiphertext`]. If there was an error reading
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
        schnorr::sign(rng, &self.0, message)
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.public_key().fmt(f)
    }
}

/// A public key, used to verify messages.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(StaticPubKey);

impl PublicKey {
    /// Decode a public key from a 32-byte slice.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PublicKey> {
        StaticPubKey::from_canonical_bytes(b).map(PublicKey)
    }

    /// Encode the public key as a 32-byte array.
    #[must_use]
    pub const fn encode(&self) -> [u8; STATIC_PUB_KEY_LEN] {
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
        schnorr::verify(&self.0, message, sig)
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
        let pk = PrivateKey::random(rng).public_key();

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
    fn private_key_round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let k = PrivateKey::random(&mut rng);

        let mut ciphertext = Vec::new();
        k.store(&mut ciphertext, &mut rng, b"hello world", 1, 1)
            .expect("should store successfully");

        let k_p = PrivateKey::load(Cursor::new(&ciphertext), b"hello world")
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
        let c = PrivateKey::random(rng);
        assert_matches!(
            b.decrypt(Cursor::new(ciphertext), io::sink(), &c.public_key()),
            Err(DecryptError::InvalidCiphertext)
        );
    }

    #[test]
    fn wrong_receiver() {
        let (rng, a, _, _, ciphertext) = setup(64);
        let c = PrivateKey::random(rng);

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
        let key = PrivateKey::random(&mut rng);
        let message = rng.gen::<[u8; 64]>();

        let sig = key.sign(&mut rng, Cursor::new(message)).expect("signing should be ok");

        key.public_key().verify(Cursor::new(message), &sig).expect("verification should be ok");
    }

    fn setup(n: usize) -> (rand_chacha::ChaCha20Rng, PrivateKey, PrivateKey, Vec<u8>, Vec<u8>) {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let a = PrivateKey::random(&mut rng);
        let b = PrivateKey::random(&mut rng);

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
