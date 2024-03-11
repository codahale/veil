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

        expect!["276HUHRnGU6tMj8H6JPduRKYHJ6kbyfR3Rfg5J2CPZC8RTfGkzitde3KLGofakTFs2Pi5GQBVTGgzECzrT5piynepj9NSGWgVCpkfutfUTdDcRYhoogLXdXYk3zAp8dd7KAz1G2seD948gyCtvPrHeArtvnpJEDi5kC12tGDT8kuDSmN34P2rT3KZVZyDi9YGevd4bx8WsEmxMQvj8NmGTafTCQQcfcRMvJj7ibXdXQYLPXSBc6aE4HuB2TKer1Q4VBa2D1aj8h5ekNyy2t8SZSiCC6qu9evfUCeLDXhE57ZTu2FqeE5AEAb7NjHPzXH6PQXVZRsx5pxQXgev8oA4mK8sFoYkwdptYiTEMPtAwQPF8HqmWDVY4aV96E34Z6VjzYYczpsARptbcnuwdrT2s3rDinGErB3LFZ6tq9ZdSNpA9tEKCooV85rTfvkC6URGfbq5J8xFWooU6WYskMDF7JBq9r9QD6wn42dLdaAwPRVyKV11azBVf1MdvmUzmTHcVaGzaVNni8n1mMMYf8cRmfN8eydMMZYR6YQo9SkmKU2yz3hXcXCTSj6hcFDA4w8pdWmkeFWj8xp469cFkLXbDgsn4mFf7MPXiXsciS3FYA7eSugHQCWv9Jw3Bb9W7mPYF113PPgvGnA45QhZoBG55N4KHxsCC1DxWdRFT224ajWtrsNxk2Ve9bizqq73y2L95PTM6x6oCZQqGCS4K7eVwfH5hqm4X9ySsxGcjWDfkgmrGHCxxfhZYHpoBvjzjUENHv6mGpBsQW2VWhPH5ZanMvGRaKzVYEai5TgUhUBk4UcUmdiup42NjmqKymMJoRr7CqaxM3ZaEC6vibffbApgnsmRpQ6sErDDsTELZQPGmgZKLHLy18jGecCfDoKLMvcm1VkL23nMyDeZDxzqXRRmVS5sTQ8XCfiJ5kjyqswGxrexUxq4PV1DydiH48ZcRDxe4r5TjvkFxH9qchf8skRqXrh74QzMQKJCcNdoaG5n6cpcbknZKViBmr2T3v5neR7sFFJCRFDEwRhMr4tzNn6sGTuTBhUrWmELq71YwfeG9HdiGsZeSB2r7GEqBHh6eueBrtind7iSgWhZK6KCY5DmfinAUjuoymKUVx4m3MCt4FYivz38bjVXMxzvi3nLEyGW83UK4yAvy1X1VWXWqbcMM5XvhhqFsS48sFUKnXLgPJwfhMnfequkg8qeSFTGgPsbvpqhBJDoXJF6barfCGRTP6XYdr725Wqq81ycBXmDUA5ZtEFf11DvtnrJyEbv9QxgHjKaeJ8TdJGnobAukp3HE9s2pQ5C5ropWPxzcVXeFU2Zk1YHHGNP22J22u7ojPFw9o1Gi8W6EWPMVZP5hNfcSdozv3ApDoYqDcMdeX1aXAmrGXBbyy2yezADszwT67b2ahKmZPjHJex1s8sApVEuTdXnENw5NdqzWGXfvYHHaYhy4HNkTvrp5AoNgFuSUPKJPGTVjc3vGPtLAJhKLHSVpvQdZbpepNVdQ1dp2J3wAVDjyHWooafuV13HJvbtLaPSeuWU4LbSG81WjnZkRZKEYLarUn6Q3Yp5dh3nc2FbJEdJvPXcjivPKee12ygk7VwiEdJdHN2EwNdkQLL77w2B57v5zAH3rcJ5b2ojuCabnjyvWXnyyTFwjXd9ddEf73gXtvK4APHUuYK2pYDAaHjMkHAkFHmrMkafkmjT8ERo"].assert_eq(&pk.to_string());

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
