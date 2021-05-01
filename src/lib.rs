#![warn(missing_docs)]

//! The Veil hybrid cryptosystem.
//!
//! Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
//! authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
//! Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
//! encrypted. As a result, a global passive adversary would be unable to gain any information from
//! a Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise
//! their true length, and fake recipients can be added to disguise their true number from other
//! recipients.
//!
//! You should not use this.

use std::{cmp, fmt, io};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::Rng;

mod common;
pub mod hpke;
pub mod mres;
pub mod pbenc;
pub mod scaldf;
pub mod schnorr;

/// A 512-bit secret from which multiple private keys can be derived.
pub struct SecretKey {
    seed: [u8; 64],
}

impl SecretKey {
    /// Returns a randomly generated secret key.
    pub fn new() -> SecretKey {
        let mut seed = [0u8; 64];
        rand::thread_rng().fill(&mut seed);

        SecretKey { seed }
    }

    /// Derives a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn private_key(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_root(&self.seed);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        PrivateKey {
            d,
            public_key: PublicKey { q },
        }
        .derive(key_id)
    }

    /// Derives a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn public_key(&self, key_id: &str) -> PublicKey {
        self.private_key(key_id).public_key
    }
}

/// A derived private key, used to encrypt, decrypt, and sign messages.
pub struct PrivateKey {
    d: Scalar,

    /// The corresponding public key.
    pub public_key: PublicKey,
}

impl PrivateKey {
    /// Encrypts the contents of the reader such that any of the recipients will be able to decrypt
    /// it with authenticity and writes the ciphertext to the writer.
    ///
    /// Optionally adds a number of fake recipients and random padding to disguise the number of
    /// true recipients and message length.
    pub fn encrypt<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        recipients: Vec<PublicKey>,
        fakes: usize,
        padding: u64,
    ) -> io::Result<u64>
    where
        R: io::Read,
        W: io::Write,
    {
        // Add any fakes and shuffle the recipients list.
        let mut rng = rand::thread_rng();
        let mut q_rs: Vec<RistrettoPoint> = recipients.into_iter().map(|pk| pk.q).collect();
        q_rs.extend((0..fakes).map(|_| RistrettoPoint::random(&mut rng)));
        q_rs.shuffle(&mut rng);

        // Finally, encrypt.
        mres::encrypt(
            &mut io::BufReader::new(reader),
            &mut io::BufWriter::new(writer),
            &self.d,
            &self.public_key.q,
            q_rs,
            padding,
        )
    }

    /// Decrypts the contents of the reader, if possible, and writes the plaintext to the writer.
    ///
    /// If the ciphertext has been modified, was not sent by the sender, or was not encrypted for
    /// this private key, will return an error.
    pub fn decrypt<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        sender: &PublicKey,
    ) -> io::Result<u64>
    where
        R: io::Read,
        W: io::Write,
    {
        mres::decrypt(
            &mut io::BufReader::new(reader),
            &mut io::BufWriter::new(writer),
            &self.d,
            &self.public_key.q,
            &sender.q,
        )
    }

    /// Reads the contents of the reader and returns a Schnorr signature.
    pub fn sign<R: io::Read>(&self, reader: &mut R) -> io::Result<[u8; 64]> {
        let mut signer = schnorr::Signer::new(io::sink());
        io::copy(reader, &mut signer)?;

        Ok(signer.sign(&self.d, &self.public_key.q))
    }

    /// Derives a private key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn derive(&self, key_id: &str) -> PrivateKey {
        let d = scaldf::derive_scalar(&self.d, key_id);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        PrivateKey {
            d,
            public_key: PublicKey { q },
        }
    }
}

impl cmp::PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.public_key.fmt(f)
    }
}

/// A derived public key, used to verify messages.
#[derive(Eq, PartialEq, Debug)]
pub struct PublicKey {
    q: RistrettoPoint,
}

impl PublicKey {
    /// Reads the contents of the reader returns true iff the given signature was created by this
    /// public key of the exact contents.
    pub fn verify<R: io::Read>(&self, reader: &mut R, sig: &[u8; 64]) -> io::Result<bool> {
        let mut verifier = schnorr::Verifier::new();
        io::copy(reader, &mut verifier)?;

        Ok(verifier.verify(&self.q, &sig))
    }

    /// Derives a public key with the given key ID.
    ///
    /// `key_id` should be slash-separated string (e.g. `/one/two/three`) which define a path of
    /// derived keys (e.g. root -> `one` -> `two` -> `three`).
    pub fn derive(&self, key_id: &str) -> PublicKey {
        let q = scaldf::derive_point(&self.q, key_id);

        PublicKey { q }
    }
}

#[cfg(test)]
mod tests {
    use crate::SecretKey;

    #[test]
    pub fn private_keys() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c");
        let abc_p = sk.private_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }

    #[test]
    pub fn public_keys() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c").public_key;
        let abc_p = sk.public_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }
}
