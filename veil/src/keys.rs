use std::fmt::{Debug, Formatter};

use rand::{CryptoRng, Rng};

pub const PUB_KEY_LEN: usize = 32 + 32;

pub const PRIV_KEY_LEN: usize = PUB_KEY_LEN + 32 + 32;

/// A public key, including its canonical encoded form.
#[derive(Clone, Copy)]
pub struct PubKey {
    /// The X25519 encrypting key.
    pub ek: x25519_dalek::PublicKey,

    /// The Ed25519 verifying key.
    pub vk: ed25519_zebra::VerificationKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; PUB_KEY_LEN],
}

impl PubKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<PubKey> {
        let encoded = <[u8; PUB_KEY_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek, vk) = encoded.split_at(32);
        let ek = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ek).ok()?);
        let vk = ed25519_zebra::VerificationKey::try_from(<[u8; 32]>::try_from(vk).ok()?).ok()?;
        Some(PubKey { ek, vk, encoded })
    }
}

impl Debug for PubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.encoded)
    }
}

impl Eq for PubKey {}

impl PartialEq for PubKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

/// A private key, including its public key.
pub struct PrivKey {
    /// The X25519 decrypting key.
    pub dk: x25519_dalek::StaticSecret,

    /// The Ed25519 signing key.
    pub sk: ed25519_zebra::SigningKey,

    /// The corresponding [`PubKey`] for the private key.
    pub pub_key: PubKey,

    /// The private key's canonical encoded form.
    pub encoded: [u8; PRIV_KEY_LEN],
}

impl PrivKey {
    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PrivKey {
        let dk = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let ek = x25519_dalek::PublicKey::from(&dk);
        let sk = ed25519_zebra::SigningKey::new(&mut rng);
        let vk = ed25519_zebra::VerificationKey::from(&sk);

        let mut pub_encoded = Vec::with_capacity(PUB_KEY_LEN);
        pub_encoded.extend_from_slice(ek.as_bytes());
        pub_encoded.extend_from_slice(vk.as_ref());

        let mut priv_encoded = Vec::with_capacity(PRIV_KEY_LEN);
        priv_encoded.extend_from_slice(&pub_encoded);
        priv_encoded.extend_from_slice(dk.as_bytes());
        priv_encoded.extend_from_slice(sk.as_ref());

        PrivKey {
            dk,
            sk,
            pub_key: PubKey {
                ek,
                vk,
                encoded: pub_encoded.try_into().expect("should be public key sized"),
            },
            encoded: priv_encoded.try_into().expect("should be private key sized"),
        }
    }

    /// Decodes the given slice as a private key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<PrivKey> {
        let encoded = <[u8; PRIV_KEY_LEN]>::try_from(b.as_ref()).ok()?;
        let (pub_key, dk) = encoded.split_at(PUB_KEY_LEN);
        let (dk, sk) = dk.split_at(32);
        let pub_key = PubKey::from_canonical_bytes(pub_key)?;
        let dk = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(dk).ok()?);
        let sk = ed25519_zebra::SigningKey::from(<[u8; 32]>::try_from(sk).ok()?);

        Some(PrivKey { dk, sk, pub_key, encoded })
    }
}

impl Eq for PrivKey {}

impl PartialEq for PrivKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}
