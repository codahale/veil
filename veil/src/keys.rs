use std::fmt::{Debug, Formatter};

use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand::{CryptoRng, Rng};

pub const EPHEMERAL_PUB_KEY_LEN: usize = 32 + 32;

pub const STATIC_PUB_KEY_LEN: usize = 1184 + 32 + 32;

pub const STATIC_PRIV_KEY_LEN: usize = STATIC_PUB_KEY_LEN + 2400 + 32 + 32;

/// A static public key, including its canonical encoded form.
#[derive(Clone)]
pub struct StaticPubKey {
    /// The ML-KEM-768 encrypting key.
    pub ek_pq: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,

    /// The X25519 encrypting key.
    pub ek_c: x25519_dalek::PublicKey,

    /// The Ed25519 verifying key.
    pub vk: ed25519_zebra::VerificationKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; STATIC_PUB_KEY_LEN],
}

impl StaticPubKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticPubKey> {
        let encoded = <[u8; STATIC_PUB_KEY_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek_pq, ek_c) = encoded.split_at(1184);
        let (ek_c, vk) = ek_c.split_at(32);
        let ek_pq = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &ek_pq.try_into().ok()?,
        );
        let ek_c = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ek_c).ok()?);
        let vk = ed25519_zebra::VerificationKey::try_from(<[u8; 32]>::try_from(vk).ok()?).ok()?;
        Some(StaticPubKey { ek_pq, ek_c, vk, encoded })
    }
}

impl Debug for StaticPubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.encoded)
    }
}

impl Eq for StaticPubKey {}

impl PartialEq for StaticPubKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

/// A private key, including its public key.
pub struct StaticPrivKey {
    /// The ML-KEM decrypting key.
    pub dk_pq: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,

    /// The X25519 decrypting key.
    pub dk_c: x25519_dalek::StaticSecret,

    /// The Ed25519 signing key.
    pub sk: ed25519_zebra::SigningKey,

    /// The corresponding [`PubKey`] for the private key.
    pub pub_key: StaticPubKey,

    /// The private key's canonical encoded form.
    pub encoded: [u8; STATIC_PRIV_KEY_LEN],
}

impl StaticPrivKey {
    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> StaticPrivKey {
        let (dk_pq, ek_pq) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate(&mut rng);
        let dk_c = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let ek_c = x25519_dalek::PublicKey::from(&dk_c);
        let sk = ed25519_zebra::SigningKey::new(&mut rng);
        let vk = ed25519_zebra::VerificationKey::from(&sk);

        let mut pub_encoded = Vec::with_capacity(STATIC_PUB_KEY_LEN);
        pub_encoded.extend_from_slice(&ek_pq.as_bytes());
        pub_encoded.extend_from_slice(ek_c.as_bytes());
        pub_encoded.extend_from_slice(vk.as_ref());

        let mut priv_encoded = Vec::with_capacity(STATIC_PRIV_KEY_LEN);
        priv_encoded.extend_from_slice(&pub_encoded);
        priv_encoded.extend_from_slice(&dk_pq.as_bytes());
        priv_encoded.extend_from_slice(dk_c.as_bytes());
        priv_encoded.extend_from_slice(sk.as_ref());

        StaticPrivKey {
            dk_pq,
            dk_c,
            sk,
            pub_key: StaticPubKey {
                ek_pq,
                ek_c,
                vk,
                encoded: pub_encoded.try_into().expect("should be public key sized"),
            },
            encoded: priv_encoded.try_into().expect("should be private key sized"),
        }
    }

    /// Decodes the given slice as a private key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticPrivKey> {
        let encoded = <[u8; STATIC_PRIV_KEY_LEN]>::try_from(b.as_ref()).ok()?;
        let (pub_key, dk_pq) = encoded.split_at(STATIC_PUB_KEY_LEN);
        let (dk_pq, dk_c) = dk_pq.split_at(2400);
        let (dk_c, sk) = dk_c.split_at(32);
        let pub_key = StaticPubKey::from_canonical_bytes(pub_key)?;
        let dk_pq = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &dk_pq.try_into().ok()?,
        );
        let dk_c = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(dk_c).ok()?);
        let sk = ed25519_zebra::SigningKey::from(<[u8; 32]>::try_from(sk).ok()?);

        Some(StaticPrivKey { dk_pq, dk_c, sk, pub_key, encoded })
    }
}

impl Eq for StaticPrivKey {}

impl PartialEq for StaticPrivKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}

/// An ephemeral public key, including its canonical encoded form.
#[derive(Clone)]
pub struct EphemeralPubKey {
    /// The X25519 encrypting key.
    pub ek: x25519_dalek::PublicKey,

    /// The Ed25519 verifying key.
    pub vk: ed25519_zebra::VerificationKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; EPHEMERAL_PUB_KEY_LEN],
}

impl EphemeralPubKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<EphemeralPubKey> {
        let encoded = <[u8; EPHEMERAL_PUB_KEY_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek, vk) = encoded.split_at(32);
        let ek = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ek).ok()?);
        let vk = ed25519_zebra::VerificationKey::try_from(<[u8; 32]>::try_from(vk).ok()?).ok()?;
        Some(EphemeralPubKey { ek, vk, encoded })
    }
}

impl Debug for EphemeralPubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.encoded)
    }
}

impl Eq for EphemeralPubKey {}

impl PartialEq for EphemeralPubKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

/// A private key, including its public key.
pub struct EphemeralPrivKey {
    /// The X25519 decrypting key.
    pub dk: x25519_dalek::StaticSecret,

    /// The Ed25519 signing key.
    pub sk: ed25519_zebra::SigningKey,

    /// The corresponding [`PubKey`] for the private key.
    pub pub_key: EphemeralPubKey,
}

impl EphemeralPrivKey {
    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> EphemeralPrivKey {
        let dk = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let ek = x25519_dalek::PublicKey::from(&dk);
        let sk = ed25519_zebra::SigningKey::new(&mut rng);
        let vk = ed25519_zebra::VerificationKey::from(&sk);

        let mut encoded = Vec::with_capacity(EPHEMERAL_PUB_KEY_LEN);
        encoded.extend_from_slice(ek.as_bytes());
        encoded.extend_from_slice(vk.as_ref());

        EphemeralPrivKey {
            dk,
            sk,
            pub_key: EphemeralPubKey {
                ek,
                vk,
                encoded: encoded.try_into().expect("should be public key sized"),
            },
        }
    }
}

impl Eq for EphemeralPrivKey {}

impl PartialEq for EphemeralPrivKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}
