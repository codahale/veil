use std::fmt::{Debug, Formatter};

use fips204::{ml_dsa_65, traits::SerDes as _};
use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand::{CryptoRng, Rng};

pub const EPHEMERAL_PUB_KEY_LEN: usize = 32 + ml_dsa_65::PK_LEN + 32;

pub const STATIC_PUB_KEY_LEN: usize = 1184 + 32 + ml_dsa_65::PK_LEN + 32;

pub const STATIC_PRIV_KEY_LEN: usize = STATIC_PUB_KEY_LEN + 2400 + 32 + ml_dsa_65::SK_LEN + 32;

/// A static public key, including its canonical encoded form.
#[derive(Clone)]
pub struct StaticPubKey {
    /// The ML-KEM-768 encrypting key.
    pub ek_pq: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,

    /// The X25519 encrypting key.
    pub ek_c: x25519_dalek::PublicKey,

    /// The ML-DSA-65 verifying key.
    pub vk_pq: ml_dsa_65::PublicKey,

    /// The Ed25519 verifying key.
    pub vk_c: ed25519_dalek::VerifyingKey,

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
        let (ek_c, vk_pq) = ek_c.split_at(32);
        let (vk_pq, vk_c) = vk_pq.split_at(ml_dsa_65::PK_LEN);
        let ek_pq = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &ek_pq.try_into().ok()?,
        );
        let ek_c = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ek_c).ok()?);
        let vk_pq = ml_dsa_65::PublicKey::try_from_bytes(
            vk_pq.try_into().expect("should be ML-DSA-65 public key sized"),
        )
        .ok()?;
        let vk_c = ed25519_dalek::VerifyingKey::from_bytes(
            vk_c.try_into().expect("should be Ed25519 public key sized"),
        )
        .ok()?;
        Some(StaticPubKey { ek_pq, ek_c, vk_pq, vk_c, encoded })
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

    /// The ML-DSA-65 signing key.
    pub sk_pq: ml_dsa_65::PrivateKey,

    /// The Ed25519 signing key.
    pub sk_c: ed25519_dalek::SigningKey,

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
        let (vk_pq, sk_pq) = ml_dsa_65::try_keygen_with_rng_vt(&mut rng).expect("should generate");
        let sk_c = ed25519_dalek::SigningKey::from_bytes(&rng.gen());
        let vk_c = sk_c.verifying_key();

        let mut pub_encoded = Vec::with_capacity(STATIC_PUB_KEY_LEN);
        pub_encoded.extend_from_slice(&ek_pq.as_bytes());
        pub_encoded.extend_from_slice(ek_c.as_bytes());
        pub_encoded.extend_from_slice(&vk_pq.clone().into_bytes());
        pub_encoded.extend_from_slice(vk_c.as_bytes());

        let mut priv_encoded = Vec::with_capacity(STATIC_PRIV_KEY_LEN);
        priv_encoded.extend_from_slice(&pub_encoded);
        priv_encoded.extend_from_slice(&dk_pq.as_bytes());
        priv_encoded.extend_from_slice(dk_c.as_bytes());
        priv_encoded.extend_from_slice(&sk_pq.clone().into_bytes());
        priv_encoded.extend_from_slice(sk_c.as_bytes());

        StaticPrivKey {
            dk_pq,
            dk_c,
            sk_pq,
            sk_c,
            pub_key: StaticPubKey {
                ek_pq,
                ek_c,
                vk_pq,
                vk_c,
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
        let (dk_c, sk_pq) = dk_c.split_at(32);
        let (sk_pq, sk_c) = sk_pq.split_at(ml_dsa_65::SK_LEN);
        let pub_key = StaticPubKey::from_canonical_bytes(pub_key)?;
        let dk_pq = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &dk_pq.try_into().ok()?,
        );
        let dk_c = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(dk_c).ok()?);
        let sk_pq = ml_dsa_65::PrivateKey::try_from_bytes(
            sk_pq.try_into().expect("should be ML-DSA-65 private key sized"),
        )
        .ok()?;
        let sk_c = ed25519_dalek::SigningKey::from(<[u8; 32]>::try_from(sk_c).ok()?);

        Some(StaticPrivKey { dk_pq, dk_c, sk_pq, sk_c, pub_key, encoded })
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
    pub ek_c: x25519_dalek::PublicKey,

    /// The ML-DSA-65 verifying key.
    pub vk_pq: ml_dsa_65::PublicKey,

    /// The Ed25519 verifying key.
    pub vk_c: ed25519_dalek::VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; EPHEMERAL_PUB_KEY_LEN],
}

impl EphemeralPubKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<EphemeralPubKey> {
        let encoded = <[u8; EPHEMERAL_PUB_KEY_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek_c, vk_pq) = encoded.split_at(32);
        let (vk_pq, vk_c) = vk_pq.split_at(ml_dsa_65::PK_LEN);
        let ek_c = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ek_c).ok()?);
        let vk_pq = ml_dsa_65::PublicKey::try_from_bytes(
            vk_pq.try_into().expect("should be ML-DSA-65 public key sized"),
        )
        .ok()?;
        let vk_c = ed25519_dalek::VerifyingKey::from_bytes(
            vk_c.try_into().expect("should be Ed25519 public key sized"),
        )
        .ok()?;
        Some(EphemeralPubKey { ek_c, vk_pq, vk_c, encoded })
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
    pub dk_c: x25519_dalek::StaticSecret,

    /// The ML-DSA-65 signing key.
    pub sk_pq: ml_dsa_65::PrivateKey,

    /// The Ed25519 signing key.
    pub sk_c: ed25519_dalek::SigningKey,

    /// The corresponding [`PubKey`] for the private key.
    pub pub_key: EphemeralPubKey,
}

impl EphemeralPrivKey {
    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> EphemeralPrivKey {
        let dk_c = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let ek_c = x25519_dalek::PublicKey::from(&dk_c);
        let (vk_pq, sk_pq) = ml_dsa_65::try_keygen_with_rng_vt(&mut rng).expect("should generate");
        let sk_c = ed25519_dalek::SigningKey::from_bytes(&rng.gen());
        let vk_c = sk_c.verifying_key();

        let mut encoded = Vec::with_capacity(EPHEMERAL_PUB_KEY_LEN);
        encoded.extend_from_slice(ek_c.as_bytes());
        encoded.extend_from_slice(&vk_pq.clone().into_bytes());
        encoded.extend_from_slice(vk_c.as_bytes());

        EphemeralPrivKey {
            dk_c,
            sk_pq,
            sk_c,
            pub_key: EphemeralPubKey {
                ek_c,
                vk_pq,
                vk_c,
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
