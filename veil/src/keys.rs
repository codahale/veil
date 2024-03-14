use std::fmt::{Debug, Formatter};

use fips204::{ml_dsa_65, traits::SerDes as _};
use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand::{CryptoRng, Rng};

pub const EPHEMERAL_PK_LEN: usize = 32 + ml_dsa_65::PK_LEN + 32;

pub const STATIC_PK_LEN: usize = 1184 + 32 + ml_dsa_65::PK_LEN + 32;

pub const STATIC_SK_LEN: usize = STATIC_PK_LEN + 2400 + 32 + ml_dsa_65::SK_LEN + 32;

/// A static public key, including its canonical encoded form.
#[derive(Clone)]
pub struct StaticPublicKey {
    /// The ML-KEM-768 encrypting key.
    pub ek_pq: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,

    /// The X25519 encrypting key.
    pub ek_c: x25519_dalek::PublicKey,

    /// The ML-DSA-65 verifying key.
    pub vk_pq: ml_dsa_65::PublicKey,

    /// The Ed25519 verifying key.
    pub vk_c: ed25519_dalek::VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; STATIC_PK_LEN],
}

impl StaticPublicKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticPublicKey> {
        let encoded = <[u8; STATIC_PK_LEN]>::try_from(b.as_ref()).ok()?;
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
        Some(StaticPublicKey { ek_pq, ek_c, vk_pq, vk_c, encoded })
    }
}

impl Debug for StaticPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.encoded)
    }
}

impl Eq for StaticPublicKey {}

impl PartialEq for StaticPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

/// A secret key, including its public key.
pub struct StaticSecretKey {
    /// The ML-KEM decrypting key.
    pub dk_pq: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,

    /// The X25519 decrypting key.
    pub dk_c: x25519_dalek::StaticSecret,

    /// The ML-DSA-65 signing key.
    pub sk_pq: ml_dsa_65::PrivateKey,

    /// The Ed25519 signing key.
    pub sk_c: ed25519_dalek::SigningKey,

    /// The corresponding [`StaticPublicKey`] for the secret key.
    pub pub_key: StaticPublicKey,

    /// The secret key's canonical encoded form.
    pub encoded: [u8; STATIC_SK_LEN],
}

impl StaticSecretKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> StaticSecretKey {
        let (dk_pq, ek_pq) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate(&mut rng);
        let dk_c = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let ek_c = x25519_dalek::PublicKey::from(&dk_c);
        let (vk_pq, sk_pq) = ml_dsa_65::try_keygen_with_rng_vt(&mut rng).expect("should generate");
        let sk_c = ed25519_dalek::SigningKey::from_bytes(&rng.gen());
        let vk_c = sk_c.verifying_key();

        let mut pub_encoded = Vec::with_capacity(STATIC_PK_LEN);
        pub_encoded.extend_from_slice(&ek_pq.as_bytes());
        pub_encoded.extend_from_slice(ek_c.as_bytes());
        pub_encoded.extend_from_slice(&vk_pq.clone().into_bytes());
        pub_encoded.extend_from_slice(vk_c.as_bytes());

        let mut sec_encoded = Vec::with_capacity(STATIC_SK_LEN);
        sec_encoded.extend_from_slice(&pub_encoded);
        sec_encoded.extend_from_slice(&dk_pq.as_bytes());
        sec_encoded.extend_from_slice(dk_c.as_bytes());
        sec_encoded.extend_from_slice(&sk_pq.clone().into_bytes());
        sec_encoded.extend_from_slice(sk_c.as_bytes());

        StaticSecretKey {
            dk_pq,
            dk_c,
            sk_pq,
            sk_c,
            pub_key: StaticPublicKey {
                ek_pq,
                ek_c,
                vk_pq,
                vk_c,
                encoded: pub_encoded.try_into().expect("should be public key sized"),
            },
            encoded: sec_encoded.try_into().expect("should be secret key sized"),
        }
    }

    /// Decodes the given slice as a secret key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticSecretKey> {
        let encoded = <[u8; STATIC_SK_LEN]>::try_from(b.as_ref()).ok()?;
        let (pub_key, dk_pq) = encoded.split_at(STATIC_PK_LEN);
        let (dk_pq, dk_c) = dk_pq.split_at(2400);
        let (dk_c, sk_pq) = dk_c.split_at(32);
        let (sk_pq, sk_c) = sk_pq.split_at(ml_dsa_65::SK_LEN);
        let pub_key = StaticPublicKey::from_canonical_bytes(pub_key)?;
        let dk_pq = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &dk_pq.try_into().ok()?,
        );
        let dk_c = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(dk_c).ok()?);
        let sk_pq = ml_dsa_65::PrivateKey::try_from_bytes(
            sk_pq.try_into().expect("should be ML-DSA-65 secret key sized"),
        )
        .ok()?;
        let sk_c = ed25519_dalek::SigningKey::from(<[u8; 32]>::try_from(sk_c).ok()?);

        Some(StaticSecretKey { dk_pq, dk_c, sk_pq, sk_c, pub_key, encoded })
    }
}

impl Eq for StaticSecretKey {}

impl PartialEq for StaticSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}

/// An ephemeral public key, including its canonical encoded form.
#[derive(Clone)]
pub struct EphemeralPublicKey {
    /// The X25519 encrypting key.
    pub ek_c: x25519_dalek::PublicKey,

    /// The ML-DSA-65 verifying key.
    pub vk_pq: ml_dsa_65::PublicKey,

    /// The Ed25519 verifying key.
    pub vk_c: ed25519_dalek::VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; EPHEMERAL_PK_LEN],
}

impl EphemeralPublicKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<EphemeralPublicKey> {
        let encoded = <[u8; EPHEMERAL_PK_LEN]>::try_from(b.as_ref()).ok()?;
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
        Some(EphemeralPublicKey { ek_c, vk_pq, vk_c, encoded })
    }
}

impl Debug for EphemeralPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.encoded)
    }
}

impl Eq for EphemeralPublicKey {}

impl PartialEq for EphemeralPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

/// An ephemeral secret key, including its public key.
pub struct EphemeralSecretKey {
    /// The X25519 decrypting key.
    pub dk_c: x25519_dalek::StaticSecret,

    /// The ML-DSA-65 signing key.
    pub sk_pq: ml_dsa_65::PrivateKey,

    /// The Ed25519 signing key.
    pub sk_c: ed25519_dalek::SigningKey,

    /// The corresponding [`EphemeralPublicKey`] for the secret key.
    pub pub_key: EphemeralPublicKey,
}

impl EphemeralSecretKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> EphemeralSecretKey {
        let dk_c = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let ek_c = x25519_dalek::PublicKey::from(&dk_c);
        let (vk_pq, sk_pq) = ml_dsa_65::try_keygen_with_rng_vt(&mut rng).expect("should generate");
        let sk_c = ed25519_dalek::SigningKey::from_bytes(&rng.gen());
        let vk_c = sk_c.verifying_key();

        let mut encoded = Vec::with_capacity(EPHEMERAL_PK_LEN);
        encoded.extend_from_slice(ek_c.as_bytes());
        encoded.extend_from_slice(&vk_pq.clone().into_bytes());
        encoded.extend_from_slice(vk_c.as_bytes());

        EphemeralSecretKey {
            dk_c,
            sk_pq,
            sk_c,
            pub_key: EphemeralPublicKey {
                ek_c,
                vk_pq,
                vk_c,
                encoded: encoded.try_into().expect("should be public key sized"),
            },
        }
    }
}

impl Eq for EphemeralSecretKey {}

impl PartialEq for EphemeralSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}
