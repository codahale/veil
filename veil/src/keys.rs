use std::fmt::{Debug, Formatter};

use arrayref::array_refs;
use fips204::{
    ml_dsa_65::{self},
    traits::SerDes as _,
};
use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand::{CryptoRng, Rng, RngCore};

pub const EPHEMERAL_PK_LEN: usize = ml_dsa_65::PK_LEN;

pub const STATIC_PK_LEN: usize = 1184 + ml_dsa_65::PK_LEN;

pub const STATIC_SK_LEN: usize = STATIC_PK_LEN + 2400 + ml_dsa_65::SK_LEN;

pub type MlDsa65SigningKey = ml_dsa_65::PrivateKey;

pub type MlDsa65VerifyingKey = ml_dsa_65::PublicKey;

type MlKem768EncryptingKey = ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>;

type MlKem768DecryptingKey = ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>;

/// A static public key, including its canonical encoded form.
#[derive(Clone)]
pub struct StaticPublicKey {
    /// The ML-KEM-768 encrypting key.
    pub ek: MlKem768EncryptingKey,

    /// The ML-DSA-65 verifying key.
    pub vk: MlDsa65VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; STATIC_PK_LEN],
}

impl StaticPublicKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticPublicKey> {
        let encoded = <[u8; STATIC_PK_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek, vk) = array_refs![&encoded, 1184, ml_dsa_65::PK_LEN];
        let ek = MlKem768EncryptingKey::from_bytes(ek.into());
        let vk = MlDsa65VerifyingKey::try_from_bytes(*vk).ok()?;
        Some(StaticPublicKey { ek, vk, encoded })
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
    pub dk: MlKem768DecryptingKey,

    /// The ML-DSA-65 signing key.
    pub sk: MlDsa65SigningKey,

    /// The corresponding [`StaticPublicKey`] for the secret key.
    pub pub_key: StaticPublicKey,

    /// The secret key's canonical encoded form.
    pub encoded: [u8; STATIC_SK_LEN],
}

impl StaticSecretKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + RngCore) -> StaticSecretKey {
        let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate(&mut rng);
        let (vk, sk) = ml_dsa_65::try_keygen_with_rng_vt(&mut rng).expect("should generate");

        let mut pub_encoded = Vec::with_capacity(STATIC_PK_LEN);
        pub_encoded.extend_from_slice(&ek.as_bytes());
        pub_encoded.extend_from_slice(&vk.clone().into_bytes());

        let mut sec_encoded = Vec::with_capacity(STATIC_SK_LEN);
        sec_encoded.extend_from_slice(&pub_encoded);
        sec_encoded.extend_from_slice(&dk.as_bytes());
        sec_encoded.extend_from_slice(&sk.clone().into_bytes());

        StaticSecretKey {
            dk,
            sk,
            pub_key: StaticPublicKey {
                ek,
                vk,
                encoded: pub_encoded.try_into().expect("should be public key sized"),
            },
            encoded: sec_encoded.try_into().expect("should be secret key sized"),
        }
    }

    /// Decodes the given slice as a secret key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticSecretKey> {
        let encoded = <[u8; STATIC_SK_LEN]>::try_from(b.as_ref()).ok()?;
        let (pub_key, dk, sk) = array_refs![&encoded, STATIC_PK_LEN, 2400, ml_dsa_65::SK_LEN];
        let pub_key = StaticPublicKey::from_canonical_bytes(pub_key)?;
        let dk = MlKem768DecryptingKey::from_bytes(dk.into());
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(*sk).ok()?;

        Some(StaticSecretKey { dk, sk, pub_key, encoded })
    }
}

impl Eq for StaticSecretKey {}

impl PartialEq for StaticSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}

impl Debug for StaticSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticSecretKey")
            .field("dk", &"[redacted]")
            .field("sk", &"[redacted]")
            .field("pub_key", &self.pub_key)
            .field("encoded", &"[redacted]")
            .finish()
    }
}

/// An ephemeral public key, including its canonical encoded form.
#[derive(Clone)]
pub struct EphemeralPublicKey {
    /// The ML-DSA-65 verifying key.
    pub vk: MlDsa65VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; EPHEMERAL_PK_LEN],
}

impl EphemeralPublicKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<EphemeralPublicKey> {
        let encoded = <[u8; EPHEMERAL_PK_LEN]>::try_from(b.as_ref()).ok()?;
        let vk = MlDsa65VerifyingKey::try_from_bytes(encoded).ok()?;
        Some(EphemeralPublicKey { vk, encoded })
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
    /// The ML-DSA-65 signing key.
    pub sk: MlDsa65SigningKey,

    /// The corresponding [`EphemeralPublicKey`] for the secret key.
    pub pub_key: EphemeralPublicKey,
}

impl EphemeralSecretKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> EphemeralSecretKey {
        let (vk, sk) = ml_dsa_65::try_keygen_with_rng_vt(&mut rng).expect("should generate");

        let mut encoded = Vec::with_capacity(EPHEMERAL_PK_LEN);
        encoded.extend_from_slice(&vk.clone().into_bytes());

        EphemeralSecretKey {
            sk,
            pub_key: EphemeralPublicKey {
                vk,
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

impl Debug for EphemeralSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralSecretKey")
            .field("dk", &"[redacted]")
            .field("sk", &"[redacted]")
            .field("pub_key", &self.pub_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn static_secret_key_round_trip() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let ssk = StaticSecretKey::random(rng);
        let ssk_p = StaticSecretKey::from_canonical_bytes(ssk.encoded).expect("should deserialize");
        assert_eq!(ssk.pub_key, ssk_p.pub_key);
    }

    #[test]
    fn static_public_key_round_trip() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let spk = StaticSecretKey::random(rng).pub_key;
        let spk_p = StaticPublicKey::from_canonical_bytes(spk.encoded).expect("should deserialize");
        assert_eq!(spk, spk_p);
    }

    #[test]
    fn ephemeral_public_key_round_trip() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let epk = EphemeralSecretKey::random(rng).pub_key;
        let epk_p =
            EphemeralPublicKey::from_canonical_bytes(epk.encoded).expect("should deserialize");
        assert_eq!(epk, epk_p);
    }
}
