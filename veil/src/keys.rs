use std::fmt::{Debug, Formatter};

use arrayref::array_refs;
use fips204::{
    ml_dsa_65::{self},
    traits::SerDes as _,
};
use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand::{CryptoRng, Rng, RngCore};

pub const EPHEMERAL_PK_LEN: usize = 32 + ml_dsa_65::PK_LEN + 32;

pub const STATIC_PK_LEN: usize = 1184 + 32 + ml_dsa_65::PK_LEN + 32;

pub const STATIC_SK_LEN: usize = 32 + // ML-KEM seed d  
   32 + // ML-KEM seed z */ 
   32 + // X25519 secret key 
   32  + // ML-DSA seed ξ
   32; // Ed25519 secret key

pub type Ed25519SigningKey = ed25519_dalek::SigningKey;

pub type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;

pub type MlDsa65SigningKey = ml_dsa_65::PrivateKey;

pub type MlDsa65VerifyingKey = ml_dsa_65::PublicKey;

type MlKem768EncryptingKey = ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>;

type MlKem768DecryptingKey = ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>;

type X25519PublicKey = x25519_dalek::PublicKey;

type X25519SecretKey = x25519_dalek::StaticSecret;

/// A static public key, including its canonical encoded form.
#[derive(Clone)]
pub struct StaticPublicKey {
    /// The ML-KEM-768 encrypting key.
    pub ek_pq: MlKem768EncryptingKey,

    /// The X25519 encrypting key.
    pub ek_c: X25519PublicKey,

    /// The ML-DSA-65 verifying key.
    pub vk_pq: MlDsa65VerifyingKey,

    /// The Ed25519 verifying key.
    pub vk_c: Ed25519VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; STATIC_PK_LEN],
}

impl StaticPublicKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticPublicKey> {
        let encoded = <[u8; STATIC_PK_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek_pq, ek_c, vk_pq, vk_c) = array_refs![&encoded, 1184, 32, ml_dsa_65::PK_LEN, 32];
        let ek_pq = MlKem768EncryptingKey::from_bytes(ek_pq.into());
        let ek_c = X25519PublicKey::from(*ek_c);
        let vk_pq = MlDsa65VerifyingKey::try_from_bytes(*vk_pq).ok()?;
        let vk_c = Ed25519VerifyingKey::from_bytes(vk_c).ok()?;
        Some(StaticPublicKey { ek_pq, ek_c, vk_pq, vk_c, encoded })
    }

    fn from_parts(
        ek_pq: MlKem768EncryptingKey,
        ek_c: X25519PublicKey,
        vk_pq: MlDsa65VerifyingKey,
        vk_c: Ed25519VerifyingKey,
    ) -> StaticPublicKey {
        let mut encoded = Vec::with_capacity(STATIC_PK_LEN);
        encoded.extend_from_slice(&ek_pq.as_bytes());
        encoded.extend_from_slice(ek_c.as_bytes());
        encoded.extend_from_slice(&vk_pq.clone().into_bytes());
        encoded.extend_from_slice(vk_c.as_bytes());

        StaticPublicKey {
            ek_pq,
            ek_c,
            vk_pq,
            vk_c,
            encoded: encoded.try_into().expect("should be public key sized"),
        }
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

impl AsRef<Ed25519VerifyingKey> for &StaticPublicKey {
    fn as_ref(&self) -> &Ed25519VerifyingKey {
        &self.vk_c
    }
}

impl AsRef<MlDsa65VerifyingKey> for &StaticPublicKey {
    fn as_ref(&self) -> &MlDsa65VerifyingKey {
        &self.vk_pq
    }
}

/// A secret key, including its public key.
pub struct StaticSecretKey {
    /// The ML-KEM decrypting key.
    pub dk_pq: MlKem768DecryptingKey,

    /// The X25519 decrypting key.
    pub dk_c: X25519SecretKey,

    /// The ML-DSA-65 signing key.
    pub sk_pq: MlDsa65SigningKey,

    /// The Ed25519 signing key.
    pub sk_c: Ed25519SigningKey,

    /// The corresponding [`StaticPublicKey`] for the secret key.
    pub pub_key: StaticPublicKey,

    /// The secret key's canonical encoded form.
    pub encoded: [u8; STATIC_SK_LEN],
}

impl StaticSecretKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + RngCore) -> StaticSecretKey {
        let dk_pq_d = rng.gen::<[u8; 32]>();
        let dk_pq_z = rng.gen::<[u8; 32]>();
        let (dk_pq, ek_pq) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate_deterministic(
            &dk_pq_d.into(),
            &dk_pq_z.into(),
        );
        let dk_c = X25519SecretKey::random_from_rng(&mut rng);
        let ek_c = X25519PublicKey::from(&dk_c);
        let sk_pq_x = rng.gen::<[u8; 32]>();
        let (vk_pq, sk_pq) =
            ml_dsa_65::try_keygen_with_rng(&mut ConstRng::new(&sk_pq_x)).expect("should generate");
        let sk_c = Ed25519SigningKey::from_bytes(&rng.gen());
        let vk_c = sk_c.verifying_key();

        let mut sec_encoded = Vec::with_capacity(STATIC_SK_LEN);
        sec_encoded.extend_from_slice(&dk_pq_d);
        sec_encoded.extend_from_slice(&dk_pq_z);
        sec_encoded.extend_from_slice(dk_c.as_bytes());
        sec_encoded.extend_from_slice(&sk_pq_x);
        sec_encoded.extend_from_slice(sk_c.as_bytes());

        StaticSecretKey {
            dk_pq,
            dk_c,
            sk_pq,
            sk_c,
            pub_key: StaticPublicKey::from_parts(ek_pq, ek_c, vk_pq, vk_c),
            encoded: sec_encoded.try_into().expect("should be secret key sized"),
        }
    }

    /// Decodes the given slice as a secret key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticSecretKey> {
        let encoded = <[u8; STATIC_SK_LEN]>::try_from(b.as_ref()).ok()?;
        let (dk_pq_d, dk_pq_z, dk_c, sk_pq_x, sk_c) = array_refs![&encoded, 32, 32, 32, 32, 32];
        let (dk_pq, ek_pq) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate_deterministic(
            dk_pq_d.into(),
            dk_pq_z.into(),
        );
        let dk_c = X25519SecretKey::from(*dk_c);
        let ek_c = X25519PublicKey::from(&dk_c);
        let (vk_pq, sk_pq) =
            ml_dsa_65::try_keygen_with_rng(&mut ConstRng::new(sk_pq_x)).expect("should generate");
        let sk_c = Ed25519SigningKey::from(sk_c);
        let vk_c = sk_c.verifying_key();

        Some(StaticSecretKey {
            dk_pq,
            dk_c,
            sk_pq,
            sk_c,
            pub_key: StaticPublicKey::from_parts(ek_pq, ek_c, vk_pq, vk_c),
            encoded,
        })
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
            .field("dk_pq", &"[redacted]")
            .field("dk_c", &"[redacted]")
            .field("sk_pq", &"[redacted]")
            .field("sk_c", &"[redacted]")
            .field("pub_key", &self.pub_key)
            .field("encoded", &"[redacted]")
            .finish()
    }
}

impl AsRef<Ed25519SigningKey> for &StaticSecretKey {
    fn as_ref(&self) -> &Ed25519SigningKey {
        &self.sk_c
    }
}

impl AsRef<MlDsa65SigningKey> for &StaticSecretKey {
    fn as_ref(&self) -> &MlDsa65SigningKey {
        &self.sk_pq
    }
}

/// An ephemeral public key, including its canonical encoded form.
#[derive(Clone)]
pub struct EphemeralPublicKey {
    /// The X25519 encrypting key.
    pub ek_c: X25519PublicKey,

    /// The ML-DSA-65 verifying key.
    pub vk_pq: MlDsa65VerifyingKey,

    /// The Ed25519 verifying key.
    pub vk_c: Ed25519VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; EPHEMERAL_PK_LEN],
}

impl EphemeralPublicKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<EphemeralPublicKey> {
        let encoded = <[u8; EPHEMERAL_PK_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek_c, vk_pq, vk_c) = array_refs![&encoded, 32, ml_dsa_65::PK_LEN, 32];
        let ek_c = X25519PublicKey::from(*ek_c);
        let vk_pq = MlDsa65VerifyingKey::try_from_bytes(*vk_pq).ok()?;
        let vk_c = Ed25519VerifyingKey::from_bytes(vk_c).ok()?;
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

impl AsRef<Ed25519VerifyingKey> for &EphemeralPublicKey {
    fn as_ref(&self) -> &Ed25519VerifyingKey {
        &self.vk_c
    }
}

impl AsRef<MlDsa65VerifyingKey> for &EphemeralPublicKey {
    fn as_ref(&self) -> &MlDsa65VerifyingKey {
        &self.vk_pq
    }
}

/// An ephemeral secret key, including its public key.
pub struct EphemeralSecretKey {
    /// The X25519 decrypting key.
    pub dk_c: X25519SecretKey,

    /// The ML-DSA-65 signing key.
    pub sk_pq: MlDsa65SigningKey,

    /// The Ed25519 signing key.
    pub sk_c: Ed25519SigningKey,

    /// The corresponding [`EphemeralPublicKey`] for the secret key.
    pub pub_key: EphemeralPublicKey,
}

impl EphemeralSecretKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> EphemeralSecretKey {
        let dk_c = X25519SecretKey::random_from_rng(&mut rng);
        let ek_c = X25519PublicKey::from(&dk_c);
        let (vk_pq, sk_pq) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("should generate");
        let sk_c = Ed25519SigningKey::from_bytes(&rng.gen());
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

impl Debug for EphemeralSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralSecretKey")
            .field("dk_c", &"[redacted]")
            .field("sk_pq", &"[redacted]")
            .field("sk_c", &"[redacted]")
            .field("pub_key", &self.pub_key)
            .finish()
    }
}

impl AsRef<Ed25519SigningKey> for &EphemeralSecretKey {
    fn as_ref(&self) -> &Ed25519SigningKey {
        &self.sk_c
    }
}

impl AsRef<MlDsa65SigningKey> for &EphemeralSecretKey {
    fn as_ref(&self) -> &MlDsa65SigningKey {
        &self.sk_pq
    }
}

#[derive(Debug)]
struct ConstRng<'a> {
    x: Option<&'a [u8; 32]>,
}

impl<'a> CryptoRng for ConstRng<'a> {}
impl<'a> RngCore for ConstRng<'a> {
    fn next_u32(&mut self) -> u32 {
        unreachable!()
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).expect("should generate");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.copy_from_slice(self.x.take().expect("should only fill 32 bytes total"));
        Ok(())
    }
}

impl<'a> ConstRng<'a> {
    const fn new(x: &'a [u8; 32]) -> ConstRng<'a> {
        ConstRng { x: Some(x) }
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
