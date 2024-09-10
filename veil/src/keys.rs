use std::fmt::{Debug, Formatter};

use arrayref::array_refs;
use fips204::{
    ml_dsa_65::{self},
    traits::SerDes as _,
};
use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand::{CryptoRng, Rng, RngCore};

pub const STATIC_PK_LEN: usize = 1184 + ml_dsa_65::PK_LEN;

pub const STATIC_SK_LEN: usize = 32 + // ML-KEM seed d  
   32 + // ML-KEM seed z */ 
   32; // ML-DSA seed ξ

pub type MlDsa65SigningKey = ml_dsa_65::PrivateKey;

pub type MlDsa65VerifyingKey = ml_dsa_65::PublicKey;

pub type MlKem768EncryptingKey = ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>;

pub type MlKem768DecryptingKey = ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>;

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

    fn from_parts(ek: MlKem768EncryptingKey, vk: MlDsa65VerifyingKey) -> StaticPublicKey {
        let mut encoded = Vec::with_capacity(STATIC_PK_LEN);
        encoded.extend_from_slice(&ek.as_bytes());
        encoded.extend_from_slice(&vk.clone().into_bytes());

        StaticPublicKey { ek, vk, encoded: encoded.try_into().expect("should be public key sized") }
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

impl AsRef<MlDsa65VerifyingKey> for &StaticPublicKey {
    fn as_ref(&self) -> &MlDsa65VerifyingKey {
        &self.vk
    }
}

/// A secret key, including its public key.
pub struct StaticSecretKey {
    /// The ML-KEM-768 decrypting key.
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
        let dk_d = rng.gen::<[u8; 32]>();
        let dk_z = rng.gen::<[u8; 32]>();
        let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate_deterministic(
            &dk_d.into(),
            &dk_z.into(),
        );
        let sk_x = rng.gen::<[u8; 32]>();
        let (vk, sk) =
            ml_dsa_65::try_keygen_with_rng(&mut ConstRng::new(&sk_x)).expect("should generate");

        let mut sec_encoded = Vec::with_capacity(STATIC_SK_LEN);
        sec_encoded.extend_from_slice(&dk_d);
        sec_encoded.extend_from_slice(&dk_z);
        sec_encoded.extend_from_slice(&sk_x);

        StaticSecretKey {
            dk,
            sk,
            pub_key: StaticPublicKey::from_parts(ek, vk),
            encoded: sec_encoded.try_into().expect("should be secret key sized"),
        }
    }

    /// Decodes the given slice as a secret key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<StaticSecretKey> {
        let encoded = <[u8; STATIC_SK_LEN]>::try_from(b.as_ref()).ok()?;
        let (dk_d, dk_z, sk_x) = array_refs![&encoded, 32, 32, 32];
        let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate_deterministic(
            dk_d.into(),
            dk_z.into(),
        );
        let (vk, sk) =
            ml_dsa_65::try_keygen_with_rng(&mut ConstRng::new(sk_x)).expect("should generate");

        Some(StaticSecretKey { dk, sk, pub_key: StaticPublicKey::from_parts(ek, vk), encoded })
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

impl AsRef<MlDsa65SigningKey> for &StaticSecretKey {
    fn as_ref(&self) -> &MlDsa65SigningKey {
        &self.sk
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
}
