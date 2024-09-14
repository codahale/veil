use std::fmt::{Debug, Formatter};

use arrayref::array_refs;
use fips204::{
    ml_dsa_65::{self},
    traits::SerDes as _,
};
use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand::{CryptoRng, Rng, RngCore};

pub const PK_LEN: usize = 1184 + ml_dsa_65::PK_LEN;

pub const SK_LEN: usize = 32 + // ML-KEM seed d
   32 + // ML-KEM seed z
   32; // ML-DSA seed ξ

pub type SigningKey = ml_dsa_65::PrivateKey;

pub type VerifyingKey = ml_dsa_65::PublicKey;

pub type EncapsulationKey = ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>;

pub type DecapsulationKey = ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>;

/// A public key, including its canonical encoded form.
#[derive(Clone)]
pub struct PubKey {
    /// The ML-KEM-768 encapsulation key.
    pub ek: EncapsulationKey,

    /// The ML-DSA-65 verifying key.
    pub vk: VerifyingKey,

    /// The public key's canonical encoded form.
    pub encoded: [u8; PK_LEN],
}

impl PubKey {
    /// Decodes the given slice as a public key, if possible. Returns `None` if the slice is not a
    /// canonically-encoded point or if it encodes the neutral point.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<PubKey> {
        let encoded = <[u8; PK_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek, vk) = array_refs![&encoded, 1184, ml_dsa_65::PK_LEN];
        let ek = EncapsulationKey::from_bytes(ek.into());
        let vk = VerifyingKey::try_from_bytes(*vk).ok()?;
        Some(PubKey { ek, vk, encoded })
    }

    fn from_parts(ek: EncapsulationKey, vk: VerifyingKey) -> PubKey {
        let mut encoded = Vec::with_capacity(PK_LEN);
        encoded.extend_from_slice(&ek.as_bytes());
        encoded.extend_from_slice(&vk.clone().into_bytes());

        PubKey { ek, vk, encoded: encoded.try_into().expect("should be public key sized") }
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

impl AsRef<VerifyingKey> for &PubKey {
    fn as_ref(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// A secret key, including its public key.
pub struct SecKey {
    /// The ML-KEM-768 decapsulation key.
    pub dk: DecapsulationKey,

    /// The ML-DSA-65 signing key.
    pub sk: SigningKey,

    /// The corresponding [`PubKey`] for the secret key.
    pub pub_key: PubKey,

    /// The secret key's canonical encoded form.
    pub encoded: [u8; SK_LEN],
}

impl SecKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + RngCore) -> SecKey {
        let dk_d = rng.gen::<[u8; 32]>();
        let dk_z = rng.gen::<[u8; 32]>();
        let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate_deterministic(
            &dk_d.into(),
            &dk_z.into(),
        );
        let sk_x = rng.gen::<[u8; 32]>();
        let (vk, sk) =
            ml_dsa_65::try_keygen_with_rng(&mut ConstRng::new(&sk_x)).expect("should generate");

        let mut sec_encoded = Vec::with_capacity(SK_LEN);
        sec_encoded.extend_from_slice(&dk_d);
        sec_encoded.extend_from_slice(&dk_z);
        sec_encoded.extend_from_slice(&sk_x);

        SecKey {
            dk,
            sk,
            pub_key: PubKey::from_parts(ek, vk),
            encoded: sec_encoded.try_into().expect("should be secret key sized"),
        }
    }

    /// Decodes the given slice as a secret key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<SecKey> {
        let encoded = <[u8; SK_LEN]>::try_from(b.as_ref()).ok()?;
        let (dk_d, dk_z, sk_x) = array_refs![&encoded, 32, 32, 32];
        let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate_deterministic(
            dk_d.into(),
            dk_z.into(),
        );
        let (vk, sk) =
            ml_dsa_65::try_keygen_with_rng(&mut ConstRng::new(sk_x)).expect("should generate");

        Some(SecKey { dk, sk, pub_key: PubKey::from_parts(ek, vk), encoded })
    }
}

impl Eq for SecKey {}

impl PartialEq for SecKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key
    }
}

impl Debug for SecKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecKey")
            .field("dk", &"[redacted]")
            .field("sk", &"[redacted]")
            .field("pub_key", &self.pub_key)
            .field("encoded", &"[redacted]")
            .finish()
    }
}

impl AsRef<SigningKey> for &SecKey {
    fn as_ref(&self) -> &SigningKey {
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
    fn sec_key_round_trip() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let ssk = SecKey::random(rng);
        let ssk_p = SecKey::from_canonical_bytes(ssk.encoded).expect("should deserialize");
        assert_eq!(ssk.pub_key, ssk_p.pub_key);
    }

    #[test]
    fn pub_key_round_trip() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let spk = SecKey::random(rng).pub_key;
        let spk_p = PubKey::from_canonical_bytes(spk.encoded).expect("should deserialize");
        assert_eq!(spk, spk_p);
    }
}
