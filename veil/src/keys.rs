use std::fmt::{Debug, Formatter};

use fips204::{
    ml_dsa_65::{self},
    traits::{KeyGen as _, SerDes as _},
};
use lockstitch::Protocol;
use ml_kem::{EncodedSizeUser, KemCore};
use rand::{CryptoRng, Rng, RngCore};
use typenum::Unsigned;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) const ML_KEM_PK_LEN: usize =
    <<ml_kem::MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
pub(crate) const ML_KEM_CT_LEN: usize = <ml_kem::MlKem768 as KemCore>::CiphertextSize::USIZE;
pub(crate) const ML_KEM_SS_LEN: usize = <ml_kem::MlKem768 as KemCore>::SharedKeySize::USIZE;

pub const PK_LEN: usize = ML_KEM_PK_LEN + ml_dsa_65::PK_LEN;

pub const SK_LEN: usize = 256;

pub type SigningKey = ml_dsa_65::PrivateKey;

pub type VerifyingKey = ml_dsa_65::PublicKey;

pub type EncapsulationKey = ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>;

pub type DecapsulationKey = ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>;

/// A public key, including its canonical encoded form.
#[derive(Clone)]
pub struct PubKey {
    /// The ML-KEM-768 encapsulation key.
    pub ek: Box<EncapsulationKey>,

    /// The ML-DSA-65 verifying key.
    pub vk: Box<VerifyingKey>,

    /// The public key's canonical encoded form.
    pub encoded: [u8; PK_LEN],
}

impl PubKey {
    /// Decodes the given slice as a public key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<PubKey> {
        let encoded = <[u8; PK_LEN]>::try_from(b.as_ref()).ok()?;
        let (ek, vk) = encoded.split_at(ML_KEM_PK_LEN);
        let ek = EncapsulationKey::from_bytes(ek.try_into().expect("should be 1184 bytes"));
        let vk = VerifyingKey::try_from_bytes(vk.try_into().expect("should be 1952 bytes")).ok()?;
        Some(PubKey { ek: ek.into(), vk: vk.into(), encoded })
    }

    fn from_parts(ek: EncapsulationKey, vk: VerifyingKey) -> PubKey {
        let mut encoded = [0u8; PK_LEN];
        let (enc_ek, enc_vk) = encoded.split_at_mut(ML_KEM_PK_LEN);
        enc_ek.copy_from_slice(&ek.as_bytes());
        enc_vk.copy_from_slice(&vk.clone().into_bytes());

        PubKey { ek: ek.into(), vk: vk.into(), encoded }
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
    pub dk: Box<DecapsulationKey>,

    /// The ML-DSA-65 signing key.
    pub sk: Box<SigningKey>,

    /// The corresponding [`PubKey`] for the secret key.
    pub pub_key: PubKey,

    /// The secret key seed.
    pub seed: [u8; SK_LEN],
}

impl SecKey {
    /// Generates a random secret key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + RngCore) -> SecKey {
        Self::from_canonical_bytes(rng.gen::<[u8; SK_LEN]>()).expect("should parse")
    }

    /// Decodes the given slice as a secret key, if possible.
    #[must_use]
    pub fn from_canonical_bytes(b: impl AsRef<[u8]>) -> Option<SecKey> {
        let seed = <[u8; SK_LEN]>::try_from(b.as_ref()).ok()?;

        let mut key = Protocol::new("veil.key");
        key.mix("seed", &seed);

        let dk_d = key.derive_array::<32>("ml-kem-768-d");
        let dk_z = key.derive_array::<32>("ml-kem-768-z");
        let (dk, ek) = ml_kem::MlKem768::generate_deterministic(&dk_d.into(), &dk_z.into());
        let sk_x = key.derive_array::<32>("ml-dsa-65-x");
        let (vk, sk) = ml_dsa_65::KG::keygen_from_seed(&sk_x);

        Some(SecKey { dk: dk.into(), sk: sk.into(), pub_key: PubKey::from_parts(ek, vk), seed })
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
            .field("seed", &"[redacted]")
            .field("pub_key", &self.pub_key)
            .finish()
    }
}

impl AsRef<SigningKey> for &SecKey {
    fn as_ref(&self) -> &SigningKey {
        &self.sk
    }
}

impl Drop for SecKey {
    fn drop(&mut self) {
        // both keys are zeroized on drop
        self.seed.zeroize();
    }
}

impl ZeroizeOnDrop for SecKey {}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn sec_key_round_trip() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let ssk = SecKey::random(rng);
        let ssk_p = SecKey::from_canonical_bytes(ssk.seed).expect("should deserialize");
        assert_eq!(ssk.pub_key, ssk_p.pub_key);
    }

    #[test]
    fn pub_key_round_trip() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let spk = SecKey::random(rng).pub_key.clone();
        let spk_p = PubKey::from_canonical_bytes(spk.encoded).expect("should deserialize");
        assert_eq!(spk, spk_p);
    }
}
