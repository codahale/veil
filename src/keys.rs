use crrl::jq255e::{Point, Scalar};
use rand::{CryptoRng, Rng};

use crate::POINT_LEN;

#[derive(Clone, Copy)]
pub struct PubKey {
    pub q: Point,
    pub encoded: [u8; POINT_LEN],
}

impl PubKey {
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PubKey> {
        let encoded = <[u8; POINT_LEN]>::try_from(b.as_ref()).ok()?;
        let q = Point::decode(&encoded)?;
        Some(PubKey { q, encoded })
    }

    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PubKey {
        let q = Point::hash_to_curve("", &rng.gen::<[u8; 64]>());
        let encoded = q.encode();
        PubKey { q, encoded }
    }
}

pub struct PrivKey {
    pub d: Scalar,
    pub pub_key: PubKey,
}

impl PrivKey {
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PrivKey {
        loop {
            let d = Scalar::decode_reduce(&rng.gen::<[u8; 64]>());
            if d.iszero() == 0 {
                return PrivKey::from_scalar(d);
            }
        }
    }

    #[must_use]
    pub fn from_scalar(d: Scalar) -> PrivKey {
        assert_eq!(d.iszero(), 0, "private key scalars must be non-zero");

        let q = Point::mulgen(&d);
        PrivKey { d, pub_key: PubKey { q, encoded: q.encode() } }
    }
}
