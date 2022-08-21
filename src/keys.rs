use crate::POINT_LEN;
use crrl::jq255e::{Point, Scalar};
use rand::{CryptoRng, Rng};

#[derive(Clone, Copy)]
pub struct PubKey {
    pub q: Point,
    pub encoded: [u8; POINT_LEN],
}

impl PubKey {
    pub fn from_point(q: Point) -> PubKey {
        PubKey { q, encoded: q.encode() }
    }

    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PubKey> {
        Point::decode(b.as_ref()).map(PubKey::from_point)
    }
}

pub struct PrivKey {
    pub d: Scalar,
    pub pub_key: PubKey,
}

impl PrivKey {
    pub fn random(mut rng: impl CryptoRng + Rng) -> PrivKey {
        loop {
            let d = Scalar::decode_reduce(&rng.gen::<[u8; 64]>());
            if d.iszero() == 0 {
                return PrivKey::from_scalar(d);
            }
        }
    }

    pub fn from_scalar(d: Scalar) -> PrivKey {
        assert_eq!(d.iszero(), 0, "private key scalars must be non-zero");

        let q = Point::mulgen(&d);
        PrivKey { d, pub_key: PubKey { q, encoded: q.encode() } }
    }
}
