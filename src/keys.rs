use crrl::jq255e::{Point, Scalar};
use rand::{CryptoRng, Rng};

/// The length of an encoded scalar in bytes.
pub const SCALAR_LEN: usize = 32;

/// The length of an encoded point in bytes.
pub const POINT_LEN: usize = 32;

/// A public key, including its canonical encoded form.
#[derive(Clone, Copy)]
pub struct PubKey {
    pub q: Point,
    pub encoded: [u8; POINT_LEN],
}

impl PubKey {
    /// Decodes the given slice as a public key, if possible.
    #[must_use]
    pub fn decode(b: impl AsRef<[u8]>) -> Option<PubKey> {
        let encoded = <[u8; POINT_LEN]>::try_from(b.as_ref()).ok()?;
        let q = Point::decode(&encoded)?;
        (q.isneutral() == 0).then_some(PubKey { q, encoded })
    }

    /// Generates a random public key for which no private key is known.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PubKey {
        let q = Point::hash_to_curve("", &rng.gen::<[u8; 64]>());
        let encoded = q.encode();
        PubKey { q, encoded }
    }
}

/// A private key, including its public key.
pub struct PrivKey {
    pub d: Scalar,
    pub pub_key: PubKey,
}

impl PrivKey {
    /// Generates a random private key.
    #[must_use]
    pub fn random(mut rng: impl CryptoRng + Rng) -> PrivKey {
        loop {
            let d = Scalar::decode_reduce(&rng.gen::<[u8; 64]>());
            if d.iszero() == 0 {
                return PrivKey::from_scalar(d);
            }
        }
    }

    /// Creates a new private key from the given non-zero scalar.
    #[must_use]
    pub fn from_scalar(d: Scalar) -> PrivKey {
        assert_eq!(d.iszero(), 0, "private key scalars must be non-zero");

        let q = Point::mulgen(&d);
        PrivKey { d, pub_key: PubKey { q, encoded: q.encode() } }
    }
}
