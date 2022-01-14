use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::util::{StrobeExt, G};

/// Derive a scalar from the given secret key.
#[must_use]
pub fn derive_root(r: &[u8; 64]) -> Scalar {
    let mut root_df = Strobe::new(b"veil.scaldf.root", SecParam::B128);
    root_df.key(r, false);
    root_df.prf_scalar()
}

/// Derive a scalar from another scalar using the given key ID.
#[must_use]
pub fn derive_scalar(d: Scalar, key_id: &str) -> Scalar {
    key_id.trim_matches(KEY_ID_DELIM).split(KEY_ID_DELIM).fold(d, |d_p, label| {
        let mut label_df = Strobe::new(b"veil.scaldf.label", SecParam::B128);
        label_df.key(label.as_bytes(), false);
        d_p + label_df.prf_scalar()
    })
}

/// Derive a point from another point using the given key ID.
#[must_use]
pub fn derive_point(q: &RistrettoPoint, key_id: &str) -> RistrettoPoint {
    q + (G * &derive_scalar(Scalar::zero(), key_id))
}

const KEY_ID_DELIM: char = '/';

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_derivation() {
        let d = Scalar::random(&mut rand::thread_rng());
        let d1 = derive_scalar(d, "/one");
        let d2 = derive_scalar(d1, "/two");
        let d3 = derive_scalar(d2, "/three");

        let d3_p = derive_scalar(d, "/one/two/three");

        assert_eq!(d3_p, d3);
    }

    #[test]
    fn point_derivation() {
        let d = Scalar::random(&mut rand::thread_rng());
        let q = G * &d;

        let q1 = derive_point(&q, "/one");
        let q2 = derive_point(&q1, "/two");
        let q3 = derive_point(&q2, "/three");

        let q3_p = derive_point(&q, "/one/two/three");

        assert_eq!(q3_p, q3);
    }
}
