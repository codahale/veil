use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::util::{StrobeExt, G};

/// Derive a scalar from the given secret key.
pub fn derive_root(r: &[u8; 64]) -> Scalar {
    let mut root_df = Strobe::new(b"veil.scaldf.root", SecParam::B128);
    root_df.key(r, false);
    root_df.prf_scalar()
}

/// Derive a scalar from another scalar using the given key ID.
pub fn derive_scalar(d: Scalar, key_id: &str) -> Scalar {
    key_id_parts(key_id).iter().fold(d, |d_p, &label| {
        let mut label_df = Strobe::new(b"veil.scaldf.label", SecParam::B128);
        label_df.key(label.as_bytes(), false);
        d_p + label_df.prf_scalar()
    })
}

/// Derive a point from another point using the given key ID.
pub fn derive_point(q: &RistrettoPoint, key_id: &str) -> RistrettoPoint {
    q + (G * &derive_scalar(Scalar::zero(), key_id))
}

fn key_id_parts(key_id: &str) -> Vec<&str> {
    key_id.trim_matches('/').split('/').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn key_id_splitting() {
        assert_eq!(vec!["one", "two", "three"], key_id_parts("/one/two/three"));
        assert_eq!(vec!["two", "three"], key_id_parts("two/three"));
    }
}
