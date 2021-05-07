//! scaldf implements Veil's scalar derivation functions, which derive ristretto255 scalars from
//! other pieces of data.
//!
//! Scalars are generated as follows, given a protocol name `P` and datum `D`:
//!
//! ```text
//! INIT(P, level=256)
//! KEY(D)
//! PRF(64)
//! ```
//!
//! The two recognized protocol identifiers are: `veil.scaldf.label`, used to derive delta scalars
//! from labels; `veil.scaldf.root`, used to derive root scalars from secret keys.
//!

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::util::StrobeExt;

pub(crate) fn derive_root(seed: &[u8; 64]) -> Scalar {
    let mut root_df = Strobe::new(b"veil.scaldf.root", SecParam::B256);
    root_df.key(seed, false);
    root_df.prf_scalar()
}

pub(crate) fn derive_scalar(d: &Scalar, key_id: &str) -> Scalar {
    key_id_parts(key_id).iter().fold(*d, |d_p, &label| {
        let mut label_df = Strobe::new(b"veil.scaldf.label", SecParam::B256);
        label_df.key(label.as_bytes(), false);

        d_p + label_df.prf_scalar()
    })
}

pub(crate) fn derive_point(q: &RistrettoPoint, key_id: &str) -> RistrettoPoint {
    q + (RISTRETTO_BASEPOINT_POINT * derive_scalar(&Scalar::zero(), key_id))
}

fn key_id_parts(key_id: &str) -> Vec<&str> {
    key_id
        .trim_matches(|s| s == '/')
        .split(|s| s == '/')
        .collect()
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
