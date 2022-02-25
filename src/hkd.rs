//! Hierarchical key derivation.

use std::str::Split;

use crate::duplex::Duplex;
use crate::ristretto::{CanonicallyEncoded, Point, Scalar, G};

/// Derive a root scalar from the given secret key.
#[must_use]
pub fn root_key(r: &[u8]) -> Scalar {
    // Initialize the duplex.
    let mut root_df = Duplex::new("veil.hkd.root");

    // Absorb the secret key.
    root_df.absorb(r);

    // Squeeze a scalar.
    root_df.squeeze_scalar()
}

/// Derive a child private key from the given private key and key ID.
#[must_use]
pub fn private_key(d: Scalar, key_id: &str) -> Scalar {
    key_path(key_id).fold(d, |d, label| d + label_scalar(&(&d * &G), label))
}

/// Derive a child public key from the given public key and key ID.
#[must_use]
pub fn public_key(q: Point, key_id: &str) -> Point {
    key_path(key_id).fold(q, |q, label| q + (&label_scalar(&q, label) * &G))
}

/// Derive a label scalar from a parent public key and a label.
#[inline]
#[must_use]
fn label_scalar(q: &Point, label: &str) -> Scalar {
    // Initialize the duplex.
    let mut hkd = Duplex::new("veil.hkd.label");

    // Absorb the public key.
    hkd.absorb(&q.to_canonical_encoding());

    // Absorb the label.
    hkd.absorb(label.as_bytes());

    // Squeeze a scalar.
    hkd.squeeze_scalar()
}

#[inline]
fn key_path(key_id: &str) -> Split<'_, char> {
    const KEY_ID_DELIM: char = '/';
    key_id.trim_matches(KEY_ID_DELIM).split(KEY_ID_DELIM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_derivation() {
        let a = Scalar::random(&mut rand::thread_rng());
        let abc = private_key(a, "/b/c");

        let b = private_key(a, "/b");
        let c = private_key(b, "/c");

        assert_eq!(abc, c, "invalid hierarchical derivation");
    }

    #[test]
    fn hierarchical_private_keys() {
        let a = Scalar::random(&mut rand::thread_rng());
        let abc = private_key(a, "/b/c");
        let acb = private_key(a, "/c/b");

        assert_ne!(abc, acb, "invalid hierarchical derivation");
    }

    #[test]
    fn public_key_derivation() {
        let a = Scalar::random(&mut rand::thread_rng());
        let q_abc = &private_key(a, "/b/c") * &G;

        let q_a = &a * &G;
        let q_b = public_key(q_a, "/b");
        let q_c = public_key(q_b, "/c");

        assert_eq!(q_abc, q_c, "invalid hierarchical derivation");
    }

    #[test]
    fn hierarchical_public_keys() {
        let a = Point::random(&mut rand::thread_rng());
        let abc = public_key(a, "/b/c");
        let acb = public_key(a, "/c/b");

        assert_ne!(abc, acb, "invalid hierarchical derivation");
    }
}