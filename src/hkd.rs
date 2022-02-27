//! Hierarchical key derivation.

use crate::duplex::Duplex;
use crate::ristretto::{CanonicallyEncoded, Point, Scalar};

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

/// Derive a label scalar from a parent public key and a label.
#[inline]
#[must_use]
pub fn label_scalar(q: &Point, label: &impl AsRef<[u8]>) -> Scalar {
    // Initialize the duplex.
    let mut hkd = Duplex::new("veil.hkd.label");

    // Absorb the public key.
    hkd.absorb(&q.to_canonical_encoding());

    // Absorb the label.
    hkd.absorb(label.as_ref());

    // Squeeze a scalar.
    hkd.squeeze_scalar()
}
