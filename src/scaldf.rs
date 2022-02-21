//! Scalar derivation functions.

use crate::duplex::Duplex;
use crate::ristretto::Scalar;

/// Derive a root scalar from the given secret key.
#[must_use]
pub fn root_scalar(r: &[u8]) -> Scalar {
    // Initialize the duplex.
    let mut root_df = Duplex::new("veil.scaldf.root");

    // Absorb the secret key.
    root_df.absorb(r);

    // Squeeze a scalar.
    root_df.squeeze_scalar()
}

/// Derive a label scalar from a key ID.
#[must_use]
pub fn label_scalar(key_id: &str) -> Scalar {
    key_id
        .trim_matches(KEY_ID_DELIM)
        .split(KEY_ID_DELIM)
        .map(|label| {
            // Initialize the duplex.
            let mut label_df = Duplex::new("veil.scaldf.label");

            // Absorb the label.
            label_df.absorb(label.as_bytes());

            // Squeeze a scalar.
            label_df.squeeze_scalar()
        })
        .sum::<Scalar>()
}

const KEY_ID_DELIM: char = '/';

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_derivation() {
        let d1 = label_scalar("/one");
        let d2 = d1 + label_scalar("/two");
        let d3 = d2 + label_scalar("/three");

        let d3_p = label_scalar("/one/two/three");

        assert_eq!(d3_p, d3, "invalid hierarchical derivation");
    }
}
