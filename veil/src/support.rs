#![cfg(test)]

use curve25519_dalek::scalar::Scalar;
use rand::Rng;

pub fn rand_scalar() -> Scalar {
    let mut seed = [0u8; 64];
    let mut rng = rand::thread_rng();
    rng.fill(&mut seed);

    Scalar::from_bytes_mod_order_wide(&seed)
}
