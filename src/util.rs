use std::mem;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::Strobe;

pub fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("rng failure");
    out
}

pub const MAC_LEN: usize = 16;
pub const POINT_LEN: usize = 32;
pub const U32_LEN: usize = mem::size_of::<u32>();
pub const U64_LEN: usize = mem::size_of::<u64>();

pub trait StrobeExt {
    fn meta_ad_u32(&mut self, n: u32);
    fn key_point(&mut self, zz: RistrettoPoint);
    fn ad_point(&mut self, q: &RistrettoPoint);
    fn prf_scalar(&mut self) -> Scalar;
    fn prf_array<const N: usize>(&mut self) -> [u8; N];
    fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: FnOnce(&mut Strobe) -> R;
}

impl StrobeExt for Strobe {
    fn meta_ad_u32(&mut self, n: u32) {
        self.meta_ad(&n.to_le_bytes(), false);
    }

    fn key_point(&mut self, zz: RistrettoPoint) {
        self.key(zz.compress().as_bytes(), false);
    }

    fn ad_point(&mut self, q: &RistrettoPoint) {
        self.ad(q.compress().as_bytes(), false);
    }

    fn prf_scalar(&mut self) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.prf_array())
    }

    fn prf_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.prf(&mut out, false);
        out
    }

    fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: FnOnce(&mut Strobe) -> R,
    {
        // Clone the protocol's state.
        let mut clone = self.clone();

        // Key with the given secret.
        clone.key(secret, false);

        // Key with a random value.
        let r: [u8; 64] = rand_array();
        clone.key(&r, false);

        // Call the given function with the clone.
        f(&mut clone)
    }
}
