use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use strobe_rs::Strobe;

pub(crate) trait StrobeExt {
    fn key_rand(&mut self);
    fn prf_scalar(&mut self) -> Scalar;
}

impl StrobeExt for Strobe {
    fn key_rand(&mut self) {
        let mut seed = [0u8; 64];
        let mut rng = rand::thread_rng();
        rng.fill(&mut seed);
        self.key(&seed, false);
    }

    fn prf_scalar(&mut self) -> Scalar {
        let mut seed = [0u8; 64];
        self.prf(&mut seed, false);
        Scalar::from_bytes_mod_order_wide(&seed)
    }
}
