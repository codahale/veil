use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use strobe_rs::Strobe;

pub(crate) trait StrobeExt {
    fn prf_scalar(&mut self) -> Scalar;
    fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: FnOnce(&mut Strobe) -> R;
}

impl StrobeExt for Strobe {
    fn prf_scalar(&mut self) -> Scalar {
        let mut seed = [0u8; 64];
        self.prf(&mut seed, false);
        Scalar::from_bytes_mod_order_wide(&seed)
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
        let mut seed = [0u8; 64];
        let mut rng = rand::thread_rng();
        rng.fill(&mut seed);
        clone.key(&seed, false);

        // Call the given function with the clone.
        f(&mut clone)
    }
}
