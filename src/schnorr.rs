use std::io;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use std::convert::TryInto;
use strobe_rs::{SecParam, Strobe};

pub struct Signer<W: io::Write> {
    schnorr: Strobe,
    writer: W,
}

impl<W> Signer<W>
where
    W: io::Write,
{
    pub fn new(writer: W) -> Signer<W> {
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B256);
        schnorr.send_clr(&[], false);

        Signer { schnorr, writer }
    }

    pub fn sign(&mut self, d: &Scalar, q: &RistrettoPoint) -> [u8; 64] {
        self.schnorr.ad(q.compress().as_bytes(), false);

        let mut seed = [0u8; 64];

        {
            let mut clone = self.schnorr.clone();
            let mut rng = rand::thread_rng();
            rng.fill(&mut seed);
            clone.key(&seed, false);
            clone.key(d.as_bytes(), false);
            clone.prf(&mut seed, false);
        }

        let r = Scalar::from_bytes_mod_order_wide(&seed);
        let r_g = RISTRETTO_BASEPOINT_POINT * r;

        self.schnorr.ad(r_g.compress().as_bytes(), false);
        self.schnorr.prf(&mut seed, false);

        let c = Scalar::from_bytes_mod_order_wide(&seed);
        let s = d * c + r;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(c.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        sig
    }

    pub fn direct_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }
}

impl<W> io::Write for Signer<W>
where
    W: io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.schnorr.send_clr(buf, true);

        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub struct Verifier {
    schnorr: Strobe,
}

impl Verifier {
    pub fn new() -> Verifier {
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B256);
        schnorr.recv_clr(&[], false);

        Verifier { schnorr }
    }

    pub fn verify(mut self, q: &RistrettoPoint, sig: &[u8; 64]) -> bool {
        let c = match Scalar::from_canonical_bytes(sig[..32].try_into().unwrap()) {
            Some(v) => v,
            None => return false,
        };

        let s = match Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()) {
            Some(v) => v,
            None => return false,
        };

        let r_g = (RISTRETTO_BASEPOINT_POINT * s) + (-c * q);

        self.schnorr.ad(q.compress().as_bytes(), false);
        self.schnorr.ad(r_g.compress().as_bytes(), false);

        let mut seed = [0u8; 64];
        self.schnorr.prf(&mut seed, false);

        Scalar::from_bytes_mod_order_wide(&seed) == c
    }
}

impl io::Write for Verifier {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.schnorr.recv_clr(buf, true);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use crate::schnorr::{Signer, Verifier};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use std::io;
    use std::io::Write;

    #[test]
    pub fn sign_and_verify() {
        let mut rng = rand::thread_rng();
        let d = Scalar::random(&mut rng);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that").unwrap();
        signer.write(b" is in multiple pieces").unwrap();
        signer.flush().unwrap();

        let sig = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that").unwrap();
        verifier.write(b" is in multiple").unwrap();
        verifier.write(b" pieces").unwrap();
        verifier.flush().unwrap();

        assert_eq!(true, verifier.verify(&q, &sig));
    }

    #[test]
    pub fn bad_message() {
        let mut rng = rand::thread_rng();
        let d = Scalar::random(&mut rng);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that").unwrap();
        signer.write(b" is in multiple pieces").unwrap();
        signer.flush().unwrap();

        let sig = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is NOT a message that").unwrap();
        verifier.write(b" is in multiple").unwrap();
        verifier.write(b" pieces").unwrap();
        verifier.flush().unwrap();

        assert_eq!(false, verifier.verify(&q, &sig));
    }

    #[test]
    pub fn bad_key() {
        let mut rng = rand::thread_rng();
        let d = Scalar::random(&mut rng);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that").unwrap();
        signer.write(b" is in multiple pieces").unwrap();
        signer.flush().unwrap();

        let sig = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that").unwrap();
        verifier.write(b" is in multiple").unwrap();
        verifier.write(b" pieces").unwrap();
        verifier.flush().unwrap();

        assert_eq!(false, verifier.verify(&RISTRETTO_BASEPOINT_POINT, &sig));
    }
}
