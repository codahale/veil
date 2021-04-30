use std::{cmp, fmt, io};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::Rng;
use strobe_rs::{SecParam, Strobe};

mod common;
mod hpke;
mod mres;
mod schnorr;

pub struct SecretKey {
    seed: [u8; 64],
}

impl SecretKey {
    pub fn new() -> SecretKey {
        let mut seed = [0u8; 64];
        rand::thread_rng().fill(&mut seed);

        SecretKey { seed }
    }

    pub fn private_key(&self, key_id: &str) -> PrivateKey {
        let mut seed = [0u8; 64];

        let mut root_df = Strobe::new(b"veil.scaldf.root", SecParam::B256);
        root_df.key(&self.seed, false);
        root_df.prf(&mut seed, false);

        let d = Scalar::from_bytes_mod_order_wide(&seed);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        PrivateKey {
            d,
            public_key: PublicKey { q },
        }
        .derive(key_id)
    }

    pub fn public_key(&self, key_id: &str) -> PublicKey {
        self.private_key(key_id).public_key
    }
}

pub struct PrivateKey {
    d: Scalar,

    pub public_key: PublicKey,
}

impl PrivateKey {
    pub fn encrypt<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        recipients: Vec<PublicKey>,
        fakes: usize,
        padding: u64,
    ) -> io::Result<u64>
    where
        R: io::Read,
        W: io::Write,
    {
        // Add any fakes and shuffle the recipients list.
        let mut rng = rand::thread_rng();
        let mut q_rs: Vec<RistrettoPoint> = recipients.into_iter().map(|pk| pk.q).collect();
        q_rs.extend((0..fakes).map(|_| RistrettoPoint::random(&mut rng)));
        q_rs.shuffle(&mut rng);

        mres::encrypt(
            &mut io::BufReader::new(reader),
            &mut io::BufWriter::new(writer),
            &self.d,
            &self.public_key.q,
            q_rs,
            padding,
        )
    }

    pub fn decrypt<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        sender: &PublicKey,
    ) -> io::Result<u64>
    where
        R: io::Read,
        W: io::Write,
    {
        mres::decrypt(
            &mut io::BufReader::new(reader),
            &mut io::BufWriter::new(writer),
            &self.d,
            &self.public_key.q,
            &sender.q,
        )
    }

    pub fn sign<R: io::Read>(&self, reader: &mut R) -> io::Result<[u8; 64]> {
        let mut signer = schnorr::Signer::new(io::sink());
        io::copy(reader, &mut signer)?;

        Ok(signer.sign(&self.d, &self.public_key.q))
    }

    pub fn derive(&self, key_id: &str) -> PrivateKey {
        let d = derive_scalar(&self.d, key_id);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        PrivateKey {
            d,
            public_key: PublicKey { q },
        }
    }
}

impl cmp::PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.public_key.fmt(f)
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct PublicKey {
    q: RistrettoPoint,
}

impl PublicKey {
    pub fn verify<R: io::Read>(&self, reader: &mut R, sig: &[u8; 64]) -> io::Result<bool> {
        let mut verifier = schnorr::Verifier::new();
        io::copy(reader, &mut verifier)?;

        Ok(verifier.verify(&self.q, &sig))
    }

    pub fn derive(&self, key_id: &str) -> PublicKey {
        let q = derive_point(&self.q, key_id);

        PublicKey { q }
    }
}

fn derive_scalar(d: &Scalar, key_id: &str) -> Scalar {
    let mut seed = [0u8; 64];
    let mut d_p = d.clone();

    for label in key_id_parts(key_id) {
        let mut root_df = Strobe::new(b"veil.scaldf.label", SecParam::B256);
        root_df.key(label.as_bytes(), false);
        root_df.prf(&mut seed, false);

        let r = Scalar::from_bytes_mod_order_wide(&seed);

        d_p += &r;
    }

    d_p
}

fn derive_point(q: &RistrettoPoint, key_id: &str) -> RistrettoPoint {
    let r = RISTRETTO_BASEPOINT_POINT * derive_scalar(&Scalar::zero(), key_id);

    q + r
}

fn key_id_parts(key_id: &str) -> Vec<&str> {
    let poop = key_id.trim_matches(|s| s == '/');

    poop.split(|s| s == '/').collect()
}

#[cfg(test)]
mod tests {
    use crate::{key_id_parts, SecretKey};

    #[test]
    pub fn private_keys() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c");
        let abc_p = sk.private_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }

    #[test]
    pub fn public_keys() {
        let sk = SecretKey::new();

        let abc = sk.private_key("/a/b/c").public_key;
        let abc_p = sk.public_key("/a").derive("b").derive("c");

        assert_eq!(abc, abc_p);
    }

    #[test]
    pub fn key_id_splitting() {
        assert_eq!(vec!["one", "two", "three"], key_id_parts("/one/two/three"));
        assert_eq!(vec!["two", "three"], key_id_parts("two/three"));
    }
}
