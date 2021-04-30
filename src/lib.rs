use std::io;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};
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
        let mut rng = OsRng::default();
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);

        SecretKey { seed }
    }

    pub fn private_key(&self) -> PrivateKey {
        let mut seed = [0u8; 64];

        let mut root_df = Strobe::new(b"veil.scaldf.root", SecParam::B256);
        root_df.key(&self.seed, false);
        root_df.prf(&mut seed, false);
        // TODO add HKD
        let d = Scalar::from_bytes_mod_order_wide(&seed);
        let q = RISTRETTO_BASEPOINT_POINT * d;

        PrivateKey {
            d,
            public_key: PublicKey { q },
        }
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
        recipients: Vec<&PublicKey>,
        padding: usize,
    ) -> io::Result<u64>
    where
        R: io::Read,
        W: io::Write,
    {
        mres::encrypt(
            reader,
            writer,
            &self.d,
            &self.public_key.q,
            recipients.into_iter().map(|pk| &pk.q).collect(),
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
        mres::decrypt(reader, writer, &self.d, &self.public_key.q, &sender.q)
    }

    pub fn sign<R: io::Read>(&self, reader: &mut R) -> io::Result<[u8; 64]> {
        let mut signer = schnorr::Signer::new();
        io::copy(reader, &mut signer)?;

        Ok(signer.sign(&self.d, &self.public_key.q))
    }
}

pub struct PublicKey {
    q: RistrettoPoint,
}

impl PublicKey {
    pub fn verify<R: io::Read>(&self, reader: &mut R, sig: &[u8; 64]) -> io::Result<bool> {
        let mut verifier = schnorr::Verifier::new();
        io::copy(reader, &mut verifier)?;

        Ok(verifier.verify(&self.q, &sig))
    }
}
