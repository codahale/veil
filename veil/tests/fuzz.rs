use std::io::{self, Cursor};

use bolero::TypeGenerator;
use rand::SeedableRng;
use rand_chacha::rand_core::OsRng;
use rand_chacha::ChaChaRng;
use veil::{PrivateKey, Signature};

#[test]
fn decrypt() {
    bolero::check!().with_type::<(u64, Vec<u8>)>().for_each(|(seed, data)| {
        let key = PrivateKey::random(ChaChaRng::seed_from_u64(*seed));
        let _ = key.decrypt(Cursor::new(data), io::sink(), &key.public_key());
    });
}

#[test]
fn encrypt() {
    bolero::check!().with_type::<(u64, Vec<u8>)>().for_each(|(seed, data)| {
        let key = PrivateKey::random(ChaChaRng::seed_from_u64(*seed));
        key.encrypt(OsRng, Cursor::new(data), io::sink(), &[key.public_key()], None, None)
            .expect("should encrypt without error");
    });
}

#[test]
fn sign() {
    bolero::check!().with_type::<(u64, Vec<u8>)>().for_each(|(seed, data)| {
        let key = PrivateKey::random(ChaChaRng::seed_from_u64(*seed));
        key.sign(OsRng, Cursor::new(data)).expect("should sign without error");
    });
}

#[test]
fn verify() {
    #[derive(Debug, TypeGenerator)]
    struct Input {
        seed: u64,
        sig: [u8; 32],
        message: Vec<u8>,
    }

    bolero::check!().with_type().for_each(|input: &Input| {
        let key = PrivateKey::random(ChaChaRng::seed_from_u64(input.seed));
        if let Some(sig) = Signature::decode(input.sig) {
            let _ = key.public_key().verify(Cursor::new(&input.message), &sig);
        }
    });
}
