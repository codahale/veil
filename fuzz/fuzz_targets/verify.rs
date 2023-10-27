#![no_main]
use std::io::Cursor;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::rngs::OsRng;
use veil::{PrivateKey, Signature};

#[derive(Debug, Arbitrary)]
struct Input {
    sig: [u8; 32],
    message: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let key = PrivateKey::random(OsRng);
    if let Some(sig) = Signature::decode(&input.sig) {
        let _ = key.public_key().verify(Cursor::new(input.message), &sig);
    }
});
