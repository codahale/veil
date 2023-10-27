#![no_main]
use std::io::{self, Cursor};

use libfuzzer_sys::fuzz_target;
use rand::rngs::OsRng;
use veil::PrivateKey;

fuzz_target!(|data: &[u8]| {
    let key = PrivateKey::random(OsRng);
    let _ = key.decrypt(Cursor::new(data), io::sink(), &key.public_key());
});
