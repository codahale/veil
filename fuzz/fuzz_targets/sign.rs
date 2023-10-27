#![no_main]
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rand::rngs::OsRng;
use veil::PrivateKey;

fuzz_target!(|data: &[u8]| {
    let key = PrivateKey::random(OsRng);
    key.sign(OsRng, Cursor::new(data)).expect("should sign without error");
});
