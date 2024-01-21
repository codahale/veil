#![allow(elided_lifetimes_in_paths)]

use std::{
    io,
    io::{Cursor, Read},
};

use divan::counter::BytesCount;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use veil::{Digest, PrivateKey};

const KB: u64 = 1024;
const LENS: &[u64] = &[0, KB, 8 * KB, 32 * KB, 64 * KB, 128 * KB, KB * KB];

#[divan::bench(args = LENS)]
fn encrypt(bencher: divan::Bencher, len: u64) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk_a = PrivateKey::random(&mut rng);
            let pk_b = PrivateKey::random(&mut rng);
            (rng, pk_a, pk_b, io::repeat(0).take(len), io::sink())
        })
        .counter(BytesCount::new(len))
        .bench_values(|(rng, pk_a, pk_b, plaintext, ciphertext)| {
            pk_a.encrypt(rng, plaintext, ciphertext, &[pk_b.public_key()], None, None).unwrap()
        });
}

#[divan::bench(args = LENS)]
fn decrypt(bencher: divan::Bencher, len: u64) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk_a = PrivateKey::random(&mut rng);
            let pk_b = PrivateKey::random(&mut rng);
            let mut ciphertext = Cursor::new(Vec::new());
            pk_a.encrypt(
                &mut rng,
                io::repeat(0).take(len),
                &mut ciphertext,
                &[pk_b.public_key()],
                None,
                None,
            )
            .unwrap();
            (pk_a, pk_b, Cursor::new(ciphertext.into_inner()))
        })
        .counter(BytesCount::new(len))
        .bench_refs(|(pk_a, pk_b, ciphertext)| {
            pk_b.decrypt(ciphertext, io::sink(), &pk_a.public_key()).unwrap()
        });
}

#[divan::bench(args = LENS)]
fn sign(bencher: divan::Bencher, len: u64) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            (rng, pk, io::repeat(0).take(len))
        })
        .counter(BytesCount::new(len))
        .bench_refs(|(rng, pk, message)| pk.sign(rng, message).unwrap());
}

#[divan::bench(args = LENS)]
fn verify(bencher: divan::Bencher, len: u64) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            let sig = pk.sign(rng, io::repeat(0).take(len)).unwrap();
            (pk, io::repeat(0).take(len), sig)
        })
        .counter(BytesCount::new(len))
        .bench_refs(|(pk, message, sig)| pk.public_key().verify(message, sig));
}

#[divan::bench(args = LENS)]
fn digest(bencher: divan::Bencher, len: u64) {
    bencher
        .with_inputs(|| io::repeat(0).take(len))
        .counter(BytesCount::new(len))
        .bench_values(|message| Digest::new(&[""; 0], message).unwrap());
}

const TIME_COSTS: &[u8] = &[1, 2, 4, 6, 8];

#[divan::bench(args = TIME_COSTS)]
fn pbenc_time(bencher: divan::Bencher, time: u8) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            (rng, pk)
        })
        .bench_values(|(rng, pk)| pk.store(io::sink(), rng, b"passphrase", time, 0));
}

const MEMORY_COSTS: &[u8] = &[1, 2, 4, 6, 8];

#[divan::bench(args = MEMORY_COSTS)]
fn pbenc_memory(bencher: divan::Bencher, memory: u8) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            (rng, pk)
        })
        .bench_values(|(rng, pk)| pk.store(io::sink(), rng, b"passphrase", 0, memory));
}

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}
