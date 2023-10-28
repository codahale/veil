use std::io;
use std::io::{Cursor, Read};

use divan::counter::BytesCount;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use veil::{Digest, PrivateKey};

const KB: u64 = 1024;
const LENS: &[u64] = &[0, KB, 8 * KB, 32 * KB, 64 * KB, 128 * KB, KB * KB];

#[divan::bench(consts = LENS)]
fn encrypt<const LEN: u64>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk_a = PrivateKey::random(&mut rng);
            let pk_b = PrivateKey::random(&mut rng);
            (rng, pk_a, pk_b, io::repeat(0).take(LEN), io::sink())
        })
        .counter(BytesCount::new(LEN))
        .bench_values(|(rng, pk_a, pk_b, plaintext, ciphertext)| {
            pk_a.encrypt(rng, plaintext, ciphertext, &[pk_b.public_key()], None, None).unwrap()
        });
}

#[divan::bench(consts = LENS)]
fn decrypt<const LEN: u64>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk_a = PrivateKey::random(&mut rng);
            let pk_b = PrivateKey::random(&mut rng);
            let mut ciphertext = Cursor::new(Vec::new());
            pk_a.encrypt(
                &mut rng,
                io::repeat(0).take(LEN),
                &mut ciphertext,
                &[pk_b.public_key()],
                None,
                None,
            )
            .unwrap();
            (pk_a, pk_b, Cursor::new(ciphertext.into_inner()))
        })
        .counter(BytesCount::new(LEN))
        .bench_refs(|(pk_a, pk_b, ciphertext)| {
            pk_b.decrypt(ciphertext, io::sink(), &pk_a.public_key()).unwrap()
        });
}

#[divan::bench(consts = LENS)]
fn sign<const LEN: u64>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            (rng, pk, io::repeat(0).take(LEN))
        })
        .counter(BytesCount::new(LEN))
        .bench_refs(|(rng, pk, message)| pk.sign(rng, message).unwrap());
}

#[divan::bench(consts = LENS)]
fn verify<const LEN: u64>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            let sig = pk.sign(rng, io::repeat(0).take(LEN)).unwrap();
            (pk, io::repeat(0).take(LEN), sig)
        })
        .counter(BytesCount::new(LEN))
        .bench_refs(|(pk, message, sig)| pk.public_key().verify(message, sig));
}

#[divan::bench(consts = LENS)]
fn digest<const LEN: u64>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| io::repeat(0).take(LEN))
        .counter(BytesCount::new(LEN))
        .bench_values(|message| Digest::new(&[] as &[&str], message).unwrap());
}

const TIME_COSTS: &[u8] = &[1, 2, 4, 6, 8];

#[divan::bench(consts = TIME_COSTS)]
fn pbenc_time<const TIME: u8>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            (rng, pk)
        })
        .bench_values(|(rng, pk)| pk.store(io::sink(), rng, b"passphrase", TIME, 0));
}

const MEMORY_COSTS: &[u8] = &[1, 2, 4, 6, 8];

#[divan::bench(consts = MEMORY_COSTS)]
fn pbenc_memory<const MEMORY: u8>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            (rng, pk)
        })
        .bench_values(|(rng, pk)| pk.store(io::sink(), rng, b"passphrase", 0, MEMORY));
}

fn main() {
    divan::main();
}
