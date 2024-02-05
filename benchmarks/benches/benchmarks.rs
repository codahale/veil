use std::{
    io,
    io::{Cursor, Read},
};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use veil::{Digest, PrivateKey};

const LENS: &[(u64, &str)] = &[(0, "0B"), (1024 * 1024, "1MiB"), (10 * 1024 * 1024, "10MiB")];

fn encrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group("encrypt");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len));
        g.bench_function(id, |b| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk_a = PrivateKey::random(&mut rng);
            let pk_b = PrivateKey::random(&mut rng);
            b.iter(|| {
                pk_a.encrypt(
                    &mut rng,
                    io::repeat(0).take(len),
                    io::sink(),
                    &[pk_b.public_key()],
                    None,
                    None,
                )
                .unwrap()
            });
        });
    }
    g.finish();
}

fn decrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group("decrypt");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len));
        g.bench_function(id, |b| {
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
            let ciphertext = Cursor::new(ciphertext.into_inner());
            b.iter(|| pk_b.decrypt(ciphertext.clone(), io::sink(), &pk_a.public_key()).unwrap());
        });
    }
    g.finish();
}

fn sign(c: &mut Criterion) {
    let mut g = c.benchmark_group("sign");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len));
        g.bench_function(id, |b| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            b.iter(|| pk.sign(&mut rng, io::repeat(0).take(len)).unwrap());
        });
    }
    g.finish();
}

fn verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len));
        g.bench_function(id, |b| {
            let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
            let pk = PrivateKey::random(&mut rng);
            let sig = pk.sign(rng, io::repeat(0).take(len)).unwrap();
            b.iter(|| pk.public_key().verify(io::repeat(0).take(len), &sig).unwrap());
        });
    }
    g.finish();
}

fn digest(c: &mut Criterion) {
    let mut g = c.benchmark_group("digest");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len));
        g.bench_function(id, |b| {
            b.iter(|| Digest::new(&[""; 0], io::repeat(0).take(len)).unwrap());
        });
    }
    g.finish();
}

fn pbenc(c: &mut Criterion) {
    let mut g = c.benchmark_group("pbenc");
    for time in [1, 2, 4, 8] {
        for memory in [1, 2, 4, 8] {
            g.bench_function(format!("t={time}/m={memory}"), |b| {
                let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
                let pk = PrivateKey::random(&mut rng);
                b.iter(|| pk.store(io::sink(), &mut rng, b"passphrase", time, memory));
            });
        }
    }
    g.finish();
}

criterion_group!(benches, encrypt, decrypt, sign, verify, digest, pbenc);
criterion_main!(benches);
