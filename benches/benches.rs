use std::io;
use std::io::{Cursor, Read};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use veil::{Digest, SecretKey};

fn bench_encrypt(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let sk_a = SecretKey::random(&mut rng);
    let pk_a = sk_a.private_key();

    let sk_b = SecretKey::random(&mut rng);
    let pk_b = sk_b.private_key();

    let mut encrypt = c.benchmark_group("encrypt");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        encrypt.throughput(Throughput::Elements(n));
        encrypt.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                pk_a.encrypt(
                    &mut rng,
                    &mut io::repeat(0).take(n),
                    &mut io::sink(),
                    &[pk_b.public_key()],
                    black_box(None),
                    black_box(None),
                )
                .unwrap()
            });
        });
    }
    encrypt.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let sk_a = SecretKey::random(&mut rng);
    let pk_a = sk_a.private_key();

    let sk_b = SecretKey::random(&mut rng);
    let pk_b = sk_b.private_key();

    let mut decrypt = c.benchmark_group("decrypt");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        let mut ciphertext = Cursor::new(Vec::new());
        pk_a.encrypt(
            &mut rng,
            &mut io::repeat(0).take(n),
            &mut ciphertext,
            &[pk_b.public_key()],
            black_box(None),
            black_box(None),
        )
        .unwrap();
        let ciphertext = ciphertext.into_inner();

        decrypt.throughput(Throughput::Elements(n));
        decrypt.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                pk_b.decrypt(
                    &mut Cursor::new(ciphertext.clone()),
                    &mut io::sink(),
                    &pk_a.public_key(),
                )
                .unwrap();
            });
        });
    }
    decrypt.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let sk_a = SecretKey::random(&mut rng);
    let pk_a = sk_a.private_key();

    let mut sign = c.benchmark_group("sign");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        sign.throughput(Throughput::Elements(n));
        sign.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| pk_a.sign(&mut rng, &mut io::repeat(0).take(n)).unwrap());
        });
    }
    sign.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let sk_a = SecretKey::random(&mut rng);
    let pk_a = sk_a.private_key();

    let mut verify = c.benchmark_group("verify");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        let sig = pk_a.sign(&mut rng, &mut io::repeat(0).take(n)).unwrap();
        verify.throughput(Throughput::Elements(n));
        verify.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| pk_a.public_key().verify(&mut io::repeat(0).take(n), &sig).unwrap());
        });
    }
    verify.finish();
}

fn bench_pbenc(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let sk = SecretKey::random(&mut rng);

    c.bench_function("pbenc", |b| {
        b.iter(|| sk.encrypt(&mut rng, black_box("passphrase"), black_box(10), black_box(10)))
    });
}

fn bench_digest(c: &mut Criterion) {
    let mut digest = c.benchmark_group("digest");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        digest.throughput(Throughput::Elements(n));
        digest.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| Digest::new(&[] as &[&str], &mut io::repeat(0).take(n)).unwrap());
        });
    }
    digest.finish();
}

const KB: u64 = 1024;

criterion_group!(
    external,
    bench_encrypt,
    bench_decrypt,
    bench_sign,
    bench_verify,
    bench_pbenc,
    bench_digest
);

criterion_main!(external);
