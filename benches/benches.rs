use std::io;
use std::io::{Cursor, Read};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use veil::SecretKey;

fn bench_encrypt(c: &mut Criterion) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let sk_b = SecretKey::new();
    let pk_b = sk_b.private_key("/three/four");

    let mut encrypt = c.benchmark_group("encrypt");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        encrypt.throughput(Throughput::Elements(n));
        encrypt.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                pk_a.encrypt(
                    &mut io::repeat(0).take(n),
                    &mut io::sink(),
                    &[pk_b.public_key()],
                    black_box(0),
                    black_box(0),
                )
                .unwrap()
            });
        });
    }
    encrypt.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let sk_b = SecretKey::new();
    let pk_b = sk_b.private_key("/three/four");

    let mut decrypt = c.benchmark_group("decrypt");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        let mut ciphertext = Cursor::new(Vec::new());
        pk_a.encrypt(
            &mut io::repeat(0).take(n),
            &mut ciphertext,
            &[pk_b.public_key()],
            black_box(0),
            black_box(0),
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
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let mut sign = c.benchmark_group("sign");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        sign.throughput(Throughput::Elements(n));
        sign.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| pk_a.sign(&mut io::repeat(0).take(n)).unwrap());
        });
    }
    sign.finish();
}

fn bench_verify(c: &mut Criterion) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let mut verify = c.benchmark_group("verify");
    for n in [0, KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        let sig = pk_a.sign(&mut io::repeat(0).take(n)).unwrap();
        verify.throughput(Throughput::Elements(n));
        verify.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| pk_a.public_key().verify(&mut io::repeat(0).take(n), &sig).unwrap());
        });
    }
    verify.finish();
}

fn bench_pbenc(c: &mut Criterion) {
    let sk = SecretKey::new();

    c.bench_function("pbenc", |b| {
        b.iter(|| sk.encrypt(black_box("passphrase"), black_box(10), black_box(10)))
    });
}

const KB: u64 = 1024;

criterion_group!(external, bench_encrypt, bench_decrypt, bench_sign, bench_verify, bench_pbenc);

criterion_main!(external);
