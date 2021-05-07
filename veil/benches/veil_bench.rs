use std::io;

use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};

use std::io::Read;
use veil::SecretKey;

fn criterion_encrypt(c: &mut Criterion) {
    let mut encrypt = c.benchmark_group("encrypt");
    encrypt.bench_with_input("0KB", &0, bench_encrypt);
    encrypt.bench_with_input("1KB", &1_000, bench_encrypt);
    encrypt.bench_with_input("10KB", &10_000, bench_encrypt);
    encrypt.bench_with_input("100KB", &100_000, bench_encrypt);
    encrypt.bench_with_input("1MB", &1_000_000, bench_encrypt);
    encrypt.bench_with_input("10MB", &10_000_000, bench_encrypt);
}

fn bench_encrypt(b: &mut Bencher, n: &u64) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let sk_b = SecretKey::new();
    let pk_b = sk_b.private_key("/three/four");

    b.iter(|| {
        pk_a.encrypt(
            &mut io::repeat(0).take(*n),
            &mut io::sink(),
            vec![pk_b.public_key()],
            black_box(0),
            black_box(0),
        )
        .unwrap()
    });
}

fn criterion_sign(c: &mut Criterion) {
    let mut sign = c.benchmark_group("sign");
    sign.bench_with_input("0KB", &0, bench_sign);
    sign.bench_with_input("1KB", &1000, bench_sign);
    sign.bench_with_input("10KB", &10_000, bench_sign);
    sign.bench_with_input("100KB", &100_000, bench_sign);
    sign.bench_with_input("1MB", &1_000_000, bench_sign);
    sign.bench_with_input("10MB", &10_000_000, bench_sign);
}

fn bench_sign(b: &mut Bencher, n: &u64) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    b.iter(|| pk_a.sign(&mut io::repeat(0).take(*n)).unwrap());
}

fn criterion_pbenc(c: &mut Criterion) {
    let sk = SecretKey::new();

    c.bench_function("SecretKey/encrypt", |b| {
        b.iter(|| {
            sk.encrypt(
                black_box("passphrase".as_bytes()),
                black_box(10),
                black_box(10),
            )
        })
    });
}

criterion_group!(benches, criterion_encrypt, criterion_sign, criterion_pbenc);
criterion_main!(benches);
