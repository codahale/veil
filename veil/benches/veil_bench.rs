use std::io;
use std::io::Read;

use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion, Throughput};

use veil::SecretKey;

fn criterion_encrypt(c: &mut Criterion) {
    let mut encrypt = c.benchmark_group("encrypt");
    for i in vec![0u64, 1_000, 10_000, 100_000, 1_000_000] {
        encrypt.throughput(Throughput::Elements(i));
        encrypt.bench_with_input(format!("{}", i), &i, bench_encrypt);
    }
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
    for i in vec![0u64, 1_000, 10_000, 100_000, 1_000_000] {
        sign.throughput(Throughput::Elements(i));
        sign.bench_with_input(format!("{}", i), &i, bench_sign);
    }
}

fn bench_sign(b: &mut Bencher, n: &u64) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    b.iter(|| pk_a.sign(&mut io::repeat(0).take(*n)).unwrap());
}

fn criterion_pbenc(c: &mut Criterion) {
    let sk = SecretKey::new();

    c.bench_function("SecretKey/encrypt", |b| {
        b.iter(|| sk.encrypt(black_box("passphrase".as_bytes()), black_box(10), black_box(10)))
    });
}

criterion_group!(benches, criterion_encrypt, criterion_sign, criterion_pbenc);
criterion_main!(benches);
