use std::io;
use std::io::Read;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use veil::SecretKey;

fn bench_encrypt(c: &mut Criterion) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let sk_b = SecretKey::new();
    let pk_b = sk_b.private_key("/three/four");

    let mut encrypt = c.benchmark_group("encrypt");
    for i in vec![0 * KB, 1 * KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        encrypt.throughput(Throughput::Elements(i));
        encrypt.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, n| {
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
        });
    }
    encrypt.finish();
}

fn bench_sign(c: &mut Criterion) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let mut sign = c.benchmark_group("sign");
    for i in vec![0 * KB, 1 * KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB] {
        sign.throughput(Throughput::Elements(i));
        sign.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, n| {
            b.iter(|| pk_a.sign(&mut io::repeat(0).take(*n)).unwrap());
        });
    }
    sign.finish();
}

fn bench_pbenc(c: &mut Criterion) {
    let sk = SecretKey::new();

    c.bench_function("pbenc", |b| {
        b.iter(|| sk.encrypt(black_box("passphrase".as_bytes()), black_box(10), black_box(10)))
    });
}

const KB: u64 = 1024;

criterion_group!(benches, bench_encrypt, bench_sign, bench_pbenc);
criterion_main!(benches);
