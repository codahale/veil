use std::io;
use std::io::{Cursor, Read};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use veil::{Digest, PrivateKey};

fn bench_encrypt(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let pk_a = PrivateKey::random(&mut rng);
    let pk_b = PrivateKey::random(&mut rng);

    let mut encrypt = c.benchmark_group("encrypt");
    for n in [0, KB, 8 * KB, 32 * KB, 64 * KB, 128 * KB] {
        encrypt.throughput(Throughput::Bytes(n));
        encrypt.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                pk_a.encrypt(
                    &mut rng,
                    io::repeat(0).take(n),
                    io::sink(),
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

    let pk_a = PrivateKey::random(&mut rng);
    let pk_b = PrivateKey::random(&mut rng);

    let mut decrypt = c.benchmark_group("decrypt");
    for n in [0, KB, 8 * KB, 32 * KB, 64 * KB, 128 * KB] {
        let mut ciphertext = Cursor::new(Vec::new());
        pk_a.encrypt(
            &mut rng,
            io::repeat(0).take(n),
            &mut ciphertext,
            &[pk_b.public_key()],
            black_box(None),
            black_box(None),
        )
        .unwrap();
        let ciphertext = ciphertext.into_inner();

        decrypt.throughput(Throughput::Bytes(n));
        decrypt.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                pk_b.decrypt(Cursor::new(ciphertext.clone()), io::sink(), &pk_a.public_key())
                    .unwrap();
            });
        });
    }
    decrypt.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let pk_a = PrivateKey::random(&mut rng);

    let mut sign = c.benchmark_group("sign");
    for n in [0, KB, 8 * KB, 32 * KB, 64 * KB, 128 * KB] {
        sign.throughput(Throughput::Bytes(n));
        sign.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| pk_a.sign(&mut rng, io::repeat(0).take(n)).unwrap());
        });
    }
    sign.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let pk_a = PrivateKey::random(&mut rng);

    let mut verify = c.benchmark_group("verify");
    for n in [0, KB, 8 * KB, 32 * KB, 64 * KB, 128 * KB] {
        let sig = pk_a.sign(&mut rng, io::repeat(0).take(n)).unwrap();
        verify.throughput(Throughput::Bytes(n));
        verify.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| pk_a.public_key().verify(io::repeat(0).take(n), &sig).unwrap());
        });
    }
    verify.finish();
}

fn bench_pbenc(c: &mut Criterion) {
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

    let pk = PrivateKey::random(&mut rng);

    let mut pbenc = c.benchmark_group("pbenc");

    for time_cost in [0, 4] {
        for memory_cost in [0, 4] {
            pbenc.bench_with_input(
                format!("t={time_cost}/s={memory_cost}"),
                &(time_cost, memory_cost),
                |b, &(time_cost, memory_cost)| {
                    b.iter(|| {
                        pk.store(
                            Cursor::new(vec![]),
                            &mut rng,
                            black_box(b"passphrase"),
                            time_cost,
                            memory_cost,
                        )
                    })
                },
            );
        }
    }

    pbenc.finish();
}

fn bench_digest(c: &mut Criterion) {
    let mut digest = c.benchmark_group("digest");
    for n in [0, KB, 8 * KB, 32 * KB, 64 * KB, 128 * KB] {
        digest.throughput(Throughput::Bytes(n));
        digest.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| Digest::new(&[] as &[&str], io::repeat(0).take(n)).unwrap());
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
    bench_digest,
    bench_pbenc,
);

criterion_main!(external);
