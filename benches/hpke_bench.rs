use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use veil_rs::hpke::{decrypt, encrypt};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng::default();

    let d_s = Scalar::random(&mut rng);
    let q_s = RISTRETTO_BASEPOINT_POINT * d_s;

    let d_e = Scalar::random(&mut rng);
    let q_e = RISTRETTO_BASEPOINT_POINT * d_e;

    let d_r = Scalar::random(&mut rng);
    let q_r = RISTRETTO_BASEPOINT_POINT * d_r;

    let plaintext = b"this is a test";
    let ciphertext = encrypt(&d_s, &q_s, &d_e, &q_e, &q_r, plaintext);

    c.bench_function("encrypt", |b| {
        b.iter(|| black_box(encrypt(&d_s, &q_s, &d_e, &q_e, &q_r, plaintext)))
    });

    c.bench_function("decrypt", |b| {
        b.iter(|| black_box(decrypt(&d_r, &q_r, &q_s, &ciphertext)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
