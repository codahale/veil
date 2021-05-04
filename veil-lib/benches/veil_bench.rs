use std::io;

use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};

use veil_lib::SecretKey;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");
    group.bench_with_input("0KB", &0, bench_encrypt);
    group.bench_with_input("1KB", &1_000, bench_encrypt);
    group.bench_with_input("10KB", &10_000, bench_encrypt);
    group.bench_with_input("100KB", &100_000, bench_encrypt);
    group.bench_with_input("1MB", &1_000_000, bench_encrypt);
    group.bench_with_input("10MB", &10_000_000, bench_encrypt);
}

fn bench_encrypt(b: &mut Bencher, n: &u64) {
    let sk_a = SecretKey::new();
    let pk_a = sk_a.private_key("/one/two");

    let sk_b = SecretKey::new();
    let pk_b = sk_b.private_key("/three/four");

    b.iter(|| {
        pk_a.encrypt(
            &mut Zero(*n),
            &mut Discard,
            vec![pk_b.public_key()],
            black_box(0),
            black_box(0),
        )
        .unwrap()
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

struct Zero(u64);

impl io::Read for Zero {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0 == 0 {
            Ok(0)
        } else if buf.len() as u64 > self.0 {
            self.0 = 0;
            Ok(buf.len())
        } else {
            self.0 -= buf.len() as u64;
            Ok(buf.len())
        }
    }
}

struct Discard;

impl io::Write for Discard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
