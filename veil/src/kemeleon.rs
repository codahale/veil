//! The Kemeleon obfuscated encoding algorithm for ML-KEM-768.
//!
//! https://eprint.iacr.org/2024/1086.pdf

// TODO test output
// TODO update docs

use ml_kem::kem::{Decapsulate as _, Encapsulate as _};
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};

use crate::keys::{self, MlKem768DecryptingKey};

pub const ENC_CT_LEN: usize = 1252;

pub fn encapsulate(
    ek: &keys::MlKem768EncryptingKey,
    mut rng: impl CryptoRng + Rng,
) -> ([u8; ENC_CT_LEN], [u8; 32]) {
    loop {
        let (kem_ct, kem_ss) = ek.encapsulate(&mut rng).expect("should encapsulate");
        if let Some(kem_ect) = encode_ct(&mut rng, kem_ct.into()) {
            return (kem_ect, kem_ss.into());
        }
    }
}

pub fn decapsulate(dk: &MlKem768DecryptingKey, e_ct: [u8; ENC_CT_LEN]) -> [u8; 32] {
    let ct = decode_ct(e_ct);
    dk.decapsulate(&ct.into()).expect("should decapsulate").into()
}

fn encode_ct(mut rng: impl CryptoRng + Rng, c: [u8; 1088]) -> Option<[u8; 1252]> {
    // Split the ciphertext into pieces and decode them.
    let mut u = [[0; N]; K];
    let mut chunks = c.chunks_exact(320);
    for (u, c) in u.iter_mut().zip(chunks.by_ref()) {
        *u = ring_decode_and_decompress10(c.try_into().expect("should be 320 bytes"));
    }
    let v =
        ring_decode_and_decompress4(chunks.remainder().try_into().expect("should be 128 bytes"));

    // Add additional randomness to the vector.
    for u_i in u.iter_mut().flatten() {
        let mut a;
        loop {
            a = rng.gen_range(0..5);
            if decompress(compress(*u_i + a, 10), 10) == *u_i {
                break;
            }
        }
        *u_i += a;
    }

    // Accumulate the coefficients.
    let mut r = BigUint::ZERO;
    let mut coeff = BigUint::from(1u64);
    for t_i in u.iter().flatten() {
        r += &coeff * t_i;
        coeff *= Q;
    }

    // If the MSB is 1, we can't encode this vector.
    if r.bit(MAX_R) {
        return None;
    }

    // Copy the bits of the encoded vector.
    let mut out = [0u8; 1252];
    let bits = r.to_bytes_le();
    out[..bits.len()].copy_from_slice(&bits);

    // Mask the top five bits of the encoded vector.
    let mask = BIT_MASK & rng.gen::<u8>();
    out[1252 - 128 - 1] |= mask;

    // Perform rejection sampling based on the second part.
    for v_i in v.iter() {
        if *v_i == 0 && rng.gen_range(0..(Q / 4)) == 0 {
            return None;
        }
    }

    // Append the second part of the ciphertext.
    out[1124..].copy_from_slice(&c[960..]);
    Some(out)
}

fn decode_ct(mut e_ct: [u8; 1252]) -> [u8; 1088] {
    // Unmask the top five bits of the encoded vector.
    e_ct[1252 - 128 - 1] &= !BIT_MASK;

    // Decode the vector.
    let r = BigUint::from_bytes_le(&e_ct[..1124]);
    let mut u = [[0u16; N]; K];
    let mut coeff = BigUint::from(1u64);
    let mut f = BigUint::ZERO;
    for u_i in u.iter_mut().flatten() {
        let big_u_i = ((&r - &f) / &coeff) % BigUint::from(Q);
        coeff *= BigUint::from(Q);
        f += &big_u_i;
        *u_i = big_u_i.iter_u64_digits().next().unwrap_or(0) as u16;
    }

    // Re-compress u and append v verbatim.
    let mut ct = [0; 1088];
    {
        let mut ct = ct.chunks_exact_mut(320);
        for (c, f) in ct.by_ref().zip(u.iter().copied()) {
            c.copy_from_slice(&ring_compress_and_encode10(f));
        }
        ct.into_remainder().copy_from_slice(&e_ct[1124..]);
    }
    ct
}

const BIT_MASK: u8 = 0b1111_1000;

const MAX_R: u64 = 8987;
const BARRETT_MULTIPLIER: u64 = 5039; // 4¹² / q
const BARRETT_SHIFT: usize = 24; // log₂(4¹²)

// ML-KEM global constants.
const Q: u16 = 3329;
const N: usize = 256;

// ML-KEM-768 parameters. The code makes assumptions based on these values,
// they can't be changed blindly.
const K: usize = 3;

/// FieldElement is an integer modulo q, an element of ℤ_q. It is always reduced.
type FieldElement = u16;

// Maps a field element uniformly to the range 0 to 2ᵈ-1, according to FIPS 203 (DRAFT), Definition
// 4.5.
const fn compress(x: FieldElement, d: u8) -> u16 {
    // We want to compute (x * 2ᵈ) / q, rounded to nearest integer, with 1/2
    // rounding up (see FIPS 203 (DRAFT), Section 2.3).

    // Barrett reduction produces a quotient and a remainder in the range [0, 2q),
    // such that dividend = quotient * q + remainder.
    let dividend = (x as u32) << d; // x * 2ᵈ
    let mut quotient =
        (((dividend as u64).wrapping_mul(BARRETT_MULTIPLIER)) >> BARRETT_SHIFT) as u32;
    let remainder = dividend.wrapping_sub(quotient.wrapping_mul(Q as u32));

    // Since the remainder is in the range [0, 2q), not [0, q), we need to
    // portion it into three spans for rounding.
    //
    //     [ 0,       q/2     ) -> round to 0
    //     [ q/2,     q + q/2 ) -> round to 1
    //     [ q + q/2, 2q      ) -> round to 2
    //
    // We can convert that to the following logic: add 1 if remainder > q/2,
    // then add 1 again if remainder > q + q/2.
    //
    // Note that if remainder > x, then ⌊x⌋ - remainder underflows, and the top
    // bit of the difference will be set.
    quotient = quotient.wrapping_add((Q as u32 / 2).wrapping_sub(remainder) >> 31 & 1);
    quotient += (Q as u32 + (Q as u32) / 2 - remainder) >> 31 & 1;

    // quotient might have overflowed at this point, so reduce it by masking.
    let mask = (1u32 << d) - 1;
    (quotient & mask) as u16
}

// Maps a number x between 0 and 2ᵈ-1 uniformly to the full range of field elements, according to
// FIPS 203 (DRAFT), Definition 4.6.
const fn decompress(y: u16, d: u8) -> FieldElement {
    // We want to compute (y * q) / 2ᵈ, rounded to nearest integer, with 1/2
    // rounding up (see FIPS 203 (DRAFT), Section 2.3).

    let dividend = (y as u32).wrapping_mul(Q as u32);
    let mut quotient = dividend >> d; // (y * q) / 2ᵈ

    // The d'th least-significant bit of the dividend (the most significant bit
    // of the remainder) is 1 for the top half of the values that divide to the
    // same quotient, which are the ones that round up.
    quotient = quotient.wrapping_add((dividend >> (d - 1)) & 1);

    // quotient is at most (2¹¹-1) * q / 2¹¹ + 1 = 3328, so it didn't overflow.
    quotient as u16
}

// RingElement is a polynomial, an element of R_q, represented as an array according to FIPS 203
// (DRAFT), Section 2.4.
type RingElement = [FieldElement; N];

/// Decodes a 128-byte encoding of a ring element where each four bits are mapped to an equidistant
/// distribution.
///
/// It implements ByteDecode₄, according to FIPS 203 (DRAFT), Algorithm 5, followed by Decompress₄,
/// according to FIPS 203 (DRAFT), Definition 4.6.
fn ring_decode_and_decompress4(b: [u8; 128]) -> RingElement {
    let mut f = [0; N];
    for (f, b) in f.chunks_exact_mut(2).zip(b) {
        f[0] = decompress((b & 0b1111) as u16, 4);
        f[1] = decompress((b >> 4) as u16, 4);
    }
    f
}

/// Returns a 320-byte encoding of a ring element, compressing four coefficients per five bytes.
///
/// It implements Compress₁₀, according to FIPS 203 (DRAFT), Definition 4.5, followed by
/// ByteEncode₁₀, according to FIPS 203 (DRAFT), Algorithm 4.
fn ring_compress_and_encode10(f: RingElement) -> [u8; 320] {
    let mut b = [0; 320];
    for (f, b) in f.chunks_exact(4).zip(b.chunks_exact_mut(5)) {
        let mut x = 0u64;
        x |= compress(f[0], 10) as u64;
        x |= (compress(f[1], 10) as u64) << 10;
        x |= (compress(f[2], 10) as u64) << 20;
        x |= (compress(f[3], 10) as u64) << 30;
        b[0] = (x) as u8;
        b[1] = (x >> 8) as u8;
        b[2] = (x >> 16) as u8;
        b[3] = (x >> 24) as u8;
        b[4] = (x >> 32) as u8;
    }
    b
}

/// Decode a 320-byte encoding of a ring element where each ten bits are mapped to an equidistant
/// distribution.
///
/// It implements ByteDecode₁₀, according to FIPS 203 (DRAFT), Algorithm 5, followed by
/// Decompress₁₀, according to FIPS 203 (DRAFT), Definition 4.6.
fn ring_decode_and_decompress10(b: [u8; 320]) -> RingElement {
    let mut f = [0; N];
    for (f, b) in f.chunks_exact_mut(4).zip(b.chunks_exact(5)) {
        let x = (b[0] as u64)
            | (b[1] as u64) << 8
            | (b[2] as u64) << 16
            | (b[3] as u64) << 24
            | (b[4] as u64) << 32;
        f[0] = decompress((x & 0b11_1111_1111) as u16, 10);
        f[1] = decompress((x >> 10 & 0b11_1111_1111) as u16, 10);
        f[2] = decompress((x >> 20 & 0b11_1111_1111) as u16, 10);
        f[3] = decompress((x >> 30 & 0b11_1111_1111) as u16, 10);
    }
    f
}

#[cfg(test)]
mod tests {
    use ml_kem::KemCore as _;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn round_trip() {
        for _ in 0..10 {
            let (dk, ek) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate(&mut OsRng);
            let (ect, sk) = encapsulate(&ek, OsRng);
            let sk_p = decapsulate(&dk, ect);
            assert_eq!(sk, sk_p);
        }
    }
}
