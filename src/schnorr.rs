//! schnorr implements Veil's Schnorr signatures.
//!
//! # Signing A Message
//!
//! Signing is as follows, given a message in blocks `M_0`…`M_n`, a private scalar `d`, and a public
//! element `Q`:
//!
//! ```text
//! INIT('veil.schnorr', level=256)
//! SEND_CLR('',  more=false)
//! SEND_CLR(M_0, more=true)
//! SEND_CLR(M_1, more=true)
//! …
//! SEND_CLR(M_n, more=true)
//! AD(Q)
//! ```
//!
//! (The signer's public key is included after the message to allow `veil.mres` to search for a
//! header without having to buffer the results.)
//!
//! The protocol's state is then cloned, the clone is keyed with 64 bytes of random data and the
//! signer's private key, an ephemeral scalar is derived from PRF output:
//!
//! ```text
//! KEY(rand(64))
//! KEY(d)
//! PRF(64) -> r
//! ```
//!
//! The clone's state is discarded, and `r` is returned to the parent:
//!
//! ```text
//! R = G^r
//! AD(R)
//! PRF(64) -> c
//! s = d_s*c + r
//! ```
//!
//! The resulting signature consists of the two scalars, `c` and `s`.
//!
//! # Verifying A Signature
//!
//! To verify, `veil.schnorr` is run with a message in blocks `M_0`…`M_n` and a public element `Q`:
//!
//! ```text
//! INIT('veil.schnorr', level=256)
//! RECV_CLR('',  more=false)
//! RECV_CLR(M_0, more=true)
//! RECV_CLR(M_1, more=true)
//! …
//! RECV_CLR(M_n, more=true)
//! AD(Q)
//! R' = Q^-c + G^s
//! AD(R')
//! PRF(64) -> c'
//! ```
//!
//! Finally, the verifier compares `c' == c`. If the two scalars are equivalent, the signature is
//! valid.
//!
//! # Security, Forgeability, and Malleability
//!
//! This construction is equivalent to Construction 13.12 of Modern Cryptography 3e, and is the
//! combination of the Fiat-Shamir transform applied to the Schnorr identification scheme, and per
//! Theorem 13.11, secure if the discrete-logarithm problem is hard relative to ristretto255.
//!
//! The Schnorr signature scheme is [strongly unforgeable under chosen message attack (SUF-CMA) in
//! the random oracle model](https://www.di.ens.fr/david.pointcheval/Documents/Papers/2000_joc.pdf)
//! and [even with practical cryptographic hash functions](http://www.neven.org/papers/schnorr.pdf).
//! As a consequence, the signatures are non-malleable.
//!
//! # Indistinguishability and Pseudorandomness
//!
//! Per [Fleischhacker et al.](https://eprint.iacr.org/2011/673.pdf), this construction produces
//! indistinguishable signatures (i.e., signatures which do not reveal anything about the signing
//! key or signed message). When encrypted with an unrelated key (i.e., via `veil.mres`), the
//! construction is isomorphic to Fleischhacker et al.'s DRPC compiler for producing pseudorandom
//! signatures, which are indistinguishable from random.
//!
//! # Ephemeral Scalar Hedging
//!
//! In deriving the ephemeral scalar from a cloned context, `veil.schnorr` uses [Aranha et al.'s
//! "hedged signature" technique](https://eprint.iacr.org/2019/956.pdf) to mitigate against both
//! catastrophic randomness failures and differential fault attacks against purely deterministic
//! signature schemes.

use std::convert::TryInto;
use std::io::{Result, Write};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use strobe_rs::{SecParam, Strobe};

use crate::util::StrobeExt;

pub(crate) const SIGNATURE_LEN: usize = SCALAR_LEN * 2;
const SCALAR_LEN: usize = 32;

pub(crate) struct Signer<W: Write> {
    schnorr: Strobe,
    writer: W,
}

impl<W> Signer<W>
where
    W: Write,
{
    pub(crate) fn new(writer: W) -> Signer<W> {
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B256);
        schnorr.send_clr(&[], false);
        Signer { schnorr, writer }
    }

    #[allow(clippy::many_single_char_names)]
    pub(crate) fn sign(&mut self, d: &Scalar, q: &RistrettoPoint) -> [u8; SIGNATURE_LEN] {
        // Add the signer's public key as associated data.
        self.schnorr.ad_point(q);

        // Derive an ephemeral scalar from the protocol's current state, the signer's private key,
        // and a random nonce.
        let r = self.schnorr.hedge(d.as_bytes(), StrobeExt::prf_scalar);

        // Add the ephemeral public key as associated data.
        let r_g = RISTRETTO_BASEPOINT_POINT * r;
        self.schnorr.ad_point(&r_g);

        // Derive a challenge scalar from PRF output.
        let c = self.schnorr.prf_scalar();

        // Calculate the signature scalar.
        let s = d * c + r;

        // Return the challenge and signature scalars.
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..SCALAR_LEN].copy_from_slice(c.as_bytes());
        sig[SCALAR_LEN..].copy_from_slice(s.as_bytes());
        sig
    }

    pub(crate) fn into_inner(self) -> W {
        self.writer
    }
}

impl<W> Write for Signer<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.schnorr.send_clr(buf, true);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

pub(crate) struct Verifier {
    schnorr: Strobe,
}

impl Verifier {
    pub(crate) fn new() -> Verifier {
        let mut schnorr = Strobe::new(b"veil.schnorr", SecParam::B256);
        schnorr.recv_clr(&[], false);
        Verifier { schnorr }
    }

    pub fn verify(self, q: &RistrettoPoint, sig: &[u8; SIGNATURE_LEN]) -> bool {
        self.verify_inner(q, sig).unwrap_or(false)
    }

    #[inline]
    fn verify_inner(mut self, q: &RistrettoPoint, sig: &[u8; SIGNATURE_LEN]) -> Option<bool> {
        // Add the signer's public key as associated data.
        self.schnorr.ad_point(q);

        // Decode the challenge and signature scalars.
        let c = Scalar::from_canonical_bytes(sig[..SCALAR_LEN].try_into().ok()?)?;
        let s = Scalar::from_canonical_bytes(sig[SCALAR_LEN..].try_into().ok()?)?;

        // Re-calculate the ephemeral public key and add it as associated data.
        let r_g = (RISTRETTO_BASEPOINT_POINT * s) + (-c * q);
        self.schnorr.ad_point(&r_g);

        // Re-derive the challenge scalar.
        let c_p = self.schnorr.prf_scalar();

        // Return true iff c' == c.
        Some(c_p == c)
    }
}

impl Write for Verifier {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.schnorr.recv_clr(buf, true);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;

    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    use crate::util;

    use super::*;

    #[test]
    pub fn sign_and_verify() -> Result<()> {
        let d = Scalar::from_bytes_mod_order_wide(&util::rand_array());
        let q = RISTRETTO_BASEPOINT_POINT * d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let sig = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(true, verifier.verify(&q, &sig));

        Ok(())
    }

    #[test]
    pub fn bad_message() -> Result<()> {
        let d = Scalar::from_bytes_mod_order_wide(&util::rand_array());
        let q = RISTRETTO_BASEPOINT_POINT * d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let sig = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is NOT a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(false, verifier.verify(&q, &sig));

        Ok(())
    }

    #[test]
    pub fn bad_key() -> Result<()> {
        let d = Scalar::from_bytes_mod_order_wide(&util::rand_array());
        let q = RISTRETTO_BASEPOINT_POINT * d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let sig = signer.sign(&d, &q);

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(false, verifier.verify(&RISTRETTO_BASEPOINT_POINT, &sig));

        Ok(())
    }

    #[test]
    pub fn bad_sig() -> Result<()> {
        let d = Scalar::from_bytes_mod_order_wide(&util::rand_array());
        let q = RISTRETTO_BASEPOINT_POINT * d;

        let mut signer = Signer::new(io::sink());
        signer.write(b"this is a message that")?;
        signer.write(b" is in multiple pieces")?;
        signer.flush()?;

        let mut sig = signer.sign(&d, &q);
        sig[22] ^= 1;

        let mut verifier = Verifier::new();
        verifier.write(b"this is a message that")?;
        verifier.write(b" is in multiple")?;
        verifier.write(b" pieces")?;
        verifier.flush()?;

        assert_eq!(false, verifier.verify(&q, &sig));

        Ok(())
    }
}
