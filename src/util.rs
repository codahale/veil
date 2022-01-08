use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use std::io::Write;
use std::{io, mem};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use strobe_rs::Strobe;

/// Generate a random `u8` array.
pub fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// The generator point for ristretto255.
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// The length of a MAC in bytes.
pub const MAC_LEN: usize = 16;

/// The length of a compressed ristretto255 point in bytes.
pub const POINT_LEN: usize = 32;

/// The length of a `u32` in bytes.
pub const U32_LEN: usize = mem::size_of::<u32>();

/// The length of a `u64` in bytes.
pub const U64_LEN: usize = mem::size_of::<u64>();

/// Additional convenience methods for [Strobe] instances.
pub trait StrobeExt {
    /// Add the given `u32` as little endian encoded meta associated data.
    fn meta_ad_u32(&mut self, n: u32);

    /// Add the compressed form of the given point as associated data.
    fn ad_point(&mut self, q: &RistrettoPoint);

    /// Derive a scalar from PRF output.
    fn prf_scalar(&mut self) -> Scalar;

    /// Derive an array from PRF output.
    fn prf_array<const N: usize>(&mut self) -> [u8; N];

    /// Clone the current instance, key it with the given secret, key it again with random data, and
    /// pass the clone to the given function.
    fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: FnOnce(&mut Strobe) -> R;

    /// Create a writer which passes writes through `SEND_CLR` before passing them to the given
    /// writer.
    fn send_clr_writer<W>(self, w: W) -> SendClrWriter<W>
    where
        W: Write;

    /// Create a writer which passes writes through `SEND_ENC` before passing them to the given
    /// writer.
    fn send_enc_writer<W>(self, w: W) -> SendEncWriter<W>
    where
        W: Write;

    /// Create a writer which passes writes through `RECV_CLR` before passing them to the given
    /// writer.
    fn recv_clr_writer<W>(self, w: W) -> RecvClrWriter<W>
    where
        W: Write;
}

impl StrobeExt for Strobe {
    fn meta_ad_u32(&mut self, n: u32) {
        self.meta_ad(&n.to_le_bytes(), false);
    }

    fn ad_point(&mut self, q: &RistrettoPoint) {
        self.ad(q.compress().as_bytes(), false);
    }

    fn prf_scalar(&mut self) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.prf_array())
    }

    fn prf_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.prf(&mut out, false);
        out
    }

    fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: FnOnce(&mut Strobe) -> R,
    {
        // Clone the protocol's state.
        let mut clone = self.clone();

        // Key with the given secret.
        clone.key(secret, false);

        // Key with a random value.
        let r: [u8; 64] = rand_array();
        clone.key(&r, false);

        // Call the given function with the clone.
        f(&mut clone)
    }

    fn send_clr_writer<W>(mut self, w: W) -> SendClrWriter<W>
    where
        W: Write,
    {
        self.send_clr(&[], false);
        SendClrWriter(self, w)
    }

    fn send_enc_writer<W>(mut self, w: W) -> SendEncWriter<W>
    where
        W: Write,
    {
        self.send_enc(&mut [], false);
        SendEncWriter(self, w)
    }

    fn recv_clr_writer<W>(mut self, w: W) -> RecvClrWriter<W>
    where
        W: Write,
    {
        self.recv_clr(&[], false);
        RecvClrWriter(self, w)
    }
}

macro_rules! strobe_writer {
    ($t:ident, $strobe:ident, $buf:ident, $writer:ident, $body:block) => {
        pub struct $t<W: Write>(Strobe, W);

        impl<W: Write> $t<W> {
            pub fn into_inner(self) -> (Strobe, W) {
                (self.0, self.1)
            }
        }

        impl<W: Write> Write for $t<W> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let $strobe = &mut self.0;
                let $buf = buf;
                let $writer = &mut self.1;
                $body
            }

            fn flush(&mut self) -> io::Result<()> {
                self.1.flush()
            }
        }
    };
}

strobe_writer!(SendClrWriter, strobe, buf, w, {
    strobe.send_clr(buf, true);
    w.write(buf)
});

strobe_writer!(SendEncWriter, strobe, buf, w, {
    let mut input = Vec::from(buf);
    strobe.send_enc(&mut input, true);
    w.write(&input)
});

strobe_writer!(RecvClrWriter, strobe, buf, w, {
    strobe.recv_clr(buf, true);
    w.write(buf)
});
