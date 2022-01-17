use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use std::io::{self, Write};
use strobe_rs::{SecParam, Strobe};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Protocol(Strobe);

impl Zeroize for Protocol {
    fn zeroize(&mut self) {
        // Because Strobe doesn't implement Zeroize natively, we're overwriting the state instead by
        // using the RATCHET operation with the security parameter in bytes. This will overwrite the
        // full state.
        self.0.ratchet(DEFAULT_SEC as usize / 8, false);
    }
}

impl ZeroizeOnDrop for Protocol {}

impl Drop for Protocol {
    fn drop(&mut self) {
        self.zeroize();
    }
}

const DEFAULT_SEC: SecParam = SecParam::B128;

impl Protocol {
    #[must_use]
    pub fn new(name: &str) -> Protocol {
        Protocol(Strobe::new(name.as_bytes(), DEFAULT_SEC))
    }

    /// Add the given `u32` as little endian encoded meta associated data.
    #[inline]
    pub fn meta_ad_u32(&mut self, n: u32) {
        self.0.meta_ad(&n.to_le_bytes(), false);
    }

    #[inline]
    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.0.ad(data, more);
    }

    #[inline]
    pub fn key(&mut self, data: &[u8], more: bool) {
        self.0.key(data, more);
    }

    #[inline]
    pub fn recv_clr(&mut self, data: &[u8], more: bool) {
        self.0.send_clr(data, more);
    }

    #[inline]
    pub fn send_enc(&mut self, data: &mut [u8], more: bool) {
        self.0.send_enc(data, more);
    }

    #[inline]
    pub fn recv_enc(&mut self, data: &mut [u8], more: bool) {
        self.0.recv_enc(data, more);
    }

    #[inline]
    pub fn send_mac(&mut self, data: &mut [u8], more: bool) {
        self.0.send_mac(data, more);
    }

    #[inline]
    pub fn recv_mac(&mut self, data: &mut [u8]) -> Result<(), strobe_rs::AuthError> {
        self.0.recv_mac(data)
    }

    #[inline]
    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        self.0.prf(data, more);
    }

    /// Add the compressed form of the given point as associated data.
    #[inline]
    pub fn ad_point(&mut self, q: &RistrettoPoint) {
        self.0.ad(q.compress().as_bytes(), false);
    }

    /// Derive a scalar from PRF output.
    #[must_use]
    #[inline]
    pub fn prf_scalar(&mut self) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.prf_array())
    }

    /// Derive an array from PRF output.
    #[must_use]
    #[inline]
    pub fn prf_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.0.prf(&mut out, false);
        out
    }

    /// Clone the current instance, key it with the given secret, key it again with random data, and
    /// pass the clone to the given function.
    #[must_use]
    pub fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: Fn(&mut Protocol) -> R,
    {
        // Clone the protocol's state.
        let mut clone = Protocol(self.0.clone());

        // Key with the given secret.
        clone.key(secret, false);

        // Key with a random value.
        let mut r = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut r);
        clone.key(&r, false);

        // Call the given function with the clone.
        f(&mut clone)
    }

    /// Create a writer which passes writes through `SEND_CLR` before passing them to the given
    /// writer.
    #[must_use]
    #[inline]
    pub fn send_clr_writer<W>(mut self, w: W) -> SendClrWriter<W>
    where
        W: Write,
    {
        self.0.send_clr(&[], false);
        SendClrWriter(self, w)
    }

    /// Create a writer which passes writes through `SEND_ENC` before passing them to the given
    /// writer.
    #[must_use]
    #[inline]
    pub fn send_enc_writer<W>(mut self, w: W) -> SendEncWriter<W>
    where
        W: Write,
    {
        self.send_enc(&mut [], false);
        SendEncWriter(self, w)
    }

    /// Create a writer which passes writes through `RECV_CLR` before passing them to the given
    /// writer.
    #[must_use]
    #[inline]
    pub fn recv_clr_writer<W>(mut self, w: W) -> RecvClrWriter<W>
    where
        W: Write,
    {
        self.0.recv_clr(&[], false);
        RecvClrWriter(self, w)
    }
}

macro_rules! strobe_writer {
    ($t:ident, $strobe:ident, $buf:ident, $writer:ident, $body:block) => {
        pub struct $t<W: Write>(Protocol, W);

        impl<W: Write> $t<W> {
            #[must_use]
            pub fn into_inner(self) -> (Protocol, W) {
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
    strobe.0.send_clr(buf, true);
    w.write(buf)
});

strobe_writer!(SendEncWriter, strobe, buf, w, {
    let mut input = Vec::from(buf);
    strobe.0.send_enc(&mut input, true);
    w.write(&input)
});

strobe_writer!(RecvClrWriter, strobe, buf, w, {
    strobe.0.recv_clr(buf, true);
    w.write(buf)
});
