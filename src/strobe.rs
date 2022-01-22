use std::io::{self, Write};

use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use serde::Serialize;
use strobe_rs::Strobe;

/// An extension trait for [Strobe] instances.
pub trait StrobeExt {
    /// Bincodes `data`, appends it to `label`, and passes it to `AD` with the `meta` flag.
    fn metadata<T: ?Sized>(&mut self, label: &str, data: &T)
    where
        T: Serialize;

    /// Derive a scalar from PRF output.
    #[must_use]
    fn prf_scalar(&mut self, label: &str) -> Scalar;

    /// Derive an array from PRF output.
    #[must_use]
    fn prf_array<const N: usize>(&mut self, label: &str) -> [u8; N];

    /// Clone the current instance, key it with the given secret, key it again with random data, and
    /// pass the clone to the given function.
    #[must_use]
    fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: Fn(&mut Strobe) -> R;

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
    fn metadata<T: ?Sized>(&mut self, label: &str, data: &T)
    where
        T: Serialize,
    {
        self.meta_ad(label.as_bytes(), false);
        self.meta_ad(&bincode::serialize(data).expect("invalid data"), true);
    }

    fn prf_scalar(&mut self, label: &str) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.prf_array(label))
    }

    fn prf_array<const N: usize>(&mut self, label: &str) -> [u8; N] {
        self.metadata(label, &(N as u32));

        let mut out = [0u8; N];
        self.prf(&mut out, false);
        out
    }

    fn hedge<R, F>(&self, secret: &[u8], f: F) -> R
    where
        F: Fn(&mut Strobe) -> R,
    {
        // Clone the protocol's state.
        let mut clone = self.clone();

        // Key with the given secret.
        clone.meta_ad(b"secret-value", false);
        clone.meta_ad(&(secret.len() as u32).to_le_bytes(), true);
        clone.key(secret, false);

        // Key with a random value.
        let mut r = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut r);
        clone.meta_ad(b"hedged-value", false);
        clone.meta_ad(&(r.len() as u32).to_le_bytes(), true);
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
        #[must_use]
        pub struct $t<W: Write>(Strobe, W);

        impl<W: Write> $t<W> {
            #[must_use]
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
