use std::io;
use std::io::Write;

use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use secrecy::{Secret, Zeroize};
use xoodyak::{XoodyakCommon, XoodyakHash, XoodyakKeyed};

const BLOCK_LEN: usize = 32 * 1024;

pub struct AbsorbWriter<W: Write> {
    duplex: XoodyakHash,
    writer: W,
    buffer: Vec<u8>,
    n: u64,
}

impl<W: Write> Write for AbsorbWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.n += buf.len() as u64;
        self.buffer.extend(buf);
        while self.buffer.len() > BLOCK_LEN {
            self.duplex.absorb(self.buffer.drain(..BLOCK_LEN).as_slice());
        }
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.duplex.absorb(&self.buffer);
        self.writer.flush()
    }
}

impl<W: Write> AbsorbWriter<W> {
    pub fn into_inner(mut self) -> io::Result<(XoodyakHash, W, u64)> {
        self.flush()?;
        Ok((self.duplex, self.writer, self.n))
    }
}

pub trait XoodyakExt {
    fn squeeze_scalar(&mut self) -> Scalar;
}

pub trait XoodyakHashExt: XoodyakExt {
    fn to_keyed(self, name: &str) -> XoodyakKeyed;

    fn hedge<R, F>(&self, secret: &[u8], f: F) -> Secret<R>
    where
        F: Fn(&mut Self) -> R,
        R: Zeroize;

    fn absorb_writer<W>(self, writer: W) -> AbsorbWriter<W>
    where
        W: Write;
}

impl<X: XoodyakCommon> XoodyakExt for X {
    fn squeeze_scalar(&mut self) -> Scalar {
        // Squeeze a derived key.
        let mut b = [0u8; 64];
        self.squeeze_key(&mut b);

        // Map the derived key to a scalar.
        let d = Scalar::from_bytes_mod_order_wide(&b);

        // Zeroize the temp buffer.
        b.zeroize();

        // Return the scalar.
        d
    }
}

impl XoodyakHashExt for XoodyakHash {
    fn to_keyed(mut self, name: &str) -> XoodyakKeyed {
        // Squeeze a 344-bit key. This is the maximum input size for the keyed mode.
        let mut key = [0u8; 43];
        self.squeeze_key(&mut key);

        // Initialize a new duplex with the key and name.
        let mut keyed = XoodyakKeyed::new(&key, None, None, None).expect("invalid key len");
        keyed.absorb(name.as_bytes());

        // Zeroize the temp key.
        key.zeroize();

        // Return the duplex.
        keyed
    }

    fn hedge<R, F>(&self, secret: &[u8], f: F) -> Secret<R>
    where
        F: Fn(&mut Self) -> R,
        R: Zeroize,
    {
        // Clone the duplex's state.
        let mut clone = self.clone();

        // Absorb the given secret.
        clone.absorb(secret);

        // Generate a random value.
        let mut r = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut r);

        // Absorb the random value.
        clone.absorb(&r);

        // Zeroize the random value.
        r.zeroize();

        // Call the given function with the clone.
        f(&mut clone).into()
    }

    fn absorb_writer<W>(self, writer: W) -> AbsorbWriter<W>
    where
        W: Write,
    {
        AbsorbWriter { duplex: self, writer, buffer: Vec::with_capacity(BLOCK_LEN), n: 0 }
    }
}
