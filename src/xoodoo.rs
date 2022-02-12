use std::io;
use std::io::Write;

use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use secrecy::{Secret, Zeroize};
use xoodyak::{XoodyakCommon, XoodyakKeyed};

/// A [Write] adapter which tees writes into an unkeyed duplex.
pub struct AbsorbWriter<W: Write> {
    duplex: XoodyakKeyed,
    writer: W,
    buffer: Vec<u8>,
    n: u64,
}

impl<W: Write> AbsorbWriter<W> {
    /// Create a new [AbsorbWriter] with the given duplex and writer.
    pub fn new(duplex: XoodyakKeyed, writer: W) -> AbsorbWriter<W> {
        AbsorbWriter { duplex, writer, buffer: Vec::with_capacity(16 * 1024), n: 0 }
    }
}

const ABSORB_RATE: usize = 16;

impl<W: Write> Write for AbsorbWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.n += buf.len() as u64;
        self.buffer.extend(buf);
        let max = self.buffer.len() - (self.buffer.len() % ABSORB_RATE);
        if max >= ABSORB_RATE {
            self.duplex.absorb_more(self.buffer.drain(..max).as_slice(), ABSORB_RATE);
        }
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.duplex.absorb_more(&self.buffer, 16);
        self.writer.flush()
    }
}

impl<W: Write> AbsorbWriter<W> {
    pub fn into_inner(mut self) -> io::Result<(XoodyakKeyed, W, u64)> {
        self.flush()?;
        Ok((self.duplex, self.writer, self.n))
    }
}

/// Derive a [Scalar] from the given duplex's output.
pub fn squeeze_scalar(duplex: &mut XoodyakKeyed) -> Scalar {
    // Squeeze a derived key.
    let mut b = [0u8; 64];
    duplex.squeeze_key(&mut b);

    // Map the derived key to a scalar.
    let d = Scalar::from_bytes_mod_order_wide(&b);

    // Zeroize the temp buffer.
    b.zeroize();

    // Return the scalar.
    d
}

/// Clone the given duplex's state, absorb the given secret and 64 bytes of random data with the
/// clone, and pass the clone to the given function. Wraps the result in a [Secret].
pub fn hedge<R, F>(duplex: &XoodyakKeyed, secret: &[u8], f: F) -> Secret<R>
where
    F: Fn(&mut XoodyakKeyed) -> R,
    R: Zeroize,
{
    // Clone the duplex's state.
    let mut clone = duplex.clone();

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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn absorb_writer() {
        let duplex =
            XoodyakKeyed::new(&[], None, None, Some(b"ok")).expect("unable to construct duplex");
        let mut w = AbsorbWriter::new(duplex, Cursor::new(Vec::new()));
        w.write_all(b"this is a message that").expect("write failure");
        w.write_all(b" is written in multiple pieces").expect("write failure");
        let (mut one, m1, n1) = w.into_inner().expect("unwrap failure");

        assert_eq!(
            b"this is a message that is written in multiple pieces",
            m1.into_inner().as_slice()
        );
        assert_eq!(52, n1);

        let duplex =
            XoodyakKeyed::new(&[], None, None, Some(b"ok")).expect("unable to construct duplex");
        let mut w = AbsorbWriter::new(duplex, Cursor::new(Vec::new()));
        w.write_all(b"this is a message that").expect("write failure");
        w.write_all(b" is written in multiple").expect("write failure");
        w.write_all(b" pieces").expect("write failure");
        let (mut two, m2, n2) = w.into_inner().expect("unwrap failure");

        assert_eq!(
            b"this is a message that is written in multiple pieces",
            m2.into_inner().as_slice()
        );
        assert_eq!(52, n2);

        assert_eq!(one.squeeze_to_vec(4), two.squeeze_to_vec(4));
    }
}
