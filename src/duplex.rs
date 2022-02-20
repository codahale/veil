use crate::ristretto::Scalar;
use std::io;
use std::io::Write;

use rand::Rng;
use subtle::ConstantTimeEq;
use xoodyak::{XoodyakCommon, XoodyakKeyed};

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// A cryptographic duplex, implemented here with Xoodyak.
pub struct Duplex {
    state: XoodyakKeyed,
}

impl Duplex {
    /// Create a new [Duplex] using the given name as a constant key.
    #[must_use]
    pub fn new(name: &str) -> Duplex {
        Duplex {
            state: XoodyakKeyed::new(name.as_bytes(), None, None, None)
                .expect("unable to construct duplex"),
        }
    }

    /// Absorb the given data.
    pub fn absorb(&mut self, data: &[u8]) {
        self.state.absorb(data);
    }

    /// Squeeze `n` bytes from the duplex.
    #[must_use]
    pub fn squeeze(&mut self, n: usize) -> Vec<u8> {
        self.state.squeeze_to_vec(n)
    }

    /// Fill the given output slice with bytes squeezed from the duplex.
    pub fn squeeze_into(&mut self, out: &mut [u8]) {
        self.state.squeeze(out)
    }

    /// Squeeze 32 bytes from the duplex and map them to a [Scalar].
    #[must_use]
    pub fn squeeze_scalar(&mut self) -> Scalar {
        // Squeeze a derived key.
        let mut b = [0u8; 32];
        self.state.squeeze_key(&mut b);

        // Map the derived key to a scalar.
        Scalar::from_bytes_mod_order(b)
    }

    /// Clone the duplex and use it to absorb the given secret and 64 random bytes. Pass the clone
    /// to the given function and return the result of that function as a secret.
    #[must_use]
    pub fn hedge<R, F>(&self, secret: &Scalar, f: F) -> R
    where
        F: Fn(&mut Duplex) -> R,
    {
        // Clone the duplex's state.
        let mut clone = Duplex { state: self.state.clone() };

        // Absorb the given secret.
        clone.absorb(secret.as_bytes());

        // Absorb a random value.
        clone.absorb(&rand::thread_rng().gen::<[u8; 64]>());

        // Call the given function with the clone.
        f(&mut clone)
    }

    /// Re-key the duplex with the given key.
    pub fn rekey(&mut self, key: &[u8]) {
        self.state.absorb_key_and_nonce(key, None, None, None).expect("unable to re-key duplex")
    }

    /// Ratchets the duplex's state for forward secrecy.
    pub fn ratchet(&mut self) {
        self.state.ratchet();
    }

    /// Encrypt the given plaintext. **Provides no guarantees for authenticity.**
    #[must_use]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.state.encrypt_to_vec(plaintext).expect("unable to encrypt")
    }

    /// Decrypt the given plaintext. **Provides no guarantees for authenticity.**
    #[must_use]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.state.decrypt_to_vec(ciphertext).expect("unable to decrypt")
    }

    /// Move the duplex and the given writer into an [AbsorbWriter].
    #[must_use]
    pub fn absorb_stream<W>(self, writer: W) -> AbsorbWriter<W>
    where
        W: Write,
    {
        AbsorbWriter { duplex: self, writer, buffer: Vec::with_capacity(16 * 1024), n: 0 }
    }

    /// Encrypt and seal the given plaintext, adding [TAG_LEN] bytes to the end.
    /// **Guarantees authenticity.**
    #[must_use]
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Allocate output buffer.
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);

        // Encrypt plaintext.
        out.extend(self.encrypt(plaintext));

        // Generate authentication tag.
        out.extend(self.squeeze(TAG_LEN));

        // Return ciphertext and tag.
        out
    }

    /// Decrypt and unseal the given ciphertext. If the ciphertext is invalid, returns `None`.
    /// **Guarantees authenticity.**
    #[must_use]
    pub fn unseal(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // Check for undersized ciphertexts.
        if ciphertext.len() < TAG_LEN {
            return None;
        }

        // Split into ciphertext and tag.
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);

        // Decrypt the plaintext.
        let plaintext = self.decrypt(ciphertext);

        // Compare the given tag with the counterfactual tag in constant time.
        let tag_p = self.squeeze(TAG_LEN);
        if tag.ct_eq(&tag_p).into() {
            // Return the plaintext, now authenticated.
            Some(plaintext)
        } else {
            None
        }
    }
}

/// A [Write] adapter which tees writes into a duplex.
pub struct AbsorbWriter<W: Write> {
    duplex: Duplex,
    writer: W,
    buffer: Vec<u8>,
    n: u64,
}

const ABSORB_RATE: usize = 16;

impl<W: Write> Write for AbsorbWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.n += buf.len() as u64;
        self.buffer.extend(buf);
        let max = self.buffer.len() - (self.buffer.len() % ABSORB_RATE);
        if max >= ABSORB_RATE {
            self.duplex.state.absorb_more(self.buffer.drain(..max).as_slice(), ABSORB_RATE);
        }
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.duplex.state.absorb_more(&self.buffer, 16);
        self.writer.flush()
    }
}

impl<W: Write> AbsorbWriter<W> {
    /// Unwrap the writer into the inner duplex and writer. Also returns the number of bytes
    /// written.
    pub fn into_inner(mut self) -> io::Result<(Duplex, W, u64)> {
        self.flush()?;
        Ok((self.duplex, self.writer, self.n))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn absorb_writer() {
        let duplex = Duplex::new("ok");
        let mut w = duplex.absorb_stream(Cursor::new(Vec::new()));
        w.write_all(b"this is a message that").expect("write failure");
        w.write_all(b" is written in multiple pieces").expect("write failure");
        let (mut one, m1, n1) = w.into_inner().expect("unwrap failure");

        assert_eq!(
            b"this is a message that is written in multiple pieces",
            m1.into_inner().as_slice()
        );
        assert_eq!(52, n1);

        let duplex = Duplex::new("ok");
        let mut w = duplex.absorb_stream(Cursor::new(Vec::new()));
        w.write_all(b"this is a message that").expect("write failure");
        w.write_all(b" is written in multiple").expect("write failure");
        w.write_all(b" pieces").expect("write failure");
        let (mut two, m2, n2) = w.into_inner().expect("unwrap failure");

        assert_eq!(
            b"this is a message that is written in multiple pieces",
            m2.into_inner().as_slice()
        );
        assert_eq!(52, n2);

        assert_eq!(one.squeeze(4), two.squeeze(4));
    }
}
