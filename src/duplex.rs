//! Implements a cryptographic duplex using Cyclist/Keccak.

use std::io;
use std::io::{Read, Write};

use cyclist::keccyak::{Keccyak128Hash, Keccyak128Keyed};
use cyclist::Cyclist;
use rand::{CryptoRng, Rng};

use crate::ecc::{CanonicallyEncoded, Point, Scalar};
use crate::read_chunk;

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// An unkeyed cryptographic duplex.
#[derive(Clone)]
pub struct UnkeyedDuplex {
    state: Keccyak128Hash,
}

impl UnkeyedDuplex {
    /// Create a new [`UnkeyedDuplex`] with the given domain separation string.
    #[must_use]
    pub fn new(domain: &str) -> UnkeyedDuplex {
        // Initialize an empty hash.
        let mut state = Keccyak128Hash::default();

        // Absorb the domain separation string.
        state.absorb(domain.as_bytes());

        UnkeyedDuplex { state }
    }

    /// Extract a key from this duplex's state and use it to create a keyed duplex.
    pub fn into_keyed(mut self) -> KeyedDuplex {
        const KEY_LEN: usize = 64;

        let mut key = [0u8; KEY_LEN];
        self.state.squeeze_key_mut(&mut key);

        KeyedDuplex { state: Keccyak128Keyed::new(&key, None, None) }
    }
}

/// A keyed cryptographic duplex.
#[derive(Clone)]
pub struct KeyedDuplex {
    state: Keccyak128Keyed,
}

impl KeyedDuplex {
    /// Encrypt the given plaintext in place. **Provides no guarantees for authenticity.**
    pub fn encrypt_mut(&mut self, in_out: &mut [u8]) {
        self.state.encrypt_mut(in_out);
    }

    /// Decrypt the given ciphertext in place. **Provides no guarantees for authenticity.**
    pub fn decrypt_mut(&mut self, in_out: &mut [u8]) {
        self.state.decrypt_mut(in_out);
    }

    /// Encrypt and seal the given plaintext in place, adding [`TAG_LEN`] bytes to the end.
    /// **Guarantees authenticity.**
    pub fn seal_mut(&mut self, in_out: &mut [u8]) {
        self.state.seal_mut(in_out);
    }

    /// Decrypt and unseal the given ciphertext in place. If the ciphertext is valid, returns the
    /// length of the plaintext; if invalid, returns `None`.
    /// **Guarantees authenticity.**
    #[must_use]
    pub fn unseal_mut<'a>(&mut self, in_out: &'a mut [u8]) -> Option<&'a [u8]> {
        self.state.open_mut(in_out).then_some(&in_out[..in_out.len() - TAG_LEN])
    }
}

/// Common duplex output operations.
pub trait Squeeze {
    /// Fill the given output slice with bytes squeezed from the duplex.
    fn squeeze_mut(&mut self, out: &mut [u8]);

    /// Squeeze `n` bytes from the duplex.
    #[must_use]
    fn squeeze<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.squeeze_mut(&mut b);
        b
    }

    /// Squeeze 64 bytes from the duplex and map them to a [`Scalar`].
    #[must_use]
    fn squeeze_scalar(&mut self) -> Scalar {
        Scalar::decode_reduce(&self.squeeze::<64>())
    }
}

impl Squeeze for UnkeyedDuplex {
    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.state.squeeze_mut(out);
    }
}

impl Squeeze for KeyedDuplex {
    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.state.squeeze_mut(out);
    }
}

// Common duplex input operations.
pub trait Absorb: Clone {
    /// The number of bytes which can be absorbed before the state is permuted.
    fn absorb_rate(&self) -> usize;

    /// Absorb the given slice of data.
    fn absorb(&mut self, data: &[u8]);

    /// Extend a previous absorb operation with the given slice of data.
    fn absorb_more(&mut self, data: &[u8]);

    /// Absorb a point.
    fn absorb_point(&mut self, q: &Point) {
        self.absorb(&q.as_canonical_bytes());
    }

    /// Absorb the entire contents of the given reader as a single operation.
    fn absorb_reader(&mut self, reader: impl Read) -> io::Result<u64> {
        self.absorb_reader_into(reader, io::sink())
    }

    /// Copy the contents of `reader` into `writer`, absorbing the contents as a single operation.
    fn absorb_reader_into(
        &mut self,
        mut reader: impl Read,
        mut writer: impl Write,
    ) -> io::Result<u64> {
        let mut buf = vec![0u8; self.absorb_rate() * 32];
        let mut first = true;
        let mut written = 0;

        loop {
            // Read a block of data.
            let n = read_chunk(&mut reader, &mut buf)?;
            let block = &buf[..n];

            // Absorb the block.
            if first {
                self.absorb(block);
                first = false;
            } else {
                self.absorb_more(block);
            }

            // Write the block.
            writer.write_all(block)?;
            written += u64::try_from(n).expect("unexpected overflow");

            // If the block was undersized, we're at the end of the reader.
            if n < buf.len() {
                break;
            }
        }

        Ok(written)
    }

    /// Clone the duplex and use it to absorb the given secret and 64 random bytes. Pass the clone
    /// to the given function and return the result of that function as a secret.
    #[must_use]
    fn hedge<R>(
        &self,
        mut rng: impl Rng + CryptoRng,
        secret: &[u8],
        f: impl Fn(&mut Self) -> R,
    ) -> R {
        // Clone the duplex's state.
        let mut clone = self.clone();

        // Absorb the given secret.
        clone.absorb(secret);

        // Absorb a random value.
        clone.absorb(&rng.gen::<[u8; 64]>());

        // Call the given function with the clone.
        f(&mut clone)
    }
}

impl Absorb for UnkeyedDuplex {
    fn absorb_rate(&self) -> usize {
        self.state.absorb_rate()
    }

    fn absorb(&mut self, data: &[u8]) {
        self.state.absorb(data);
    }

    fn absorb_more(&mut self, data: &[u8]) {
        self.state.absorb_more(data);
    }
}

impl Absorb for KeyedDuplex {
    fn absorb_rate(&self) -> usize {
        self.state.absorb_rate()
    }

    fn absorb(&mut self, data: &[u8]) {
        self.state.absorb(data);
    }

    fn absorb_more(&mut self, data: &[u8]) {
        self.state.absorb_more(data);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn ind_cpa_round_trip() {
        let plaintext = b"this is an example plaintext";

        let mut unkeyed = UnkeyedDuplex::new("test");
        unkeyed.absorb(b"this is a new key");
        unkeyed.absorb(b"this is some more data");

        let mut keyed = unkeyed.into_keyed();
        let mut ciphertext = plaintext.to_vec();
        keyed.encrypt_mut(&mut ciphertext);

        let mut unkeyed = UnkeyedDuplex::new("test");
        unkeyed.absorb(b"this is a new key");
        unkeyed.absorb(b"this is some more data");

        let mut keyed = unkeyed.into_keyed();
        keyed.decrypt_mut(&mut ciphertext);
        assert_eq!(plaintext.to_vec(), ciphertext);
    }

    #[test]
    fn ind_cca_round_trip() {
        let plaintext = b"this is an example plaintext";

        let mut duplex = UnkeyedDuplex::new("test").into_keyed();
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        duplex.seal_mut(&mut ciphertext);

        let mut duplex = UnkeyedDuplex::new("test").into_keyed();
        assert_eq!(Some(plaintext.as_slice()), duplex.unseal_mut(&mut ciphertext));
    }

    #[test]
    fn absorb_blocks() {
        let mut one = UnkeyedDuplex::new("ok");
        one.absorb_reader(Cursor::new(b"this is a message")).expect("error absorbing");

        let mut two = UnkeyedDuplex::new("ok");
        two.absorb_reader(Cursor::new(b"this is a message")).expect("error absorbing");

        assert_eq!(one.squeeze::<4>(), two.squeeze::<4>());
    }
}
