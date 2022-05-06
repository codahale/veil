//! Implements a cryptographic duplex using Cyclist/Keccak.

use std::io;
use std::io::Read;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use cyclist::keccak::{Keccyak128Hash, Keccyak128Keyed};
use cyclist::Cyclist;
use rand::{CryptoRng, Rng};

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// An unkeyed cryptographic duplex.
#[derive(Clone)]
pub struct UnkeyedDuplex {
    state: Keccyak128Hash,
}

impl UnkeyedDuplex {
    /// Create a new [UnkeyedDuplex] with the given domain separation string.
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
    /// Encrypt the given plaintext. **Provides no guarantees for authenticity.**
    #[must_use]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.state.encrypt(plaintext)
    }

    /// Decrypt the given plaintext. **Provides no guarantees for authenticity.**
    #[must_use]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.state.decrypt(ciphertext)
    }

    /// Encrypt and seal the given plaintext, adding [TAG_LEN] bytes to the end.
    /// **Guarantees authenticity.**
    #[must_use]
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.state.seal(plaintext)
    }

    /// Decrypt and unseal the given ciphertext. If the ciphertext is invalid, returns `None`.
    /// **Guarantees authenticity.**
    #[must_use]
    pub fn unseal(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.state.open(ciphertext)
    }
}

/// Common duplex output operations.
pub trait Squeeze {
    /// Fill the given output slice with bytes squeezed from the duplex.
    fn squeeze_mut(&mut self, out: &mut [u8]);

    /// Squeeze `n` bytes from the duplex.
    #[must_use]
    fn squeeze(&mut self, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        self.squeeze_mut(&mut b);
        b
    }

    /// Squeeze 64 bytes from the duplex and map them to a [Scalar].
    #[must_use]
    fn squeeze_scalar(&mut self) -> Scalar {
        loop {
            // Squeeze a 512-bit integer.
            let mut b = [0u8; 64];
            self.squeeze_mut(&mut b);

            // Map the integer to a scalar mod l and return if ≠ 0.
            let d = Scalar::from_bytes_mod_order_wide(&b);
            if d != Scalar::zero() {
                return d;
            }
        }
    }
}

impl Squeeze for UnkeyedDuplex {
    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.state.squeeze_mut(out)
    }
}

impl Squeeze for KeyedDuplex {
    fn squeeze_mut(&mut self, out: &mut [u8]) {
        self.state.squeeze_mut(out)
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

    /// Absorb a Ristretto point.
    fn absorb_point(&mut self, q: &RistrettoPoint) {
        self.absorb(q.compress().as_bytes());
    }

    /// Absorb the entire contents of the given reader as a single operation.
    fn absorb_reader(&mut self, mut reader: impl Read) -> io::Result<()> {
        let block_len = self.absorb_rate() * 32;

        let mut buf = Vec::with_capacity(block_len);
        let mut first = true;

        loop {
            // Read a block of data.
            let n = (&mut reader).take(block_len as u64).read_to_end(&mut buf)?;
            let block = &buf[..n];

            // Absorb the block.
            if first {
                self.absorb(block);
                first = false;
            } else {
                self.absorb_more(block);
            }

            // If the block was undersized, we're at the end of the reader.
            if n < block_len {
                break;
            }

            // Reset the buffer.
            buf.clear();
        }

        Ok(())
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
        self.state.absorb(data)
    }

    fn absorb_more(&mut self, data: &[u8]) {
        self.state.absorb_more(data)
    }
}

impl Absorb for KeyedDuplex {
    fn absorb_rate(&self) -> usize {
        self.state.absorb_rate()
    }

    fn absorb(&mut self, data: &[u8]) {
        self.state.absorb(data)
    }

    fn absorb_more(&mut self, data: &[u8]) {
        self.state.absorb_more(data)
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
        let ciphertext = keyed.encrypt(plaintext);

        let mut unkeyed = UnkeyedDuplex::new("test");
        unkeyed.absorb(b"this is a new key");
        unkeyed.absorb(b"this is some more data");

        let mut keyed = unkeyed.into_keyed();
        assert_eq!(plaintext.to_vec(), keyed.decrypt(&ciphertext));
    }

    #[test]
    fn ind_cca_round_trip() {
        let plaintext = b"this is an example plaintext";

        let mut duplex = UnkeyedDuplex::new("test").into_keyed();
        let ciphertext = duplex.seal(plaintext);

        let mut duplex = UnkeyedDuplex::new("test").into_keyed();
        assert_eq!(Some(plaintext.to_vec()), duplex.unseal(&ciphertext));
    }

    #[test]
    fn absorb_blocks() {
        let mut one = UnkeyedDuplex::new("ok");
        one.absorb_reader(Cursor::new(b"this is a message")).expect("error absorbing");

        let mut two = UnkeyedDuplex::new("ok");
        two.absorb_reader(Cursor::new(b"this is a message")).expect("error absorbing");

        assert_eq!(one.squeeze(4), two.squeeze(4));
    }
}
