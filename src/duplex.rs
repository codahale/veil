//! Implements a cryptographic duplex using Xoodyak.

use std::io;
use std::io::Read;

use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;
use xoodyak::{XoodyakCommon, XoodyakKeyed};

use crate::ristretto::Scalar;

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

    /// Squeeze 64 bytes from the duplex and map them to a [Scalar].
    #[must_use]
    pub fn squeeze_scalar(&mut self) -> Scalar {
        // Squeeze a 512-bit integer.
        let mut b = [0u8; 64];
        self.state.squeeze(&mut b);

        // Map the integer to a scalar mod l.
        Scalar::from_bytes_mod_order_wide(&b)
    }

    /// Clone the duplex and use it to absorb the given secret and 64 random bytes. Pass the clone
    /// to the given function and return the result of that function as a secret.
    #[must_use]
    pub fn hedge<R, F>(&self, mut rng: impl Rng + CryptoRng, secret: &Scalar, f: F) -> R
    where
        F: Fn(&mut Duplex) -> R,
    {
        // Clone the duplex's state.
        let mut clone = Duplex { state: self.state.clone() };

        // Absorb the given secret.
        clone.absorb(secret.as_bytes());

        // Absorb a random value.
        clone.absorb(&rng.gen::<[u8; 64]>());

        // Call the given function with the clone.
        f(&mut clone)
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

    /// Absorb the entire contents of the given reader in 32KiB-sized blocks.
    pub fn absorb_blocks(&mut self, mut reader: impl Read) -> io::Result<()> {
        let mut buf = Vec::with_capacity(BLOCK_LEN);

        loop {
            // Read a block of data.
            let n = (&mut reader).take(BLOCK_LEN as u64).read_to_end(&mut buf)?;
            let block = &buf[..n];

            // Absorb the block.
            self.absorb(block);

            // If the block was undersized, we're at the end of the reader.
            if n < BLOCK_LEN {
                break;
            }

            // Reset the buffer.
            buf.clear();
        }

        Ok(())
    }

    /// Encrypt and seal the given plaintext, adding [TAG_LEN] bytes to the end.
    /// **Guarantees authenticity.**
    #[must_use]
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Allocate output buffer.
        let mut out = vec![0u8; plaintext.len() + TAG_LEN];

        // Encrypt plaintext.
        self.state.encrypt(&mut out, plaintext).expect("unable to encrypt");

        // Generate authentication tag.
        self.state.squeeze(&mut out[plaintext.len()..]);

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

const BLOCK_LEN: usize = 32 * 1024;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn ind_cpa_round_trip() {
        let plaintext = b"this is an example plaintext";

        let mut duplex = Duplex::new("test");
        duplex.absorb(b"this is a new key");
        duplex.absorb(b"this is some more data");
        duplex.ratchet();
        let ciphertext = duplex.encrypt(plaintext);

        let mut duplex = Duplex::new("test");
        duplex.absorb(b"this is a new key");
        duplex.absorb(b"this is some more data");
        duplex.ratchet();
        assert_eq!(plaintext.to_vec(), duplex.decrypt(&ciphertext));
    }

    #[test]
    fn ind_cca_round_trip() {
        let plaintext = b"this is an example plaintext";

        let mut duplex = Duplex::new("test");
        let ciphertext = duplex.seal(plaintext);

        let mut duplex = Duplex::new("test");
        assert_eq!(Some(plaintext.to_vec()), duplex.unseal(&ciphertext));
    }

    #[test]
    fn absorb_blocks() {
        let mut one = Duplex::new("ok");
        one.absorb_blocks(Cursor::new(b"this is a message")).expect("error absorbing");

        let mut two = Duplex::new("ok");
        two.absorb_blocks(Cursor::new(b"this is a message")).expect("error absorbing");

        assert_eq!(one.squeeze(4), two.squeeze(4));
    }
}
