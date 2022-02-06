//! High-level operations for STROBE.

use std::io::{self, Write};

use crate::constants::MAC_LEN;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use secrecy::{Secret, Zeroize};
use strobe_rs::{SecParam, Strobe};

/// A Strobe protocol.
pub struct Protocol(Strobe);

impl Protocol {
    /// Create a new [Protocol].
    pub fn new(label: &str) -> Protocol {
        Protocol(Strobe::new(label.as_bytes(), SecParam::B128))
    }

    /// Derive a scalar from PRF output.
    #[must_use]
    pub fn prf_scalar(&mut self, label: &str) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.prf(label))
    }

    /// Derive an array from PRF output.
    #[must_use]
    pub fn prf<const N: usize>(&mut self, label: &str) -> [u8; N] {
        let mut out = [0u8; N];
        self.prf_fill(label, &mut out);
        out
    }

    /// Derive a `Vec` from PRF output.
    #[must_use]
    pub fn prf_vec(&mut self, label: &str, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        self.prf_fill(label, &mut out);
        out
    }

    /// Fill a slice with PRF output.
    pub fn prf_fill(&mut self, label: &str, out: &mut [u8]) {
        self.meta_ad_len(label, out.len() as u64);

        self.0.prf(out, false);
    }

    /// Include the data as associated data.
    pub fn ad(&mut self, label: &str, data: &[u8]) {
        self.meta_ad_len(label, data.len() as u64);
        self.0.ad(data, false);
    }

    /// Send the data as cleartext.
    pub fn send<'a>(&mut self, label: &str, data: &'a [u8]) -> &'a [u8] {
        self.meta_ad_len(label, data.len() as u64);
        self.0.send_clr(data, false);
        data
    }

    /// Receive the data as cleartext.
    pub fn receive(&mut self, label: &str, data: &[u8]) {
        self.meta_ad_len(label, data.len() as u64);
        self.0.recv_clr(data, false);
    }

    /// Encrypt the given plaintext and return the ciphertext.
    #[must_use]
    pub fn encrypt(&mut self, label: &str, plaintext: &[u8]) -> Vec<u8> {
        self.meta_ad_len(label, plaintext.len() as u64);

        let mut ciphertext = Vec::from(plaintext);
        self.0.send_enc(&mut ciphertext, false);
        ciphertext
    }

    /// Decrypt the given ciphertext and return the plaintext.
    #[must_use]
    pub fn decrypt(&mut self, label: &str, ciphertext: &[u8]) -> Secret<Vec<u8>> {
        self.meta_ad_len(label, ciphertext.len() as u64);

        let mut plaintext = Vec::from(ciphertext);
        self.0.recv_enc(&mut plaintext, false);
        plaintext.into()
    }

    /// Key the protocol with the given key.
    pub fn key(&mut self, label: &str, key: &[u8]) {
        self.meta_ad_len(label, key.len() as u64);
        self.0.key(key, false);
    }

    /// Calculate a MAC of the given length.
    #[must_use]
    pub fn mac(&mut self, label: &str) -> Vec<u8> {
        self.meta_ad_len(label, MAC_LEN as u64);

        let mut out = vec![0u8; MAC_LEN];
        self.0.send_mac(&mut out, false);
        out
    }

    /// Verify the given MAC.
    pub fn verify_mac(&mut self, label: &str, mac: &[u8]) -> Option<()> {
        self.meta_ad_len(label, mac.len() as u64);

        let mut mac = Vec::from(mac);
        self.0.recv_mac(&mut mac).ok()
    }

    /// Clone the current instance, key it with the given secret, key it again with random data, and
    /// pass the clone to the given function.
    #[must_use]
    pub fn hedge<R, F>(&self, secret: &[u8], f: F) -> Secret<R>
    where
        F: Fn(&mut Protocol) -> R,
        R: Zeroize,
    {
        // Clone the protocol's state.
        let mut clone = Protocol(self.0.clone());

        // Key with the given secret.
        clone.key("secret-value", secret);

        // Generate a random value.
        let mut r = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut r);

        // Key with the random value.
        clone.key("hedged-value", &r);

        // Zeroize the random value.
        r.zeroize();

        // Call the given function with the clone.
        f(&mut clone).into()
    }

    /// Create a writer which passes writes through `SEND_CLR` before passing them to the given
    /// writer.
    pub fn send_clr_writer<W>(mut self, label: &str, w: W) -> SendClrWriter<W>
    where
        W: Write,
    {
        self.0.meta_ad(format!("{}-start", label).as_bytes(), false);
        self.0.send_clr(&[], false);
        SendClrWriter(self, w, 0, label.to_string())
    }

    /// Create a writer which passes writes through `RECV_CLR` before passing them to the given
    /// writer.
    pub fn recv_clr_writer<W>(mut self, label: &str, w: W) -> RecvClrWriter<W>
    where
        W: Write,
    {
        self.0.meta_ad(format!("{}-start", label).as_bytes(), false);
        self.0.recv_clr(&[], false);
        RecvClrWriter(self, w, 0, label.to_string())
    }

    /// Include the given label and length as associated-metadata.
    fn meta_ad_len(&mut self, label: &str, n: u64) {
        self.0.meta_ad(label.as_bytes(), false);
        self.0.meta_ad(&n.to_le_bytes(), true);
    }
}

macro_rules! protocol_writer {
    ($t:ident, $strobe:ident, $buf:ident, $writer:ident, $body:block) => {
        #[must_use]
        pub struct $t<W: Write>(Protocol, W, u64, String);

        impl<W: Write> $t<W> {
            #[must_use]
            pub fn into_inner(self) -> (Protocol, W, u64) {
                let mut p = self.0;
                p.meta_ad_len(&format!("{}-end", self.3), self.2);
                (p, self.1, self.2)
            }
        }

        impl<W: Write> Write for $t<W> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.2 += buf.len() as u64;
                let $strobe = &mut self.0 .0;
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

protocol_writer!(SendClrWriter, strobe, buf, w, {
    strobe.send_clr(buf, true);
    w.write_all(buf)?;
    Ok(buf.len())
});

protocol_writer!(RecvClrWriter, strobe, buf, w, {
    strobe.recv_clr(buf, true);
    w.write_all(buf)?;
    Ok(buf.len())
});
