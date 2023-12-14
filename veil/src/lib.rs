//! The Veil hybrid cryptosystem.
//!
//! Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
//! authentic multi-receiver messages which are indistinguishable from random noise by an attacker.
//! Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
//! encrypted. As a result, a global passive adversary would be unable to gain any information from
//! a Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise
//! their true length, and fake receivers can be added to disguise their true number from other
//! receivers.
//!
//! You should not use this.
//!
//!
//! ```rust
//! use std::io;
//! use std::io::Cursor;
//! use veil::PrivateKey;
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! // Alice generates a private key.
//! let alice_priv = PrivateKey::random(rand::thread_rng());
//!
//! // Bea generates a private key.
//! let bea_priv = PrivateKey::random(rand::thread_rng());
//!
//! // Alice and Bea share public keys.
//! let alice_pub = alice_priv.public_key();
//! let bea_pub = bea_priv.public_key();
//!
//! // Alice encrypts a secret message for Bea.
//! let mut ciphertext = Cursor::new(Vec::new());
//! alice_priv.encrypt(
//!   rand::thread_rng(),
//!   Cursor::new("this is a secret message"),
//!   &mut ciphertext,
//!   &[bea_pub],
//!   Some(20),
//!   Some(1234),
//! )?;
//!
//! // Bea decrypts the message.
//! let mut plaintext = Cursor::new(Vec::new());
//! bea_priv.decrypt(
//!   Cursor::new(ciphertext.into_inner()),
//!   &mut plaintext,
//!   &alice_pub,
//! )?;
//!
//! // Having decrypted the message, Bea can read the plaintext.
//! assert_eq!(b"this is a secret message".to_vec(), plaintext.into_inner(), "invalid plaintext");
//! #
//! #   Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use self::{digest::*, errors::*, schnorr::Signature, veil::*};

mod blockio;
mod digest;
mod errors;
mod keys;
mod mres;
mod pbenc;
mod schnorr;
mod sres;
mod veil;
