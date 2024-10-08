//! The Veil cryptosystem.
//!
//! Veil is an incredibly experimental cryptosystem for sending and receiving confidential,
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
//! use rand::rngs::OsRng;
//! use veil::SecretKey;
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! // Alice generates a secret key.
//! let alice_priv = SecretKey::random(OsRng);
//!
//! // Bea generates a secret key.
//! let bea_priv = SecretKey::random(OsRng);
//!
//! // Alice and Bea share public keys.
//! let alice_pub = alice_priv.public_key();
//! let bea_pub = bea_priv.public_key();
//!
//! // Alice encrypts a secret message for Bea.
//! let mut ciphertext = Cursor::new(Vec::new());
//! alice_priv.encrypt(
//!   OsRng,
//!   Cursor::new("this is a secret message"),
//!   &mut ciphertext,
//!   &[bea_pub],
//!   Some(20),
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

pub use self::{digest::*, errors::*, sig::Signature, veil::*};

mod digest;
mod errors;
mod kemeleon;
mod keys;
mod message;
mod pbenc;
mod sig;
mod veil;
