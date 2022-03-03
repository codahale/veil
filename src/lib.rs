//! The Veil hybrid cryptosystem.
//!
//! Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
//! authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
//! Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
//! encrypted. As a result, a global passive adversary would be unable to gain any information from
//! a Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise
//! their true length, and fake recipients can be added to disguise their true number from other
//! recipients.
//!
//! You should not use this.
//!
//!
//! ```rust
//! use std::io;
//! use std::io::Cursor;
//! use veil::SecretKey;
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! // Alice generates a secret key.
//! let alice_sk = SecretKey::random(rand::thread_rng());
//!
//! // Bea generates a secret key.
//! let bea_sk = SecretKey::random(rand::thread_rng());
//!
//! // Alice derives a private key for messaging with Bea and shares the corresponding public key.
//! let alice_priv = alice_sk.private_key().derive(&["friends", "bea"]);
//! let alice_pub = alice_priv.public_key();
//!
//! // Bea derives a private key for messaging with Alice and shares the corresponding public key.
//! let bea_priv = bea_sk.private_key().derive(&["buddies", "cool-ones", "alice"]);
//! let bea_pub = bea_priv.public_key();
//!
//! // Alice encrypts a secret message for Bea.
//! let mut ciphertext = Cursor::new(Vec::new());
//! alice_priv.encrypt(
//!   rand::thread_rng(),
//!   &mut Cursor::new("this is a secret message"),
//!   &mut ciphertext,
//!   &[bea_pub],
//!   Some(20),
//!   Some(1234),
//! )?;
//!
//! // Bea decrypts the message.
//! let mut plaintext = Cursor::new(Vec::new());
//! bea_priv.decrypt(
//!   &mut Cursor::new(ciphertext.into_inner()),
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
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_lifetimes,
    unused_qualifications,
    missing_debug_implementations,
    clippy::cognitive_complexity,
    clippy::missing_const_for_fn,
    clippy::needless_borrow
)]

pub use crate::schnorr::Signature;

pub use self::digest::*;
pub use self::errors::*;
pub use self::veil::*;

mod digest;
mod duplex;
mod errors;
mod hkd;
mod mres;
mod pbenc;
mod ristretto;
mod schnorr;
mod sres;
mod veil;
