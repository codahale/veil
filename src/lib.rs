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

use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::Group;
use p256::{NonZeroScalar, ProjectivePoint};

pub use self::ascii::*;
pub use self::digest::*;
pub use self::errors::*;
pub use self::schnorr::Signature;
pub use self::veil::*;

mod ascii;
mod digest;
mod duplex;
mod errors;
mod mres;
mod pbenc;
mod schnorr;
mod sres;
mod veil;

/// The length of an encoded point in bytes.
pub(crate) const POINT_LEN: usize = 33;

/// The length of an encoded scalar in bytes.
pub(crate) const SCALAR_LEN: usize = 32;

pub(crate) fn decode_point(b: impl AsRef<[u8]>) -> Option<ProjectivePoint> {
    let b: [u8; POINT_LEN] = b.as_ref().try_into().ok()?;
    let q: Option<ProjectivePoint> = ProjectivePoint::from_bytes(&b.into()).into();
    q.filter(|q| (!q.is_identity()).into())
}

pub(crate) fn decode_scalar(b: impl AsRef<[u8]>) -> Option<NonZeroScalar> {
    let b: [u8; SCALAR_LEN] = b.as_ref().try_into().ok()?;
    NonZeroScalar::from_repr(b.into()).into()
}
