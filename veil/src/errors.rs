use std::io;

use thiserror::Error;

/// An error returned when a public key cannot be parsed.
#[derive(Error, Debug)]
#[error("invalid public key")]
pub struct PublicKeyError;

/// Errors returned during decryption.
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// An error returned when a message cannot be decrypted with the given keys.
    ///
    /// The ciphertext may have been altered, or the message may not have been encrypted with those
    /// keys.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// An error returned when there was an underlying IO error during decryption.
    #[error("error decrypting: {0}")]
    IoError(#[from] io::Error),
}

/// Errors returned during verification.
#[derive(Error, Debug)]
pub enum VerificationError {
    /// An error returned when a signature cannot be verified.
    ///
    /// The message or signature may have been altered, or the message may not have been signed with
    /// the given key.
    #[error("invalid signature")]
    InvalidSignature,

    /// An error returned when there was an underlying IO error during verification.
    #[error("error verifying: {0}")]
    IoError(#[from] io::Error),
}
