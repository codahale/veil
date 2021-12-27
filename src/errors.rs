use std::io;

use thiserror::Error;

/// Error due to invalid public key format.
#[derive(Error, Debug, Eq, PartialEq, Copy, Clone)]
#[error("invalid public key")]
pub struct PublicKeyError;

/// Error due to invalid signature format.
#[derive(Error, Debug, Eq, PartialEq, Copy, Clone)]
#[error("invalid signature")]
pub struct SignatureError;

/// The error type for message decryption.
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// Error due to message/private key/public key mismatch.
    ///
    /// The ciphertext may have been altered, the message may not have been encrypted by the given
    /// sender, or the message may not have been encrypted for the given recipient.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// An error returned when there was an underlying IO error during decryption.
    #[error("error decrypting: {0}")]
    IoError(#[from] io::Error),
}

/// The error type for message verification.
#[derive(Error, Debug)]
pub enum VerificationError {
    /// Error due to signature/message/public key mismatch.
    ///
    /// The message or signature may have been altered, or the message may not have been signed with
    /// the given key.
    #[error("invalid signature")]
    InvalidSignature,

    /// The reader containing the message returned an IO error.
    #[error("error verifying: {0}")]
    IoError(#[from] io::Error),
}
