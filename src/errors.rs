use std::io;

use thiserror::Error;

/// An error returned when decrypting a message was unsuccessful.
#[derive(Debug, Error)]
pub enum DecryptError {
    /// Decryption was unsuccessful due to a message/private key/public key mismatch.
    ///
    /// The ciphertext may have been altered, the message may not have been encrypted by the given
    /// sender, or the message may not have been encrypted for the given recipient.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// Decryption was unsuccessful due to an IO error reading the ciphertext or writing the
    /// plaintext.
    #[error("error decrypting: {0}")]
    IoError(#[from] io::Error),
}

/// An error returned when verifying a signature was unsuccessful.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Verification was unsuccessful due to a signature/message/public key mismatch.
    ///
    /// The message or signature may have been altered, or the message may not have been signed with
    /// the given key.
    #[error("invalid signature")]
    InvalidSignature,

    /// Verification was unsuccessful due to an IO error reading the message.
    #[error("error verifying: {0}")]
    IoError(#[from] io::Error),
}

/// An error returned when parsing a signature was unsuccessful.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid signature")]
pub struct ParseSignatureError;

/// An error returned when parsing a public key was unsuccessful.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid public key")]
pub struct ParsePublicKeyError;

/// An error returned when parsing a digest was unsuccessful.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid digest")]
pub struct ParseDigestError;
