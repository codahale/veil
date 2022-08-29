use std::io;

use thiserror::Error;

/// An error returned when encrypting a message was unsuccessful.
#[derive(Debug, Error)]
pub enum EncryptError {
    /// Encryption was unsuccessful because the user-provided parameters are invalid.
    #[error("invalid parameters: {0}")]
    InvalidParams(#[from] argon2::Error),

    /// Encryption was unsuccessful due to an IO error reading the plaintext or writing the
    /// ciphertext.
    #[error("error decrypting: {0}")]
    IoError(#[from] io::Error),
}

/// An error returned when decrypting a message was unsuccessful.
#[derive(Debug, Error)]
pub enum DecryptError {
    /// Decryption was unsuccessful due to a message/private key/public key mismatch.
    ///
    /// The ciphertext may have been altered, the message may not have been encrypted by the given
    /// sender, or the message may not have been encrypted for the given receiver.
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
pub enum ParseSignatureError {
    /// Parsing failed because the value was not the correct length.
    #[error("invalid signature length")]
    InvalidLength,

    /// Parsing failed because the signature was not valid base58.
    #[error("invalid base58 encoding")]
    InvalidEncoding(#[from] bs58::decode::Error),
}

/// An error returned when parsing a public key was unsuccessful.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid public key")]
pub enum ParsePublicKeyError {
    /// Parsing failed because the value was not a valid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Parsing failed because the public key was not valid base58.
    #[error("invalid base58 encoding")]
    InvalidEncoding(#[from] bs58::decode::Error),
}

/// An error returned when parsing a digest was unsuccessful.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ParseDigestError {
    /// Parsing failed because the value was not the correct length.
    #[error("invalid digest length")]
    InvalidLength,

    /// Parsing failed because the digest was not valid base58.
    #[error("invalid base58 encoding")]
    InvalidEncoding(#[from] bs58::decode::Error),
}
