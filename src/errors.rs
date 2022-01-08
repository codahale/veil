use std::io;

use thiserror::Error;

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
