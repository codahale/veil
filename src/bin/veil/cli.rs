use std::path::PathBuf;

use argh::FromArgs;
use clio::{Input, Output};

#[derive(Debug, FromArgs)]
/// Stupid crypto tricks.
pub struct Opts {
    #[argh(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand)]
pub enum Command {
    SecretKey(SecretKeyArgs),
    PublicKey(PublicKeyArgs),
    DeriveKey(DeriveKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Sign(SignArgs),
    Verify(VerifyArgs),
}

#[derive(Debug, FromArgs)]
/// Generate a new secret key.
#[argh(subcommand, name = "secret-key")]
pub struct SecretKeyArgs {
    #[argh(positional)]
    pub output: PathBuf,

    /// the time parameter for secret key encryption
    #[argh(option, default = "1<<7")]
    pub time: u32,

    /// the space parameter for secret key encryption
    #[argh(option, default = "1<<10")]
    pub space: u32,

    /// read the passphrase from the given file
    #[argh(option)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, FromArgs)]
/// Derive a public key from a secret key.
#[argh(subcommand, name = "public-key")]
pub struct PublicKeyArgs {
    #[argh(positional)]
    pub secret_key: PathBuf,

    #[argh(positional)]
    pub key_id: String,

    /// read the passphrase from the given file
    #[argh(option)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, FromArgs)]
/// Derive a public key from another public key.
#[argh(subcommand, name = "derive-key")]
pub struct DeriveKeyArgs {
    #[argh(positional)]
    pub public_key: String,

    #[argh(positional)]
    pub sub_key_id: String,
}

#[derive(Debug, FromArgs)]
/// Encrypt a message.
#[argh(subcommand, name = "encrypt")]
pub struct EncryptArgs {
    #[argh(positional)]
    pub secret_key: PathBuf,

    #[argh(positional)]
    pub key_id: String,

    #[argh(positional, from_str_fn(str_to_input))]
    pub plaintext: Input,

    #[argh(positional, from_str_fn(str_to_output))]
    pub ciphertext: Output,

    #[argh(positional)]
    pub recipients: Vec<String>,

    /// number of fake recipients to add
    #[argh(option, default = "0")]
    pub fakes: usize,

    /// number of random padding bytes to add
    #[argh(option, default = "0")]
    pub padding: u64,

    /// read the passphrase from the given file
    #[argh(option)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, FromArgs)]
/// Decrypt a message.
#[argh(subcommand, name = "decrypt")]
pub struct DecryptArgs {
    #[argh(positional)]
    pub secret_key: PathBuf,

    #[argh(positional)]
    pub key_id: String,

    #[argh(positional, from_str_fn(str_to_input))]
    pub ciphertext: Input,

    #[argh(positional, from_str_fn(str_to_output))]
    pub plaintext: Output,

    #[argh(positional)]
    pub sender: String,

    /// read the passphrase from the given file
    #[argh(option)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, FromArgs)]
/// Sign a message.
#[argh(subcommand, name = "sign")]
pub struct SignArgs {
    #[argh(positional)]
    pub secret_key: PathBuf,

    #[argh(positional)]
    pub key_id: String,

    #[argh(positional, from_str_fn(str_to_input))]
    pub message: Input,

    /// read the passphrase from the given file
    #[argh(option)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, FromArgs)]
/// Verify a signature.
#[argh(subcommand, name = "verify")]
pub struct VerifyArgs {
    /// the signer's public key
    #[argh(positional)]
    pub public_key: String,

    #[argh(positional, from_str_fn(str_to_input))]
    pub message: Input,

    #[argh(positional)]
    pub signature: String,
}

fn str_to_input(value: &str) -> Result<Input, String> {
    Input::new(value).map_err(|e| e.to_string())
}

fn str_to_output(value: &str) -> Result<Output, String> {
    Output::new(value).map_err(|e| e.to_string())
}
