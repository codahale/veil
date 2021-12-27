use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use clap::{AppSettings, Parser, Subcommand, ValueHint};
use clap_generate::Shell;
use clio::{Input, Output};

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(setting = AppSettings::SubcommandRequired)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Subcommand)]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
pub enum Command {
    SecretKey(SecretKeyArgs),
    PublicKey(PublicKeyArgs),
    DeriveKey(DeriveKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Sign(SignArgs),
    Verify(VerifyArgs),
    Complete(CompleteArgs),
}

/// Generate a new secret key.
#[derive(Debug, Parser)]
pub struct SecretKeyArgs {
    /// The output path for the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    pub output: PathBuf,

    /// The time parameter for encryption.
    #[clap(long, default_value = "128")]
    pub time: u32,

    /// The space parameter for encryption.
    #[clap(long, default_value = "1024")]
    pub space: u32,

    /// The path to read the passphrase from
    #[clap(long, value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

/// Derive a public key from a secret key.
#[derive(Debug, Parser)]
pub struct PublicKeyArgs {
    /// The path of the encrypted secret key.
    #[clap( value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    /// The ID of the generated public key.
    pub key_id: OsString,

    /// The path to read the passphrase from.
    #[clap(long,  value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

/// Derive a public key from another public key..
#[derive(Debug, Parser)]
pub struct DeriveKeyArgs {
    /// The public key.
    pub public_key: OsString,

    /// The sub ID of the generated public key.
    pub sub_key_id: OsString,
}

/// Encrypt a message for a set of recipients.
#[derive(Debug, Parser)]
pub struct EncryptArgs {
    /// The path of the encrypted secret key.
    #[clap( value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    /// The ID of the public key to use.
    pub key_id: OsString,

    /// The path to the input file or '-' for stdin.
    #[clap(
        parse(try_from_os_str = input_from_os_str),
        value_hint = ValueHint::FilePath,
    )]
    pub plaintext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(
        parse(try_from_os_str = output_from_os_str),
        value_hint = ValueHint::FilePath,
    )]
    pub ciphertext: Output,

    /// The recipient's public key.
    #[clap(required = true)]
    pub recipients: Vec<OsString>,

    /// Add fake recipients.
    #[clap(long, default_value = "0")]
    pub fakes: usize,

    /// Add random bytes of padding.
    #[clap(long, default_value = "0")]
    pub padding: u64,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

/// Decrypt and verify a message.
#[derive(Debug, Parser)]
pub struct DecryptArgs {
    /// The path of the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    /// The ID of the public key.
    pub key_id: OsString,

    /// The path to the input file or '-' for stdin.
    #[clap(
        parse(try_from_os_str = input_from_os_str),
        value_hint = ValueHint::FilePath,
    )]
    pub ciphertext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(
        parse(try_from_os_str = output_from_os_str),
        value_hint = ValueHint::FilePath,
    )]
    pub plaintext: Output,

    /// The sender's public key.
    pub sender: OsString,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

/// Sign a message.
#[derive(Debug, Parser)]
pub struct SignArgs {
    /// The path of the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    /// The ID of the public key to use.
    pub key_id: OsString,

    /// The path to the message file or '-' for stdin.
    #[clap(
        parse(try_from_os_str = input_from_os_str),
        value_hint = ValueHint::FilePath,
    )]
    pub message: Input,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

/// Verify a signature.
#[derive(Debug, Parser)]
pub struct VerifyArgs {
    /// The signer's public key.
    pub public_key: OsString,

    /// The path to the message file or '-' for stdin.
    #[clap(
      parse(try_from_os_str = input_from_os_str),
      value_hint = ValueHint::FilePath,
    )]
    pub message: Input,

    /// The signature of the message.
    pub signature: OsString,
}

/// Generate shell completion scripts.
#[derive(Debug, Parser)]
#[clap(setting = AppSettings::Hidden)]
pub struct CompleteArgs {
    /// The type of shell completion script to generate: bash, elvish, fish, powershell, or zsh.
    pub shell: Shell,

    /// Output directory for shell completion scripts.
    #[clap(value_hint = ValueHint::DirPath)]
    pub output: OsString,
}

fn input_from_os_str(path: &OsStr) -> Result<Input, String> {
    Input::new(path).map_err(|e| e.to_string())
}

fn output_from_os_str(path: &OsStr) -> Result<Output, String> {
    Output::new(path).map_err(|e| e.to_string())
}
