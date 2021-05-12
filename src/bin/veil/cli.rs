use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use clap::{crate_description, crate_name, crate_version, AppSettings, Clap, ValueHint};
use clio::{Input, Output};

#[derive(Debug, Clap)]
#[clap(bin_name = crate_name!(), about = crate_description!(), version = crate_version!())]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::SubcommandRequired)]
#[clap(setting = AppSettings::VersionlessSubcommands)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Clap)]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
pub enum Command {
    SecretKey(SecretKeyArgs),
    PublicKey(PublicKeyArgs),
    DeriveKey(DeriveKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Sign(SignArgs),
    Verify(VerifyArgs),
}

#[derive(Debug, Clap)]
#[clap(about = "Generate a new secret key.")]
pub struct SecretKeyArgs {
    #[clap(about = "The output path for the encrypted secret key", value_hint = ValueHint::FilePath)]
    pub output: PathBuf,

    #[clap(long, about = "The time parameter for encryption", default_value = "128")]
    pub time: u32,

    #[clap(long, about = "The space parameter for encryption", default_value = "1024")]
    pub space: u32,

    #[clap(long, about = "The path to read the passphrase from", value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clap)]
#[clap(about = "Derive a public key from a secret key.")]
pub struct PublicKeyArgs {
    #[clap(about = "The path of the encrypted secret key", value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the generated public key")]
    pub key_id: OsString,

    #[clap(long, about = "The path to read the passphrase from", value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clap)]
#[clap(about = "Derive a public key from another public key.")]
pub struct DeriveKeyArgs {
    #[clap(about = "The public key")]
    pub public_key: OsString,

    #[clap(about = "The sub ID of the generated public key")]
    pub sub_key_id: OsString,
}

#[derive(Debug, Clap)]
#[clap(about = "Encrypt a message for a set of recipients.")]
pub struct EncryptArgs {
    #[clap(about = "The path of the encrypted secret key", value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the public key to use")]
    pub key_id: OsString,

    #[clap(about = "The path to the input file", parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    pub plaintext: Input,

    #[clap(about = "The path to the output file", parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath)]
    pub ciphertext: Output,

    #[clap(about = "The recipient's public key", required = true)]
    pub recipients: Vec<OsString>,

    #[clap(about = "Add fake recipients", long, default_value = "0")]
    pub fakes: usize,

    #[clap(about = "Add random bytes of padding", long, default_value = "0")]
    pub padding: u64,

    #[clap(about = "The path to read the passphrase from", long, value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clap)]
#[clap(about = "Decrypt and verify a message.")]
pub struct DecryptArgs {
    #[clap(about = "The path of the encrypted secret key", value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the public key")]
    pub key_id: OsString,

    #[clap(about = "The path to the input file", parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    pub ciphertext: Input,

    #[clap(about = "The path to the output file", parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath)]
    pub plaintext: Output,

    #[clap(about = "The sender's public key")]
    pub sender: OsString,

    #[clap(about = "The path to read the passphrase from", long, value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clap)]
#[clap(about = "Sign a message.")]
pub struct SignArgs {
    #[clap(about = "The path of the encrypted secret key", value_hint = ValueHint::FilePath)]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the public key to use")]
    pub key_id: OsString,

    #[clap(about = "The path to the message file", parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    pub message: Input,

    #[clap(about = "The path to read the passphrase from", long, value_hint = ValueHint::FilePath)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clap)]
#[clap(about = "Verify a signature.")]
pub struct VerifyArgs {
    #[clap(about = "The signer's public key")]
    pub public_key: OsString,

    #[clap(about = "The path to the message file", parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    pub message: Input,

    #[clap(about = "The signature of the message")]
    pub signature: OsString,
}

fn input_from_os_str(path: &OsStr) -> Result<Input, String> {
    Input::new(path).map_err(|e| e.to_string())
}

fn output_from_os_str(path: &OsStr) -> Result<Output, String> {
    Output::new(path).map_err(|e| e.to_string())
}
