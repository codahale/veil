use std::os::raw::c_int;
use std::path::PathBuf;

use clap::{AppSettings, Clap};
use clio::{Input, Output};

#[derive(Clap)]
#[clap(name = "veil-tool", bin_name = "veil-tool", about = "Stupid crypto tricks.")]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: Command,

    #[clap(flatten)]
    pub flags: GlobalFlags,
}

#[derive(Clap)]
pub struct GlobalFlags {
    #[clap(long, about = "The file descriptor from which the passphrase should be read")]
    pub passphrase_fd: Option<c_int>,
}

#[derive(Clap)]
pub enum Command {
    #[clap(about = "Generate a new secret key")]
    SecretKey(SecretKeyCmd),

    #[clap(about = "Derive a public key from a secret key")]
    PublicKey(PublicKeyCmd),

    #[clap(about = "Derive a public key from another public key")]
    DeriveKey(DeriveKeyCmd),

    #[clap(about = "Encrypt a message for a set of recipients")]
    Encrypt(EncryptCmd),

    #[clap(about = "Decrypt and verify a message")]
    Decrypt(DecryptCmd),

    #[clap(about = "Sign a message")]
    Sign(SignCmd),

    #[clap(about = "Verify a signature")]
    Verify(VerifyCmd),
}

#[derive(Clap)]
pub struct SecretKeyCmd {
    #[clap(about = "The output path for the encrypted secret key", parse(from_os_str))]
    pub output: PathBuf,
}

#[derive(Clap)]
pub struct PublicKeyCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the public key to generate")]
    pub key_id: String,
}

#[derive(Clap)]
pub struct DeriveKeyCmd {
    #[clap(about = "The public key")]
    pub public_key: String,

    #[clap(about = "The ID of the public key to generate")]
    pub sub_key_id: String,
}

#[derive(Clap)]
pub struct EncryptCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the private key to use")]
    pub key_id: String,

    #[clap(
    about = "The path to the plaintext file or '-' for STDIN",
    parse(try_from_str = clio::Input::new)
    )]
    pub plaintext: Input,

    #[clap(about = "The path to the ciphertext file or '-' for STDOUT", parse(try_from_str = clio::Output::new))]
    pub ciphertext: Output,

    #[clap(required = true, about = "The recipients' public keys")]
    pub recipients: Vec<String>,

    #[clap(long, default_value = "0", about = "Add fake recipients")]
    pub fakes: usize,

    #[clap(long, default_value = "0", about = "Add bytes of random padding")]
    pub padding: u64,
}

#[derive(Clap)]
pub struct DecryptCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the private key to use")]
    pub key_id: String,

    #[clap(about = "The path to the ciphertext file or '-' for STDIN", parse(try_from_str = clio::Input::new))]
    pub ciphertext: Input,

    #[clap(about = "The path to the plaintext file or '-' for STDOUT", parse(try_from_str = clio::Output::new))]
    pub plaintext: Output,

    #[clap(about = "The sender's public key")]
    pub sender: String,
}

#[derive(Clap)]
pub struct SignCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[clap(about = "The ID of the private key to use")]
    pub key_id: String,

    #[clap(about = "The path to the message or '-' for STDIN", parse(try_from_str = clio::Input::new))]
    pub message: Input,
}

#[derive(Clap)]
pub struct VerifyCmd {
    #[clap(about = "The signer's public key")]
    pub public_key: String,

    #[clap(about = "The path to the message or '-' for STDIN", parse(try_from_str = clio::Input::new))]
    pub message: Input,

    #[clap(about = "The signature")]
    pub signature: String,
}
