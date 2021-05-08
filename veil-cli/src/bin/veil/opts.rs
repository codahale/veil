use std::os::raw::c_int;
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "veil", about = "Stupid crypto tricks.")]
pub struct Opts {
    #[structopt(subcommand)]
    pub cmd: Command,

    #[structopt(
        long = "passphrase-fd",
        help = "The file descriptor from which the passphrase should be read"
    )]
    pub passphrase_fd: Option<c_int>,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    #[structopt(about = "Generate a new secret key", display_order = 0)]
    SecretKey(SecretKeyCmd),

    #[structopt(about = "Derive a public key from a secret key", display_order = 1)]
    PublicKey(PublicKeyCmd),

    #[structopt(
        about = "Derive a public key from another public key",
        display_order = 2
    )]
    DeriveKey(DeriveKeyCmd),

    #[structopt(about = "Encrypt a message for a set of recipients", display_order = 3)]
    Encrypt(EncryptCmd),

    #[structopt(about = "Decrypt and verify a message", display_order = 4)]
    Decrypt(DecryptCmd),

    #[structopt(about = "Sign a message", display_order = 5)]
    Sign(SignCmd),

    #[structopt(about = "Verify a signature", display_order = 6)]
    Verify(VerifyCmd),
}

#[derive(Debug, StructOpt)]
pub struct SecretKeyCmd {
    #[structopt(
        help = "The output path for the encrypted secret key",
        parse(from_os_str)
    )]
    pub output: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct PublicKeyCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[structopt(help = "The ID of the public key to generate")]
    pub key_id: String,
}

#[derive(Debug, StructOpt)]
pub struct DeriveKeyCmd {
    #[structopt(help = "The public key")]
    pub public_key: String,

    #[structopt(help = "The ID of the public key to generate")]
    pub sub_key_id: String,
}

#[derive(Debug, StructOpt)]
pub struct EncryptCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[structopt(help = "The ID of the private key to use")]
    pub key_id: String,

    #[structopt(
        help = "The path to the plaintext file or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    pub plaintext: clio::Input,

    #[structopt(
        help = "The path to the ciphertext file or '-' for STDOUT",
        parse(try_from_os_str = clio::Output::try_from_os_str)
    )]
    pub ciphertext: clio::Output,

    #[structopt(required = true, help = "The recipients' public keys")]
    pub recipients: Vec<String>,

    #[structopt(long = "fakes", default_value = "0", help = "Add fake recipients")]
    pub fakes: usize,

    #[structopt(
        long = "padding",
        default_value = "0",
        help = "Add bytes of random padding"
    )]
    pub padding: u64,
}

#[derive(Debug, StructOpt)]
pub struct DecryptCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[structopt(help = "The ID of the private key to use")]
    pub key_id: String,

    #[structopt(
        help = "The path to the ciphertext file or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    pub ciphertext: clio::Input,

    #[structopt(
        help = "The path to the plaintext file or '-' for STDOUT",
        parse(try_from_os_str = clio::Output::try_from_os_str)
    )]
    pub plaintext: clio::Output,

    #[structopt(help = "The sender's public key")]
    pub sender: String,
}

#[derive(Debug, StructOpt)]
pub struct SignCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    pub secret_key: PathBuf,

    #[structopt(help = "The ID of the private key to use")]
    pub key_id: String,

    #[structopt(
        help = "The path to the message or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    pub message: clio::Input,
}

#[derive(Debug, StructOpt)]
pub struct VerifyCmd {
    #[structopt(help = "The signer's public key")]
    pub public_key: String,

    #[structopt(
        help = "The path to the message or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    pub message: clio::Input,

    #[structopt(help = "The signature")]
    pub signature: String,
}
