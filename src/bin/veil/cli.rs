use argh::FromArgs;
use clio::{Input, Output};

// TODO support non-UTF8 paths, blocking on https://github.com/google/argh/issues/33

#[derive(Debug, FromArgs)]
#[argh(description = "Stupid crypto tricks.")]
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
#[argh(subcommand, name = "secret-key", description = "Generate a new secret key.")]
pub struct SecretKeyArgs {
    #[argh(positional)]
    pub output: String,

    #[argh(option, default = "1<<7", description = "the time parameter for secret key encryption")]
    pub time: u32,

    #[argh(
        option,
        default = "1<<10",
        description = "the space parameter for secret key encryption"
    )]
    pub space: u32,

    #[argh(option, description = "read the passphrase from the given file")]
    pub passphrase_file: Option<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "public-key", description = "Derive a public key from a secret key.")]
pub struct PublicKeyArgs {
    #[argh(positional)]
    pub secret_key: String,

    #[argh(positional)]
    pub key_id: String,

    #[argh(option, description = "read the passphrase from the given file")]
    pub passphrase_file: Option<String>,
}

#[derive(Debug, FromArgs)]
#[argh(
    subcommand,
    name = "derive-key",
    description = "Derive a public key from another public key."
)]
pub struct DeriveKeyArgs {
    #[argh(positional)]
    pub public_key: String,

    #[argh(positional)]
    pub sub_key_id: String,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "encrypt", description = "Encrypt a message.")]
pub struct EncryptArgs {
    #[argh(positional)]
    pub secret_key: String,

    #[argh(positional)]
    pub key_id: String,

    #[argh(positional, from_str_fn(str_to_input))]
    pub plaintext: Input,

    #[argh(positional, from_str_fn(str_to_output))]
    pub ciphertext: Output,

    #[argh(positional)]
    pub recipients: Vec<String>,

    #[argh(option, default = "0", description = "number of fake recipients to add")]
    pub fakes: usize,

    #[argh(option, default = "0", description = "number of random padding bytes to add")]
    pub padding: u64,

    #[argh(option, description = "read the passphrase from the given file")]
    pub passphrase_file: Option<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "decrypt", description = "Decrypt a message.")]
pub struct DecryptArgs {
    #[argh(positional)]
    pub secret_key: String,

    #[argh(positional)]
    pub key_id: String,

    #[argh(positional, from_str_fn(str_to_input))]
    pub ciphertext: Input,

    #[argh(positional, from_str_fn(str_to_output))]
    pub plaintext: Output,

    #[argh(positional)]
    pub sender: String,

    #[argh(option, description = "read the passphrase from the given file")]
    pub passphrase_file: Option<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "sign", description = "Sign a message.")]
pub struct SignArgs {
    #[argh(positional)]
    pub secret_key: String,

    #[argh(positional)]
    pub key_id: String,

    #[argh(positional, from_str_fn(str_to_input))]
    pub message: Input,

    #[argh(option, description = "read the passphrase from the given file")]
    pub passphrase_file: Option<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "verify", description = "Verify a signature.")]
pub struct VerifyArgs {
    #[argh(positional, description = "the signer's public key")]
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
