use std::path::PathBuf;

use std::os::raw::c_int;
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
    SecretKey {
        #[structopt(
            help = "The output path for the encrypted secret key",
            parse(from_os_str)
        )]
        output: PathBuf,
    },

    #[structopt(about = "Derive a public key from a secret key", display_order = 1)]
    PublicKey {
        #[structopt(help = "The path to the secret key", parse(from_os_str))]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the public key to generate")]
        key_id: String,
    },

    #[structopt(
        about = "Derive a public key from another public key",
        display_order = 2
    )]
    DeriveKey {
        #[structopt(help = "The public key")]
        public_key: String,

        #[structopt(help = "The ID of the public key to generate")]
        sub_key_id: String,
    },

    #[structopt(about = "Encrypt a message for a set of recipients", display_order = 3)]
    Encrypt {
        #[structopt(help = "The path to the secret key", parse(from_os_str))]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the plaintext file", parse(from_os_str))]
        plaintext: PathBuf,

        #[structopt(help = "The path to the ciphertext file", parse(from_os_str))]
        ciphertext: PathBuf,

        #[structopt(
            required = true,
            short = "r",
            long = "--recipient",
            help = "The recipients' public keys"
        )]
        recipients: Vec<String>,

        #[structopt(long = "fakes", default_value = "0", help = "Add fake recipients")]
        fakes: usize,

        #[structopt(
            long = "padding",
            default_value = "0",
            help = "Add bytes of random padding"
        )]
        padding: u64,
    },

    #[structopt(about = "Decrypt and verify a message", display_order = 4)]
    Decrypt {
        #[structopt(help = "The path to the secret key", parse(from_os_str))]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the ciphertext file", parse(from_os_str))]
        ciphertext: PathBuf,

        #[structopt(help = "The path to the plaintext file", parse(from_os_str))]
        plaintext: PathBuf,

        #[structopt(help = "The sender's public key")]
        sender: String,
    },

    #[structopt(about = "Sign a message", display_order = 5)]
    Sign {
        #[structopt(help = "The path to the secret key", parse(from_os_str))]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the message", parse(from_os_str))]
        message: PathBuf,
    },

    #[structopt(about = "Verify a signature", display_order = 6)]
    Verify {
        #[structopt(help = "The signer's public key")]
        public_key: String,

        #[structopt(help = "The path to the message", parse(from_os_str))]
        message: PathBuf,

        #[structopt(help = "The signature")]
        signature: String,
    },
}
