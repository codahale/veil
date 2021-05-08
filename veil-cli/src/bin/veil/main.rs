use std::fs;
use std::io::Read;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};

use anyhow::Result;
use filedescriptor::FileDescriptor;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature};

fn main() -> Result<()> {
    let cli = Opts::from_args();
    match cli.cmd {
        Command::SecretKey(mut cmd) => cmd.run(cli.passphrase_fd),
        Command::PublicKey(mut cmd) => cmd.run(cli.passphrase_fd),
        Command::DeriveKey(mut cmd) => cmd.run(None),
        Command::Encrypt(mut cmd) => cmd.run(cli.passphrase_fd),
        Command::Decrypt(mut cmd) => cmd.run(cli.passphrase_fd),
        Command::Sign(mut cmd) => cmd.run(cli.passphrase_fd),
        Command::Verify(mut cmd) => cmd.run(None),
    }
}

trait Cmd {
    fn run(&mut self, fd: Option<c_int>) -> Result<()>;
}

#[derive(StructOpt, Debug)]
#[structopt(name = "veil", about = "Stupid crypto tricks.")]
struct Opts {
    #[structopt(subcommand)]
    cmd: Command,

    #[structopt(
        long = "passphrase-fd",
        help = "The file descriptor from which the passphrase should be read"
    )]
    passphrase_fd: Option<c_int>,
}

#[derive(StructOpt, Debug)]
enum Command {
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
struct SecretKeyCmd {
    #[structopt(
        help = "The output path for the encrypted secret key",
        parse(from_os_str)
    )]
    output: PathBuf,
}

impl Cmd for SecretKeyCmd {
    fn run(&mut self, fd: Option<c_int>) -> Result<()> {
        let secret_key = SecretKey::new();
        let passphrase = read_passphrase(fd)?;
        let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
        fs::write(&mut self.output, ciphertext).map_err(anyhow::Error::from)
    }
}

#[derive(Debug, StructOpt)]
struct PublicKeyCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[structopt(help = "The ID of the public key to generate")]
    key_id: String,
}

impl Cmd for PublicKeyCmd {
    fn run(&mut self, fd: Option<c_int>) -> Result<()> {
        let secret_key = open_secret_key(&self.secret_key, fd)?;
        let public_key = secret_key.public_key(&self.key_id);
        println!("{}", public_key);
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
struct DeriveKeyCmd {
    #[structopt(help = "The public key")]
    public_key: String,

    #[structopt(help = "The ID of the public key to generate")]
    sub_key_id: String,
}

impl Cmd for DeriveKeyCmd {
    fn run(&mut self, _fd: Option<c_int>) -> Result<()> {
        let root = self.public_key.parse::<PublicKey>()?;
        let public_key = root.derive(&self.sub_key_id);
        println!("{}", public_key);
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
struct EncryptCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[structopt(help = "The ID of the private key to use")]
    key_id: String,

    #[structopt(
        help = "The path to the plaintext file or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    plaintext: clio::Input,

    #[structopt(
        help = "The path to the ciphertext file or '-' for STDOUT",
        parse(try_from_os_str = clio::Output::try_from_os_str)
    )]
    ciphertext: clio::Output,

    #[structopt(required = true, help = "The recipients' public keys")]
    recipients: Vec<String>,

    #[structopt(long = "fakes", default_value = "0", help = "Add fake recipients")]
    fakes: usize,

    #[structopt(
        long = "padding",
        default_value = "0",
        help = "Add bytes of random padding"
    )]
    padding: u64,
}

impl Cmd for EncryptCmd {
    fn run(&mut self, fd: Option<c_int>) -> Result<()> {
        let secret_key = open_secret_key(&self.secret_key, fd)?;
        let private_key = secret_key.private_key(&self.key_id);
        let pks = self
            .recipients
            .iter()
            .map(|s| s.parse::<PublicKey>().map_err(anyhow::Error::from))
            .collect::<Result<Vec<PublicKey>>>()?;
        private_key.encrypt(
            &mut self.plaintext,
            &mut self.ciphertext,
            pks,
            self.fakes,
            self.padding,
        )?;
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
pub struct DecryptCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[structopt(help = "The ID of the private key to use")]
    key_id: String,

    #[structopt(
        help = "The path to the ciphertext file or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    ciphertext: clio::Input,

    #[structopt(
        help = "The path to the plaintext file or '-' for STDOUT",
        parse(try_from_os_str = clio::Output::try_from_os_str)
    )]
    plaintext: clio::Output,

    #[structopt(help = "The sender's public key")]
    sender: String,
}

impl Cmd for DecryptCmd {
    fn run(&mut self, fd: Option<c_int>) -> Result<()> {
        let secret_key = open_secret_key(&self.secret_key, fd)?;
        let private_key = secret_key.private_key(&self.key_id);
        let sender = self.sender.parse::<PublicKey>()?;
        private_key.decrypt(&mut self.ciphertext, &mut self.plaintext, &sender)?;
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
struct SignCmd {
    #[structopt(help = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[structopt(help = "The ID of the private key to use")]
    key_id: String,

    #[structopt(
        help = "The path to the message or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    message: clio::Input,
}

impl Cmd for SignCmd {
    fn run(&mut self, fd: Option<c_int>) -> Result<()> {
        let secret_key = open_secret_key(&self.secret_key, fd)?;
        let private_key = secret_key.private_key(&self.key_id);
        let sig = private_key.sign(&mut self.message)?;
        println!("{}", sig);
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
struct VerifyCmd {
    #[structopt(help = "The signer's public key")]
    public_key: String,

    #[structopt(
        help = "The path to the message or '-' for STDIN",
        parse(try_from_os_str = clio::Input::try_from_os_str)
    )]
    message: clio::Input,

    #[structopt(help = "The signature")]
    signature: String,
}

impl Cmd for VerifyCmd {
    fn run(&mut self, _fd: Option<c_int>) -> Result<()> {
        let signer = self.public_key.parse::<PublicKey>()?;
        let sig: Signature = self.signature.parse()?;
        signer.verify(&mut self.message, &sig)?;
        Ok(())
    }
}

fn open_secret_key(path: &Path, passphrase_fd: Option<c_int>) -> Result<SecretKey> {
    let passphrase = read_passphrase(passphrase_fd)?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}

fn read_passphrase(passphrase_fd: Option<i32>) -> Result<String> {
    match passphrase_fd {
        Some(fd) => {
            let mut buffer = String::new();
            let mut input = FileDescriptor::new(fd);
            input.read_to_string(&mut buffer)?;
            Ok(buffer)
        }
        None => Ok(rpassword::read_password_from_tty(Some(
            "Enter passphrase: ",
        ))?),
    }
}
