use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{AppSettings, Subcommand, ValueHint};
use clap::{Command as ClapCommand, IntoApp, Parser};
use clap_complete::generate_to;
use clap_complete::Shell;
use clio::{Input, Output};
use mimalloc::MiMalloc;
use secrecy::{ExposeSecret, Secret};

use veil::{PublicKey, SecretKey, Signature};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    match opts.cmd {
        Command::SecretKey(cmd) => cmd.run(),
        Command::PublicKey(cmd) => cmd.run(),
        Command::DeriveKey(cmd) => cmd.run(),
        Command::Encrypt(cmd) => cmd.run(),
        Command::Decrypt(cmd) => cmd.run(),
        Command::Sign(cmd) => cmd.run(),
        Command::Verify(cmd) => cmd.run(),
        Command::Complete(cmd) => cmd.run(),
    }
}

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(subcommand_required(true))]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

trait Cmd {
    fn run(self) -> Result<()>;
}

#[derive(Debug, Subcommand)]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
enum Command {
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
struct SecretKeyArgs {
    /// The output path for the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    output: PathBuf,

    /// The time parameter for encryption.
    #[clap(long, default_value = "128")]
    time: u32,

    /// The space parameter for encryption.
    #[clap(long, default_value = "1024")]
    space: u32,

    /// The path to read the passphrase from
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for SecretKeyArgs {
    fn run(self) -> Result<()> {
        let passphrase = prompt_passphrase(&self.passphrase_file)?;
        let secret_key = SecretKey::new();
        let ciphertext = secret_key.encrypt(passphrase.expose_secret(), self.time, self.space);
        fs::write(self.output, ciphertext)?;
        Ok(())
    }
}

/// Derive a public key from a secret key.
#[derive(Debug, Parser)]
struct PublicKeyArgs {
    /// The path of the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    secret_key: PathBuf,

    /// The ID of the generated public key.
    key_id: String,

    /// The path to the public key file or '-' for stdout.
    #[clap(parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath, default_value="-")]
    output: Output,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for PublicKeyArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let public_key = secret_key.public_key(&self.key_id);
        write!(self.output.lock(), "{}", public_key)?;
        Ok(())
    }
}

/// Derive a public key from another public key.
#[derive(Debug, Parser)]
struct DeriveKeyArgs {
    /// The public key.
    public_key: PublicKey,

    /// The sub ID of the generated public key.
    sub_key_id: String,

    /// The path to the public key file or '-' for stdout.
    #[clap(parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath, default_value="-")]
    output: Output,
}

impl Cmd for DeriveKeyArgs {
    fn run(mut self) -> Result<()> {
        let public_key = self.public_key.derive(&self.sub_key_id);
        write!(self.output.lock(), "{}", public_key)?;
        Ok(())
    }
}

/// Encrypt a message for a set of recipients.
#[derive(Debug, Parser)]
struct EncryptArgs {
    /// The path of the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    secret_key: PathBuf,

    /// The ID of the public key to use.
    key_id: String,

    /// The path to the input file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    plaintext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath)]
    ciphertext: Output,

    /// The recipient's public key.
    #[clap(required = true)]
    recipients: Vec<PublicKey>,

    /// Add fake recipients.
    #[clap(long, default_value = "0")]
    fakes: usize,

    /// Add random bytes of padding.
    #[clap(long, default_value = "0")]
    padding: u64,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for EncryptArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key(&self.key_id);
        private_key.encrypt(
            &mut self.plaintext.lock(),
            &mut self.ciphertext.lock(),
            &self.recipients,
            self.fakes,
            self.padding,
        )?;
        Ok(())
    }
}

/// Decrypt and verify a message.
#[derive(Debug, Parser)]
struct DecryptArgs {
    /// The path of the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    secret_key: PathBuf,

    /// The ID of the public key.
    key_id: String,

    /// The path to the input file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    ciphertext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath)]
    plaintext: Output,

    /// The sender's public key.
    sender: PublicKey,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for DecryptArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key(&self.key_id);
        private_key.decrypt(
            &mut self.ciphertext.lock(),
            &mut self.plaintext.lock(),
            &self.sender,
        )?;
        Ok(())
    }
}

/// Sign a message.
#[derive(Debug, Parser)]
struct SignArgs {
    /// The path of the encrypted secret key.
    #[clap(value_hint = ValueHint::FilePath)]
    secret_key: PathBuf,

    /// The ID of the public key to use.
    key_id: String,

    /// The path to the message file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    message: Input,

    /// The path to the signature file or '-' for stdout.
    #[clap(parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath, default_value="-")]
    output: Output,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for SignArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key(&self.key_id);
        let sig = private_key.sign(&mut self.message.lock())?;
        write!(self.output.lock(), "{}", sig)?;
        Ok(())
    }
}

/// Verify a signature.
#[derive(Debug, Parser)]
struct VerifyArgs {
    /// The signer's public key.
    public_key: PublicKey,

    /// The path to the message file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    message: Input,

    /// The signature of the message.
    signature: Signature,
}

impl Cmd for VerifyArgs {
    fn run(mut self) -> Result<()> {
        self.public_key.verify(&mut self.message.lock(), &self.signature)?;
        Ok(())
    }
}

/// Generate shell completion scripts.
#[derive(Debug, Parser)]
#[clap(hide(true))]
struct CompleteArgs {
    /// The type of shell completion script to generate: bash, elvish, fish, powershell, or zsh.
    shell: Shell,

    /// Output directory for shell completion scripts.
    #[clap(value_hint = ValueHint::DirPath)]
    output: PathBuf,
}

impl Cmd for CompleteArgs {
    fn run(self) -> Result<()> {
        let mut app: ClapCommand = Opts::command();
        generate_to(self.shell, &mut app, "veil", &self.output)?;
        Ok(())
    }
}

fn decrypt_secret_key(passphrase_file: &Option<PathBuf>, path: &Path) -> Result<SecretKey> {
    let passphrase = prompt_passphrase(passphrase_file)?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.expose_secret(), &ciphertext)?;
    Ok(sk)
}

fn prompt_passphrase(passphrase_file: &Option<PathBuf>) -> Result<Secret<String>> {
    match passphrase_file {
        Some(p) => Ok(fs::read_to_string(p)?.into()),
        None => Ok(rpassword::read_password_from_tty(Some("Enter passphrase: "))?.into()),
    }
}

fn input_from_os_str(path: &OsStr) -> Result<Input, String> {
    Input::new(path).map_err(|e| e.to_string())
}

fn output_from_os_str(path: &OsStr) -> Result<Output, String> {
    Output::new(path).map_err(|e| e.to_string())
}
