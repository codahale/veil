use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::{fs, result};

use anyhow::Result;
use clap::{App, IntoApp, Parser};
use clap::{AppSettings, Subcommand, ValueHint};
use clap_complete::generate_to;
use clap_complete::Shell;
use clio::{Input, Output};
use mimalloc::MiMalloc;

use veil::{PublicKey, PublicKeyError, SecretKey, Signature};

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
#[clap(setting = AppSettings::SubcommandRequired)]
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
        let ciphertext = secret_key.encrypt(&passphrase, self.time, self.space);
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
    key_id: OsString,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for PublicKeyArgs {
    fn run(self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let public_key = secret_key.public_key(self.key_id.to_string_lossy().as_ref());
        println!("{}", public_key);
        Ok(())
    }
}

/// Derive a public key from another public key..
#[derive(Debug, Parser)]
struct DeriveKeyArgs {
    /// The public key.
    public_key: OsString,

    /// The sub ID of the generated public key.
    sub_key_id: OsString,
}

impl Cmd for DeriveKeyArgs {
    fn run(self) -> Result<()> {
        let root = self.public_key.to_string_lossy().as_ref().parse::<PublicKey>()?;
        let public_key = root.derive(self.sub_key_id.to_string_lossy().as_ref());
        println!("{}", public_key);
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
    key_id: OsString,

    /// The path to the input file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    plaintext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath)]
    ciphertext: Output,

    /// The recipient's public key.
    #[clap(required = true)]
    recipients: Vec<OsString>,

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
        let private_key = secret_key.private_key(self.key_id.to_string_lossy().as_ref());
        let pks = self
            .recipients
            .iter()
            .map(|s| s.to_string_lossy().as_ref().parse::<PublicKey>())
            .collect::<result::Result<Vec<PublicKey>, PublicKeyError>>()?;
        private_key.encrypt(
            &mut self.plaintext.lock(),
            &mut self.ciphertext.lock(),
            pks,
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
    key_id: OsString,

    /// The path to the input file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    ciphertext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(parse(try_from_os_str = output_from_os_str), value_hint = ValueHint::FilePath)]
    plaintext: Output,

    /// The sender's public key.
    sender: OsString,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for DecryptArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key(self.key_id.to_string_lossy().as_ref());
        let sender = self.sender.to_string_lossy().parse()?;
        private_key.decrypt(&mut self.ciphertext.lock(), &mut self.plaintext.lock(), &sender)?;
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
    key_id: OsString,

    /// The path to the message file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    message: Input,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Cmd for SignArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key(self.key_id.to_string_lossy().as_ref());
        let sig = private_key.sign(&mut self.message.lock())?;
        println!("{}", sig);
        Ok(())
    }
}

/// Verify a signature.
#[derive(Debug, Parser)]
struct VerifyArgs {
    /// The signer's public key.
    public_key: OsString,

    /// The path to the message file or '-' for stdin.
    #[clap(parse(try_from_os_str = input_from_os_str), value_hint = ValueHint::FilePath)]
    message: Input,

    /// The signature of the message.
    signature: OsString,
}

impl Cmd for VerifyArgs {
    fn run(mut self) -> Result<()> {
        let signer = self.public_key.to_string_lossy().as_ref().parse::<PublicKey>()?;
        let sig = self.signature.to_string_lossy().as_ref().parse::<Signature>()?;
        signer.verify(&mut self.message.lock(), &sig)?;
        Ok(())
    }
}

/// Generate shell completion scripts.
#[derive(Debug, Parser)]
#[clap(setting = AppSettings::Hidden)]
struct CompleteArgs {
    /// The type of shell completion script to generate: bash, elvish, fish, powershell, or zsh.
    shell: Shell,

    /// Output directory for shell completion scripts.
    #[clap(value_hint = ValueHint::DirPath)]
    output: OsString,
}

impl Cmd for CompleteArgs {
    fn run(self) -> Result<()> {
        let mut app: App = Opts::into_app();
        generate_to(self.shell, &mut app, "veil", &self.output)?;
        Ok(())
    }
}

fn decrypt_secret_key(passphrase_file: &Option<PathBuf>, path: &Path) -> Result<SecretKey> {
    let passphrase = prompt_passphrase(passphrase_file)?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(&passphrase, &ciphertext)?;
    Ok(sk)
}

fn prompt_passphrase(passphrase_file: &Option<PathBuf>) -> Result<String> {
    match passphrase_file {
        Some(p) => Ok(fs::read_to_string(p)?),
        None => Ok(rpassword::read_password_from_tty(Some("Enter passphrase: "))?),
    }
}

fn input_from_os_str(path: &OsStr) -> Result<Input, String> {
    Input::new(path).map_err(|e| e.to_string())
}

fn output_from_os_str(path: &OsStr) -> Result<Output, String> {
    Output::new(path).map_err(|e| e.to_string())
}
