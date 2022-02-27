use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::{AppSettings, Command, IntoApp, Parser, Subcommand, ValueHint};
use clap_complete::{generate_to, Shell};
use clio::{Input, Output};
use mimalloc::MiMalloc;

use veil::{Digest, PublicKey, SecretKey, Signature};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    match opts.cmd {
        Cmd::SecretKey(cmd) => cmd.run(),
        Cmd::PublicKey(cmd) => cmd.run(),
        Cmd::DeriveKey(cmd) => cmd.run(),
        Cmd::Encrypt(cmd) => cmd.run(),
        Cmd::Decrypt(cmd) => cmd.run(),
        Cmd::Sign(cmd) => cmd.run(),
        Cmd::Verify(cmd) => cmd.run(),
        Cmd::Digest(cmd) => cmd.run(),
        Cmd::Complete(cmd) => cmd.run(),
    }
}

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(subcommand_required(true))]
struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

trait Runnable {
    fn run(self) -> Result<()>;
}

#[derive(Debug, Subcommand)]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
enum Cmd {
    SecretKey(SecretKeyArgs),
    PublicKey(PublicKeyArgs),
    DeriveKey(DeriveKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Sign(SignArgs),
    Verify(VerifyArgs),
    Digest(DigestArgs),
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

impl Runnable for SecretKeyArgs {
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

    /// Derive a sub-key using the given key path.
    #[clap(long, short, multiple_values(true))]
    key_path: Vec<String>,

    /// The path to the public key file or '-' for stdout.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath, default_value = "-")]
    output: Output,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for PublicKeyArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let public_key = secret_key.public_key().derive(&self.key_path);
        write!(self.output.lock(), "{}", public_key)?;
        Ok(())
    }
}

/// Derive a public key from another public key.
#[derive(Debug, Parser)]
struct DeriveKeyArgs {
    /// The public key.
    public_key: PublicKey,

    /// Derive a sub-key using the given key path.
    #[clap(long, short, multiple_values(true), required(true))]
    key_path: Vec<String>,

    /// The path to the public key file or '-' for stdout.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath, default_value = "-")]
    output: Output,
}

impl Runnable for DeriveKeyArgs {
    fn run(mut self) -> Result<()> {
        let public_key = self.public_key.derive(&self.key_path);
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

    /// Derive a sub-key using the given key path.
    #[clap(long, short, multiple_values(true))]
    key_path: Vec<String>,

    /// The path to the input file or '-' for stdin.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath)]
    plaintext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath)]
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

impl Runnable for EncryptArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key().derive(&self.key_path);
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

    /// Derive a sub-key using the given key path.
    #[clap(long, short, multiple_values(true))]
    key_path: Vec<String>,

    /// The path to the input file or '-' for stdin.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath)]
    ciphertext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath)]
    plaintext: Output,

    /// The sender's public key.
    sender: PublicKey,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for DecryptArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key().derive(&self.key_path);
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

    /// Derive a sub-key using the given key path.
    #[clap(long, short, multiple_values(true))]
    key_path: Vec<String>,

    /// The path to the message file or '-' for stdin.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath)]
    message: Input,

    /// The path to the signature file or '-' for stdout.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath, default_value = "-")]
    output: Output,

    /// The path to read the passphrase from.
    #[clap(long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for SignArgs {
    fn run(mut self) -> Result<()> {
        let secret_key = decrypt_secret_key(&self.passphrase_file, &self.secret_key)?;
        let private_key = secret_key.private_key().derive(&self.key_path);
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
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath)]
    message: Input,

    /// The signature of the message.
    signature: Signature,
}

impl Runnable for VerifyArgs {
    fn run(mut self) -> Result<()> {
        self.public_key.verify(&mut self.message.lock(), &self.signature)?;
        Ok(())
    }
}

/// Calculate a message digest.
#[derive(Debug, Parser)]
struct DigestArgs {
    /// Associated metadata to be included in the digest.
    #[clap(long, short)]
    metadata: Vec<String>,

    /// Compare the computed digest to a given digest.
    #[clap(long, value_name = "DIGEST")]
    check: Option<Digest>,

    /// The path to the message file or '-' for stdin.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath)]
    message: Input,

    /// The path to the digest file or '-' for stdout.
    #[clap(parse(try_from_os_str = TryFrom::try_from), value_hint = ValueHint::FilePath, default_value = "-")]
    output: Output,
}

impl Runnable for DigestArgs {
    fn run(mut self) -> Result<()> {
        let digest = Digest::new(&self.metadata, &mut self.message.lock())?;
        if let Some(check) = self.check {
            if check == digest {
                Ok(())
            } else {
                Err(anyhow!("digest mismatch"))
            }
        } else {
            write!(self.output.lock(), "{}", digest)?;
            Ok(())
        }
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

impl Runnable for CompleteArgs {
    fn run(self) -> Result<()> {
        let mut app: Command = Opts::command();
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
