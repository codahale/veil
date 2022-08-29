use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::{AppSettings, IntoApp, Parser, Subcommand, ValueHint};
use clap_complete::{generate_to, Shell};
use clio::{Input, Output};
use mimalloc::MiMalloc;
use unicode_normalization::UnicodeNormalization;

use veil::{Digest, PrivateKey, PublicKey, Signature};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        Cmd::PrivateKey(cmd) => cmd.run(),
        Cmd::PublicKey(cmd) => cmd.run(),
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
    PrivateKey(PrivateKeyArgs),
    PublicKey(PublicKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Sign(SignArgs),
    Verify(VerifyArgs),
    Digest(DigestArgs),
    Complete(CompleteArgs),
}

/// Generate a new private key.
#[derive(Debug, Parser)]
struct PrivateKeyArgs {
    /// The path to the encrypted private key file or '-' for stdout.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    output: Output,

    /// The time parameter for encryption, logarithmic scale.
    #[clap(action, long, default_value = "6")]
    time: u8,

    /// The space parameter for encryption, logarithmic scale..
    #[clap(action, long, default_value = "12")]
    space: u8,

    /// The path to read the passphrase from
    #[clap(action, long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for PrivateKeyArgs {
    fn run(mut self) -> Result<()> {
        let mut rng = rand::thread_rng();
        let passphrase = prompt_passphrase(&self.passphrase_file)?;
        let private_key = PrivateKey::random(&mut rng);
        private_key.store(self.output.lock(), rng, &passphrase, self.time, self.space)?;
        Ok(())
    }
}

/// Derive a public key from a private key.
#[derive(Debug, Parser)]
struct PublicKeyArgs {
    /// The path of the encrypted private key.
    #[clap(action, value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the public key file or '-' for stdout.
    #[clap(value_parser, value_hint = ValueHint::FilePath, default_value = "-")]
    output: Output,

    /// The path to read the passphrase from.
    #[clap(action, long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for PublicKeyArgs {
    fn run(mut self) -> Result<()> {
        let private_key = decrypt_private_key(&self.passphrase_file, &self.private_key)?;
        let public_key = private_key.public_key();
        write!(self.output.lock(), "{}", public_key)?;
        Ok(())
    }
}

/// Encrypt a message for a set of receivers.
#[derive(Debug, Parser)]
struct EncryptArgs {
    /// The path of the encrypted private key.
    #[clap(action, value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the input file or '-' for stdin.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    plaintext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    ciphertext: Output,

    /// The receivers' public keys.
    #[clap(action, required = true)]
    receivers: Vec<PublicKey>,

    /// Add fake receivers.
    #[clap(action, long)]
    fakes: Option<usize>,

    /// Add random bytes of padding.
    #[clap(action, long)]
    padding: Option<usize>,

    /// The path to read the passphrase from.
    #[clap(action, long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for EncryptArgs {
    fn run(mut self) -> Result<()> {
        let private_key = decrypt_private_key(&self.passphrase_file, &self.private_key)?;
        private_key.encrypt(
            rand::thread_rng(),
            &mut self.plaintext.lock(),
            &mut self.ciphertext.lock(),
            &self.receivers,
            self.fakes,
            self.padding,
        )?;
        Ok(())
    }
}

/// Decrypt and verify a message.
#[derive(Debug, Parser)]
struct DecryptArgs {
    /// The path of the encrypted private key.
    #[clap(action, value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the input file or '-' for stdin.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    ciphertext: Input,

    /// The path to the output file or '-' for stdout.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    plaintext: Output,

    /// The sender's public key.
    #[clap(action)]
    sender: PublicKey,

    /// The path to read the passphrase from.
    #[clap(action, long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for DecryptArgs {
    fn run(mut self) -> Result<()> {
        let private_key = decrypt_private_key(&self.passphrase_file, &self.private_key)?;
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
    /// The path of the encrypted private key.
    #[clap(action, value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the message file or '-' for stdin.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    message: Input,

    /// The path to the signature file or '-' for stdout.
    #[clap(value_parser, value_hint = ValueHint::FilePath, default_value = "-")]
    output: Output,

    /// The path to read the passphrase from.
    #[clap(action, long, value_hint = ValueHint::FilePath)]
    passphrase_file: Option<PathBuf>,
}

impl Runnable for SignArgs {
    fn run(mut self) -> Result<()> {
        let private_key = decrypt_private_key(&self.passphrase_file, &self.private_key)?;
        let sig = private_key.sign(rand::thread_rng(), &mut self.message.lock())?;
        write!(self.output.lock(), "{}", sig)?;
        Ok(())
    }
}

/// Verify a signature.
#[derive(Debug, Parser)]
struct VerifyArgs {
    /// The signer's public key.
    #[clap(action)]
    public_key: PublicKey,

    /// The path to the message file or '-' for stdin.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    message: Input,

    /// The signature of the message.
    #[clap(action)]
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
    #[clap(action, long, short)]
    metadata: Vec<String>,

    /// Compare the computed digest to a given digest.
    #[clap(action, long, value_name = "DIGEST")]
    check: Option<Digest>,

    /// The path to the message file or '-' for stdin.
    #[clap(value_parser, value_hint = ValueHint::FilePath)]
    message: Input,

    /// The path to the digest file or '-' for stdout.
    #[clap(value_parser, value_hint = ValueHint::FilePath, default_value = "-")]
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
    #[clap(action)]
    shell: Shell,

    /// Output directory for shell completion scripts.
    #[clap(action, value_hint = ValueHint::DirPath)]
    output: PathBuf,
}

impl Runnable for CompleteArgs {
    fn run(self) -> Result<()> {
        let mut app = Opts::command();
        generate_to(self.shell, &mut app, "veil", &self.output)?;
        Ok(())
    }
}

fn decrypt_private_key(passphrase_file: &Option<PathBuf>, path: &Path) -> Result<PrivateKey> {
    let passphrase = prompt_passphrase(passphrase_file)?;
    let ciphertext = File::open(path)?;
    let pk = PrivateKey::load(ciphertext, &passphrase)?;
    Ok(pk)
}

fn prompt_passphrase(passphrase_file: &Option<PathBuf>) -> Result<Vec<u8>> {
    match passphrase_file {
        Some(p) => Ok(fs::read(p)?),
        None => Ok(rpassword::prompt_password("Enter passphrase: ")
            .map(|s| s.nfc().collect::<String>().as_bytes().to_vec())?),
    }
}
