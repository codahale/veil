use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{generate_to, Shell};
use console::Term;

use veil::{Digest, PrivateKey, PublicKey, Signature};

fn main() {
    let mut cmd = Opts::command();
    let opts = Opts::parse();
    if let Err(e) = match opts.cmd {
        Cmd::PrivateKey(cmd) => cmd.run(),
        Cmd::PublicKey(cmd) => cmd.run(),
        Cmd::Encrypt(cmd) => cmd.run(),
        Cmd::Decrypt(cmd) => cmd.run(),
        Cmd::Sign(cmd) => cmd.run(),
        Cmd::Verify(cmd) => cmd.run(),
        Cmd::Digest(cmd) => cmd.run(),
        Cmd::Complete(cmd) => cmd.run(),
    } {
        cmd.error(clap::error::ErrorKind::Io, format!("{:?}", e)).exit()
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

trait Runnable {
    fn run(self) -> Result<()>;
}

#[derive(Debug, Subcommand)]
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
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    output: PathBuf,

    /// The time cost for encryption (in 2^t iterations).
    #[arg(long, default_value = "8")]
    time_cost: u8,

    /// The memory cost for encryption (in 2^m KiB).
    #[arg(long, default_value = "8")]
    memory_cost: u8,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl Runnable for PrivateKeyArgs {
    fn run(self) -> Result<()> {
        let mut rng = rand::thread_rng();
        let output = open_output(&self.output, true)?;
        let passphrase = self.passphrase_input.read_passphrase()?;
        let private_key = PrivateKey::random(&mut rng);
        private_key
            .store(output, rng, &passphrase, self.time_cost, self.memory_cost)
            .with_context(|| format!("unable to write to {:?}", &self.output))?;
        Ok(())
    }
}

/// Derive a public key from a private key.
#[derive(Debug, Parser)]
struct PublicKeyArgs {
    #[command(flatten)]
    private_key: PrivateKeyInput,

    /// The path to the public key file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = "-", value_name = "PATH")]
    output: PathBuf,
}

impl Runnable for PublicKeyArgs {
    fn run(self) -> Result<()> {
        let mut output = open_output(&self.output, false)?;
        let private_key = self.private_key.decrypt()?;
        let public_key = private_key.public_key();
        write!(output, "{}", public_key)
            .with_context(|| format!("unable to write to {:?}", &self.output))?;
        Ok(())
    }
}

/// Encrypt a message for a set of receivers.
#[derive(Debug, Parser)]
struct EncryptArgs {
    #[command(flatten)]
    private_key: PrivateKeyInput,

    /// The path to the input file or '-' for stdin.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    input: PathBuf,

    /// The path to the output file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    output: PathBuf,

    /// The receivers' public keys.
    #[arg(
        short = 'r',
        long = "receiver",
        value_name = "KEY",
        num_args(1..),
        required = true,
        action(ArgAction::Append),
    )]
    receivers: Vec<PublicKey>,

    /// Add fake receivers.
    #[arg(long, value_name = "COUNT")]
    fakes: Option<usize>,

    /// Add random bytes of padding.
    #[arg(long, value_name = "BYTES")]
    padding: Option<usize>,
}

impl Runnable for EncryptArgs {
    fn run(self) -> Result<()> {
        let input = open_input(&self.input)?;
        let output = open_output(&self.output, true)?;
        let private_key = self.private_key.decrypt()?;
        private_key
            .encrypt(rand::thread_rng(), input, output, &self.receivers, self.fakes, self.padding)
            .with_context(|| "unable to encrypt message")?;
        Ok(())
    }
}

/// Decrypt and verify a message.
#[derive(Debug, Parser)]
struct DecryptArgs {
    #[command(flatten)]
    private_key: PrivateKeyInput,

    /// The path to the input file or '-' for stdin.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    input: PathBuf,

    /// The path to the output file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    output: PathBuf,

    /// The sender's public key.
    #[arg(short, long, value_name = "KEY")]
    sender: PublicKey,
}

impl Runnable for DecryptArgs {
    fn run(self) -> Result<()> {
        let input = open_input(&self.input)?;
        let output = open_output(&self.output, true)?;
        let private_key = self.private_key.decrypt()?;
        private_key
            .decrypt(input, output, &self.sender)
            .with_context(|| "unable to decrypt message")?;
        Ok(())
    }
}

/// Sign a message.
#[derive(Debug, Parser)]
struct SignArgs {
    #[command(flatten)]
    private_key: PrivateKeyInput,

    /// The path to the message file or '-' for stdin.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    input: PathBuf,

    /// The path to the signature file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = "-", value_name = "PATH")]
    output: PathBuf,
}

impl Runnable for SignArgs {
    fn run(self) -> Result<()> {
        let input = open_input(&self.input)?;
        let mut output = open_output(&self.output, false)?;
        let private_key = self.private_key.decrypt()?;
        let sig = private_key
            .sign(rand::thread_rng(), input)
            .with_context(|| "unable to sign message")?;
        write!(output, "{}", sig)
            .with_context(|| format!("error writing to {:?}", &self.output))?;
        Ok(())
    }
}

/// Verify a signature.
#[derive(Debug, Parser)]
struct VerifyArgs {
    /// The signer's public key.
    #[arg()]
    public_key: PublicKey,

    /// The path to the message file or '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    input: PathBuf,

    /// The signature of the message.
    #[arg()]
    signature: Signature,
}

impl Runnable for VerifyArgs {
    fn run(self) -> Result<()> {
        let input = open_input(&self.input)?;
        self.public_key
            .verify(input, &self.signature)
            .with_context(|| "unable to verify signature")?;
        Ok(())
    }
}

/// Calculate a message digest.
#[derive(Debug, Parser)]
struct DigestArgs {
    /// Associated metadata to be included in the digest.
    #[arg(long, short)]
    metadata: Vec<String>,

    /// Compare the computed digest to a given digest.
    #[arg(long, value_name = "DIGEST")]
    check: Option<Digest>,

    /// The path to the message file or '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    input: PathBuf,

    /// The path to the digest file or '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath, default_value = "-")]
    output: PathBuf,
}

impl Runnable for DigestArgs {
    fn run(self) -> Result<()> {
        let input = open_input(&self.input)?;
        let digest =
            Digest::new(&self.metadata, input).with_context(|| "unable to digest message")?;
        if let Some(check) = self.check {
            ensure!(check == digest, "digest mismatch");
        } else {
            write!(open_output(&self.output, false)?, "{}", digest)?;
        }
        Ok(())
    }
}

/// Generate shell completion scripts.
#[derive(Debug, Parser)]
#[command(hide(true))]
struct CompleteArgs {
    /// The type of shell completion script to generate: bash, elvish, fish, powershell, or zsh.
    #[arg()]
    shell: Shell,

    /// Output directory for shell completion scripts.
    #[arg(value_hint = ValueHint::DirPath)]
    output: PathBuf,
}

impl Runnable for CompleteArgs {
    fn run(self) -> Result<()> {
        let mut app = Opts::command();
        generate_to(self.shell, &mut app, "veil", &self.output)
            .with_context(|| format!("unable to write to {:?}", &self.output))?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
struct PrivateKeyInput {
    /// The path of the encrypted private key.
    #[arg(short = 'k', long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    private_key: PathBuf,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl PrivateKeyInput {
    fn decrypt(&self) -> Result<PrivateKey> {
        self.passphrase_input.decrypt_private_key(&self.private_key)
    }
}

#[derive(Debug, Parser)]
struct PassphraseInput {
    /// Read the passphrase from the given file descriptor.
    #[arg(long)]
    #[cfg(unix)]
    passphrase_fd: Option<std::os::unix::prelude::RawFd>,
}

impl PassphraseInput {
    fn read_passphrase(&self) -> Result<Vec<u8>> {
        if cfg!(unix) {
            if let Some(fd) = self.passphrase_fd {
                return Self::read_from_fd(fd);
            }
        }

        self.prompt_for_passphrase()
    }

    #[cfg(unix)]
    fn read_from_fd(fd: i32) -> Result<Vec<u8>> {
        use std::os::unix::prelude::FromRawFd;

        let mut out = Vec::new();
        unsafe { File::from_raw_fd(fd) }
            .read_to_end(&mut out)
            .with_context(|| format!("unable to read from file descriptor {}", fd))?;
        Ok(out)
    }

    fn prompt_for_passphrase(&self) -> Result<Vec<u8>> {
        let mut term = Term::stderr();
        let _ = term.write(b"Enter passphrase: ")?;
        let passphrase = term.read_secure_line()?;
        ensure!(!passphrase.is_empty(), "no passphrase entered");
        Ok(passphrase.as_bytes().to_vec())
    }

    fn decrypt_private_key(&self, path: &Path) -> Result<PrivateKey> {
        let passphrase = self.read_passphrase()?;
        let ciphertext =
            File::open(path).with_context(|| format!("unable to open file {:?}", path))?;
        PrivateKey::load(ciphertext, &passphrase).with_context(|| "unable to decrypt private key")
    }
}

fn open_input(path: &Path) -> Result<Box<dyn Read>> {
    if path.as_os_str() == "-" {
        ensure!(!atty::is(atty::Stream::Stdin), "stdin is a tty");
        Ok(Box::new(io::stdin().lock()))
    } else {
        let f = File::open(path).with_context(|| format!("unable to open file {:?}", path))?;
        Ok(Box::new(f))
    }
}

fn open_output(path: &Path, binary: bool) -> Result<Box<dyn Write>> {
    if path.as_os_str() == "-" {
        ensure!(!(binary && atty::is(atty::Stream::Stdout)), "stdout is a tty");
        Ok(Box::new(io::stdout().lock()))
    } else {
        let f = File::create(path).with_context(|| format!("unable to create file {:?}", path))?;
        Ok(Box::new(f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_validity() {
        Opts::command().debug_assert();
    }
}
