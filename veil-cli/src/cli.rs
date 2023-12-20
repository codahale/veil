use std::{
    error::Error,
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process,
};

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{generate_to, Shell};
use console::Term;
use rand::rngs::OsRng;
use thiserror::Error;
use veil::{DecryptError, Digest, PrivateKey, PublicKey, Signature};

fn main() {
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
        e.print();
        process::exit(-1);
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

trait Runnable {
    fn run(self) -> Result<(), CliError>;
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
    fn run(self) -> Result<(), CliError> {
        let output = open_output(&self.output, true)?;
        let passphrase = self.passphrase_input.read_passphrase()?;
        let private_key = PrivateKey::random(OsRng);
        private_key
            .store(output, OsRng, &passphrase, self.time_cost, self.memory_cost)
            .map_err(|e| CliError::WriteIo(e, self.output))?;
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
    fn run(self) -> Result<(), CliError> {
        let mut output = open_output(&self.output, false)?;
        let private_key = self.private_key.decrypt()?;
        let public_key = private_key.public_key();
        write!(output, "{public_key}").map_err(|e| CliError::WriteIo(e, self.output))
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
    fn run(self) -> Result<(), CliError> {
        let input = open_input(&self.input)?;
        let output = open_output(&self.output, true)?;
        let private_key = self.private_key.decrypt()?;
        private_key
            .encrypt(OsRng, input, output, &self.receivers, self.fakes, self.padding)
            .map_err(|e| match e {
                veil::EncryptError::ReadIo(e) => CliError::ReadIo(e, self.input),
                veil::EncryptError::WriteIo(e) => CliError::WriteIo(e, self.output),
            })?;
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
    fn run(self) -> Result<(), CliError> {
        let input = open_input(&self.input)?;
        let output = open_output(&self.output, true)?;
        let private_key = self.private_key.decrypt()?;
        private_key.decrypt(input, output, &self.sender).map_err(|e| match e {
            DecryptError::InvalidCiphertext => CliError::InvalidCiphertext,
            DecryptError::ReadIo(e) => CliError::ReadIo(e, self.input),
            DecryptError::WriteIo(e) => CliError::WriteIo(e, self.input),
        })?;
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
    fn run(self) -> Result<(), CliError> {
        let input = open_input(&self.input)?;
        let mut output = open_output(&self.output, false)?;
        let private_key = self.private_key.decrypt()?;
        let sig = private_key.sign(OsRng, input).map_err(|e| CliError::ReadIo(e, self.input))?;
        write!(output, "{sig}").map_err(|e| CliError::WriteIo(e, self.output))?;
        Ok(())
    }
}

/// Verify a signature.
#[derive(Debug, Parser)]
struct VerifyArgs {
    /// The signer's public key.
    #[arg(long, value_name = "KEY")]
    signer: PublicKey,

    /// The signature of the message.
    #[arg(long, value_name = "SIG")]
    signature: Signature,

    /// The path to the message file or '-' for stdin.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    input: PathBuf,
}

impl Runnable for VerifyArgs {
    fn run(self) -> Result<(), CliError> {
        let input = open_input(&self.input)?;
        self.signer.verify(input, &self.signature).map_err(|e| match e {
            veil::VerifyError::InvalidSignature => CliError::InvalidSignature,
            veil::VerifyError::ReadIo(e) => CliError::ReadIo(e, self.input),
        })?;
        Ok(())
    }
}

/// Calculate a message digest.
#[derive(Debug, Parser)]
struct DigestArgs {
    /// Associated metadata to be included in the digest.
    #[arg(short, long)]
    metadata: Vec<String>,

    /// Compare the computed digest to a given digest.
    #[arg(long, value_name = "DIGEST", group("out"))]
    check: Option<Digest>,

    /// The path to the message file or '-' for stdin.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    input: PathBuf,

    /// The path to the digest file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = "-", value_name = "PATH", group("out"))]
    output: PathBuf,
}

impl Runnable for DigestArgs {
    fn run(self) -> Result<(), CliError> {
        let input = open_input(&self.input)?;
        let digest =
            Digest::new(&self.metadata, input).map_err(|e| CliError::ReadIo(e, self.input))?;
        if let Some(check) = self.check {
            if check != digest {
                return Err(CliError::DigestMismatch);
            }
        } else {
            write!(open_output(&self.output, false)?, "{digest}").map_err(CliError::TermIo)?;
        }
        Ok(())
    }
}

/// Generate shell completion scripts.
#[derive(Debug, Parser)]
#[command(hide(true))]
struct CompleteArgs {
    /// The type of shell completion script to generate: bash, elvish, fish, powershell, or zsh.
    #[arg(long)]
    shell: Shell,

    /// Output directory for shell completion scripts.
    #[arg(short, long, value_hint = ValueHint::DirPath)]
    output: PathBuf,
}

impl Runnable for CompleteArgs {
    fn run(self) -> Result<(), CliError> {
        let mut app = Opts::command();
        generate_to(self.shell, &mut app, "veil", &self.output)
            .map_err(|e| CliError::WriteIo(e, self.output))?;
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
    fn decrypt(&self) -> Result<PrivateKey, CliError> {
        let passphrase = self.passphrase_input.read_passphrase()?;
        let ciphertext = File::open(&self.private_key)
            .map_err(|e| CliError::ReadIo(e, self.private_key.to_path_buf()))?;
        PrivateKey::load(ciphertext, &passphrase).map_err(CliError::BadPassphrase)
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
    fn read_passphrase(&self) -> Result<Vec<u8>, CliError> {
        if cfg!(unix) {
            if let Some(fd) = self.passphrase_fd {
                return Self::read_from_fd(fd);
            }
        }

        self.prompt_for_passphrase()
    }

    #[cfg(unix)]
    fn read_from_fd(fd: i32) -> Result<Vec<u8>, CliError> {
        use std::os::unix::prelude::FromRawFd;

        let mut out = Vec::new();
        unsafe { File::from_raw_fd(fd) }
            .read_to_end(&mut out)
            .map_err(|e| CliError::FdIo(e, fd))?;
        Ok(out)
    }

    fn prompt_for_passphrase(&self) -> Result<Vec<u8>, CliError> {
        let mut term = Term::stderr();
        let _ = term.write(b"Enter passphrase: ").map_err(CliError::TermIo)?;
        let passphrase = term.read_secure_line().map_err(CliError::TermIo)?;
        if passphrase.is_empty() {
            return Err(CliError::EmptyPassphrase);
        }
        Ok(passphrase.as_bytes().to_vec())
    }
}

fn open_input(path: &Path) -> Result<Box<dyn Read>, CliError> {
    if path.as_os_str() == "-" {
        if io::stdin().is_terminal() {
            return Err(CliError::StdinTty);
        }
        Ok(Box::new(io::stdin().lock()))
    } else {
        let f = File::open(path).map_err(|e| CliError::ReadIo(e, path.to_path_buf()))?;
        Ok(Box::new(f))
    }
}

fn open_output(path: &Path, binary: bool) -> Result<Box<dyn Write>, CliError> {
    if path.as_os_str() == "-" {
        if binary && io::stdout().is_terminal() {
            return Err(CliError::StdoutTty);
        }
        Ok(Box::new(io::stdout().lock()))
    } else {
        let f = File::create(path).map_err(|e| CliError::WriteIo(e, path.to_path_buf()))?;
        Ok(Box::new(f))
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("unable to read from stdin: is a tty")]
    StdinTty,

    #[error("unable to write to stdout: is a tty")]
    StdoutTty,

    #[error("terminal io error")]
    TermIo(#[source] io::Error),

    #[error("unable to read from file descriptor {1}")]
    FdIo(#[source] io::Error, i32),

    #[error("unable to read from {1:?}")]
    ReadIo(#[source] io::Error, PathBuf),

    #[error("unable to write to {1:?}")]
    WriteIo(#[source] io::Error, PathBuf),

    #[error("no passphrase entered")]
    EmptyPassphrase,

    #[error("unable to decrypt private key")]
    BadPassphrase(#[source] DecryptError),

    #[error("digest mismatch")]
    DigestMismatch,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid ciphertext")]
    InvalidCiphertext,
}

impl CliError {
    fn print(&self) {
        bunt::eprintln!("{[red+bold]}: {}", "error", self);

        let mut source = self.source();
        while let Some(cause) = source {
            bunt::eprintln!("{[red]}: {}", "cause", cause);
            source = cause.source();
        }
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
