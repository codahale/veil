use std::{
    error::Error,
    fs::File,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process,
};

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{Shell, generate_to};
use console::Term;
use rand::rngs::OsRng;
use thiserror::Error;
use veil::{
    DecryptError, Digest, ParsePublicKeyError, ParseSignatureError, PublicKey, SecretKey, Signature,
};

fn main() {
    let opts = Opts::parse();
    if let Err(e) = match opts.cmd {
        Cmd::SecretKey(cmd) => cmd.run(),
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

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Cmd {
    SecretKey(SecretKeyArgs),
    PublicKey(PublicKeyArgs),
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
    /// The path to the encrypted secret key file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    output: PathBuf,

    /// The time cost for encryption (in 2^t iterations).
    #[arg(long, default_value = "8")]
    time_cost: u8,

    /// The memory cost for encryption (in 2^m KiB).
    #[arg(long, default_value = "8")]
    memory_cost: u8,

    /// The number of parallel tasks to use (in 2^p threads). [default: log2(NUM_CPU)]
    #[arg(long)]
    parallelism: Option<u8>,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl Runnable for SecretKeyArgs {
    fn run(self) -> Result<(), CliError> {
        let passphrase = self.passphrase_input.read_passphrase()?;
        let output = open_output(&self.output, true)?;
        let secret_key = SecretKey::random(OsRng);
        let p = (num_cpus::get().min(255) as f64).log2() as u8;
        secret_key
            .store(
                output,
                OsRng,
                &passphrase,
                self.time_cost,
                self.memory_cost,
                self.parallelism.unwrap_or(p),
            )
            .map_err(|e| CliError::WriteIo(e, self.output))?;
        Ok(())
    }
}

/// Derive a public key from a secret key.
#[derive(Debug, Parser)]
struct PublicKeyArgs {
    #[command(flatten)]
    secret_key: SecretKeyInput,

    /// The path to the public key file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, default_value = "-", value_name = "PATH")]
    output: PathBuf,
}

impl Runnable for PublicKeyArgs {
    fn run(self) -> Result<(), CliError> {
        let secret_key = self.secret_key.decrypt()?;
        let mut output = open_output(&self.output, false)?;
        let public_key = secret_key.public_key();
        write!(output, "{public_key}").map_err(|e| CliError::WriteIo(e, self.output))
    }
}

/// Encrypt a message for a set of receivers.
#[derive(Debug, Parser)]
struct EncryptArgs {
    #[command(flatten)]
    secret_key: SecretKeyInput,

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
        value_name = "PATH",
        num_args(1..),
        required = true,
        action(ArgAction::Append),
        value_hint = ValueHint::FilePath,
    )]
    receivers: Vec<PathBuf>,

    /// Add fake receivers.
    #[arg(long, value_name = "COUNT")]
    fakes: Option<usize>,
}

impl Runnable for EncryptArgs {
    fn run(self) -> Result<(), CliError> {
        let secret_key = self.secret_key.decrypt()?;
        let input = open_input(&self.input)?;
        let output = open_output(&self.output, true)?;
        let receivers =
            self.receivers.into_iter().map(open_public_key).collect::<Result<Vec<_>, _>>()?;
        secret_key.encrypt(OsRng, input, output, &receivers, self.fakes).map_err(|e| match e {
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
    secret_key: SecretKeyInput,

    /// The path to the input file or '-' for stdin.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    input: PathBuf,

    /// The path to the output file or '-' for stdout.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    output: PathBuf,

    /// The sender's public key.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    sender: PathBuf,
}

impl Runnable for DecryptArgs {
    fn run(self) -> Result<(), CliError> {
        let input = open_input(&self.input)?;
        let output = open_output(&self.output, true)?;
        let secret_key = self.secret_key.decrypt()?;
        let sender = open_public_key(self.sender)?;
        secret_key.decrypt(input, output, &sender).map_err(|e| match e {
            DecryptError::InvalidCiphertext => CliError::InvalidCiphertext,
            DecryptError::ReadIo(e) => CliError::ReadIo(e, self.input),
            DecryptError::WriteIo(e) => CliError::WriteIo(e, self.input),
            DecryptError::InvalidBlockType(b) => CliError::InvalidBlockType(b),
        })?;
        Ok(())
    }
}

/// Sign a message.
#[derive(Debug, Parser)]
struct SignArgs {
    #[command(flatten)]
    secret_key: SecretKeyInput,

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
        let secret_key = self.secret_key.decrypt()?;
        let sig = secret_key.sign(OsRng, input).map_err(|e| CliError::ReadIo(e, self.input))?;
        write!(output, "{sig}").map_err(|e| CliError::WriteIo(e, self.output))?;
        Ok(())
    }
}

/// Verify a signature.
#[derive(Debug, Parser)]
struct VerifyArgs {
    /// The signer's public key.
    #[arg(long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    signer: PathBuf,

    /// The signature of the message.
    #[arg(long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    signature: PathBuf,

    /// The path to the message file or '-' for stdin.
    #[arg(short, long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    input: PathBuf,
}

impl Runnable for VerifyArgs {
    fn run(self) -> Result<(), CliError> {
        let input = open_input(&self.input)?;
        let signer = open_public_key(self.signer)?;
        let signature = open_signature(self.signature)?;
        signer.verify(input, &signature).map_err(|e| match e {
            veil::VerifyError::InvalidSignature => CliError::BadSignature,
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
struct SecretKeyInput {
    /// The path of the encrypted secret key.
    #[arg(short = 'k', long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    secret_key: PathBuf,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl SecretKeyInput {
    fn decrypt(&self) -> Result<SecretKey, CliError> {
        let passphrase = self.passphrase_input.read_passphrase()?;
        let ciphertext = File::open(&self.secret_key)
            .map_err(|e| CliError::ReadIo(e, self.secret_key.to_path_buf()))?;
        SecretKey::load(ciphertext, &passphrase).map_err(CliError::BadPassphrase)
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

fn open_signature(path: PathBuf) -> Result<Signature, CliError> {
    let mut s = String::with_capacity(2048);
    let mut f = File::open(&path).map_err(|e| CliError::ReadIo(e, path.clone()))?;
    f.read_to_string(&mut s).map_err(|e| CliError::ReadIo(e, path.clone()))?;
    s.parse().map_err(|e| CliError::InvalidSignature(e, path.clone()))
}

fn open_public_key(path: PathBuf) -> Result<PublicKey, CliError> {
    let mut s = String::with_capacity(2048);
    let mut f = File::open(&path).map_err(|e| CliError::ReadIo(e, path.clone()))?;
    f.read_to_string(&mut s).map_err(|e| CliError::ReadIo(e, path.clone()))?;
    s.parse().map_err(|e| CliError::InvalidPublicKey(e, path.clone()))
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

    #[error("unable to decrypt secret key")]
    BadPassphrase(#[source] DecryptError),

    #[error("digest mismatch")]
    DigestMismatch,

    #[error("invalid signature at {1:?}")]
    InvalidSignature(#[source] ParseSignatureError, PathBuf),

    #[error("unable to verify signature")]
    BadSignature,

    #[error("invalid ciphertext")]
    InvalidCiphertext,

    #[error("invalid block type: {0:02x}")]
    InvalidBlockType(u8),

    #[error("invalid public key at {1:?}")]
    InvalidPublicKey(#[source] ParsePublicKeyError, PathBuf),
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
