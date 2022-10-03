use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{generate_to, Shell};
use console::Term;

use veil::{Digest, PrivateKey, PublicKey, Signature};

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
    #[command(display_order(1))]
    PrivateKey(PrivateKeyArgs),
    #[command(display_order(2))]
    PublicKey(PublicKeyArgs),
    #[command(display_order(3))]
    Encrypt(EncryptArgs),
    #[command(display_order(4))]
    Decrypt(DecryptArgs),
    #[command(display_order(5))]
    Sign(SignArgs),
    #[command(display_order(6))]
    Verify(VerifyArgs),
    #[command(display_order(7))]
    Digest(DigestArgs),
    #[command(display_order(8))]
    Complete(CompleteArgs),
}

/// Generate a new private key.
#[derive(Debug, Parser)]
struct PrivateKeyArgs {
    /// The path to the encrypted private key file or '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath)]
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
        let passphrase = self.passphrase_input.read_passphrase()?;
        let private_key = PrivateKey::random(&mut rng);
        private_key.store(
            open_output(&self.output, true)?,
            rng,
            &passphrase,
            self.time_cost,
            self.memory_cost,
        )?;
        Ok(())
    }
}

/// Derive a public key from a private key.
#[derive(Debug, Parser)]
struct PublicKeyArgs {
    /// The path of the encrypted private key.
    #[arg(value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the public key file or '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath, default_value = "-")]
    output: PathBuf,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl Runnable for PublicKeyArgs {
    fn run(self) -> Result<()> {
        let private_key = self.passphrase_input.decrypt_private_key(&self.private_key)?;
        let public_key = private_key.public_key();
        write!(open_output(&self.output, false)?, "{}", public_key)?;
        Ok(())
    }
}

/// Encrypt a message for a set of receivers.
#[derive(Debug, Parser)]
struct EncryptArgs {
    /// The path of the encrypted private key.
    #[arg(value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the input file or '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    plaintext: PathBuf,

    /// The path to the output file or '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath)]
    ciphertext: PathBuf,

    /// The receivers' public keys.
    #[arg(required = true)]
    receivers: Vec<PublicKey>,

    /// Add fake receivers.
    #[arg(long)]
    fakes: Option<usize>,

    /// Add random bytes of padding.
    #[arg(long)]
    padding: Option<usize>,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl Runnable for EncryptArgs {
    fn run(self) -> Result<()> {
        let private_key = self.passphrase_input.decrypt_private_key(&self.private_key)?;
        private_key.encrypt(
            rand::thread_rng(),
            open_input(&self.plaintext)?,
            open_output(&self.ciphertext, true)?,
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
    #[arg(value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the input file or '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    ciphertext: PathBuf,

    /// The path to the output file or '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath)]
    plaintext: PathBuf,

    /// The sender's public key.
    #[arg()]
    sender: PublicKey,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl Runnable for DecryptArgs {
    fn run(self) -> Result<()> {
        let private_key = self.passphrase_input.decrypt_private_key(&self.private_key)?;
        private_key.decrypt(
            open_input(&self.ciphertext)?,
            open_output(&self.plaintext, true)?,
            &self.sender,
        )?;
        Ok(())
    }
}

/// Sign a message.
#[derive(Debug, Parser)]
struct SignArgs {
    /// The path of the encrypted private key.
    #[arg(value_hint = ValueHint::FilePath)]
    private_key: PathBuf,

    /// The path to the message file or '-' for stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    message: PathBuf,

    /// The path to the signature file or '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath, default_value = "-")]
    output: PathBuf,

    #[command(flatten)]
    passphrase_input: PassphraseInput,
}

impl Runnable for SignArgs {
    fn run(self) -> Result<()> {
        let private_key = self.passphrase_input.decrypt_private_key(&self.private_key)?;
        let sig = private_key.sign(rand::thread_rng(), open_input(&self.message)?)?;
        write!(open_output(&self.output, false)?, "{}", sig)?;
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
    message: PathBuf,

    /// The signature of the message.
    #[arg()]
    signature: Signature,
}

impl Runnable for VerifyArgs {
    fn run(self) -> Result<()> {
        self.public_key.verify(open_input(&self.message)?, &self.signature)?;
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
    message: PathBuf,

    /// The path to the digest file or '-' for stdout.
    #[arg(value_hint = ValueHint::FilePath, default_value = "-")]
    output: PathBuf,
}

impl Runnable for DigestArgs {
    fn run(self) -> Result<()> {
        let digest = Digest::new(&self.metadata, open_input(&self.message)?)?;
        if let Some(check) = self.check {
            if check == digest {
                Ok(())
            } else {
                Err(anyhow!("digest mismatch"))
            }
        } else {
            write!(open_output(&self.output, false)?, "{}", digest)?;
            Ok(())
        }
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
        generate_to(self.shell, &mut app, "veil", &self.output)?;
        Ok(())
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
        unsafe { File::from_raw_fd(fd) }.read_to_end(&mut out)?;
        Ok(out)
    }

    fn prompt_for_passphrase(&self) -> Result<Vec<u8>> {
        let mut term = Term::stderr();
        let _ = term.write(b"Enter passphrase: ")?;
        let passphrase = term.read_secure_line()?;
        if passphrase.is_empty() {
            bail!("No passphrase entered");
        }
        Ok(passphrase.as_bytes().to_vec())
    }

    fn decrypt_private_key(&self, path: &Path) -> Result<PrivateKey> {
        let passphrase = self.read_passphrase()?;
        let ciphertext = File::open(path)?;
        Ok(PrivateKey::load(ciphertext, &passphrase)?)
    }
}

fn open_input(path: &Path) -> Result<Box<dyn Read>> {
    if path.as_os_str() == "-" {
        if atty::is(atty::Stream::Stdin) {
            bail!("stdin is a tty");
        }
        Ok(Box::new(io::stdin().lock()))
    } else {
        Ok(Box::new(File::open(path)?))
    }
}

fn open_output(path: &Path, binary: bool) -> Result<Box<dyn Write>> {
    if path.as_os_str() == "-" {
        if binary && atty::is(atty::Stream::Stdout) {
            bail!("stdout is a tty");
        }
        Ok(Box::new(io::stdout().lock()))
    } else {
        Ok(Box::new(File::create(path)?))
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
