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
        Command::SecretKey(mut cmd) => secret_key(&mut cmd),
        Command::PublicKey(cmd) => public_key(&cmd),
        Command::DeriveKey(cmd) => derive_key(&cmd),
        Command::Encrypt(mut cmd) => encrypt(&mut cmd),
        Command::Decrypt(mut cmd) => decrypt(&mut cmd),
        Command::Sign(mut cmd) => sign(&mut cmd),
        Command::Verify(mut cmd) => verify(&mut cmd),
        Command::Complete(mut cmd) => complete(&mut cmd),
    }
}

fn secret_key(cmd: &mut SecretKeyArgs) -> Result<()> {
    let passphrase = prompt_passphrase(&cmd.passphrase_file)?;
    let secret_key = SecretKey::new();
    let ciphertext = secret_key.encrypt(&passphrase, cmd.time, cmd.space);
    fs::write(&mut cmd.output, ciphertext)?;
    Ok(())
}

fn public_key(cmd: &PublicKeyArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let public_key = secret_key.public_key(cmd.key_id.to_string_lossy().as_ref());
    println!("{}", public_key);
    Ok(())
}

fn derive_key(cmd: &DeriveKeyArgs) -> Result<()> {
    let root = cmd.public_key.to_string_lossy().as_ref().parse::<PublicKey>()?;
    let public_key = root.derive(cmd.sub_key_id.to_string_lossy().as_ref());
    println!("{}", public_key);
    Ok(())
}

fn encrypt(cmd: &mut EncryptArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let private_key = secret_key.private_key(cmd.key_id.to_string_lossy().as_ref());
    let pks = cmd
        .recipients
        .iter()
        .map(|s| s.to_string_lossy().as_ref().parse::<PublicKey>())
        .collect::<result::Result<Vec<PublicKey>, PublicKeyError>>()?;
    private_key.encrypt(
        &mut cmd.plaintext.lock(),
        &mut cmd.ciphertext.lock(),
        pks,
        cmd.fakes,
        cmd.padding,
    )?;
    Ok(())
}

fn decrypt(cmd: &mut DecryptArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let private_key = secret_key.private_key(cmd.key_id.to_string_lossy().as_ref());
    let sender = cmd.sender.to_string_lossy().parse()?;
    private_key.decrypt(&mut cmd.ciphertext.lock(), &mut cmd.plaintext.lock(), &sender)?;
    Ok(())
}

fn sign(cmd: &mut SignArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let private_key = secret_key.private_key(cmd.key_id.to_string_lossy().as_ref());
    let sig = private_key.sign(&mut cmd.message.lock())?;
    println!("{}", sig);
    Ok(())
}

fn verify(cmd: &mut VerifyArgs) -> Result<()> {
    let signer = cmd.public_key.to_string_lossy().as_ref().parse::<PublicKey>()?;
    let sig = cmd.signature.to_string_lossy().as_ref().parse::<Signature>()?;
    signer.verify(&mut cmd.message.lock(), &sig)?;
    Ok(())
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

fn complete(cmd: &mut CompleteArgs) -> Result<()> {
    let mut app: App = Opts::into_app();
    generate_to(cmd.shell, &mut app, "veil", &cmd.output)?;
    Ok(())
}

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(setting = AppSettings::SubcommandRequired)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
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

/// Derive a public key from another public key..
#[derive(Debug, Parser)]
struct DeriveKeyArgs {
    /// The public key.
    public_key: OsString,

    /// The sub ID of the generated public key.
    sub_key_id: OsString,
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

fn input_from_os_str(path: &OsStr) -> Result<Input, String> {
    Input::new(path).map_err(|e| e.to_string())
}

fn output_from_os_str(path: &OsStr) -> Result<Output, String> {
    Output::new(path).map_err(|e| e.to_string())
}
