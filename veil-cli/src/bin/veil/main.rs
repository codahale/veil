use std::io::Read;
use std::os::raw::c_int;
use std::path::Path;
use std::{fs, io};

use anyhow::Result;
use filedescriptor::FileDescriptor;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature};

use crate::opts::{Command, Input, Opts, Output};

mod opts;

fn main() -> Result<()> {
    let cli = Opts::from_args();
    match cli.cmd {
        Command::SecretKey { output } => secret_key(&mut fs::File::create(output)?),
        Command::PublicKey { secret_key, key_id } => {
            let secret_key = open_secret_key(&secret_key, cli.passphrase_fd)?;
            public_key(secret_key, &key_id)
        }
        Command::DeriveKey {
            public_key,
            sub_key_id,
        } => derive_key(&public_key, &sub_key_id),
        Command::Encrypt {
            secret_key,
            key_id,
            plaintext,
            ciphertext,
            recipients,
            fakes,
            padding,
        } => {
            let secret_key = open_secret_key(&secret_key, cli.passphrase_fd)?;
            match (plaintext, ciphertext) {
                (Input::StdIn, Output::StdOut) => encrypt(
                    secret_key,
                    &key_id,
                    &mut io::stdin(),
                    &mut io::stdout(),
                    recipients,
                    fakes,
                    padding,
                ),
                (Input::Path(input), Output::StdOut) => encrypt(
                    secret_key,
                    &key_id,
                    &mut fs::File::open(input)?,
                    &mut io::stdout(),
                    recipients,
                    fakes,
                    padding,
                ),
                (Input::StdIn, Output::Path(output)) => encrypt(
                    secret_key,
                    &key_id,
                    &mut io::stdin(),
                    &mut fs::File::create(output)?,
                    recipients,
                    fakes,
                    padding,
                ),
                (Input::Path(input), Output::Path(output)) => encrypt(
                    secret_key,
                    &key_id,
                    &mut fs::File::open(input)?,
                    &mut fs::File::create(output)?,
                    recipients,
                    fakes,
                    padding,
                ),
            }
        }
        Command::Decrypt {
            secret_key,
            key_id,
            ciphertext,
            plaintext,
            sender,
        } => {
            let secret_key = open_secret_key(&secret_key, cli.passphrase_fd)?;
            match (ciphertext, plaintext) {
                (Input::StdIn, Output::StdOut) => decrypt(
                    secret_key,
                    &key_id,
                    &mut io::stdin(),
                    &mut io::stdout(),
                    &sender,
                ),
                (Input::Path(input), Output::StdOut) => decrypt(
                    secret_key,
                    &key_id,
                    &mut fs::File::open(input)?,
                    &mut io::stdout(),
                    &sender,
                ),
                (Input::StdIn, Output::Path(output)) => decrypt(
                    secret_key,
                    &key_id,
                    &mut io::stdin(),
                    &mut fs::File::create(output)?,
                    &sender,
                ),
                (Input::Path(input), Output::Path(output)) => decrypt(
                    secret_key,
                    &key_id,
                    &mut fs::File::open(input)?,
                    &mut fs::File::create(output)?,
                    &sender,
                ),
            }
        }
        Command::Sign {
            secret_key,
            key_id,
            message,
        } => {
            let secret_key = open_secret_key(&secret_key, cli.passphrase_fd)?;
            match message {
                Input::StdIn => sign(secret_key, &key_id, &mut io::stdin()),
                Input::Path(p) => sign(secret_key, &key_id, &mut fs::File::open(p)?),
            }
        }
        Command::Verify {
            public_key,
            message,
            signature,
        } => match message {
            Input::StdIn => verify(&public_key, &mut io::stdin(), &signature),
            Input::Path(p) => verify(&public_key, &mut fs::File::open(p)?, &signature),
        },
    }
}

fn secret_key<W>(output: &mut W) -> Result<()>
where
    W: io::Write,
{
    let secret_key = SecretKey::new();
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    output.write_all(&ciphertext)?;
    Ok(())
}

fn public_key(secret_key: SecretKey, key_id: &str) -> Result<()> {
    let public_key = secret_key.public_key(key_id);
    println!("{}", public_key);
    Ok(())
}

fn derive_key(public_key: &str, key_id: &str) -> Result<()> {
    let root = public_key.parse::<PublicKey>()?;
    let public_key = root.derive(key_id);
    println!("{}", public_key);
    Ok(())
}

fn encrypt<R, W>(
    secret_key: SecretKey,
    key_id: &str,
    plaintext: &mut R,
    ciphertext: &mut W,
    recipients: Vec<String>,
    fakes: usize,
    padding: u64,
) -> Result<()>
where
    R: io::Read,
    W: io::Write,
{
    let private_key = secret_key.private_key(key_id);
    let pks = recipients
        .into_iter()
        .map(|s| s.parse::<PublicKey>().map_err(anyhow::Error::from))
        .collect::<Result<Vec<PublicKey>>>()?;

    private_key.encrypt(plaintext, ciphertext, pks, fakes, padding)?;

    Ok(())
}

fn decrypt<R, W>(
    secret_key: SecretKey,
    key_id: &str,
    ciphertext: &mut R,
    plaintext: &mut W,
    sender_ascii: &str,
) -> Result<()>
where
    R: io::Read,
    W: io::Write,
{
    let private_key = secret_key.private_key(key_id);
    let sender = sender_ascii.parse::<PublicKey>()?;
    private_key.decrypt(ciphertext, plaintext, &sender)?;
    Ok(())
}

fn sign<R>(secret_key: SecretKey, key_id: &str, message: &mut R) -> Result<()>
where
    R: io::Read,
{
    let private_key = secret_key.private_key(key_id);
    let sig = private_key.sign(message)?;
    println!("{}", sig);
    Ok(())
}

fn verify<R>(signer: &str, message: &mut R, signature: &str) -> Result<()>
where
    R: io::Read,
{
    let signer = signer.parse::<PublicKey>()?;
    let sig: Signature = signature.parse()?;
    signer.verify(message, &sig)?;
    Ok(())
}

fn open_secret_key(path: &Path, passphrase_fd: Option<c_int>) -> Result<SecretKey> {
    let passphrase = match passphrase_fd {
        Some(fd) => {
            let mut buffer = String::new();
            let mut input = FileDescriptor::new(fd);
            input.read_to_string(&mut buffer)?;
            buffer
        }
        None => rpassword::read_password_from_tty(Some("Enter passphrase: "))?,
    };
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}
