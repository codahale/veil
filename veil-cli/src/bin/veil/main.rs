use std::io::Read;
use std::os::raw::c_int;
use std::path::Path;
use std::{fs, io};

use anyhow::Result;
use filedescriptor::FileDescriptor;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature};

use crate::opts::{Command, Opts};

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
            let mut plaintext = plaintext;
            let mut ciphertext = ciphertext;
            encrypt(
                secret_key,
                &key_id,
                &mut plaintext,
                &mut ciphertext,
                recipients,
                fakes,
                padding,
            )
        }
        Command::Decrypt {
            secret_key,
            key_id,
            ciphertext,
            plaintext,
            sender,
        } => {
            let secret_key = open_secret_key(&secret_key, cli.passphrase_fd)?;
            let mut ciphertext = ciphertext;
            let mut plaintext = plaintext;
            decrypt(
                secret_key,
                &key_id,
                &mut ciphertext,
                &mut plaintext,
                &sender,
            )
        }
        Command::Sign {
            secret_key,
            key_id,
            message,
        } => {
            let secret_key = open_secret_key(&secret_key, cli.passphrase_fd)?;
            let mut message = message;
            sign(secret_key, &key_id, &mut message)
        }
        Command::Verify {
            public_key,
            message,
            signature,
        } => {
            let mut message = message;
            verify(&public_key, &mut message, &signature)
        }
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
