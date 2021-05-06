use std::io::Write;
use std::path::Path;
use std::{fs, io, mem};

use anyhow::Result;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature};

use crate::cli::{Command, Opts};

mod cli;

fn main() -> Result<()> {
    let cli = Opts::from_args();
    match cli.cmd {
        Command::SecretKey { output } => secret_key(&output),
        Command::PublicKey { secret_key, key_id } => public_key(&secret_key, &key_id),
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
        } => encrypt(
            &secret_key,
            &key_id,
            &plaintext,
            &ciphertext,
            recipients,
            fakes,
            padding,
        ),
        Command::Decrypt {
            secret_key,
            key_id,
            ciphertext,
            plaintext,
            sender,
        } => decrypt(&secret_key, &key_id, &ciphertext, &plaintext, &sender),
        Command::Sign {
            secret_key,
            key_id,
            message,
        } => sign(&secret_key, &key_id, &message),
        Command::Verify {
            public_key,
            message,
            signature,
        } => verify(&public_key, &message, &signature),
    }
}

fn secret_key(output_path: &Path) -> Result<()> {
    let secret_key = SecretKey::new();
    let mut f = open_output(output_path)?;
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    f.write_all(&ciphertext)?;
    Ok(())
}

fn public_key(secret_key_path: &Path, key_id: &str) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let public_key = secret_key.public_key(key_id);
    println!("{}", public_key);
    Ok(())
}

fn derive_key(public_key_ascii: &str, key_id: &str) -> Result<()> {
    let root = public_key_ascii.parse::<PublicKey>()?;
    let public_key = root.derive(key_id);
    println!("{}", public_key);
    Ok(())
}

fn encrypt(
    secret_key_path: &Path,
    key_id: &str,
    plaintext_path: &Path,
    ciphertext_path: &Path,
    recipients: Vec<String>,
    fakes: usize,
    padding: u64,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut plaintext = open_input(plaintext_path)?;
    let mut ciphertext = open_output(ciphertext_path)?;
    let pks = recipients
        .into_iter()
        .map(|s| s.parse::<PublicKey>().map_err(anyhow::Error::from))
        .collect::<Result<Vec<PublicKey>>>()?;

    private_key.encrypt(&mut plaintext, &mut ciphertext, pks, fakes, padding)?;

    Ok(())
}

fn decrypt(
    secret_key_path: &Path,
    key_id: &str,
    ciphertext_path: &Path,
    plaintext_path: &Path,
    sender_ascii: &str,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let sender = sender_ascii.parse::<PublicKey>()?;
    let mut ciphertext = open_input(ciphertext_path)?;
    let mut plaintext = open_output(plaintext_path)?;

    if let Err(e) = private_key.decrypt(&mut ciphertext, &mut plaintext, &sender) {
        if plaintext_path != Path::new("-") {
            mem::drop(plaintext);
            fs::remove_file(plaintext_path)?;
        }
        return Err(anyhow::Error::from(e));
    }

    Ok(())
}

fn sign(secret_key_path: &Path, key_id: &str, message_path: &Path) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut message = open_input(message_path)?;

    let sig = private_key.sign(&mut message)?;
    println!("{}", sig);

    Ok(())
}

fn verify(signer_ascii: &str, message_path: &Path, signature_ascii: &str) -> Result<()> {
    let signer = signer_ascii.parse::<PublicKey>()?;
    let sig: Signature = signature_ascii.parse()?;
    let mut message = open_input(message_path)?;
    signer.verify(&mut message, &sig)?;
    Ok(())
}

fn open_input(path: &Path) -> Result<Box<dyn io::Read>> {
    Ok(if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(path)?)
    })
}

fn open_output(path: &Path) -> Result<Box<dyn io::Write>> {
    Ok(if path == Path::new("-") {
        Box::new(io::stdout())
    } else {
        Box::new(fs::File::create(path)?)
    })
}

fn open_secret_key(path: &Path) -> Result<SecretKey> {
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}
