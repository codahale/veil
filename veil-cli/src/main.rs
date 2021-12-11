use std::path::{Path, PathBuf};
use std::{fs, result};

use anyhow::Result;
use clap::Parser;
use mimalloc::MiMalloc;

use cli::*;
use veil::{PublicKey, PublicKeyError, SecretKey, Signature};

#[deny(missing_docs)]
mod cli;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    let opts = Opts::try_parse()?;
    match opts.cmd {
        Command::SecretKey(mut cmd) => secret_key(&mut cmd),
        Command::PublicKey(cmd) => public_key(&cmd),
        Command::DeriveKey(cmd) => derive_key(&cmd),
        Command::Encrypt(mut cmd) => encrypt(&mut cmd),
        Command::Decrypt(mut cmd) => decrypt(&mut cmd),
        Command::Sign(mut cmd) => sign(&mut cmd),
        Command::Verify(mut cmd) => verify(&mut cmd),
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
