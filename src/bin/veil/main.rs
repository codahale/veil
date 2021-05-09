use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use cli::*;
use veil::{PublicKey, SecretKey, Signature, VeilError};

mod cli;

fn main() -> Result<()> {
    let opts: Opts = argh::from_env();
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
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), cmd.time, cmd.space);
    fs::write(&mut cmd.output, ciphertext)?;
    Ok(())
}

fn public_key(cmd: &PublicKeyArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let public_key = secret_key.public_key(&cmd.key_id.to_str().ok_or(VeilError::InvalidKeyId)?);
    println!("{}", public_key);
    Ok(())
}

fn derive_key(cmd: &DeriveKeyArgs) -> Result<()> {
    let root = cmd.public_key.to_str().ok_or(VeilError::InvalidPublicKey)?.parse::<PublicKey>()?;
    let public_key = root.derive(&cmd.sub_key_id.to_str().ok_or(VeilError::InvalidKeyId)?);
    println!("{}", public_key);
    Ok(())
}

fn encrypt(cmd: &mut EncryptArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let private_key = secret_key.private_key(&cmd.key_id.to_str().ok_or(VeilError::InvalidKeyId)?);
    let pks = cmd
        .recipients
        .iter()
        .map(|s| {
            s.to_str()
                .ok_or(VeilError::InvalidPublicKey)?
                .parse::<PublicKey>()
                .map_err(anyhow::Error::from)
        })
        .collect::<Result<Vec<PublicKey>>>()?;
    private_key.encrypt(&mut cmd.plaintext, &mut cmd.ciphertext, pks, cmd.fakes, cmd.padding)?;
    Ok(())
}

fn decrypt(cmd: &mut DecryptArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let private_key = secret_key.private_key(&cmd.key_id.to_str().ok_or(VeilError::InvalidKeyId)?);
    let sender = cmd.sender.to_str().ok_or(VeilError::InvalidPublicKey)?.parse::<PublicKey>()?;
    private_key.decrypt(&mut cmd.ciphertext, &mut cmd.plaintext, &sender)?;
    Ok(())
}

fn sign(cmd: &mut SignArgs) -> Result<()> {
    let secret_key = decrypt_secret_key(&cmd.passphrase_file, &cmd.secret_key)?;
    let private_key = secret_key.private_key(&cmd.key_id.to_str().ok_or(VeilError::InvalidKeyId)?);
    let sig = private_key.sign(&mut cmd.message)?;
    println!("{}", sig);
    Ok(())
}

fn verify(cmd: &mut VerifyArgs) -> Result<()> {
    let signer =
        cmd.public_key.to_str().ok_or(VeilError::InvalidPublicKey)?.parse::<PublicKey>()?;
    let sig: Signature = cmd.signature.to_str().ok_or(VeilError::InvalidSignature)?.parse()?;
    signer.verify(&mut cmd.message, &sig)?;
    Ok(())
}

fn decrypt_secret_key(passphrase_file: &Option<PathBuf>, path: &Path) -> Result<SecretKey> {
    let passphrase = prompt_passphrase(passphrase_file)?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}

fn prompt_passphrase(passphrase_file: &Option<PathBuf>) -> Result<String> {
    match passphrase_file {
        Some(p) => Ok(fs::read_to_string(p)?),
        None => Ok(rpassword::read_password_from_tty(Some("Enter passphrase: "))?),
    }
}
