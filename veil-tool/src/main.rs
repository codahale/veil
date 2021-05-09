use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use clap::Clap;
use filedescriptor::FileDescriptor;

use cli::*;
use veil::{PublicKey, SecretKey, Signature};

mod cli;

fn main() -> Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        Command::SecretKey(mut cmd) => secret_key(&mut cmd, &opts.flags),
        Command::PublicKey(cmd) => public_key(&cmd, &opts.flags),
        Command::DeriveKey(cmd) => derive_key(&cmd),
        Command::Encrypt(mut cmd) => encrypt(&mut cmd, &opts.flags),
        Command::Decrypt(mut cmd) => decrypt(&mut cmd, &opts.flags),
        Command::Sign(mut cmd) => sign(&mut cmd, &opts.flags),
        Command::Verify(mut cmd) => verify(&mut cmd),
    }
}

fn secret_key(cmd: &mut SecretKeyCmd, flags: &GlobalFlags) -> Result<()> {
    let passphrase = prompt_passphrase(flags)?;
    let secret_key = SecretKey::new();
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    fs::write(&mut cmd.output, ciphertext)?;
    Ok(())
}

fn public_key(cmd: &PublicKeyCmd, flags: &GlobalFlags) -> Result<()> {
    let secret_key = decrypt_secret_key(flags, &cmd.secret_key)?;
    let public_key = secret_key.public_key(&cmd.key_id);
    println!("{}", public_key);
    Ok(())
}

fn derive_key(cmd: &DeriveKeyCmd) -> Result<()> {
    let root = cmd.public_key.parse::<PublicKey>()?;
    let public_key = root.derive(&cmd.sub_key_id);
    println!("{}", public_key);
    Ok(())
}

fn encrypt(cmd: &mut EncryptCmd, flags: &GlobalFlags) -> Result<()> {
    let secret_key = decrypt_secret_key(flags, &cmd.secret_key)?;
    let private_key = secret_key.private_key(&cmd.key_id);
    let pks = cmd
        .recipients
        .iter()
        .map(|s| s.parse::<PublicKey>().map_err(anyhow::Error::from))
        .collect::<Result<Vec<PublicKey>>>()?;
    private_key.encrypt(&mut cmd.plaintext, &mut cmd.ciphertext, pks, cmd.fakes, cmd.padding)?;
    Ok(())
}

fn decrypt(cmd: &mut DecryptCmd, flags: &GlobalFlags) -> Result<()> {
    let secret_key = decrypt_secret_key(flags, &cmd.secret_key)?;
    let private_key = secret_key.private_key(&cmd.key_id);
    let sender = cmd.sender.parse::<PublicKey>()?;
    private_key.decrypt(&mut cmd.ciphertext, &mut cmd.plaintext, &sender)?;
    Ok(())
}

fn sign(cmd: &mut SignCmd, flags: &GlobalFlags) -> Result<()> {
    let secret_key = decrypt_secret_key(flags, &cmd.secret_key)?;
    let private_key = secret_key.private_key(&cmd.key_id);
    let sig = private_key.sign(&mut cmd.message)?;
    println!("{}", sig);
    Ok(())
}

fn verify(cmd: &mut VerifyCmd) -> Result<()> {
    let signer = cmd.public_key.parse::<PublicKey>()?;
    let sig: Signature = cmd.signature.parse()?;
    signer.verify(&mut cmd.message, &sig)?;
    Ok(())
}

fn decrypt_secret_key(flags: &GlobalFlags, path: &Path) -> Result<SecretKey> {
    let passphrase = prompt_passphrase(flags)?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}

fn prompt_passphrase(flags: &GlobalFlags) -> Result<String> {
    match flags.passphrase_fd {
        Some(fd) => {
            let mut buffer = String::new();
            let mut input = FileDescriptor::new(fd);
            input.read_to_string(&mut buffer)?;
            Ok(buffer)
        }
        None => Ok(rpassword::read_password_from_tty(Some("Enter passphrase: "))?),
    }
}
