use std::fs;
use std::io::Read;
use std::os::raw::c_int;
use std::path::Path;

use anyhow::Result;
use filedescriptor::FileDescriptor;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature};

use crate::opts::{
    Command, DecryptCmd, DeriveKeyCmd, EncryptCmd, Opts, PublicKeyCmd, SecretKeyCmd, SignCmd,
    VerifyCmd,
};

mod opts;

fn main() -> Result<()> {
    let cli = Opts::from_args();
    match cli.cmd {
        Command::SecretKey(cmd) => secret_key(cmd),
        Command::PublicKey(cmd) => public_key(cmd, cli.passphrase_fd),
        Command::DeriveKey(cmd) => derive_key(cmd),
        Command::Encrypt(mut cmd) => encrypt(&mut cmd, cli.passphrase_fd),
        Command::Decrypt(mut cmd) => decrypt(&mut cmd, cli.passphrase_fd),
        Command::Sign(mut cmd) => sign(&mut cmd, cli.passphrase_fd),
        Command::Verify(mut cmd) => verify(&mut cmd),
    }
}

fn secret_key(cmd: SecretKeyCmd) -> Result<()> {
    let secret_key = SecretKey::new();
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    fs::write(cmd.output, ciphertext).map_err(anyhow::Error::from)
}

fn public_key(cmd: PublicKeyCmd, fd: Option<c_int>) -> Result<()> {
    let secret_key = open_secret_key(&cmd.secret_key, fd)?;
    let public_key = secret_key.public_key(&cmd.key_id);
    println!("{}", public_key);
    Ok(())
}

fn derive_key(cmd: DeriveKeyCmd) -> Result<()> {
    let root = cmd.public_key.parse::<PublicKey>()?;
    let public_key = root.derive(&cmd.sub_key_id);
    println!("{}", public_key);
    Ok(())
}

fn encrypt(cmd: &mut EncryptCmd, fd: Option<c_int>) -> Result<()> {
    let secret_key = open_secret_key(&cmd.secret_key, fd)?;
    let private_key = secret_key.private_key(&cmd.key_id);
    let pks = cmd
        .recipients
        .iter()
        .map(|s| s.parse::<PublicKey>().map_err(anyhow::Error::from))
        .collect::<Result<Vec<PublicKey>>>()?;
    private_key.encrypt(
        &mut cmd.plaintext,
        &mut cmd.ciphertext,
        pks,
        cmd.fakes,
        cmd.padding,
    )?;
    Ok(())
}

fn decrypt(cmd: &mut DecryptCmd, fd: Option<c_int>) -> Result<()> {
    let secret_key = open_secret_key(&cmd.secret_key, fd)?;
    let private_key = secret_key.private_key(&cmd.key_id);
    let sender = cmd.sender.parse::<PublicKey>()?;
    private_key.decrypt(&mut cmd.ciphertext, &mut cmd.plaintext, &sender)?;
    Ok(())
}

fn sign(cmd: &mut SignCmd, fd: Option<c_int>) -> Result<()> {
    let secret_key = open_secret_key(&cmd.secret_key, fd)?;
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
