#![cfg(feature = "cli")]
use std::fs;
use std::path::PathBuf;
use std::str;

use anyhow::Result;
use assert_cmd::Command;

#[test]
pub fn bootstrap_and_send_a_message() -> Result<()> {
    let dir = tempfile::tempdir()?;

    // Alice picks a passphrase.
    let passphrase_path_a = &dir.path().join("passphrase-a");
    fs::write(passphrase_path_a, "excelsior")?;

    // Alice generates a secret key.
    let secret_key_path_a = &dir.path().join("secret-key-a");
    create_secret_key(secret_key_path_a, passphrase_path_a)?;

    // Alice generates a public key.
    let public_key_a = generate_public_key(secret_key_path_a, passphrase_path_a, "/friends/bea")?;

    // Bea picks a passphrase.
    let passphrase_path_b = &dir.path().join("passphrase-b");
    fs::write(passphrase_path_b, "dingus")?;

    // Bea generates a secret key.
    let secret_key_path_b = &dir.path().join("secret-key-b");
    create_secret_key(secret_key_path_b, passphrase_path_b)?;

    // Bea generates a public key.
    let public_key_b = generate_public_key(secret_key_path_b, passphrase_path_b, "/friends/alice")?;

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a secret message")?;

    // Alice encrypts the message for Bea.
    let ciphertext_path = &dir.path().join("message.veil");
    let mut cmd = Command::cargo_bin("veil")?;
    cmd.arg("encrypt")
        .arg(secret_key_path_a)
        .arg("/friends/bea")
        .arg(message_file)
        .arg(ciphertext_path)
        .arg(&public_key_b)
        .arg("--fakes")
        .arg("20")
        .arg("--padding")
        .arg("1204")
        .arg("--passphrase-file")
        .arg(passphrase_path_a)
        .assert()
        .success();

    // Bea decrypts the message.
    let plaintext_path = &dir.path().join("message.txt");
    let mut cmd = Command::cargo_bin("veil")?;
    cmd.arg("decrypt")
        .arg(secret_key_path_b)
        .arg("/friends/alice")
        .arg(ciphertext_path)
        .arg(plaintext_path)
        .arg(&public_key_a)
        .arg("--passphrase-file")
        .arg(passphrase_path_b)
        .assert()
        .success();

    // Bea reads the message.
    let msg = fs::read_to_string(plaintext_path)?;
    assert_eq!("this is a secret message", msg);

    Ok(())
}

fn generate_public_key(
    secret_key_path: &PathBuf,
    passphrase_path: &PathBuf,
    key_id: &str,
) -> Result<String> {
    let mut cmd = Command::cargo_bin("veil")?;
    let success = cmd
        .arg("public-key")
        .arg(secret_key_path)
        .arg(key_id)
        .arg("--passphrase-file")
        .arg(passphrase_path)
        .assert()
        .success();
    let out = success.get_output();
    let public_key = str::from_utf8(&out.stdout)?.trim();
    Ok(public_key.to_string())
}

fn create_secret_key(secret_key_path: &PathBuf, passphrase_path: &PathBuf) -> Result<()> {
    let mut cmd = Command::cargo_bin("veil")?;
    cmd.arg("secret-key")
        .arg(secret_key_path)
        .arg("--passphrase-file")
        .arg(passphrase_path)
        .arg("--time")
        .arg("10")
        .arg("--space")
        .arg("15")
        .assert()
        .success();

    Ok(())
}
