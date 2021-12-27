#![cfg(feature = "cli")]

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use duct::cmd;

const VEIL_PATH: &str = env!("CARGO_BIN_EXE_veil");

#[test]
pub fn encrypt_and_decrypt_a_message() -> Result<()> {
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
    cmd!(
        VEIL_PATH,
        "encrypt",
        secret_key_path_a,
        "/friends/bea",
        message_file,
        ciphertext_path,
        &public_key_b,
        "--fakes",
        "20",
        "--padding",
        "1024",
        "--passphrase-file",
        passphrase_path_a,
    )
    .run()?;

    // Bea decrypts the message.
    let plaintext_path = &dir.path().join("message.txt");
    cmd!(
        VEIL_PATH,
        "decrypt",
        secret_key_path_b,
        "/friends/alice",
        ciphertext_path,
        plaintext_path,
        &public_key_a,
        "--passphrase-file",
        passphrase_path_b,
    )
    .run()?;

    // Bea reads the message.
    let msg = fs::read_to_string(plaintext_path)?;
    assert_eq!("this is a secret message", msg);

    Ok(())
}

#[test]
fn sign_and_verify_message() -> Result<()> {
    let dir = tempfile::tempdir()?;

    // Alice picks a passphrase.
    let passphrase_path = &dir.path().join("passphrase-a");
    fs::write(passphrase_path, "excelsior")?;

    // Alice generates a secret key.
    let secret_key_path = &dir.path().join("secret-key-a");
    create_secret_key(secret_key_path, passphrase_path)?;

    // Alice generates a public key.
    let public_key = generate_public_key(secret_key_path, passphrase_path, "/friends")?;

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a public message")?;

    // Alice signs the message.
    let sig = cmd!(
        VEIL_PATH,
        "sign",
        secret_key_path,
        "/friends",
        message_file,
        "--passphrase-file",
        passphrase_path,
    )
    .read()?;

    cmd!(VEIL_PATH, "verify", public_key, message_file, sig).run()?;

    Ok(())
}

fn generate_public_key(
    secret_key_path: &PathBuf,
    passphrase_path: &PathBuf,
    key_id: &str,
) -> Result<String> {
    let out = cmd!(
        VEIL_PATH,
        "public-key",
        secret_key_path,
        key_id,
        "--passphrase-file",
        passphrase_path
    )
    .read()?;
    Ok(out)
}

fn create_secret_key(secret_key_path: &PathBuf, passphrase_path: &PathBuf) -> Result<()> {
    cmd!(
        VEIL_PATH,
        "secret-key",
        secret_key_path,
        "--passphrase-file",
        passphrase_path,
        "--time",
        "10",
        "--space",
        "15",
    )
    .run()?;

    Ok(())
}
