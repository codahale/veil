#![cfg(feature = "cli")]

use std::path::PathBuf;
use std::str;
use std::{env, fs};

use anyhow::Result;
use duct::cmd;

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
    cmd!(
        bin_path(),
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
        bin_path(),
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

fn generate_public_key(
    secret_key_path: &PathBuf,
    passphrase_path: &PathBuf,
    key_id: &str,
) -> Result<String> {
    let out = cmd!(
        bin_path(),
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
        bin_path(),
        "secret-key",
        secret_key_path,
        "--passphrase-file",
        passphrase_path,
        "--time",
        "10",
        "--space",
        "15",
    )
    .stdout_capture()
    .run()?;

    Ok(())
}

fn bin_path() -> PathBuf {
    // Adapted from
    // https://github.com/rust-lang/cargo/blob/485670b3983b52289a2f353d589c57fae2f60f82/tests/testsuite/support/mod.rs#L507
    let target_dir = env::current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path
        })
        .unwrap();
    target_dir.join(format!("veil{}", env::consts::EXE_SUFFIX))
}
