#![cfg(unix)]

use std::fs;

use anyhow::Result;
use xshell::{cmd, Shell};

const VEIL_PATH: &str = env!("CARGO_BIN_EXE_veil");

macro_rules! bash_cmd {
    ($sh:expr, $cmd:literal) => {{
        let bash = format!($cmd);
        cmd!($sh, "bash -c {bash}")
    }};
}

#[test]
pub fn encrypt_and_decrypt_a_message() -> Result<()> {
    let sh = Shell::new()?;
    let dir = sh.create_temp_dir()?;

    // Alice picks a passphrase.
    let alice_passphrase = "excelsior";

    // Alice generates a private key.
    let private_key_path_a = &dir.path().join("private-key-a");
    bash_cmd!(sh, "{VEIL_PATH} private-key {private_key_path_a:?} --time-cost=0 --memory-cost=0 --passphrase-fd=3 3< <(echo -n {alice_passphrase})")
        .run()
        .expect("error creating private key");

    // Alice generates a public key.
    let public_key_a = bash_cmd!(sh, "{VEIL_PATH} public-key {private_key_path_a:?} --passphrase-fd=3 3< <(echo -n {alice_passphrase})")
        .read()
        .expect("error generating public key");

    // Bea picks a passphrase.
    let bea_passphrase = "dingus";

    // Bea generates a private key.
    let private_key_path_b = &dir.path().join("private-key-b");
    bash_cmd!(sh, "{VEIL_PATH} private-key {private_key_path_b:?} --time-cost=0 --memory-cost=0 --passphrase-fd=3 3< <(echo -n {bea_passphrase})")
        .run()
        .expect("error creating private key");

    // Bea generates a public key.
    let public_key_b = bash_cmd!(sh, "{VEIL_PATH} public-key {private_key_path_b:?} --passphrase-fd=3 3< <(echo -n {bea_passphrase})")
        .read()
        .expect("error generating public key");

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a secret message").expect("error writing message file");

    // Alice encrypts the message for Bea.
    let ciphertext_path = &dir.path().join("message.veil");
    bash_cmd!(sh, "{VEIL_PATH} encrypt {private_key_path_a:?} {message_file:?} {ciphertext_path:?} {public_key_b} --fakes=20 --padding=1024 --passphrase-fd=3 3< <(echo -n {alice_passphrase})")
        .run()
        .expect("error encrypting message");

    // Bea decrypts the message.
    let plaintext_path = &dir.path().join("message.txt");
    bash_cmd!(sh, "{VEIL_PATH} decrypt {private_key_path_b:?} {ciphertext_path:?} {plaintext_path:?} {public_key_a} --passphrase-fd=3 3< <(echo -n {bea_passphrase})")
        .run()
        .expect("error decrypting message");

    // Bea reads the message.
    let msg = fs::read_to_string(plaintext_path).expect("error reading message");
    assert_eq!("this is a secret message", msg, "invalid plaintext");

    Ok(())
}

#[test]
fn sign_and_verify_message() -> Result<()> {
    let sh = Shell::new()?;
    let dir = sh.create_temp_dir()?;

    // Alice picks a passphrase.
    let alice_passphrase = "excelsior";

    // Alice generates a private key.
    let private_key_path = &dir.path().join("private-key-a");
    bash_cmd!(sh, "{VEIL_PATH} private-key {private_key_path:?} --time-cost=0 --memory-cost=0 --passphrase-fd=3 3< <(echo -n {alice_passphrase})")
        .run()
        .expect("error creating private key");

    // Alice generates a public key.
    let public_key = bash_cmd!(sh, "{VEIL_PATH} public-key {private_key_path:?} --passphrase-fd=3 3< <(echo -n {alice_passphrase})")
        .read()
        .expect("error generating public key");

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a public message").expect("error writing message file");

    // Alice signs the message.
    let sig = bash_cmd!(sh, "{VEIL_PATH} sign {private_key_path:?} {message_file:?} --passphrase-fd=3 3< <(echo -n {alice_passphrase})")
        .read()
        .expect("error signing message");

    // Bea verifies the signature.
    cmd!(sh, "{VEIL_PATH} verify {public_key} {message_file} {sig}")
        .run()
        .expect("error verifying signature");

    Ok(())
}
