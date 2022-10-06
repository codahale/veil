#![cfg(unix)]

use std::fs;

use anyhow::Result;
use xshell::{cmd, Shell};

const VEIL_PATH: &str = env!("CARGO_BIN_EXE_veil");

macro_rules! veil_cmd {
    ($sh:expr, $cmd:literal, $passphrase:expr) => {{
        let bash = format!(
            "{VEIL_PATH} {} --passphrase-fd=3 3< <(echo -n {})",
            format!($cmd),
            $passphrase
        );
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
    veil_cmd!(
        sh,
        "private-key -o {private_key_path_a:?} --time-cost=0 --memory-cost=0 ",
        alice_passphrase
    )
    .run()?;

    // Alice generates a public key.
    let public_key_a =
        veil_cmd!(sh, "public-key -k {private_key_path_a:?}", alice_passphrase).read()?;

    // Bea picks a passphrase.
    let bea_passphrase = "dingus";

    // Bea generates a private key.
    let private_key_path_b = &dir.path().join("private-key-b");
    veil_cmd!(
        sh,
        "private-key -o {private_key_path_b:?} --time-cost=0 --memory-cost=0",
        bea_passphrase
    )
    .run()?;

    // Bea generates a public key.
    let public_key_b =
        veil_cmd!(sh, "public-key -k {private_key_path_b:?}", bea_passphrase).read()?;

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a secret message")?;

    // Alice encrypts the message for Bea.
    let ciphertext_path = &dir.path().join("message.veil");
    veil_cmd!(
        sh,
        "encrypt -k {private_key_path_a:?} -i {message_file:?} -o {ciphertext_path:?} -r {public_key_b} --fakes=20 --padding=1024", 
        alice_passphrase
    )
    .run()?;

    // Bea decrypts the message.
    let plaintext_path = &dir.path().join("message.txt");
    veil_cmd!(
        sh,
        "decrypt -k {private_key_path_b:?} -i {ciphertext_path:?} -o {plaintext_path:?} -s {public_key_a}",
        bea_passphrase
    )
    .run()?;

    // Bea reads the message.
    let msg = fs::read_to_string(plaintext_path)?;
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
    veil_cmd!(
        sh,
        "private-key -o {private_key_path:?} --time-cost=0 --memory-cost=0",
        alice_passphrase
    )
    .run()?;

    // Alice generates a public key.
    let public_key =
        veil_cmd!(sh, "public-key -k {private_key_path:?}", alice_passphrase).read()?;

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a public message")?;

    // Alice signs the message.
    let sig = veil_cmd!(sh, "sign -k {private_key_path:?} -i {message_file:?}", alice_passphrase)
        .read()?;

    // Bea verifies the signature.
    cmd!(sh, "{VEIL_PATH} verify {public_key} {message_file} {sig}").run()?;

    Ok(())
}
