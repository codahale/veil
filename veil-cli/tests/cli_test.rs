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
fn encrypt_and_decrypt_a_message() -> Result<()> {
    let sh = Shell::new()?;
    let dir = sh.create_temp_dir()?;

    // Alice picks a passphrase.
    let alice_passphrase = "excelsior";

    // Alice generates a secret key.
    let secret_key_path_a = &dir.path().join("secret-key-a");
    veil_cmd!(
        sh,
        "secret-key -o {secret_key_path_a:?} --time-cost=0 --memory-cost=0 ",
        alice_passphrase
    )
    .run()?;

    // Alice generates a public key.
    let public_key_path_a = &dir.path().join("public-key-a");
    veil_cmd!(sh, "public-key -k {secret_key_path_a:?} -o {public_key_path_a:?}", alice_passphrase)
        .run()?;

    // Bea picks a passphrase.
    let bea_passphrase = "dingus";

    // Bea generates a secret key.
    let secret_key_path_b = &dir.path().join("secret-key-b");
    veil_cmd!(
        sh,
        "secret-key -o {secret_key_path_b:?} --time-cost=0 --memory-cost=0",
        bea_passphrase
    )
    .run()?;

    // Bea generates a public key.
    let public_key_path_b = &dir.path().join("public-key-b");
    veil_cmd!(sh, "public-key -k {secret_key_path_b:?} -o {public_key_path_b:?}", bea_passphrase)
        .run()?;

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a secret message")?;

    // Alice encrypts the message for Bea.
    let ciphertext_path = &dir.path().join("message.veil");
    veil_cmd!(
        sh,
        "encrypt -k {secret_key_path_a:?} -i {message_file:?} -o {ciphertext_path:?} -r {public_key_path_b:?} --fakes=20", 
        alice_passphrase
    )
    .run()?;

    // Bea decrypts the message.
    let plaintext_path = &dir.path().join("message.txt");
    veil_cmd!(
        sh,
        "decrypt -k {secret_key_path_b:?} -i {ciphertext_path:?} -o {plaintext_path:?} -s {public_key_path_a:?}",
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

    // Alice generates a secret key.
    let secret_key_path = &dir.path().join("secret-key-a");
    veil_cmd!(
        sh,
        "secret-key -o {secret_key_path:?} --time-cost=0 --memory-cost=0",
        alice_passphrase
    )
    .run()?;

    // Alice generates a public key.
    let public_key_path = &dir.path().join("public-key-a");
    veil_cmd!(sh, "public-key -k {secret_key_path:?} -o {public_key_path:?}", alice_passphrase)
        .run()?;

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a public message")?;

    // Alice signs the message.
    let sig_file = &dir.path().join("message.sig");
    veil_cmd!(
        sh,
        "sign -k {secret_key_path:?} -i {message_file:?} -o {sig_file:?}",
        alice_passphrase
    )
    .run()?;

    // Bea verifies the signature.
    cmd!(
        sh,
        "{VEIL_PATH} verify --signer {public_key_path} -i {message_file} --signature {sig_file}"
    )
    .run()?;

    Ok(())
}
