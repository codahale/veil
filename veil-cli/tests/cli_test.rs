#![cfg(unix)]

use std::fs;
use std::path::Path;

use anyhow::Result;
use duct::cmd;

const VEIL_PATH: &str = env!("CARGO_BIN_EXE_veil");

macro_rules! subcmd {
    ( $( $arg:expr, )* $(,)? ) => {
        {
            use std::ffi::OsString;
            let mut out = OsString::new();
            $(
                out.push(Into::<OsString>::into($arg));
                out.push(" ");
            )*
            out
        }
    };
}

#[test]
pub fn encrypt_and_decrypt_a_message() {
    let dir = tempfile::tempdir().expect("error creating temp dir");

    // Alice picks a passphrase.
    let alice_passphrase = "excelsior";

    // Alice generates a private key.
    let private_key_path_a = &dir.path().join("private-key-a");
    create_private_key(private_key_path_a, alice_passphrase).expect("error creating private key");

    // Alice generates a public key.
    let public_key_a = cmd!(
        "/bin/bash",
        "-c",
        subcmd!(
            VEIL_PATH,
            "public-key",
            private_key_path_a,
            "--passphrase-fd",
            "3",
            "3<",
            format!("<(echo -n {})", alice_passphrase),
        )
    )
    .read()
    .expect("error creating public key");

    // Bea picks a passphrase.
    let bea_passphrase = "dingus";

    // Bea generates a private key.
    let private_key_path_b = &dir.path().join("private-key-b");
    create_private_key(private_key_path_b, bea_passphrase).expect("error creating private key");

    // Bea generates a public key.
    let public_key_b = cmd!(
        "/bin/bash",
        "-c",
        subcmd!(
            VEIL_PATH,
            "public-key",
            private_key_path_b,
            "--passphrase-fd",
            "3",
            "3<",
            format!("<(echo -n {})", bea_passphrase),
        )
    )
    .read()
    .expect("error creating public key");

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a secret message").expect("error writing message file");

    // Alice encrypts the message for Bea.
    let ciphertext_path = &dir.path().join("message.veil");
    cmd!(
        "/bin/bash",
        "-c",
        subcmd!(
            VEIL_PATH,
            "encrypt",
            private_key_path_a,
            message_file,
            ciphertext_path,
            &public_key_b,
            "--fakes",
            "20",
            "--padding",
            "1024",
            "--passphrase-fd",
            "3",
            "3<",
            format!("<(echo -n {})", alice_passphrase),
        )
    )
    .run()
    .expect("error encrypting message");

    // Bea decrypts the message.
    let plaintext_path = &dir.path().join("message.txt");
    cmd!(
        "/bin/bash",
        "-c",
        subcmd!(
            VEIL_PATH,
            "decrypt",
            private_key_path_b,
            ciphertext_path,
            plaintext_path,
            &public_key_a,
            "--passphrase-fd",
            "3",
            "3<",
            format!("<(echo -n {})", bea_passphrase),
        )
    )
    .run()
    .expect("error decrypting message");

    // Bea reads the message.
    let msg = fs::read_to_string(plaintext_path).expect("error reading message");
    assert_eq!("this is a secret message", msg, "invalid plaintext");
}

#[test]
fn sign_and_verify_message() {
    let dir = tempfile::tempdir().expect("error creating temp dir");

    // Alice picks a passphrase.
    let alice_passphrase = "excelsior";

    // Alice generates a private key.
    let private_key_path = &dir.path().join("private-key-a");
    create_private_key(private_key_path, alice_passphrase).expect("error creating private key");

    // Alice generates a public key.
    let public_key = cmd!(
        "/bin/bash",
        "-c",
        subcmd!(
            VEIL_PATH,
            "public-key",
            private_key_path,
            "--passphrase-fd",
            "3",
            "3<",
            format!("<(echo -n {})", alice_passphrase),
        )
    )
    .read()
    .expect("error creating public key");

    // Alice writes a plaintext message.
    let message_file = &dir.path().join("message");
    fs::write(message_file, "this is a public message").expect("error writing message file");

    // Alice signs the message.
    let sig = cmd!(
        "/bin/bash",
        "-c",
        subcmd!(
            VEIL_PATH,
            "sign",
            private_key_path,
            message_file,
            "--passphrase-fd",
            "3",
            "3<",
            format!("<(echo -n {})", alice_passphrase),
        )
    )
    .read()
    .expect("error signing message");

    cmd!(VEIL_PATH, "verify", public_key, message_file, sig)
        .run()
        .expect("error verifying signature");
}

fn create_private_key(private_key_path: &Path, passphrase: &str) -> Result<()> {
    cmd!(
        "/bin/bash",
        "-c",
        subcmd!(
            VEIL_PATH,
            "private-key",
            private_key_path,
            "--time-cost=0",
            "--memory-cost=0",
            "--passphrase-fd",
            "3",
            "3<",
            format!("<(echo -n {})", passphrase),
        )
    )
    .run()?;

    Ok(())
}
