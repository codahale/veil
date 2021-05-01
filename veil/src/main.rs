use std::io::Write;
use std::{fs, io};

use clap::{App, SubCommand};

use veil_lib::SecretKey;

fn main() -> io::Result<()> {
    let matches = App::new("veil")
        .version("0.1.0")
        .about("Stupid crypto tricks")
        .subcommand(
            SubCommand::with_name("secret-key")
                .display_order(0)
                .about("Generate a new secret key")
                .args_from_usage("<output> 'The output path for the encrypted secret key'"),
        )
        .subcommand(
            SubCommand::with_name("public-key")
                .display_order(1)
                .about("Derive a public key from a secret key")
                .args_from_usage(
                    "<secret-key> 'The path to the secret key'
                <key-id> 'The ID of the public key to generate'
                <output> 'The output path for the public key'",
                ),
        )
        .subcommand(
            SubCommand::with_name("derive-key")
                .display_order(2)
                .about("Derive a public key from another public key")
                .args_from_usage(
                    "<public-key> 'The path to the secret key'
                <sub-key-id> 'The ID of the public key to generate'
                <output> 'The output path for the public key'",
                ),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .display_order(3)
                .about("Encrypt a message for a set of recipients")
                .args_from_usage(
                    "<secret-key> 'The path to the secret key'
                <key-id> 'The ID of the private key to use'
                <plaintext> 'The path to the plaintext file'
                <ciphertext> 'The path to the ciphertext file'
                <recipients...> 'The public keys of the recipients'
                --fakes=N 'Add N fake recipients'
                --padding=N 'Add N bytes of padding'",
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .display_order(4)
                .about("Decrypt and verify a message")
                .args_from_usage(
                    "<secret-key> 'The path to the secret key'
                <key-id> 'The ID of the private key to use'
                <ciphertext> 'The path to the ciphertext file'
                <plaintext> 'The path to the plaintext file'
                <sender> 'The public key of the sender'",
                ),
        )
        .subcommand(
            SubCommand::with_name("sign")
                .display_order(5)
                .about("Create a signature for a message")
                .args_from_usage(
                    "<secret-key> 'The path to the secret key'
                <key-id> 'The ID of the private key to use'
                <message> 'The path to the message'
                <signature> 'The path to the signature'",
                ),
        )
        .subcommand(
            SubCommand::with_name("verify")
                .display_order(5)
                .about("Verify a signature for a message")
                .args_from_usage(
                    "<public-key> 'The path to the signer's public key'
                <message> 'The path to the message'
                <signature> 'The path to the signature'",
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("secret-key", Some(matches)) => {
            secret_key(matches.value_of("output").expect("output required"))?;
        }
        ("public-key", Some(matches)) => {
            public_key(
                matches.value_of("secret-key").expect("secret key required"),
                matches.value_of("key-id").expect("key ID required"),
                matches.value_of("output").expect("output required"),
            )?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn secret_key(output_path: &str) -> io::Result<usize> {
    let secret_key = SecretKey::new();
    let mut f = open_output(output_path)?;
    let passphrase = rpassword::prompt_password_stderr("Enter passphrase: ")?;
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 10, 10);
    f.write(&ciphertext)
}

fn public_key(secret_key_path: &str, key_id: &str, output_path: &str) -> io::Result<usize> {
    let secret_key = open_secret_key(secret_key_path)?;
    let public_key = secret_key.public_key(key_id);
    let mut output = open_output(output_path)?;
    output.write(public_key.to_ascii().as_bytes())
}

fn open_input(path: &str) -> io::Result<Box<dyn io::Read>> {
    let output: Box<dyn io::Read> = match path {
        "-" => Box::new(io::stdin()),
        path => Box::new(fs::File::open(path)?),
    };
    Ok(output)
}

fn open_output(path: &str) -> io::Result<Box<dyn io::Write>> {
    let output: Box<dyn io::Write> = match path {
        "-" => Box::new(io::stdout()),
        path => Box::new(fs::File::create(path)?),
    };
    Ok(output)
}

fn open_secret_key(path: &str) -> io::Result<SecretKey> {
    let passphrase = rpassword::prompt_password_stderr("Enter passphrase: ")?;
    let ciphertext = fs::read(path)?;
    let secret_key = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext);
    secret_key.ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid passphrase",
    ))
}
