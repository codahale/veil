use std::io::Write;
use std::{fs, io};

use clap::{App, AppSettings, SubCommand};

use veil_lib::{PrivateKey, PublicKey, SecretKey, Signature};

fn main() -> io::Result<()> {
    let matches = App::new("veil")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version("0.1.0")
        .about("Stupid crypto tricks")
        .subcommand(
            SubCommand::with_name("secret-key")
                .display_order(0)
                .about("Generate a new secret key")
                .args_from_usage(
                    "
                <output> 'The output path for the encrypted secret key'",
                ),
        )
        .subcommand(
            SubCommand::with_name("public-key")
                .display_order(1)
                .about("Derive a public key from a secret key")
                .args_from_usage(
                    "
                <secret-key> 'The path to the secret key'
                <key-id> 'The ID of the public key to generate'
                <output> 'The output path for the public key'",
                ),
        )
        .subcommand(
            SubCommand::with_name("derive-key")
                .display_order(2)
                .about("Derive a public key from another public key")
                .args_from_usage(
                    "
                <public-key> 'The path to the secret key'
                <sub-key-id> 'The ID of the public key to generate'
                <output> 'The output path for the public key'",
                ),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .display_order(3)
                .about("Encrypt a message for a set of recipients")
                .args_from_usage(
                    "
                <secret-key> 'The path to the secret key'
                <key-id> 'The ID of the private key to use'
                <plaintext> 'The path to the plaintext file'
                <ciphertext> 'The path to the ciphertext file'
                -r, --recipient=<KEY>... 'The public keys of the recipients'
                [--fakes=<N>] 'Add N fake recipients'
                [--padding=<N>] 'Add N bytes of padding'",
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .display_order(4)
                .about("Decrypt and verify a message")
                .args_from_usage(
                    "
                <secret-key> 'The path to the secret key'
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
                    "
                <secret-key> 'The path to the secret key'
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
                    "
                <public-key> 'The path to the signer's public key'
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
        ("derive-key", Some(matches)) => {
            derive_key(
                matches.value_of("public-key").expect("public key required"),
                matches.value_of("sub-key-id").expect("sub key ID required"),
                matches.value_of("output").expect("output required"),
            )?;
        }
        ("encrypt", Some(matches)) => {
            encrypt(
                matches.value_of("secret-key").expect("secret key required"),
                matches.value_of("key-id").expect("key ID required"),
                matches.value_of("plaintext").expect("plaintext required"),
                matches.value_of("ciphertext").expect("ciphertext required"),
                matches
                    .values_of("recipient")
                    .expect("recipients required")
                    .collect(),
                matches
                    .value_of("fakes")
                    .unwrap_or("0")
                    .parse()
                    .expect("invalid fakes"),
                matches
                    .value_of("padding")
                    .unwrap_or("0")
                    .parse()
                    .expect("invalid padding"),
            )?;
        }
        ("decrypt", Some(matches)) => {
            decrypt(
                matches.value_of("secret-key").expect("secret key required"),
                matches.value_of("key-id").expect("key ID required"),
                matches.value_of("ciphertext").expect("ciphertext required"),
                matches.value_of("plaintext").expect("plaintext required"),
                matches.value_of("sender").expect("sender required"),
            )?;
        }
        ("sign", Some(matches)) => {
            sign(
                matches.value_of("secret-key").expect("secret key required"),
                matches.value_of("key-id").expect("key ID required"),
                matches.value_of("message").expect("message required"),
                matches.value_of("signature").expect("signature required"),
            )?;
        }
        ("verify", Some(matches)) => {
            verify(
                matches.value_of("public-key").expect("public key required"),
                matches.value_of("message").expect("message required"),
                matches.value_of("signature").expect("signature required"),
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
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    f.write(&ciphertext)
}

fn public_key(secret_key_path: &str, key_id: &str, output_path: &str) -> io::Result<usize> {
    let secret_key = open_secret_key(secret_key_path)?;
    let public_key = secret_key.public_key(key_id);
    let mut output = open_output(output_path)?;
    output.write(public_key.to_ascii().as_bytes())
}

fn derive_key(public_key_path: &str, key_id: &str, output_path: &str) -> io::Result<usize> {
    let root = decode_public_key(public_key_path)?;
    let public_key = root.derive(key_id);
    let mut output = open_output(output_path)?;
    output.write(public_key.to_ascii().as_bytes())
}

fn encrypt(
    secret_key_path: &str,
    key_id: &str,
    plaintext_path: &str,
    ciphertext_path: &str,
    recipient_paths: Vec<&str>,
    fakes: usize,
    padding: u64,
) -> io::Result<u64> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut plaintext = open_input(plaintext_path)?;
    let mut ciphertext = open_output(ciphertext_path)?;

    let mut pks = Vec::with_capacity(recipient_paths.len());
    for path in recipient_paths {
        pks.push(decode_public_key(path)?);
    }

    private_key.encrypt(&mut plaintext, &mut ciphertext, pks, fakes, padding)
}

fn decrypt(
    secret_key_path: &str,
    key_id: &str,
    ciphertext_path: &str,
    plaintext_path: &str,
    sender_path: &str,
) -> io::Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let sender = decode_public_key(sender_path)?;

    try_decrypt(&sender, ciphertext_path, private_key, plaintext_path)
        .or_else(|_| fs::remove_file(plaintext_path))
}

fn try_decrypt(
    sender: &PublicKey,
    ciphertext_path: &str,
    private_key: PrivateKey,
    plaintext_path: &str,
) -> io::Result<()> {
    let mut ciphertext = open_input(ciphertext_path)?;
    let mut plaintext = open_output(plaintext_path)?;
    private_key
        .decrypt(&mut ciphertext, &mut plaintext, &sender)
        .and(Ok(()))
}

fn sign(
    secret_key_path: &str,
    key_id: &str,
    message_path: &str,
    signature_path: &str,
) -> io::Result<usize> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut message = open_input(message_path)?;
    let mut output = open_output(signature_path)?;

    let sig = private_key.sign(&mut message)?;

    output.write(sig.to_ascii().as_bytes())
}

fn verify(public_key_path: &str, message_path: &str, signature: &str) -> io::Result<()> {
    let public_key = decode_public_key(public_key_path)?;
    let sig = Signature::from_ascii(signature)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid signature"))?;

    let mut message = open_input(message_path)?;
    if !public_key.verify(&mut message, &sig)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid signature",
        ));
    }
    Ok(())
}

fn decode_public_key(path_or_key: &str) -> io::Result<PublicKey> {
    // Try to decode it from ASCII.
    if let Some(decoded) = PublicKey::from_ascii(path_or_key) {
        return Ok(decoded);
    }

    let s = fs::read_to_string(path_or_key)?;
    PublicKey::from_ascii(&s)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid public key"))
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
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = fs::read(path)?;
    let secret_key = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext);
    secret_key.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid passphrase"))
}
