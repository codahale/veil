use std::convert::TryInto;
use std::io::Write;
use std::{fs, io, mem};

use anyhow::Result;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature};

#[derive(StructOpt, Debug)]
#[structopt(name = "veil-cli", about = "Stupid crypto tricks.")]
enum Cli {
    #[structopt(about = "Generate a new secret key", display_order = 0)]
    SecretKey {
        #[structopt(help = "The output path for the encrypted secret key")]
        output: String,
    },

    #[structopt(about = "Derive a public key from a secret key", display_order = 1)]
    PublicKey {
        #[structopt(help = "The path to the secret key")]
        secret_key: String,

        #[structopt(help = "The ID of the public key to generate")]
        key_id: String,

        #[structopt(help = "The output path for the public key")]
        output: String,
    },

    #[structopt(
        about = "Derive a public key from another public key",
        display_order = 2
    )]
    DeriveKey {
        #[structopt(help = "The path to the public key")]
        public_key: String,

        #[structopt(help = "The ID of the public key to generate")]
        sub_key_id: String,

        #[structopt(help = "The output path for the public key")]
        output: String,
    },

    #[structopt(about = "Encrypt a message for a set of recipients", display_order = 3)]
    Encrypt {
        #[structopt(help = "The path to the secret key")]
        secret_key: String,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the plaintext file")]
        plaintext: String,

        #[structopt(help = "The path to the ciphertext file")]
        ciphertext: String,

        #[structopt(
            required = true,
            short = "r",
            long = "--recipient",
            help = "The recipients' public keys"
        )]
        recipients: Vec<String>,

        #[structopt(long = "fakes", default_value = "0", help = "Add fake recipients")]
        fakes: usize,

        #[structopt(
            long = "padding",
            default_value = "0",
            help = "Add bytes of random padding"
        )]
        padding: u64,
    },

    #[structopt(about = "Decrypt and verify a message", display_order = 4)]
    Decrypt {
        #[structopt(help = "The path to the secret key")]
        secret_key: String,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the ciphertext file")]
        ciphertext: String,

        #[structopt(help = "The path to the plaintext file")]
        plaintext: String,

        #[structopt(help = "The sender's public key")]
        sender: String,
    },

    #[structopt(about = "Sign a message", display_order = 5)]
    Sign {
        #[structopt(help = "The path to the secret key")]
        secret_key: String,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the message")]
        message: String,

        #[structopt(help = "The path to the signature")]
        signature: String,
    },

    #[structopt(about = "Verify a signature", display_order = 6)]
    Verify {
        #[structopt(help = "The path to the public key")]
        public_key: String,

        #[structopt(help = "The path to the message")]
        message: String,

        #[structopt(help = "The signature")]
        signature: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::from_args();
    match cli {
        Cli::SecretKey { output } => secret_key(&output),
        Cli::PublicKey {
            secret_key,
            key_id,
            output,
        } => public_key(&secret_key, &key_id, &output),
        Cli::DeriveKey {
            public_key,
            sub_key_id,
            output,
        } => derive_key(&public_key, &sub_key_id, &output),
        Cli::Encrypt {
            secret_key,
            key_id,
            plaintext,
            ciphertext,
            recipients,
            fakes,
            padding,
        } => encrypt(
            &secret_key,
            &key_id,
            &plaintext,
            &ciphertext,
            recipients,
            fakes,
            padding,
        ),
        Cli::Decrypt {
            secret_key,
            key_id,
            ciphertext,
            plaintext,
            sender,
        } => decrypt(&secret_key, &key_id, &ciphertext, &plaintext, &sender),
        Cli::Sign {
            secret_key,
            key_id,
            message,
            signature,
        } => sign(&secret_key, &key_id, &message, &signature),
        Cli::Verify {
            public_key,
            message,
            signature,
        } => verify(&public_key, &message, &signature),
    }
}

fn secret_key(output_path: &str) -> Result<()> {
    let secret_key = SecretKey::new();
    let mut f = open_output(output_path)?;
    let passphrase = rpassword::prompt_password_stderr("Enter passphrase: ")?;
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    f.write_all(&ciphertext)?;
    Ok(())
}

fn public_key(secret_key_path: &str, key_id: &str, output_path: &str) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let public_key = secret_key.public_key(key_id);
    let mut output = open_output(output_path)?;
    output.write_all(public_key.to_ascii().as_bytes())?;
    Ok(())
}

fn derive_key(public_key_path: &str, key_id: &str, output_path: &str) -> Result<()> {
    let root = decode_public_key(public_key_path)?;
    let public_key = root.derive(key_id);
    let mut output = open_output(output_path)?;
    output.write_all(public_key.to_ascii().as_bytes())?;
    Ok(())
}

fn encrypt(
    secret_key_path: &str,
    key_id: &str,
    plaintext_path: &str,
    ciphertext_path: &str,
    recipient_paths: Vec<String>,
    fakes: usize,
    padding: u64,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut plaintext = open_input(plaintext_path)?;
    let mut ciphertext = open_output(ciphertext_path)?;
    let pks = recipient_paths
        .into_iter()
        .map(|s| decode_public_key(&s))
        .collect::<Result<Vec<PublicKey>>>()?;

    private_key.encrypt(&mut plaintext, &mut ciphertext, pks, fakes, padding)?;

    Ok(())
}

fn decrypt(
    secret_key_path: &str,
    key_id: &str,
    ciphertext_path: &str,
    plaintext_path: &str,
    sender_path: &str,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let sender = decode_public_key(sender_path)?;
    let mut ciphertext = open_input(ciphertext_path)?;
    let mut plaintext = open_output(plaintext_path)?;

    if let Err(e) = private_key.decrypt(&mut ciphertext, &mut plaintext, &sender) {
        mem::drop(plaintext);
        fs::remove_file(plaintext_path)?;
        return Err(anyhow::Error::from(e));
    }

    Ok(())
}

fn sign(
    secret_key_path: &str,
    key_id: &str,
    message_path: &str,
    signature_path: &str,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut message = open_input(message_path)?;
    let mut output = open_output(signature_path)?;

    let sig = private_key.sign(&mut message)?;

    output.write_all(sig.to_ascii().as_bytes())?;

    Ok(())
}

fn verify(public_key_path: &str, message_path: &str, signature: &str) -> Result<()> {
    let public_key = decode_public_key(public_key_path)?;
    let sig: Signature = signature.try_into()?;
    let mut message = open_input(message_path)?;
    public_key.verify(&mut message, &sig)?;
    Ok(())
}

fn decode_public_key(path_or_key: &str) -> Result<PublicKey> {
    // Try to decode it from ASCII.
    if let Some(decoded) = PublicKey::from_ascii(path_or_key) {
        return Ok(decoded);
    }

    let s = fs::read_to_string(path_or_key)?;
    let pk: PublicKey = s.as_str().try_into()?;
    Ok(pk)
}

fn open_input(path: &str) -> Result<Box<dyn io::Read>> {
    let output: Box<dyn io::Read> = match path {
        "-" => Box::new(io::stdin()),
        path => Box::new(fs::File::open(path)?),
    };
    Ok(output)
}

fn open_output(path: &str) -> Result<Box<dyn io::Write>> {
    let output: Box<dyn io::Write> = match path {
        "-" => Box::new(io::stdout()),
        path => Box::new(fs::File::create(path)?),
    };
    Ok(output)
}

fn open_secret_key(path: &str) -> Result<SecretKey> {
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}
