use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io, mem};

use anyhow::Result;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature};

#[derive(StructOpt, Debug)]
#[structopt(name = "veil", about = "Stupid crypto tricks.")]
enum Cli {
    #[structopt(about = "Generate a new secret key", display_order = 0)]
    SecretKey {
        #[structopt(help = "The output path for the encrypted secret key")]
        output: PathBuf,
    },

    #[structopt(about = "Derive a public key from a secret key", display_order = 1)]
    PublicKey {
        #[structopt(help = "The path to the secret key")]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the public key to generate")]
        key_id: String,
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
    },

    #[structopt(about = "Encrypt a message for a set of recipients", display_order = 3)]
    Encrypt {
        #[structopt(help = "The path to the secret key")]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the plaintext file")]
        plaintext: PathBuf,

        #[structopt(help = "The path to the ciphertext file")]
        ciphertext: PathBuf,

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
        secret_key: PathBuf,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the ciphertext file")]
        ciphertext: PathBuf,

        #[structopt(help = "The path to the plaintext file")]
        plaintext: PathBuf,

        #[structopt(help = "The sender's public key")]
        sender: String,
    },

    #[structopt(about = "Sign a message", display_order = 5)]
    Sign {
        #[structopt(help = "The path to the secret key")]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the message")]
        message: PathBuf,
    },

    #[structopt(about = "Verify a signature", display_order = 6)]
    Verify {
        #[structopt(help = "The signer's public key")]
        public_key: String,

        #[structopt(help = "The path to the message")]
        message: PathBuf,

        #[structopt(help = "The signature")]
        signature: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::from_args();
    match cli {
        Cli::SecretKey { output } => secret_key(&output),
        Cli::PublicKey { secret_key, key_id } => public_key(&secret_key, &key_id),
        Cli::DeriveKey {
            public_key,
            sub_key_id,
        } => derive_key(&public_key, &sub_key_id),
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
        } => sign(&secret_key, &key_id, &message),
        Cli::Verify {
            public_key,
            message,
            signature,
        } => verify(&public_key, &message, &signature),
    }
}

fn secret_key(output_path: &Path) -> Result<()> {
    let secret_key = SecretKey::new();
    let mut f = open_output(output_path)?;
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    f.write_all(&ciphertext)?;
    Ok(())
}

fn public_key(secret_key_path: &Path, key_id: &str) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let public_key = secret_key.public_key(key_id);
    println!("{}", public_key);
    Ok(())
}

fn derive_key(public_key_ascii: &str, key_id: &str) -> Result<()> {
    let root = public_key_ascii.parse::<PublicKey>()?;
    let public_key = root.derive(key_id);
    println!("{}", public_key);
    Ok(())
}

fn encrypt(
    secret_key_path: &Path,
    key_id: &str,
    plaintext_path: &Path,
    ciphertext_path: &Path,
    recipients: Vec<String>,
    fakes: usize,
    padding: u64,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut plaintext = open_input(plaintext_path)?;
    let mut ciphertext = open_output(ciphertext_path)?;
    let pks = recipients
        .into_iter()
        .map(|s| s.parse::<PublicKey>().map_err(anyhow::Error::from))
        .collect::<Result<Vec<PublicKey>>>()?;

    private_key.encrypt(&mut plaintext, &mut ciphertext, pks, fakes, padding)?;

    Ok(())
}

fn decrypt(
    secret_key_path: &Path,
    key_id: &str,
    ciphertext_path: &Path,
    plaintext_path: &Path,
    sender_ascii: &str,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let sender = sender_ascii.parse::<PublicKey>()?;
    let mut ciphertext = open_input(ciphertext_path)?;
    let mut plaintext = open_output(plaintext_path)?;

    if let Err(e) = private_key.decrypt(&mut ciphertext, &mut plaintext, &sender) {
        if plaintext_path != Path::new("-") {
            mem::drop(plaintext);
            fs::remove_file(plaintext_path)?;
        }
        return Err(anyhow::Error::from(e));
    }

    Ok(())
}

fn sign(secret_key_path: &Path, key_id: &str, message_path: &Path) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path)?;
    let private_key = secret_key.private_key(key_id);
    let mut message = open_input(message_path)?;

    let sig = private_key.sign(&mut message)?;
    println!("{}", sig);

    Ok(())
}

fn verify(signer_ascii: &str, message_path: &Path, signature_ascii: &str) -> Result<()> {
    let signer = signer_ascii.parse::<PublicKey>()?;
    let sig: Signature = signature_ascii.parse()?;
    let mut message = open_input(message_path)?;
    signer.verify(&mut message, &sig)?;
    Ok(())
}

fn open_input(path: &Path) -> Result<Box<dyn io::Read>> {
    Ok(if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(path)?)
    })
}

fn open_output(path: &Path) -> Result<Box<dyn io::Write>> {
    Ok(if path == Path::new("-") {
        Box::new(io::stdout())
    } else {
        Box::new(fs::File::create(path)?)
    })
}

fn open_secret_key(path: &Path) -> Result<SecretKey> {
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "))?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}
