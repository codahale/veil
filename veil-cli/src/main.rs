use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io, mem};

use anyhow::Result;
use structopt::StructOpt;

use veil::{PublicKey, SecretKey, Signature, VeilError};

#[derive(StructOpt, Debug)]
#[structopt(name = "veil-cli", about = "Stupid crypto tricks.")]
enum Cli {
    #[structopt(about = "Generate a new secret key", display_order = 0)]
    SecretKey {
        #[structopt(help = "The output path for the encrypted secret key")]
        output: PathBuf,

        #[structopt(long = "passphrase-file", help = "The path to the passphrase file")]
        passphrase_file: Option<PathBuf>,
    },

    #[structopt(about = "Derive a public key from a secret key", display_order = 1)]
    PublicKey {
        #[structopt(help = "The path to the secret key")]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the public key to generate")]
        key_id: String,

        #[structopt(help = "The output path for the public key")]
        output: PathBuf,

        #[structopt(long = "passphrase-file", help = "The path to the passphrase file")]
        passphrase_file: Option<PathBuf>,
    },

    #[structopt(
        about = "Derive a public key from another public key",
        display_order = 2
    )]
    DeriveKey {
        #[structopt(help = "The path to the public key")]
        public_key: PathBuf,

        #[structopt(help = "The ID of the public key to generate")]
        sub_key_id: String,

        #[structopt(help = "The output path for the public key")]
        output: PathBuf,
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
        recipients: Vec<PathBuf>,

        #[structopt(long = "fakes", default_value = "0", help = "Add fake recipients")]
        fakes: usize,

        #[structopt(
            long = "padding",
            default_value = "0",
            help = "Add bytes of random padding"
        )]
        padding: u64,

        #[structopt(long = "passphrase-file", help = "The path to the passphrase file")]
        passphrase_file: Option<PathBuf>,
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
        sender: PathBuf,

        #[structopt(long = "passphrase-file", help = "The path to the passphrase file")]
        passphrase_file: Option<PathBuf>,
    },

    #[structopt(about = "Sign a message", display_order = 5)]
    Sign {
        #[structopt(help = "The path to the secret key")]
        secret_key: PathBuf,

        #[structopt(help = "The ID of the private key to use")]
        key_id: String,

        #[structopt(help = "The path to the message")]
        message: PathBuf,

        #[structopt(long = "passphrase-file", help = "The path to the passphrase file")]
        passphrase_file: Option<PathBuf>,
    },

    #[structopt(about = "Verify a signature", display_order = 6)]
    Verify {
        #[structopt(help = "The path to the public key")]
        public_key: PathBuf,

        #[structopt(help = "The path to the message")]
        message: PathBuf,

        #[structopt(help = "The signature")]
        signature: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::from_args();
    match cli {
        Cli::SecretKey {
            output,
            passphrase_file,
        } => secret_key(&output, passphrase_file),
        Cli::PublicKey {
            secret_key,
            key_id,
            output,
            passphrase_file,
        } => public_key(&secret_key, &key_id, &output, passphrase_file),
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
            passphrase_file,
        } => encrypt(
            &secret_key,
            &key_id,
            &plaintext,
            &ciphertext,
            recipients,
            fakes,
            padding,
            passphrase_file,
        ),
        Cli::Decrypt {
            secret_key,
            key_id,
            ciphertext,
            plaintext,
            sender,
            passphrase_file,
        } => decrypt(
            &secret_key,
            &key_id,
            &ciphertext,
            &plaintext,
            &sender,
            passphrase_file,
        ),
        Cli::Sign {
            secret_key,
            key_id,
            message,
            passphrase_file,
        } => sign(&secret_key, &key_id, &message, passphrase_file),
        Cli::Verify {
            public_key,
            message,
            signature,
        } => verify(&public_key, &message, &signature),
    }
}

fn secret_key(output_path: &Path, passphrase_file: Option<PathBuf>) -> Result<()> {
    let secret_key = SecretKey::new();
    let mut f = open_output(output_path)?;
    let passphrase = read_passphrase(passphrase_file)?;
    let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
    f.write_all(&ciphertext)?;
    Ok(())
}

fn public_key(
    secret_key_path: &Path,
    key_id: &str,
    output_path: &Path,
    passphrase_file: Option<PathBuf>,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path, passphrase_file)?;
    let public_key = secret_key.public_key(key_id);
    let mut output = open_output(output_path)?;
    write!(output, "{}", public_key)?;
    Ok(())
}

fn derive_key(public_key_path: &Path, key_id: &str, output_path: &Path) -> Result<()> {
    let root = decode_public_key(public_key_path)?;
    let public_key = root.derive(key_id);
    let mut output = open_output(output_path)?;
    write!(output, "{}", public_key)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encrypt(
    secret_key_path: &Path,
    key_id: &str,
    plaintext_path: &Path,
    ciphertext_path: &Path,
    recipient_paths: Vec<PathBuf>,
    fakes: usize,
    padding: u64,
    passphrase_file: Option<PathBuf>,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path, passphrase_file)?;
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
    secret_key_path: &Path,
    key_id: &str,
    ciphertext_path: &Path,
    plaintext_path: &Path,
    sender_path: &Path,
    passphrase_file: Option<PathBuf>,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path, passphrase_file)?;
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
    secret_key_path: &Path,
    key_id: &str,
    message_path: &Path,
    passphrase_file: Option<PathBuf>,
) -> Result<()> {
    let secret_key = open_secret_key(secret_key_path, passphrase_file)?;
    let private_key = secret_key.private_key(key_id);
    let mut message = open_input(message_path)?;

    let sig = private_key.sign(&mut message)?;
    println!("{}", sig);

    Ok(())
}

fn verify(public_key_path: &Path, message_path: &Path, signature: &str) -> Result<()> {
    let public_key = decode_public_key(public_key_path)?;
    let sig: Signature = signature.parse()?;
    let mut message = open_input(message_path)?;
    public_key.verify(&mut message, &sig)?;
    Ok(())
}

fn decode_public_key(path_or_key: &Path) -> Result<PublicKey> {
    path_or_key
        .to_str()
        .and_then(|s| s.parse().ok())
        .ok_or(VeilError::InvalidPublicKey)
        .or_else(|_| {
            let s = fs::read_to_string(path_or_key)?;
            s.parse()
        })
        .map_err(anyhow::Error::from)
}

fn open_input(path: &Path) -> Result<Box<dyn io::Read>> {
    if path == Path::new("-") {
        return Ok(Box::new(io::stdin()));
    }

    Ok(Box::new(fs::File::open(path)?))
}

fn open_output(path: &Path) -> Result<Box<dyn io::Write>> {
    if path == Path::new("-") {
        return Ok(Box::new(io::stdout()));
    }

    Ok(Box::new(fs::File::create(path)?))
}

fn open_secret_key(path: &Path, passphrase_file: Option<PathBuf>) -> Result<SecretKey> {
    let passphrase = read_passphrase(passphrase_file)?;
    let ciphertext = fs::read(path)?;
    let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
    Ok(sk)
}

fn read_passphrase(passphrase_file: Option<PathBuf>) -> Result<String> {
    match passphrase_file {
        Some(p) => fs::read_to_string(p),
        None => rpassword::read_password_from_tty(Some("Enter passphrase: ")),
    }
    .map_err(anyhow::Error::from)
}
