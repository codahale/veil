use std::fs;
use std::io::Read;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{AppSettings, Clap};
use filedescriptor::FileDescriptor;

use veil::{PublicKey, SecretKey, Signature};

fn main() -> Result<()> {
    let cli = Opts::parse();
    match cli.cmd {
        Command::SecretKey(mut cmd) => cmd.run(cli.flags),
        Command::PublicKey(mut cmd) => cmd.run(cli.flags),
        Command::DeriveKey(mut cmd) => cmd.run(cli.flags),
        Command::Encrypt(mut cmd) => cmd.run(cli.flags),
        Command::Decrypt(mut cmd) => cmd.run(cli.flags),
        Command::Sign(mut cmd) => cmd.run(cli.flags),
        Command::Verify(mut cmd) => cmd.run(cli.flags),
    }
}

trait Cmd {
    fn run(&mut self, flags: GlobalFlags) -> Result<()>;
}

#[derive(Clap)]
#[clap(name = "veil", about = "Stupid crypto tricks.")]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::SubcommandRequiredElseHelp)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,

    #[clap(flatten)]
    flags: GlobalFlags,
}

#[derive(Clap)]
struct GlobalFlags {
    #[clap(
        long,
        about = "The file descriptor from which the passphrase should be read"
    )]
    passphrase_fd: Option<c_int>,
}

impl GlobalFlags {
    fn decrypt_secret_key(&self, path: &Path) -> Result<SecretKey> {
        let passphrase = self.prompt_passphrase()?;
        let ciphertext = fs::read(path)?;
        let sk = SecretKey::decrypt(passphrase.as_bytes(), &ciphertext)?;
        Ok(sk)
    }

    fn prompt_passphrase(&self) -> Result<String> {
        match self.passphrase_fd {
            Some(fd) => {
                let mut buffer = String::new();
                let mut input = FileDescriptor::new(fd);
                input.read_to_string(&mut buffer)?;
                Ok(buffer)
            }
            None => Ok(rpassword::read_password_from_tty(Some(
                "Enter passphrase: ",
            ))?),
        }
    }
}

#[derive(Clap)]
enum Command {
    #[clap(about = "Generate a new secret key")]
    SecretKey(SecretKeyCmd),

    #[clap(about = "Derive a public key from a secret key")]
    PublicKey(PublicKeyCmd),

    #[clap(about = "Derive a public key from another public key")]
    DeriveKey(DeriveKeyCmd),

    #[clap(about = "Encrypt a message for a set of recipients")]
    Encrypt(EncryptCmd),

    #[clap(about = "Decrypt and verify a message")]
    Decrypt(DecryptCmd),

    #[clap(about = "Sign a message")]
    Sign(SignCmd),

    #[clap(about = "Verify a signature")]
    Verify(VerifyCmd),
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
struct SecretKeyCmd {
    #[clap(
        about = "The output path for the encrypted secret key",
        parse(from_os_str)
    )]
    output: PathBuf,
}

impl Cmd for SecretKeyCmd {
    fn run(&mut self, flags: GlobalFlags) -> Result<()> {
        let passphrase = flags.prompt_passphrase()?;
        let secret_key = SecretKey::new();
        let ciphertext = secret_key.encrypt(passphrase.as_bytes(), 1 << 7, 1 << 10);
        fs::write(&mut self.output, ciphertext)?;
        Ok(())
    }
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
struct PublicKeyCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[clap(about = "The ID of the public key to generate")]
    key_id: String,
}

impl Cmd for PublicKeyCmd {
    fn run(&mut self, flags: GlobalFlags) -> Result<()> {
        let secret_key = flags.decrypt_secret_key(&self.secret_key)?;
        let public_key = secret_key.public_key(&self.key_id);
        println!("{}", public_key);
        Ok(())
    }
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
struct DeriveKeyCmd {
    #[clap(about = "The public key")]
    public_key: String,

    #[clap(about = "The ID of the public key to generate")]
    sub_key_id: String,
}

impl Cmd for DeriveKeyCmd {
    fn run(&mut self, _flags: GlobalFlags) -> Result<()> {
        let root = self.public_key.parse::<PublicKey>()?;
        let public_key = root.derive(&self.sub_key_id);
        println!("{}", public_key);
        Ok(())
    }
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
struct EncryptCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[clap(about = "The ID of the private key to use")]
    key_id: String,

    #[clap(
        about = "The path to the plaintext file or '-' for STDIN",
        parse(try_from_str = clio::Input::new)
    )]
    plaintext: clio::Input,

    #[clap(
        about = "The path to the ciphertext file or '-' for STDOUT",
        parse(try_from_str = clio::Output::new)
    )]
    ciphertext: clio::Output,

    #[clap(required = true, about = "The recipients' public keys")]
    recipients: Vec<String>,

    #[clap(long, default_value = "0", about = "Add fake recipients")]
    fakes: usize,

    #[clap(long, default_value = "0", about = "Add bytes of random padding")]
    padding: u64,
}

impl Cmd for EncryptCmd {
    fn run(&mut self, flags: GlobalFlags) -> Result<()> {
        let secret_key = flags.decrypt_secret_key(&self.secret_key)?;
        let private_key = secret_key.private_key(&self.key_id);
        let pks = self
            .recipients
            .iter()
            .map(|s| s.parse::<PublicKey>().map_err(anyhow::Error::from))
            .collect::<Result<Vec<PublicKey>>>()?;
        private_key.encrypt(
            &mut self.plaintext,
            &mut self.ciphertext,
            pks,
            self.fakes,
            self.padding,
        )?;
        Ok(())
    }
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
pub struct DecryptCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[clap(about = "The ID of the private key to use")]
    key_id: String,

    #[clap(
        about = "The path to the ciphertext file or '-' for STDIN",
        parse(try_from_str = clio::Input::new)
    )]
    ciphertext: clio::Input,

    #[clap(
        about = "The path to the plaintext file or '-' for STDOUT",
        parse(try_from_str = clio::Output::new)
    )]
    plaintext: clio::Output,

    #[clap(about = "The sender's public key")]
    sender: String,
}

impl Cmd for DecryptCmd {
    fn run(&mut self, flags: GlobalFlags) -> Result<()> {
        let secret_key = flags.decrypt_secret_key(&self.secret_key)?;
        let private_key = secret_key.private_key(&self.key_id);
        let sender = self.sender.parse::<PublicKey>()?;
        private_key.decrypt(&mut self.ciphertext, &mut self.plaintext, &sender)?;
        Ok(())
    }
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
struct SignCmd {
    #[clap(about = "The path to the secret key", parse(from_os_str))]
    secret_key: PathBuf,

    #[clap(about = "The ID of the private key to use")]
    key_id: String,

    #[clap(
        about = "The path to the message or '-' for STDIN",
        parse(try_from_str = clio::Input::new)
    )]
    message: clio::Input,
}

impl Cmd for SignCmd {
    fn run(&mut self, flags: GlobalFlags) -> Result<()> {
        let secret_key = flags.decrypt_secret_key(&self.secret_key)?;
        let private_key = secret_key.private_key(&self.key_id);
        let sig = private_key.sign(&mut self.message)?;
        println!("{}", sig);
        Ok(())
    }
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::HelpRequired)]
#[clap(setting = AppSettings::UnifiedHelpMessage)]
struct VerifyCmd {
    #[clap(about = "The signer's public key")]
    public_key: String,

    #[clap(
        about = "The path to the message or '-' for STDIN",
        parse(try_from_str = clio::Input::new)
    )]
    message: clio::Input,

    #[clap(about = "The signature")]
    signature: String,
}

impl Cmd for VerifyCmd {
    fn run(&mut self, _flags: GlobalFlags) -> Result<()> {
        let signer = self.public_key.parse::<PublicKey>()?;
        let sig: Signature = self.signature.parse()?;
        signer.verify(&mut self.message, &sig)?;
        Ok(())
    }
}
