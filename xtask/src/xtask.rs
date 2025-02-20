use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use xshell::{Shell, cmd};

#[derive(Debug, Parser)]
struct XTask {
    #[clap(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Format, build, test, and lint.
    CI,

    // Run benchmarks.
    Bench {
        /// Additional arguments.
        #[arg(action(ArgAction::Append), allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// CLI benchmarks with Hyperfine.
    BenchCli {
        /// The subsystem to benchmark.
        #[arg(value_enum)]
        target: BenchmarkTarget,

        /// Don't use git to stash and restore changes.
        #[arg(long)]
        no_stash: bool,

        /// The input size to benchmark, in MiB.
        #[arg(long, default_value = "1024")]
        size: u64,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum BenchmarkTarget {
    Encrypt,
    Sign,
    Verify,
    Digest,
}

fn main() -> Result<()> {
    let xtask = XTask::parse();

    let sh = Shell::new()?;
    sh.change_dir(project_root());

    match xtask.cmd.unwrap_or(Command::CI) {
        Command::CI => ci(&sh),
        Command::Bench { args } => bench(&sh, args),
        Command::BenchCli { target, no_stash, size } => bench_cli(&sh, target, no_stash, size),
    }
}

fn ci(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo fmt --check").run()?;
    cmd!(sh, "cargo build --all-targets --all-features").run()?;
    cmd!(sh, "cargo test --all-features").run()?;
    cmd!(sh, "cargo clippy --all-features --tests --benches").run()?;

    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RUSTFLAGS: &str = "-C target-cpu=native";

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
const RUSTFLAGS: &str = "";

fn bench(sh: &Shell, args: Vec<String>) -> Result<()> {
    cmd!(sh, "cargo bench -p benchmarks --bench benchmarks -- {args...}")
        .env("RUSTFLAGS", RUSTFLAGS)
        .run()?;

    Ok(())
}

fn bench_cli(sh: &Shell, target: BenchmarkTarget, no_stash: bool, size: u64) -> Result<()> {
    // Convert size to bytes.
    let size = format!("{}", size * 1024 * 1024);

    // remove the old versions, if any
    cmd!(sh, "rm -f target/release/veil-experiment").run()?;
    cmd!(sh, "rm -f target/release/veil-control").run()?;

    // build the current state as release
    cmd!(sh, "cargo build --release").env("RUSTFLAGS", RUSTFLAGS).run()?;
    cmd!(sh, "cp target/release/veil target/release/veil-experiment").run()?;

    // stash the current state and build the last commit as release
    if !no_stash {
        cmd!(sh, "git stash").run()?;
    }
    cmd!(sh, "cargo build --release").env("RUSTFLAGS", RUSTFLAGS).run()?;
    cmd!(sh, "cp target/release/veil target/release/veil-control").run()?;

    // create a secret key with minimal KDF expansion, using both commands to make sure they work
    cmd!(sh, "bash -c './target/release/veil-control secret-key -o /tmp/secret-key-control --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n 'secret')'").run()?;
    cmd!(sh, "bash -c './target/release/veil-experiment secret-key -o /tmp/secret-key-experiment --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n secret)'").run()?;

    cmd!(sh, "bash -c './target/release/veil-control public-key -k /tmp/secret-key-control -o /tmp/public-key-control --passphrase-fd=3 3< <(echo -n secret)'").run()?;
    cmd!(sh, "bash -c './target/release/veil-experiment public-key -k /tmp/secret-key-experiment -o /tmp/public-key-experiment --passphrase-fd=3 3< <(echo -n secret)'").run()?;

    match target {
        BenchmarkTarget::Encrypt => {
            let control = format!(
                "head -c {size} /dev/zero | ./target/release/veil-control encrypt --passphrase-fd=3 -k /tmp/secret-key-control -i - -o /dev/null -r /tmp/public-key-control --fakes 9 3< <(echo -n secret)"
            );
            let experiment = format!(
                "head -c {size} /dev/zero | ./target/release/veil-experiment encrypt --passphrase-fd=3 -k /tmp/secret-key-experiment -i - -o /dev/null -r /tmp/public-key-experiment --fakes 9 3< <(echo -n secret)"
            );
            cmd!(sh, "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}").run()?;
        }
        BenchmarkTarget::Sign => {
            let control = format!(
                "head -c {size} /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 -k /tmp/secret-key-control -i - -o /dev/null 3< <(echo -n secret)"
            );
            let experiment = format!(
                "head -c {size} /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 -k /tmp/secret-key-experiment -i - -o /dev/null 3< <(echo -n secret)"
            );
            cmd!(sh, "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}").run()?;
        }
        BenchmarkTarget::Verify => {
            let control_sig = format!(
                "head -c {size} /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 -k /tmp/secret-key-control -i - 3< <(echo -n secret)"
            );
            let control_sig = cmd!(sh, "bash -c {control_sig}").read()?;
            let experiment_sig = format!(
                "head -c {size} /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 -k /tmp/secret-key-experiment -i - 3< <(echo -n secret)"
            );
            let experiment_sig = cmd!(sh, "bash -c {experiment_sig}").read()?;

            let control = format!(
                "head -c {size} /dev/zero | ./target/release/veil-control verify --signer /tmp/public-key-control -i - --signature {control_sig}"
            );
            let experiment = format!(
                "head -c {size} /dev/zero | ./target/release/veil-experiment verify --signer /tmp/public-key-experiment -i - --signature {experiment_sig}"
            );
            cmd!(sh, "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}").run()?;
        }
        BenchmarkTarget::Digest => {
            let control = format!(
                "head -c {size} /dev/zero | ./target/release/veil-control digest -i - -o /dev/null"
            );
            let experiment = format!(
                "head -c {size} /dev/zero | ./target/release/veil-experiment digest -i - -o /dev/null"
            );
            cmd!(sh, "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}").run()?;
        }
    }

    // restore the working set
    if !no_stash {
        cmd!(sh, "git stash pop").run()?;
    }

    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(
        &env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned()),
    )
    .ancestors()
    .nth(1)
    .unwrap()
    .to_path_buf()
}
