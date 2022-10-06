use std::env;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
struct XTask {
    #[clap(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Format, build, test, and lint.
    CI,

    /// CLI benchmarks with Hyperfine.
    Benchmark {
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
        Command::Benchmark { target, no_stash, size } => benchmark(&sh, target, no_stash, size),
    }
}

fn ci(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo fmt --check").run()?;
    cmd!(sh, "cargo build --all-targets --all-features").run()?;
    cmd!(sh, "cargo test --all-features").run()?;
    cmd!(sh, "cargo clippy --all-features --tests --benches").run()?;

    Ok(())
}

fn benchmark(sh: &Shell, target: BenchmarkTarget, no_stash: bool, size: u64) -> Result<()> {
    // Convert size to bytes.
    let size = format!("{}", size * 1024 * 1024);

    // remove the old versions, if any
    cmd!(sh, "rm -f target/release/veil-experiment").run()?;
    cmd!(sh, "rm -f target/release/veil-control").run()?;

    // build the current state as release
    cmd!(sh, "cargo build --release").run()?;
    cmd!(sh, "cp target/release/veil target/release/veil-experiment").run()?;

    // stash the current state and build the last commit as release
    if !no_stash {
        cmd!(sh, "git stash").run()?;
    }
    cmd!(sh, "cargo build --release").run()?;
    cmd!(sh, "cp target/release/veil target/release/veil-control").run()?;

    // create a private key with minimal KDF expansion, using both commands to make sure they work
    cmd!(sh, "bash -c './target/release/veil-control private-key -o /tmp/private-key-control --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n 'secret')'").run()?;
    cmd!(sh, "bash -c './target/release/veil-experiment private-key -o /tmp/private-key-experiment --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n secret)'").run()?;

    let pk_control = cmd!(sh, "bash -c './target/release/veil-control public-key -k /tmp/private-key-control --passphrase-fd=3 3< <(echo -n secret)'").read()?;
    let pk_experiment = cmd!(sh, "bash -c './target/release/veil-experiment public-key -k /tmp/private-key-experiment --passphrase-fd=3 3< <(echo -n secret)'").read()?;

    match target {
        BenchmarkTarget::Encrypt => {
            let control = format!("head -c {size} /dev/zero | ./target/release/veil-control encrypt --passphrase-fd=3 -k /tmp/private-key-control -i - -o /dev/null -r {pk_control} --fakes 9 3< <(echo -n secret)");
            let experiment = format!("head -c {size} /dev/zero | ./target/release/veil-experiment encrypt --passphrase-fd=3 -k /tmp/private-key-experiment -i - -o /dev/null -r {pk_experiment} --fakes 9 3< <(echo -n secret)");
            cmd!(sh, "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}").run()?;
        }
        BenchmarkTarget::Sign => {
            let control = format!("head -c {size} /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 -k /tmp/private-key-control -i - -o /dev/null 3< <(echo -n secret)");
            let experiment = format!("head -c {size} /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 -k /tmp/private-key-experiment -i - -o /dev/null 3< <(echo -n secret)");
            cmd!(sh, "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}").run()?;
        }
        BenchmarkTarget::Verify => {
            let control_sig = format!("head -c {size} /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 -k /tmp/private-key-control -i - 3< <(echo -n secret)");
            let control_sig = cmd!(sh, "bash -c {control_sig}").read()?;
            let experiment_sig = format!("head -c {size} /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 -k /tmp/private-key-experiment -i - 3< <(echo -n secret)");
            let experiment_sig = cmd!(sh, "bash -c {experiment_sig}").read()?;

            let control = format!("head -c {size} /dev/zero | ./target/release/veil-control verify --signer {pk_control} -i - --signature {control_sig}");
            let experiment = format!("head -c {size} /dev/zero | ./target/release/veil-experiment verify --signer {pk_experiment} -i - --signature {experiment_sig}");
            cmd!(sh, "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}").run()?;
        }
        BenchmarkTarget::Digest => {
            let control = format!(
                "head -c {size} /dev/zero | ./target/release/veil-control digest - /dev/null"
            );
            let experiment = format!(
                "head -c {size} /dev/zero | ./target/release/veil-experiment digest - /dev/null"
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
