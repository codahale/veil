use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use xshell::{cmd, Shell};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();

    let sh = Shell::new()?;
    sh.change_dir(project_root());

    if args.is_empty() {
        build(&sh, false)?;
    } else if args == vec!["ci"] {
        build(&sh, true)?;
    } else if args[0] == "benchmark" {
        if args.len() < 2 {
            bail!("invalid benchmark target");
        }
        benchmark(&sh, &args[1])?;
    }

    Ok(())
}

fn benchmark(sh: &Shell, target: &str) -> Result<()> {
    // remove the old versions, if any
    cmd!(sh, "rm -f target/release/veil-experiment").run()?;
    cmd!(sh, "rm -f target/release/veil-control").run()?;

    // build the current state as release
    cmd!(sh, "cargo build --release").run()?;
    cmd!(sh, "cp target/release/veil target/release/veil-experiment").run()?;

    // stash the current state and build the last commit as release
    cmd!(sh, "git stash").run()?;
    cmd!(sh, "cargo build --release").run()?;
    cmd!(sh, "cp target/release/veil target/release/veil-control").run()?;

    // create a private key with minimal KDF expansion, using both commands to make sure they work
    cmd!(sh, "bash -c './target/release/veil-control private-key /tmp/private-key-control --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n 'secret')'").run()?;
    cmd!(sh, "bash -c './target/release/veil-experiment private-key /tmp/private-key-experiment --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n secret)'").run()?;

    const SIZE: usize = 1024 * 1024 * 1024;
    let size = format!("{SIZE}");
    let pk_control = cmd!(sh, "bash -c './target/release/veil-control public-key /tmp/private-key-control --passphrase-fd=3 3< <(echo -n secret)'").read()?;
    let pk_experiment = cmd!(sh, "bash -c './target/release/veil-experiment public-key /tmp/private-key-experiment --passphrase-fd=3 3< <(echo -n secret)'").read()?;

    if target == "encrypt" {
        let control =format!("head -c {size} /dev/zero | ./target/release/veil-control encrypt --passphrase-fd=3 /tmp/private-key-control - /dev/null {pk_control} --fakes 9 3< <(echo -n secret)");
        let experiment =format!("head -c {size} /dev/zero | ./target/release/veil-experiment encrypt --passphrase-fd=3 /tmp/private-key-experiment - /dev/null {pk_experiment} --fakes 9 3< <(echo -n secret)");
        cmd!(
            sh,
            "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}"
        )
        .run()?;
    } else if target == "sign" {
        let control =format!("head -c {SIZE} /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 /tmp/private-key-control - /dev/null 3< <(echo -n secret)");
        let experiment =format!("head -c {SIZE} /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 /tmp/private-key-experiment - /dev/null 3< <(echo -n secret)");
        cmd!(
            sh,
            "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}"
        )
        .run()?;
    } else if target == "verify" {
        let control_sig = format!("head -c {size} /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 /tmp/private-key-control - 3< <(echo -n secret)");
        let control_sig = cmd!(sh, "bash -c {control_sig}").read()?;
        let experiment_sig = format!("head -c {size} /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 /tmp/private-key-experiment - 3< <(echo -n secret)");
        let experiment_sig = cmd!(sh, "bash -c {experiment_sig}").read()?;

        let control =format!("head -c {SIZE} /dev/zero | ./target/release/veil-control verify {pk_control} - {control_sig}");
        let experiment =format!("head -c {SIZE} /dev/zero | ./target/release/veil-experiment verify {pk_experiment} - {experiment_sig}");
        cmd!(
            sh,
            "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}"
        )
        .run()?;
    } else if target == "digest" {
        let control =
            format!("head -c {size} /dev/zero | ./target/release/veil-control digest - /dev/null");
        let experiment = format!(
            "head -c {size} /dev/zero | ./target/release/veil-experiment digest - /dev/null"
        );
        cmd!(
            sh,
            "hyperfine --warmup 10 -S /bin/bash -n control {control} -n experimental {experiment}"
        )
        .run()?;
    } else {
        bail!("unknown benchmark target");
    }

    // restore the working set
    cmd!(sh, "git stash pop").run()?;

    Ok(())
}

fn build(sh: &Shell, check: bool) -> Result<()> {
    let check = if check { " --check" } else { "--" };
    cmd!(sh, "cargo fmt {check}").run()?;
    cmd!(sh, "cargo build --all-targets --all-features").run()?;
    cmd!(sh, "cargo test --all-features").run()?;
    cmd!(sh, "cargo clippy --all-features --tests --benches").run()?;

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
