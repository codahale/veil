#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

cargo fmt
cargo build --all-targets --all-features
cargo test --all-features
cargo clippy --all-features --tests --benches
