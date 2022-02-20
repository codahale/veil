#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ensure we have the freshest build
cargo build --release

# create a secret key with minimal KDF expansion
./target/release/veil secret-key /tmp/secret-key --passphrase-file=README.md --space=1 --time=1

# benchmark encrypting a 1GiB file for 10 recipients
hyperfine --warmup 10 'cat /dev/zero | head -n 1073741824 | ./target/release/veil encrypt --passphrase-file=README.md /tmp/secret-key /one/two - /dev/null H291qG87hgrGkroZiPkFU64i1LBAk2t61LJvZfxqbV9M --fakes 9'