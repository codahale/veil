#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# build the current state as release
cargo build --release
cp target/release/veil target/release/veil-experimental

# stash the current state and build the last commit as releast
git stash
cargo build --release
cp target/release/veil target/release/veil-control

# create a secret key with minimal KDF expansion
./target/release/veil secret-key /tmp/secret-key --passphrase-file=README.md --space=1 --time=1

# benchmark encrypting a 1GiB file for 10 recipients
hyperfine --warmup 10 \
  -n control 'cat /dev/zero | head -n 1073741824 | ./target/release/veil-control encrypt --passphrase-file=README.md /tmp/secret-key /one/two - /dev/null H291qG87hgrGkroZiPkFU64i1LBAk2t61LJvZfxqbV9M --fakes 9' \
  -n experimental 'cat /dev/zero | head -n 1073741824 | ./target/release/veil-experimental encrypt --passphrase-file=README.md /tmp/secret-key /one/two - /dev/null H291qG87hgrGkroZiPkFU64i1LBAk2t61LJvZfxqbV9M --fakes 9'

# restore the working set
git stash pop