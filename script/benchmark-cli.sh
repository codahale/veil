#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# remove the old versions, if any
rm -f target/release/veil-experiment
rm -f target/release/veil-control

# build the current state as release
cargo build --release --all-features
cp target/release/veil target/release/veil-experiment

# stash the current state and build the last commit as release
git stash

cargo build --release --all-features
cp target/release/veil target/release/veil-control

# create a private key with minimal KDF expansion, using both commands to make sure they work
./target/release/veil-control private-key /tmp/private-key --passphrase-file=README.md --space=0 --time=0
./target/release/veil-experiment private-key /tmp/private-key --passphrase-file=README.md --space=0 --time=0

PUBLIC_KEY="$(./target/release/veil-control public-key /tmp/private-key --passphrase-file=README.md)"
SIZE=${SIZE:-"$((1024 * 1024 * 1024))"} # 1 GiB file

case $1 in
"encrypt")
  # benchmark encrypting a file for 10 receivers
  hyperfine --warmup 10 -S /bin/sh \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control encrypt --passphrase-file=README.md /tmp/private-key - /dev/null $PUBLIC_KEY --fakes 9" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment encrypt --passphrase-file=README.md /tmp/private-key - /dev/null $PUBLIC_KEY --fakes 9" \
    ;
  ;;
"sign")
  # benchmark signing a file
  hyperfine --warmup 10 -S /bin/sh \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control sign --passphrase-file=README.md /tmp/private-key - /dev/null" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment sign --passphrase-file=README.md /tmp/private-key - /dev/null" \
    ;
  ;;
"verify")
  # benchmark verifying a signature
  SIG=$(head -c "$SIZE" /dev/zero | ./target/release/veil-control sign --passphrase-file=README.md /tmp/private-key -)
  hyperfine --warmup 10 -S /bin/sh \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control verify $PUBLIC_KEY - $SIG" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment verify $PUBLIC_KEY - $SIG" \
    ;
  ;;
"digest")
  # benchmark hashing a file
  hyperfine --warmup 10 -S /bin/sh \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control digest - /dev/null" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment digest - /dev/null" \
    ;
  ;;
*)
  echo "unknown benchmark name"
  ;;
esac

# restore the working set
git stash pop
