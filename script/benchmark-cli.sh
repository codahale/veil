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
./target/release/veil-control private-key /tmp/private-key-control --passphrase-file=README.md --m-cost=8 --t-cost=1
./target/release/veil-experiment private-key /tmp/private-key-experiment --passphrase-file=README.md --m-cost=8 --t-cost=1

PK_CONTROL="$(./target/release/veil-control public-key /tmp/private-key-control --passphrase-file=README.md)"
PK_EXPERIMENT="$(./target/release/veil-control public-key /tmp/private-key-experiment --passphrase-file=README.md)"
SIZE=${SIZE:-"$((1024 * 1024 * 1024))"} # 1 GiB file

case $1 in
"encrypt")
  # benchmark encrypting a file for 10 receivers
  hyperfine --warmup 10 -S /bin/sh \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control encrypt --passphrase-file=README.md /tmp/private-key-control - /dev/null $PK_CONTROL --fakes 9" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment encrypt --passphrase-file=README.md /tmp/private-key-experiment - /dev/null $PK_EXPERIMENT --fakes 9" \
    ;
  ;;
"sign")
  # benchmark signing a file
  hyperfine --warmup 10 -S /bin/sh \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control sign --passphrase-file=README.md /tmp/private-key-control - /dev/null" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment sign --passphrase-file=README.md /tmp/private-key-experiment - /dev/null" \
    ;
  ;;
"verify")
  # benchmark verifying a signature
  SIG_CONTROL=$(head -c "$SIZE" /dev/zero | ./target/release/veil-control sign --passphrase-file=README.md /tmp/private-key-control -)
  SIG_EXPERIMENT=$(head -c "$SIZE" /dev/zero | ./target/release/veil-experiment sign --passphrase-file=README.md /tmp/private-key-experiment -)
  hyperfine --warmup 10 -S /bin/sh \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control verify $PK_CONTROL - $SIG_CONTROL" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment verify $PK_EXPERIMENT - $SIG_EXPERIMENT" \
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
