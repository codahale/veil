#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# remove the old versions, if any
rm -f target/release/veil-experiment
rm -f target/release/veil-control

# build the current state as release
cargo build --release
cp target/release/veil target/release/veil-experiment

# stash the current state and build the last commit as release
git stash

cargo build --release
cp target/release/veil target/release/veil-control

# create a private key with minimal KDF expansion, using both commands to make sure they work
./target/release/veil-control private-key /tmp/private-key-control --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n secret)
./target/release/veil-experiment private-key /tmp/private-key-experiment --passphrase-fd=3 --time-cost=0 --memory-cost=0 3< <(echo -n secret)

PK_CONTROL="$(./target/release/veil-control public-key /tmp/private-key-control --passphrase-fd=3 3< <(echo -n secret))"
PK_EXPERIMENT="$(./target/release/veil-experiment public-key /tmp/private-key-experiment --passphrase-fd=3  3< <(echo -n secret))"
SIZE=${SIZE:-"$((1024 * 1024 * 1024))"} # 1 GiB file

case $1 in
"encrypt")
  # benchmark encrypting a file for 10 receivers
  hyperfine --warmup 10 -S /bin/bash \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control encrypt --passphrase-fd=3 /tmp/private-key-control - /dev/null $PK_CONTROL --fakes 9 3< <(echo -n secret)" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment encrypt --passphrase-fd=3 /tmp/private-key-experiment - /dev/null $PK_EXPERIMENT --fakes 9 3< <(echo -n secret)" \
    ;
  ;;
"sign")
  # benchmark signing a file
  hyperfine --warmup 10 -S /bin/bash \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 /tmp/private-key-control - /dev/null 3< <(echo -n secret)" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 /tmp/private-key-experiment - /dev/null 3< <(echo -n secret)" \
    ;
  ;;
"verify")
  # benchmark verifying a signature
  SIG_CONTROL=$(head -c "$SIZE" /dev/zero | ./target/release/veil-control sign --passphrase-fd=3 /tmp/private-key-control - 3< <(echo -n secret))
  SIG_EXPERIMENT=$(head -c "$SIZE" /dev/zero | ./target/release/veil-experiment sign --passphrase-fd=3 /tmp/private-key-experiment - 3< <(echo -n secret))
  hyperfine --warmup 10 -S /bin/bash \
    -n control "head -c $SIZE /dev/zero | ./target/release/veil-control verify $PK_CONTROL - $SIG_CONTROL" \
    -n experimental "head -c $SIZE /dev/zero | ./target/release/veil-experiment verify $PK_EXPERIMENT - $SIG_EXPERIMENT" \
    ;
  ;;
"digest")
  # benchmark hashing a file
  hyperfine --warmup 10 -S /bin/bash \
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
