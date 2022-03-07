# Command Line Tool

The Veil cryptosystem is implemented as a command line tool `veil`.

## Installation

To install it, check out this repository and build it yourself:

```shell
git clone https://github.com/codahale/veil
cargo install
```

Because this is a cryptosystem designed by one person with no formal training and has not been
audited, it will never be packaged conveniently. Cryptographic software is primarily used in
high-risk environments where strong assurances of correctness, confidentiality, integrity, etc. are
required, and `veil` does not provide those assurances. It's more of an art installation than a
practical tool.

## Shell Completion

`veil` can generate its own shell completion scripts for Bash, Elvish, Fish, Powershell, and Zsh:

```shell
veil complete zsh /usr/local/share/zsh/site-functions/
```
