# Veil User Manual

Veil is a public-key cryptosystem that provides confidentiality, authenticity, and integrity
services for messages of arbitrary sizes and multiple receivers. Veil is implemented as a command
line tool `veil`. This document describes its feature set and usage.

## Installation

To install Veil, check out this repository and build it yourself:

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
veil complete --shell zsh --output /usr/local/share/zsh/site-functions/
```

## Creating A Secret Key

To create a secret key, use the `secret-key` command:

```shell
veil secret-key --output ./my-secret-key
```

You'll be prompted for a passphrase, and `veil` will write the encrypted secret key to
`./my-secret-key`. That's it. There's no user IDs, no key signing, no key servers, no banging on
the keyboard to generate entropy.

## Generating A Public Key

Now that you have a secret key, you also have a public key to share with others:

```shell
veil public-key --secret-key ./my-secret-key --output ./contacts/me
```

You can then give this public key to people, so they can send you encrypted messages.

## Encrypting A Message

To encrypt a message, you need your secret key, the receivers' public keys, and the message:

```shell
veil encrypt --secret-key ./my-secret-key \
     --input message.txt \
     --output message.txt.veil \
     --receiver ./contacts/alice \
     --receiver ./contacts/bob \
     --fakes 18
```

This will create a file `message.txt.veil` which the owners of the two public keys can decrypt if
they have your public key. It adds 18 fake receivers, so neither receiver really knows how many
people you sent the message to.

## Decrypting A Message

To decrypt a message, you'll need the encrypted message and the sender's public key:

```shell
veil decrypt --secret-key ./my-secret-key \
     --input reply.txt.veil \
     --output reply.txt \
     --sender ./contacts/bob
```

This will decrypt and verify the message. If successful, you'll know that the owner of the public
key encrypted that exact message for you. Otherwise, the message may not have been encrypted for
you, it may not have been encrypted by that sender, or the encrypted message may have been tampered
with.

## Signing A Message

To sign a message, you'll just need the message:

```shell
veil sign --secret-key ./my-secret-key \
     --input announcement.txt \
     --output announcement.txt.veil-sig
```

You can then share `announcement.txt` and `announcement.txt.veil-sig` and people will be able to
verify that the message is from you and has not been modified.

## Verifying A Message

To verify a signature of a message, you'll need the signer's public key, the message, and the
signature:

```shell
veil verify --signer ./contacts/me \
     --signature announcement.txt.veil-sig \
     --input announcement.txt
```

If the signature is from the given public key and the message hasn't been altered, `veil` will exit
with a status of `0`.

## Creating Message Digests

To create a digest of a message, you'll just need the message:

```shell
veil digest --input announcement.txt

#=> 5fQPsn8hoaVddFG26cWQ5QFdqxWtUPNaZ9zH2E6LYzFn
```

### Checking Message Digests

To check the digest of a message, you'll need the message and the digest:

```shell
veil digest --input announcement.txt --check '5fQPsn8hoaVddFG26cWQ5QFdqxWtUPNaZ9zH2E6LYzFn'
```

If the digest of the message matches the given digest, `veil` will exit with a status of `0`.

### Including Metadata

The `digest` command accepts an optional sequence of metadata strings which are included in the
calculation of the digest:

```shell
veil digest --input announcement.txt \
     --metadata 'announcement.txt' \
     --metadata 'made-with-veil'

#=> F8s5aLxQJbGiEhWacUAe4nDCHVSEwycDavYFqe2TyND1
```

### Message Authentication Codes

To create a MAC using a shared key, include the shared key as metadata:

```shell
veil digest --input announcement.txt \
     --metadata 'our special secret'

#=> 9UH6dDyYZ5XrYyqn9DQvuzp1zz9wtiaVfaAPvwyhTZhT
```
