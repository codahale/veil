---
title: Veil User Manual
---

The Veil cryptosystem is implemented as a command line tool `veil`.

## Installation

To install it, check out this repository and build it yourself:

```text
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

```text
veil complete zsh /usr/local/share/zsh/site-functions/
```

## Creating A Secret Key

To create a secret key, use the `secret-key` command:

```text
veil secret-key ./my-secret-key
```

You'll be prompted for a passphrase, and `veil` will write the encrypted secret key to
`./my-secret-key`.

That's it. There's no user IDs, no key signing, no key servers, no banging on the keyboard to
generate entropy.

## Generating A Public Key

Now that you have a secret key, you can generate a public key to share with others:

```text
$ veil public-key ./my-secret-key

TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa
```

This is your root public key, which means it's derived directly from your secret key:

```{.graphviz}
digraph hkd1 {
    rankdir=LR;
    node [style=rounded];
    secret_key [ label = "secret-key", shape = rect, style = bold ];
    root [ label = "root", shape = rect ];

    secret_key -> root;
}
```

You can then give this public key to people, so they can send you encrypted messages.

### Derived Keys

You can also create derived keys using a key path:

```text
$ veil public-key ./my-secret-key --key-path 'test-keys'

26UQ714wrvgp3YCFtMRoxWGM8GyxQkFBmknnudUaBQQL
```

This derives a public key from your root public key using a key path with a single label,
`test-keys`:

```{.graphviz}
digraph hkd1 {
    rankdir=LR;
    node [style=rounded];
    secret_key [ label = "secret-key", shape = rect, style = bold ];
    root [ label = "root", shape = rect ];
    test_keys [ label = "test-keys", fontname = "Courier" ]

    secret_key -> root;
    root -> test_keys;
}
```

### Hierarchically Derived Keys

You can use a key path with multiple labels to [hierarchically derive keys](../design/hkd.md):

```text
$ veil public-key ./my-secret-key --key-path 'test-keys' 'example'

BkxmubpmYmKXDJ3euSmPRcvprQBPxFUaHd95Dz76QBV
```

This derives a public key from the `test-keys` public key using the label `example`:

```{.graphviz}
digraph hkd1 {
    rankdir=LR;
    node [style=rounded];
    secret_key [ label = "secret-key", shape = rect, style = bold ];
    root [ label = "root", shape = rect ];
    test_keys [ label = "test-keys", fontname = "Courier" ]
    example [ label = "example", fontname = "Courier" ]

    secret_key -> root;
    root -> test_keys;
    test_keys -> example;
}
```

Each key path you use will produce a different public key, which allows you to give different public
keys to different people. If those people compare those public keys, they won't be able to know
they're both yours unless you tell them, or they have your root public key and guess the key path.

## Deriving A Public Key

In the same way you can use a secret key to generate a public key with a key path, you can also
derive a public key from another public key using a key path.

Let's say someone creates a public key with the key path `one` and `two`.

```text
$ veil public-key ./secret-key --key-path 'one' 'two'

TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa
```

```{.graphviz}
digraph hkd1 {
    rankdir=LR;
    node [style=rounded];
    secret_key [ label = "secret-key", shape = rect, style = bold ];
    root [ label = "root", shape = rect ];
    one [ label = "one", fontname = "Courier" ]
    two [ label = "two", fontname = "Courier" ]

    secret_key -> root;
    root -> one;
    one -> two;
}
```

But they sign a message using the key path `one`, `two`, and `three`.

```{.graphviz}
digraph hkd1 {
    rankdir=LR;
    node [style=rounded];
    secret_key [ label = "secret-key", shape = rect, style = bold ];
    root [ label = "root", shape = rect ];
    one [ label = "one", fontname = "Courier" ]
    two [ label = "two", fontname = "Courier" ]
    three [ label = "three", fontname = "Courier" ]

    secret_key -> root;
    root -> one;
    one -> two;
    two -> three;
}
```

We can compute the public key `three` given the public key `two`:

```text
$ veil derive-key TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa --key-path 'three'

BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```

```{.graphviz}
digraph hkd1 {
    rankdir=LR;
    node [style=rounded];
    two [ label = "two", fontname = "Courier" ]
    three [ label = "three", fontname = "Courier" ]

    two -> three;
}
```

This produces the same public key as if the owner of the secret key had generated the public key
with the key path `one`, `two`, and `three`:

```text
$ veil public-key ./secret-key --key-path 'one' 'two' 'three'

BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```

```{.graphviz}
digraph hkd1 {
    rankdir=LR;
    node [style=rounded];
    secret_key [ label = "secret-key", shape = rect, style = bold ];
    root [ label = "root", shape = rect ];
    one [ label = "one", fontname = "Courier" ]
    two [ label = "two", fontname = "Courier" ]
    three [ label = "three", fontname = "Courier" ]

    secret_key -> root;
    root -> one;
    one -> two;
    two -> three;
}
```

## Encrypting A Message

To encrypt a message, you need your secret key, the recipients' public keys, and the message:

```text
veil encrypt ./my-secret-key \
  message.txt message.txt.veil \
  TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa \
  BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476 \
  --key-path 'friends' 'poker' \
  --fakes 18 --padding 1234 
```

This will create a file `message.txt.veil` which the owners of the two public keys can decrypt if
they have your `friends`, `poker` public key. It adds 18 fake recipients, so neither recipient
really knows how many people you sent the message to. It also adds 1234 bytes of random padding, so
someone monitoring your communications won't know how long the message really is.

## Decrypting A Message

To decrypt a message, you'll need the key path of the public key the message was encrypted for, the
encrypted message, and the sender's public key:

```text
veil decrypt ./my-secret-key \
  reply.txt.veil reply.txt \
  TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa \
  --key-path 'friends' 'poker'
```

This will decrypt and verify the message. If successful, you'll know that the owner of the public
key encrypted that exact message for you. Otherwise, the message may not have been encrypted for
you, it may not have been encrypted by that sender, or the encrypted message may have been tampered
with.

## Signing A Message

To sign a message, you'll just need the message:

```text
$ veil sign ./my-secret-key announcement.txt --key-path 'friends' 'poker'

2sXLDBeTwHuECPp7QjWKdLYB3M9oLkjuECFDPocwgKUc7TgZyzfNYn2oLH2hen4zZ6m1vc6CwJsSBXiYhaM35udN
```

You can then share `announcement.txt` and the signature and people will be able to verify that the
message is from you and has not been modified.

## Verifying A Message

To verify a signature of a message, you'll need the signer's public key, the message, and the
signature:

```text
veil verify TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa announcement.txt \
 3yjygj91feSFzp3HJ7x1SuhBYxD3kdJEQGUCLASaiNxnPSgtCu5vjyDgHNrbAA2Qn94KHtwUesL4mv4MPYXo4kYZ 
```

If the signature is from the given public key and the message hasn't been altered, `veil` will exit
with a status of `0`.

## Creating Message Digests

To create a digest of a message, you'll just need the message:

```text
$ veil digest announcement.txt

2H7V27gNTn4bNCgfQPkxV8zZvzr64ujdHLAYafbaEVXLFyveqpZ6pGjZAomZGop6hcvyWt4QtvYwEhKELHcRVUHf
```

### Including Metadata

The `digest` command accepts optional metadata strings which are included in the calculation of the
digest:

```text
$ veil digest announcement.txt --metadata 'announcement.txt' --metadata 'made-with-veil'

5ADcvqmnuAU9nyesF6saNW2Jwbg3yTbfuyJnQ1L7n3ZSggxA5tGS4UpDE98hzhVb77oPhsACeHk8STqdo2T6ZpK
```

### Message Authentication Codes

To create a MAC using a shared key, include the shared key as metadata:

```text
$ veil digest announcement.txt --metadata 'our special secret'

4aUDnTUrGXkvdTcTi19JfwrA5xoSw9SRd86VCMe5N1mGHzFLXhvwoc716rQazXjJUpBEQjBnfqUBHsiRMBiyX1M1
```
