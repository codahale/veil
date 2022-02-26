# Deriving A Public Key

In the same way you can use a secret key to generate a public key with a label, you can also derive a public key from
another public key using a label.

Let's say someone creates a public key with the labels `one` and `two`.

```shell
veil public-key ./secret-key --key-labels 'one' 'two'

#=> TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa
```

```mermaid
flowchart LR
    s([secret]) -.-> r(root) --> one --> two
```

But they sign a message using the labels `one`, `two`, and `three`. 

```mermaid
flowchart LR
    s([secret]) -.-> r(root) --> one --> two --> three
```

We can compute the public key `three` given the public key `two`:

```shell
veil derive-key TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa --key-labels 'three'

#=> BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```

```mermaid
flowchart LR
    two --> three
```

This produces the same public key as if the owner of the secret key had generated the public key with `one`, `two`, and
`three`:

```shell
veil public-key ./secret-key --key-labels 'one' 'two' 'three'

#=> BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```

```mermaid
flowchart LR
    s([secret]) -.-> r(root) --> one --> two --> three
```
