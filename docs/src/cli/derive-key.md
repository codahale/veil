# Deriving A Public Key

In the same way you can use a secret key to generate a public key with a label, you can also derive a public key from
another public key using a label.

Let's say someone creates a public key with the labels `one` and `two`.

```shell
veil public-key ./secret-key --derive 'one' --derive 'two'

#=> TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa
```

But they sign a message using the labels `one`, `two`, and `three`. We can compute the public key `three` given the
public key `two`:

```shell
veil derive-key TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa --derive 'three'

#=> BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```

This produces the same public key as if the owner of the secret key had generated the public key with `one`, `two`, and
`three`:

```shell
veil public-key ./secret-key --derive 'one' --derive 'two' --derive 'three'

#=> BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```
