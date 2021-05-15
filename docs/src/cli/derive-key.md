# Deriving A Public Key

In the same way you can use a secret key to generate a public key with a key ID, you can also derive a public key from
another public key using a sub key ID.

Let's say someone creates a public key with the ID `/one/two`.

```shell
veil-cli public-key ./secret-key /one/two

#=> TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa
```

But they sign a message using a key ID of `/one/two/three`. We can compute the public key `/one/two/three` given the
public key `/one/two`:

```shell
veil-cli derive-key TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa /more

#=> BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```

This produces the same public key as if the owner of the secret key had generated the public key `/one/two/more`:

```shell
veil-cli public-key ./secret-key /one/two/more

#=> BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476
```
