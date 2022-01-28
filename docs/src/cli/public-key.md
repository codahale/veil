# Generating A Public Key

Now that you have a secret key, you can generate a public key to share with others:

```shell
veil public-key ./my-secret-key /test-keys/1

#=> TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa
```

This generates a public key with the key ID `/test-keys/1`. You can then give this public key to people, so they can
send you encrypted messages.

Each key ID you use will produce a different public key, which allows you to give different public keys to different
people. If those people compare those public keys, they won't be able to know they're both yours unless you tell them,
or they guess the key IDs.