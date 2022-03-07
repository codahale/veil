# Creating A Secret Key

To create a secret key, use the `secret-key` command:

```shell
veil secret-key ./my-secret-key
```

You'll be prompted for a passphrase, and `veil` will write the encrypted secret key to `./my-secret-key`.

That's it. There's no user IDs, no key signing, no key servers, no banging on the keyboard to generate entropy.
