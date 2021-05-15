# Decrypting A Message

To decrypt a message, you'll need the key ID the message was encrypted for, the encrypted message, and the sender's
public key:

```shell
veil-cli decrypt ./my-secret-key /friends/poker reply.txt.veil reply.txt \
  TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa
```

This will decrypt and verify the message. If successful, you'll know that the owner of the public key encrypted that
exact message for you.