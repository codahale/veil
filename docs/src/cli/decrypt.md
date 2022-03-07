# Decrypting A Message

To decrypt a message, you'll need the key path of the public key the message was encrypted for, the encrypted message,
and the sender's public key:

```shell
veil decrypt ./my-secret-key \
  reply.txt.veil reply.txt \
  TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa \
  --key-path 'friends' 'poker'
```

This will decrypt and verify the message. If successful, you'll know that the owner of the public key encrypted that
exact message for you. Otherwise, the message may not have been encrypted for you, it may not have been encrypted by
that sender, or the encrypted message may have been tampered with.
