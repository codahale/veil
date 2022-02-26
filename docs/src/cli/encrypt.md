# Encrypting A Message

To encrypt a message, you need your secret key, the recipients' public keys, and the message:

```shell
veil encrypt ./my-secret-key --derive 'friends' --derive 'poker' \
  message.txt message.txt.veil \
  TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa \
  BfksdzSKbmcS2Suav16dmYE2WxifqauPRL6FZpJt1476 \
  --fakes 18 --padding 1234 
```

This will create a file `message.txt.veil` which the owners of the two public keys can decrypt if they have
your `friends`, `poker` public key. It adds 18 fake recipients, so neither recipient really knows how many people you
sent the message to. It also adds 1234 bytes of random padding, so someone monitoring your communications won't know how
long the message really is.