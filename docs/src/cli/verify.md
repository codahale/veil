# Verifying A Message

To verify a signature of a message, you'll need the signer's public key, the message, and the
signature:

```shell
veil verify TkUWybv8fAvsHPhauPj7edUTVdCHuCFHazA6RjnvwJa announcement.txt \
 3yjygj91feSFzp3HJ7x1SuhBYxD3kdJEQGUCLASaiNxnPSgtCu5vjyDgHNrbAA2Qn94KHtwUesL4mv4MPYXo4kYZ 
```

If the signature is from the given public key and the message hasn't been altered, `veil` will exit
with a status of `0`.
