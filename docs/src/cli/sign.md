# Signing A Message

To sign a message, you'll need your key ID and the message to sign:

```shell
veil sign ./my-secret-key /friends/poker announcement.txt

#=> 2sXLDBeTwHuECPp7QjWKdLYB3M9oLkjuECFDPocwgKUc7TgZyzfNYn2oLH2hen4zZ6m1vc6CwJsSBXiYhaM35udN
```

You can then share `announcement.txt` and the signature and people will be able to verify that the message is from you
and has not been modified.