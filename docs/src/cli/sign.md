# Signing A Message

To sign a message, you'll just need the message:

```shell
veil sign ./my-secret-key announcement.txt --key-path 'friends' 'poker'

#=> 2sXLDBeTwHuECPp7QjWKdLYB3M9oLkjuECFDPocwgKUc7TgZyzfNYn2oLH2hen4zZ6m1vc6CwJsSBXiYhaM35udN
```

You can then share `announcement.txt` and the signature and people will be able to verify that the message is from you
and has not been modified.
