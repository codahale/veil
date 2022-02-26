# Creating Message Digests

To create a digest of a message, you'll just need the message:

```shell
veil digest announcement.txt

#=> 2H7V27gNTn4bNCgfQPkxV8zZvzr64ujdHLAYafbaEVXLFyveqpZ6pGjZAomZGop6hcvyWt4QtvYwEhKELHcRVUHf
```

## Including Metadata

The `digest` command accepts optional metadata strings which are included in the calculation of the digest:

```shell
veil digest announcement.txt --metadata 'announcement.txt' --metadata 'made-with-veil'

#=> 5ADcvqmnuAU9nyesF6saNW2Jwbg3yTbfuyJnQ1L7n3ZSggxA5tGS4UpDE98hzhVb77oPhsACeHk8STqdo2T6ZpK
```

## Message Authentication Codes

To create a MAC using a shared key, include the shared key as metadata:

```shell
veil digest announcement.txt --metadata 'our special secret'

#=> 4aUDnTUrGXkvdTcTi19JfwrA5xoSw9SRd86VCMe5N1mGHzFLXhvwoc716rQazXjJUpBEQjBnfqUBHsiRMBiyX1M1
```
