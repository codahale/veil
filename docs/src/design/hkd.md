# Key Derivation

Each participant in Veil has a secret key, which is a 64-byte random string $S$. To derive a private key from a secret
key, the secret key is mapped to a ristretto255 scalar $d$ using a STROBE protocol:

```text
INIT('veil.scaldf.root', level=256)
KEY(S)
PRF(64) -> d
```

A delta scalar $r$ is derived from an opaque label value $L$ via another STROBE protocol:

```text
INIT('veil.scaldf.label', level=256)
KEY(L)
PRF(64) -> r
```

The derived private scalar $d'$ is then calculated:

$$ d' = d + r $$

This is used iteratively to provide hierarchical key derivation. Private keys are created using hierarchical IDs
like `/friends/alice`, where the secret key is mapped to a private key via the label `/`, which is then mapped to a
private key via the label `friends`, which is then mapped to the final private key via the label `alice`.

To derive a public key from a public key $Q$, the delta scalar $r$ is first multiplied by the curve's base element, then
added to the public key element:

$$ Q' = Q + G^r $$

## Disposable Keys

This design allows for the use of disposable, anonymous keys based on a single secret key.

If Alice wants to communicate anonymously with Bea, she can generate a private key with the key
ID `/disposable/ee4c176352b1d0b2df4a699d430ea48e` and share the corresponding public key with Bea via an anonymous
channel. Unless Bea can guess that label, Bea will be unable to determine if her anonymous pen pal is Alice even if she
has Alice's key.

These disposable keys are stateless, as well: if Alice wants to burn that key, all she needs to do is forget the key ID.