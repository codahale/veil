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

This is used iteratively to provide hierarchical key derivation. Public keys are created using hierarchical IDs
like `/friends/alice`, where the secret key is mapped to a private key via the label `/`, which is then mapped to a
private key via the label `friends`, which is then mapped to the final private key via the label `alice`.

To derive a public key from a public key $Q$, the delta scalar $r$ is first multiplied by the curve's base element, then
added to the public key element:

$$ Q' = Q + G^r $$