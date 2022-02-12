# Hierarchical Key Derivation

Each participant in Veil has a secret key, which is a 64-byte random string $S$.

To derive a private key from a secret key, the secret key is absorbed with an unkeyed hash and a ristretto255 scalar $d$
derived from output:

$$
\text{Cyclist}(\epsilon, \epsilon, \epsilon) \\
\text{Absorb}(\texttt{veil.scaldf.root}) \\
\text{Absorb}(S) \\
d \gets \text{SqueezeKey}(64) \bmod \ell \\
$$

Another unkeyed hash is used to absorb an opaque label value $L$ and a delta scalar $r$ is derived from output: 

$$
\text{Cyclist}(\epsilon, \epsilon, \epsilon) \\
\text{Absorb}(\texttt{veil.scaldf.label}) \\
\text{Absorb}(L) \\
r \gets \text{SqueezeKey}(64) \bmod \ell \\
$$

The derived private scalar $d'$ is then calculated:

$$ d' = d + r $$

This is used iteratively to provide hierarchical key derivation. Private keys are created using hierarchical IDs
like `/friends/alice`, where the secret key is mapped to a private key via the label `/`, which is then mapped to a
private key via the label `friends`, which is then mapped to the final private key via the label `alice`:

$$
d_0 \gets \text{veil.scaldf.root}(S) \\
d_1 = d_0 + \text{veil.scaldf.label}(L_0) \\
\dots \\
d_n = d_{n-1} + \text{veil.scaldf.label}(L_{n-1}) \\
$$

To derive a public key from a public key $Q$, the delta scalar $r$ is first multiplied by the curve's base point, then
added to the public key point:

$$ Q' = Q + [r]G $$


## Disposable Keys

This design allows for the use of disposable, anonymous keys based on a single secret key.

If Alice wants to communicate anonymously with Bea, she can generate a private key with the key
ID `/disposable/ee4c176352b1d0b2df4a699d430ea48e` and share the corresponding public key with Bea via an anonymous
channel. Unless Bea can guess that label, Bea will be unable to determine if her anonymous pen pal is Alice even if she
has Alice's key.

These disposable keys are stateless, as well: if Alice wants to burn that key, all she needs to do is forget the key ID.