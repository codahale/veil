# Hierarchical Key Derivation

Each participant in Veil has a secret key, which is a 64-byte random string $S$.

To derive a private key from a secret key, a duplex is initialized with $S$ as the key and an initialization string as
the counter. A scalar $d$ is then derived from output:

$$
\text{Cyclist}(S, \epsilon, \texttt{veil.scaldf.root}) \\
d \gets \text{SqueezeKey}(64) \bmod \ell \\
$$

To derive a private key $d_n$ from a root scalar $d_0$ and key ID label squence $L_0..L_n$, a series of unkeyed duplexes
are used to absorb label values $L_i$ and derive delta scalars $r_i$ from output:

$$
\dots \\
\text{Cyclist}(\texttt{veil.scaldf.label}, \epsilon, \epsilon) \\
\text{Absorb}(L_i) \\
r_i \gets \text{SqueezeKey}(64) \bmod \ell \\
d_i = d_{i-1} + r_i \\
\dots \\
d_n = d_{n-1} + r_{n-1} \\
$$

This is used iteratively to provide hierarchical key derivation. Private keys are created using hierarchical IDs
like `/friends/alice`, where the secret key is mapped to a private key via the label `/`, which is then mapped to a
private key via the label `friends`, which is then mapped to the final private key via the label `alice`.

To derive a public key from a public key $Q$, the delta scalars $r_0..r_i$ are summed and multiplied by the curve's
generator $G$ which is then added to the public key point:

$$ Q' = Q + [\textstyle\sum_{i=0}^nr_i]G $$

## Disposable Keys

This design allows for the use of disposable, anonymous keys based on a single secret key.

If Alice wants to communicate anonymously with Bea, she can generate a private key with the key
ID `/disposable/ee4c176352b1d0b2df4a699d430ea48e` and share the corresponding public key with Bea via an anonymous
channel. Unless Bea can guess that label, Bea will be unable to determine if her anonymous pen pal is Alice even if she
has Alice's key.

These disposable keys are stateless, as well: if Alice wants to burn that key, all she needs to do is forget the key ID.