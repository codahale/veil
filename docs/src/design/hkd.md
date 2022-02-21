# Hierarchical Key Derivation

Each participant in Veil has a secret key, which is a string $S \rgets \allbits{512}$.

To derive a private key from a secret key, a duplex is initialized with a constant key and used to absorb $S$. A scalar
$d$ is then derived from output:

$$
\Cyclist{\literal{veil.scaldf.root}} \\
\Absorb{S} \\
d \gets \SqueezeScalar \\
$$

To derive a label scalar $r$ from a label $L$, a duplex initialized with a constant key is used to absorb $L$ and
squeeze a scalar value:

$$
\Cyclist{\literal{veil.scaldf.label}} \\
\Absorb{L} \\
r \gets \SqueezeScalar \\
$$

To derive a private key $d'$ from a root scalar $d$ and key ID label squence $L_0..L_n$, the label scalars $r_0..r_n$
are summed and added to $d$:

$$
d' \gets d + \sum_{i=0}^n{\invoke{veil.scaldf.label}{Derive}{L_i}}
$$

This is used to provide hierarchical key derivation. Private keys are created using hierarchical IDs like 
`/friends/alice`, where the secret key is mapped to a private key via `veil.scaldf.root`, which is then mapped to an
intermediate private key via the label `friends`, which is then mapped to the final private key via the label `alice`.

To derive a public key $Q'$ from a public key $Q$ and key ID label squence $L_0..L_n$, the label scalars $r_0..r_i$ are
summed and multiplied by the curve's generator $G$ which is then added to the public key point:

$$
Q' \gets Q + [\textstyle\sum_{i=0}^n{\invoke{veil.scaldf.label}{Derive}{L_i}}]G
$$

## Disposable Keys

This design allows for the use of disposable, anonymous keys based on a single secret key.

If Alice wants to communicate anonymously with Bea, she can generate a private key with the key
ID `/disposable/ee4c176352b1d0b2df4a699d430ea48e` and share the corresponding public key with Bea via an anonymous
channel. Unless Bea can guess that label, Bea will be unable to determine if her anonymous pen pal is Alice even if she
has Alice's key.

These disposable keys are stateless, as well: if Alice wants to burn that key, all she needs to do is forget the key ID.