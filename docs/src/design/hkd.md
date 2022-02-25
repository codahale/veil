# Hierarchical Key Derivation

Each participant in Veil has a secret key, which is a string $S \rgets \allbits{512}$.

## Deriving The Root Key

To derive a root private key from a secret key, a duplex is initialized with a constant key and used to absorb $S$. A
scalar $d$ is then derived from output:

$$
\Cyclist{\literal{veil.scaldf.root}} \\
\Absorb{S} \\
d \gets \SqueezeScalar \\
$$

## Deriving A Private Key From Another Private Key

To derive a private key $d'$ from another private key $d$ with a label $L$, a duplex initialized with a constant key is
used to absorb $[d]G$ and $L$ and squeeze a scalar value:

$$
\Cyclist{\literal{veil.hkd.root}} \\
\Absorb{[d]G} \\
\Absorb{L} \\
r \gets \SqueezeScalar \\
d' \gets d + r \\
$$

## Deriving A Public Key From Another Public Key

To derive a public key $Q'$ from another public key $Q$ with a label $L$, a duplex initialized with a constant key is
used to absorb $Q$ and $L$ and squeeze a scalar value:

$$
\Cyclist{\literal{veil.hkd.label}} \\
\Absorb{Q} \\
\Absorb{L} \\
r \gets \SqueezeScalar \\
Q' \gets Q + [r]G \\
$$

## Hierarchical Key IDs

This is used to provide hierarchical key derivation. Private keys are created using hierarchical key IDs like 
`/friends/alice`, where the secret key is mapped to a private key via `veil.scaldf.root`, which is then mapped to an
intermediate private key via the label `friends`, which is then mapped to the final private key via the label `alice`.

## Disposable Keys

This design allows for the use of disposable, anonymous keys based on a single secret key.

If Alice wants to communicate anonymously with Bea, she can generate a private key with the key
ID `/disposable/ee4c176352b1d0b2df4a699d430ea48e` and share the corresponding public key with Bea via an anonymous
channel. Unless Bea can guess that label, Bea will be unable to determine if her anonymous pen pal is Alice even if she
has Alice's key.

These disposable keys are stateless, as well: if Alice wants to burn that key, all she needs to do is forget the key ID.