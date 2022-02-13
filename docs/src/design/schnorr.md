# Digital Signatures

`veil.schnorr` implements a Schnorr digital signature scheme.

## Signing A Message

Signing is as follows, given a message in 16-byte blocks $M_0..M_n$, a private scalar $d$, and a public point $Q$.

First, a duplex is initialized with a constant key and used to absorb the message blocks and the signer's public key:

$$
\text{Cyclist}(\texttt{veil.schnorr}, \epsilon, \epsilon) \\
\text{AbsorbMore}(M_0, 16) \\
\text{AbsorbMore}(M_1, 16) \\
\dots \\
\text{AbsorbMore}(M_n, 16) \\
\text{Absorb}(Q) \\
$$

(The signer's public key is absorbed after the message to allow [`veil.mres`](mres.md) to search for a header without
having to buffer the results.)

The duplex's state is cloned, and the clone absorbs the signer's private key and 64 bytes of random data. The
ephemeral scalar $k$ is then derived from output:

$$
\text{Absorb}(d) \\
v \overset{R}{\gets} \mathbb{Z}_{2^{512}} \\
\text{Absorb}(v) \\
k \gets \text{SqueezeKey}(64) \bmod \ell \\
$$

The clone's state is discarded, and $k$ is returned to the parent. The commitment point $I$ is calculated and encrypted
as $S_0$:

$$
I = [k]G \\
S_0 \gets \text{Encrypt}(I) \\
$$

A challenge scalar $r$ is derived from output and used to calculate the proof scalar $s$ which is encrypted as $S_1$:

$$
r \gets \text{SqueezeKey}(64) \bmod \ell \\
s = dr + k \\
S_1 \gets \text{Encrypt}(s)
$$

The final signature is $S_0 || S_1$.

## Verifying A Signature

Verification is as follows, given a message in 16-byte blocks $M_0..M_n$, a public point $Q$, and a signature
$S_0 || S_1$.

First, a duplex is created, initialized with a constant key, and used to absorb the message blocks and the signer's
public key:

$$
\text{Cyclist}(\texttt{veil.schnorr}, \epsilon, \epsilon) \\
\text{AbsorbMore}(M_0, 16) \\
\text{AbsorbMore}(M_1, 16) \\
\dots \\
\text{AbsorbMore}(M_n, 16) \\
\text{Absorb}(Q) \\
$$

$S_0$ is decrypted and decoded as $I$ and $r$ is re-derived from output:

$$
I \gets \text{Decrypt}(S_0) \\
r \gets \text{SqueezeKey}(64) \bmod \ell \\
$$

$S_1$ is decrypted and decoded as $s$ and the counterfactual commitment point $I'$ is calculated and compared to the
signature commitment point $I$:

$$
s \gets \text{Decrypt}(S_1) \\
I' = [r]G - [s]Q \\
I' \stackrel{?}{=} I \\
$$

The signature is valid if-and-only-if $I' = I$.

## Security, Forgeability, and Malleability

This construction is equivalent to Construction 13.12 of _Modern Cryptography 3e_ and per Theorem 13.11 secure if the
discrete-logarithm problem is hard relative to ristretto255. `veil.schnorr` transmits the commitment point $I$ as part
of the signature and the verifier calculates $I'$ vs transmitting the challenge scalar $r$ and calculating $r'$. In this
way, `veil.schnorr` is closer to [EdDSA][ed25519] or the Schnorr variant proposed in the [STROBE][strobe] paper.

Some Schnorr/EdDSA implementations (e.g. [ed25519][ed25519]) suffer from malleability issues, allowing for multiple
valid signatures for a given signer and message. [Chalkias et al.][eddsa] describe a strict verification function for
Ed25519 which achieves SUF-CMA security in addition to strong binding:

> 1. Reject the signature if $S \not\in \{0,\ldots,L−1\}$.
> 2. Reject the signature if the public key $A$ is one of 8 small order points.
> 3. Reject the signature if $A$ or $R$ are non-canonical.
> 4. Compute the hash $\text{SHA2}_{512}(R||A||M)$ and reduce it mod $L$ to get a scalar $h$.
> 5. Accept if $8(S·B)−8R−8(h·A)=0$.

Rejecting $S \geq L$ makes the scheme SUF-CMA secure, and rejecting small order $A$ values makes the scheme strongly
binding. `veil.schnorr`'s use of ristretto255's canonical point and scalar encoding routines obviate the need for these
checks. Likewise, ristretto255 is a prime order group, which obviates the need for cofactoring in verification.

When implemented with a prime order group and canonical encoding routines, The Schnorr signature scheme is
[strongly unforgeable under chosen message attack (SUF-CMA) in the random oracle model][schnorr-cma] and
[even with practical cryptographic hash functions][schnorr-hash]. As a consequence, the signatures are non-malleable.

## Indistinguishability and Pseudorandomness

Per [Fleischhacker et al.][ind-sig], this construction produces indistinguishable signatures (i.e., signatures which do
not reveal anything about the signing key or signed message). When encrypted with an unrelated key (i.e., via 
$\text{Encrypt}$), the construction is isomorphic to Fleischhacker et al.'s DRPC compiler for producing pseudorandom
signatures, which are indistinguishable from random.

## Ephemeral Scalar Hedging

In deriving the ephemeral scalar from a cloned context, `veil.schnorr` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.

[ed25519]: https://eprint.iacr.org/2020/823.pdf

[eddsa]: https://eprint.iacr.org/2020/1244.pdf

[schnorr-cma]: https://www.di.ens.fr/david.pointcheval/Documents/Papers/2000_joc.pdf

[schnorr-hash]: http://www.neven.org/papers/schnorr.pdf

[ind-sig]: https://eprint.iacr.org/2011/673.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf

[strobe]: https://eprint.iacr.org/2017/003.pdf