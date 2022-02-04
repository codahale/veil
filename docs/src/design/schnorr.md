# Digital Signatures

`veil.schnorr` implements a Schnorr digital signature scheme.

## Signing A Message

Signing is as follows, given a message in blocks $M_0...M_N$, a private scalar $d$, and a public point $Q$:

```text
INIT('veil.schnorr', level=128)

AD('message-start', meta=true)
SEND_CLR('',        more=false)
SEND_CLR(M_0,       more=true)
SEND_CLR(M_1,       more=true)
…
SEND_CLR(M_N,       more=true)
AD('message-end',   meta=true)
AD(LE_U64(LEN(M)),  meta=true, more=true)

AD('signer',    meta=true)
AD(LE_U64(N_Q), meta=true, more=true)
AD(Q)
```

(The signer's public key is included after the message to allow `veil.mres` to search for a header without having to
buffer the results.)

The protocol's state is cloned, and the clone is keyed with the signer's private key and 64 bytes of random data. The
ephemeral scalar $k$ is then derived from PRF output:

```text
AD('secret-value',  meta=true)
AD(LE_U64(N_d),     meta=true, more=true)
KEY(d)

AD('hedged-value', meta=true)
AD(LE_U64(64),     meta=true, more=true)
KEY(rand(64))

AD('commitment-scalar', meta=true)
AD(LE_U64(64),          meta=true, more=true)
PRF(64) -> k
```

The clone's state is discarded, and $k$ is returned to the parent. 

The commitment point $I = [k]G$ is encrypted and sent as $S_0$:

```text
AD('commitment-point', meta=true)
AD(LE_U64(LEN(I)),     meta=true, more=true)
SEND_ENC(I) -> S_0
```

A challenge scalar $r$ is extracted from PRF output:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r
```

The proof scalar $s = dr + k$ is encrypted and sent as $S_1$:

```text
AD('proof-scalar', meta=true)
AD(LE_U64(LEN(s)), meta=true, more=true)
SEND_ENC(s) -> S_1
```

The final signature is $S_0 || S_1$.

## Verifying A Signature

To verify, `veil.schnorr` is run with a message in blocks $M_0...M_N$, a public point $Q$, and a signature $S_0 || S_1$:

```text
INIT('veil.schnorr', level=128)

AD('message-start', meta=true)
RECV_CLR('',        more=false)
RECV_CLR(M_0,       more=true)
RECV_CLR(M_1,       more=true)
…
RECV_CLR(M_N,       more=true)
AD('message-end',   meta=true)
AD(LE_U64(LEN(M)),  meta=true, more=true)

AD('signer',    meta=true)
AD(LE_U64(N_Q), meta=true, more=true)
AD(Q)
```

$S_0$ is decrypted and decoded as $I$:

```text
AD('commitment-point', meta=true)
AD(LE_U64(LEN(S_0)),   meta=true, more=true)
RECV_ENC(S_0) -> I
```

The challenge scalar $r$ is extracted from PRF output:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r
```

$S_1$ is decrypted and decoded as $s$:

```text
AD('proof-scalar',   meta=true)
AD(LE_U64(LEN(S_1)), meta=true, more=true)
RECV_ENC(S_1) -> s
```

The counterfactual commitment point $I' = [r]G - [s]Q$.

The signature is valid if-and-only-if $I' \equiv I$.

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
> 4. Compute the hash ${SHA512}(R||A||M)$ and reduce it mod $L$ to get a scalar $h$.
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
`SEND_ENC`), the construction is isomorphic to Fleischhacker et al.'s DRPC compiler for producing pseudorandom
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