# Digital Signatures

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

The protocol's state is then cloned, the clone is keyed with both 64 bytes of random data and the signer's private key,
an ephemeral scalar $k$ is derived from PRF output:

```text
AD('secret-value', meta=true)
AD(LE_U64(N_d),     meta=true, more=true)
KEY(d)

AD('hedged-value', meta=true)
AD(LE_U64(64),     meta=true, more=true)
KEY(rand(64))

AD('commitment-scalar', meta=true)
AD(LE_U64(64),          meta=true, more=true)
PRF(64) -> k
```

The clone's state is discarded, and $k$ is returned to the parent along with $I = [k]G$. 

$I$ is added as associated data and a challenge scalar $r$ is extracted from PRF output:

```text
AD('commitment-point', meta=true)
AD(LE_U64(N_I),        meta=true, more=true)
AD(I)

AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r
```

The resulting signature consists of the challenge scalar $r$ and a proof scalar $s = dr + k$.

## Verifying A Signature

To verify, `veil.schnorr` is run with a message in blocks $M_0...M_N$, a public point $Q$, and a signature $(r,s)$:

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

The public ephemeral is re-calculated as $I' = [s]G + [{-r}]Q$ and the challenge scalar $r'$ is re-derived from PRF
output:

```text
AD('commitment-point', meta=true)
AD(LE_U64(N_I),        meta=true, more=true)
AD(I')

AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r'
```

Finally, the verifier compares $r' \equiv r$. If the two scalars are equivalent, the signature is valid.

## Security, Forgeability, and Malleability

This construction is equivalent to Construction 13.12 of Modern Cryptography 3e, and is the combination of the
Fiat-Shamir transform applied to the Schnorr identification scheme, and per Theorem 13.11, secure if the
discrete-logarithm problem is hard relative to ristretto255.

The Schnorr signature scheme
is [strongly unforgeable under chosen message attack (SUF-CMA) in the random oracle model][schnorr-cma]
and [even with practical cryptographic hash functions][schnorr-hash]. As a consequence, the signatures are
non-malleable.

## Indistinguishability and Pseudorandomness

Per [Fleischhacker et al.][ind-sig], this construction produces indistinguishable signatures (i.e., signatures which do
not reveal anything about the signing key or signed message). When encrypted with an unrelated key (i.e.,
via `veil.mres`), the construction is isomorphic to Fleischhacker et al.'s DRPC compiler for producing pseudorandom
signatures, which are indistinguishable from random.

## Ephemeral Scalar Hedging

In deriving the ephemeral scalar from a cloned context, `veil.schnorr` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.


[schnorr-cma]: https://www.di.ens.fr/david.pointcheval/Documents/Papers/2000_joc.pdf

[schnorr-hash]: http://www.neven.org/papers/schnorr.pdf

[ind-sig]: https://eprint.iacr.org/2011/673.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf