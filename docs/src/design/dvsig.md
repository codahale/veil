# Designated-Verifier Signatures

## Signing A Message

Signing is as follows, given a message $M$, the signer's private scalar $d_S$, the signer's public point $Q_S$, and the
designated verifier's public point $Q_V$:

```text
INIT('veil.dvsig', level=128)
AD(Q_S)
AD(Q_V)
```

The protocol's state is then cloned, the clone is keyed with both 64 bytes of random data and the signer's private key,
an ephemeral scalar is derived from PRF output:

```text
KEY(rand(64))
KEY(d_S)
PRF(64) -> k
```

The clone's state is discarded, and $k$ is returned to the parent along with $U = [k]G$:

```text
AD(M)
AD(U)
PRF(64) -> r
```

The challenge scalar $s = k+{d_S}r$ is calculated, and the resulting signature consists of the points $U$ and 
$K = [s]Q_V$.

## Verifying A Message

To verify, `veil.dvsig` is run with a message in blocks $M$, the verifier's private scalar $d_V$, the verifier's public
point $Q_V$, the signer's public key $Q_S$:

```text
INIT('veil.dvsig', level=128)
AD(Q_S)
AD(Q_V)
AD(M)
AD(U)
PRF(64) -> r
```

The verifier calculates $K' = [{d_V}](U + [r]{Q_S})$.

Finally, the verifier compares $K' \equiv K$. If the two points are equivalent, the signature is valid.

## Security, Forgeability, and Malleability

This construction is [Steinfeld et al.'s] modification of [Schnorr's signature scheme][schnorr]. Schnorr's scheme is 
equivalent to Construction 13.12 of Modern Cryptography 3e, and is the combination of the Fiat-Shamir transform applied 
to the Schnorr identification scheme, and per Theorem 13.11, secure if the discrete-logarithm problem is hard relative 
to ristretto255.

## Designated Verification

Steinfeld et al.'s modification binds verification of the signature to the holder of a private scalar. This allows the
signer to prove the authenticity of a message to a verifier without providing the verifier a way to re-prove that to a
third party.

## Ephemeral Scalar Hedging

In deriving the ephemeral scalar from a cloned context, `veil.schnorr` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.

[hedge]: https://eprint.iacr.org/2019/956.pdf

[schnorr]: https://d-nb.info/1156214580/34

[steinfeld]: https://www.iacr.org/archive/pkc2004/29470087/29470087.pdf
