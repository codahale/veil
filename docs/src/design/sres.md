# Single-recipient Messages

`veil.sres` implements a single-recipient, deniable signcryption scheme which produces ciphertexts indistinguishable
from random noise.

## Encryption

Encryption takes a sender's key pair, $(d_S, Q_S)$, a recipient's public key, $Q_R$, a plaintext message $P$, and a
shared secret length $N_K$.

First, the protocol is initialized and the sender and recipient's public keys are sent and received, respectively:

```text
INIT('veil.sres', level=128)

AD('sender-public-key', meta=true)
AD(LE_U64(LEN(Q_S)),    meta=true, more=true)
SEND_CLR(Q_S)

AD('receiver-public-key', meta=true)
AD(LE_U64(LEN(Q_R)),      meta=true, more=true)
RECV_CLR(Q_R)
```

Second, the plaintext $P$ is encapsulated with [`veil.akem`](akem.md) using $(d_S, Q_S, Q_R)$, yielding the shared secret
$k$, the challenge scalar $r$, and the proof scalar $s$.

$r$ and $s$ are masked with random data and sent as $S_0$ and $S_1$:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(LEN(r)),     meta=true, more=true)
SEND_CLR(mask(r)) -> S_0

AD('proof-scalar', meta=true)
AD(LE_U64(LEN(s)), meta=true, more=true)
SEND_CLR(mask(s)) -> S_1
```

Finally, the protocol is keyed with $k$, the plaintext $P$ is encrypted and sent as ciphertext $C$, and a MAC $M$ is
generated and sent:

```text
AD('shared-secret',  meta=true)
AD(LE_U64(LEN(N_K)), meta=true, more=true)
KEY(k)

AD('plaintext',    meta=true)
AD(LE_U64(LEN(r)), meta=true, more=true)
SEND_ENC(P) -> C

AD('mac',  meta=true)
AD(LE_U64(N_M), meta=true, more=true)
SEND_MAC(N_M) -> M
```

The final ciphertext is $S_0 || S_1 || C || M$.

## Decryption

Encryption takes a recipient's key pair, $(d_R, Q_R)$, a sender's public key, $Q_S$, two masked scalars
$(S_0, S_1)$, a ciphertext $C$, and a MAC $M$.

First, the protocol is initialized and the sender and recipient's public keys are received and sent, respectively:

```text
INIT('veil.sres', level=128)

AD('sender-public-key', meta=true)
AD(LE_U64(LEN(Q_S)),    meta=true, more=true)
RECV_CLR(Q_S)

AD('receiver-public-key', meta=true)
AD(LE_U64(LEN(Q_R)),      meta=true, more=true)
SEND_CLR(Q_R)
```

Second, the challenge scalar $r$ and the proof scalar $s$ are received and unmasked:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(LEN(S_0)),     meta=true, more=true)
RECV_CLR(S_0) -> r

AD('proof-scalar', meta=true)
AD(LE_U64(LEN(S_1)), meta=true, more=true)
SEND_CLR(S_1) -> s
```

Third, the scalars are decapsulated with [`veil.akem`](akem.md) using $(d_R, Q_R, Q_S)$, returning a shared secret $k$
and a verification context $V$. The protocol is keyed with the shared secret $k$:

```text
AD('shared-secret', meta=true)
AD(LE_U64(LEN(N_K)),     meta=true, more=true)
KEY(k)
```

Fourth, the ciphertext $C$ is decrypted and the MAC $M$ is verified:

```text
AD('plaintext',    meta=true)
AD(LE_U64(LEN(r)), meta=true, more=true)
RECV_ENC(C) -> P

AD('mac',       meta=true)
AD(LE_U64(N_M), meta=true, more=true)
RECV_MAC(M)
```

If the `RECV_MAC` call is unsuccessful, an error is returned.

Finally, the [`veil.akem`](akem.md) verification context $V$ is called with the challenge scalar $r$ and the decrypted
plaintext $P$. If the plaintext is verified, $P$ is returned.

## IND-CCA2 Security

This construction combines the CCA-secure [`veil.akem`](akem.md) KEM with a STROBE-based CCA-secure DEM.

The STROBE-based AEAD is equivalent to Construction 5.6 of _Modern Cryptography 3e_ and is CCA-secure per Theorem 5.7,
provided STROBE's encryption is CPA-secure. STROBE's `SEND_ENC` is equivalent to Construction 3.31 and is CPA-secure per
Theorem 3.29, provided STROBE is a sufficiently strong pseudorandom function.

The inclusion of MAC verification before plaintext verification ensures that the DEM component is [committing][cce],
which is a requirement for the insider-security of the full [signcryption scheme][dent]:

> Since we require a signcryption scheme to have strong unforgeability, we actually require another property from the 
> DEM. We require that the decryption algorithm is one-to-one, i.e. we require that, for any symmetric key $K$,
> 
> $$ {D{\small EC}}_K(C_2) = {D{\small EC}}_K(C_2') \text{ if and only if } C_2 = C_2' $$
> 
> This prevents an attacker from creating a forgery $(C_1,C_2')$ from a signcryption $(C_1,C_2)$ by finding another DEM
> encryption $C_2'$ from the ciphertext $C_2$.

The SUF-CMA security of STROBE's `SEND_MAC`/`VERIFY_MAC` operations preclude an attacker from finding $(C_1, C_2')$ in
polynomial time.

## Indistinguishability From Random Noise

`veil.sres` ciphertexts are indistinguishable from random bitstrings.

The [`veil.akem`](akem.md) scalars $r$ and $s$ are uniformly distributed modulo
$\ell = 2^{252} + 27742317777372353535851937790883648493$, which leaves the top four bits of the top byte effectively
unset. These bits are masked with randomly-generated values before being sent and cleared after being received. As a
result, they are fully uniformly distributed and indistinguishable from random noise. Any 256-bit string will be decoded
into a valid scalar, making active distinguishers impossible.

The remainder of the ciphertext consists exclusively of STROBE `SEND_ENC` output, and STROBE `PRF` output. A passive
adversary capable of distinguishing between a valid ciphertext and a random bitstring would violate the CPA-security of
STROBE.

## IK-CCA Security

`veil.sres` is IK-CCA secure (per [Bellare][ik-cca]), in that it is impossible for an attacker in possession of two
public keys to determine which of the two keys a given ciphertext was encrypted with in either chosen-plaintext or
chosen-ciphertext attacks.

Informally, `veil.sres` ciphertexts consist exclusively of STROBE ciphertext and PRF output; an attacker being able to
distinguish between ciphertexts based on keying material would imply the STROBE AEAD construction is not IND-CCA2.

## Forward Sender Security

Because [`veil.akem`](akem.md) encapsulation is forward-secure for senders, so are all encrypted values after the
protocol is keyed with the shared secret $k$. A sender (or an attacker in possession of the sender's private key) will
be able to recover the two scalars, $(r, s)$, but not the plaintext.

[cce]: https://eprint.iacr.org/2017/664.pdf

[dent]: http://www.cogentcryptography.com/papers/inner.pdf

[ik-cca]: https://iacr.org/archive/asiacrypt2001/22480568.pdf
