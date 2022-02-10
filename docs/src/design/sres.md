# Single-recipient Messages

`veil.sres` implements a single-recipient, insider-secure, deniable signcryption scheme based on the Zheng signcryption
tag-KEM in _Practical Signcryption_ (Zheng-SCTK).

## Encryption

Encryption takes a sender's key pair, $(d_S, Q_S)$, a recipient's public key, $Q_R$, and a plaintext message $P$.

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

Second, the protocol's state is then cloned, the clone is keyed with the sender's private key, 64 bytes of random data,
and the plaintext message.

A commitment scalar $x$ is then derived from PRF output:

```text
AD('secret-value',   meta=true)
AD(LE_U64(LEN(d_S)), meta=true, more=true)
KEY(d_S)

AD('hedged-value', meta=true)
AD(LE_U64(64),     meta=true, more=true)
KEY(rand(64))

AD('plaintext',    meta=true)
AD(LE_U64(LEN(P)), meta=true, more=true)
KEY(P)

AD('commitment-scalar', meta=true)
AD(LE_U64(64),          meta=true, more=true)
PRF(64) -> x
```

Third, the shared secret point $K=[x]Q_R$ is calculated and used to key the protocol and the plaintext $P$ is
encrypted and sent as ciphertext $C$:

```text
AD('shared-secret',  meta=true)
AD(LE_U64(LEN(K)), meta=true, more=true)
KEY(K)

AD('plaintext',    meta=true)
AD(LE_U64(LEN(P)), meta=true, more=true)
SEND_ENC(P) -> C
```

Fifth, the protocol state is ratcheted, a challenge scalar $r$ is derived from PRF output, and a proof scalar 
$s=x/(r+d_S)$ is calculated. (In the rare event that $r+d_S=0$, the protocol is re-run with a different $x$.)

```text
AD('ratchet',  meta=true)
AD(LE_U64(32), meta=true, more=true)
RATCHET(32)

AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r
```

Both $r$ and $s$ are masked with random data and send in cleartext as $S_0$ and $S_1$:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(LEN(r)),     meta=true, more=true)
SEND_CLR(mask(r)) -> S_0

AD('proof-scalar', meta=true)
AD(LE_U64(LEN(s)), meta=true, more=true)
SEND_CLR(mask(s)) -> S_1
```

Finally, a MAC $M$ is generated and sent:

```text
AD('mac',       meta=true)
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

Second, the challenge scalar $r$ and the proof scalar $s$ are unmasked and used to calculate the shared secret
$K=[{d_R}s] (Q_S+[r]G)$, which is used to key the protocol. The ciphertext is then decrypted $C$ as the unauthenticated
plaintext $P'$:

```text
AD('shared-secret',  meta=true)
AD(LE_U64(LEN(K)), meta=true, more=true)
KEY(K)

AD('plaintext',    meta=true)
AD(LE_U64(LEN(C)), meta=true, more=true)
RECV_ENC(C) -> P'
```

Third, the protocol state is ratcheted and a counterfactual challenge scalar $r'$ is derived from PRF output:

```text
AD('ratchet',  meta=true)
AD(LE_U64(32), meta=true, more=true)
RATCHET(32)

AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r'
```

If $r' \not\equiv r$, an error is returned.

Finally, the masked scalars $S_0$ and $S_1$ are received as cleartext and the MAC $M$ is verified:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(LEN(S_1)),   meta=true, more=true)
RECV_CLR(S_0)

AD('proof-scalar',   meta=true)
AD(LE_U64(LEN(S_1)), meta=true, more=true)
RECV_CLR(S_1)

AD('mac',          meta=true)
AD(LE_U64(LEN(M)), meta=true, more=true)
RECV_MAC(M)
```

If the `RECV_MAC` call is successful, the plaintext $P'$ is returned as authentic.

## IND-CCA2 Security

This construction combines the CCA2-secure Zheng-SCTK construction from _Practical Signcryption_ (Figure 7.6) with a
STROBE-based authenticated encryption construction (`SEND_ENC`/`SENC_MAC`). The STROBE-based AE is equivalent to
Construction 5.6 of _Modern Cryptography 3e_ and is CCA-secure per Theorem 5.7 of _MC_, provided STROBE's encryption is
CPA-secure. STROBE's `SEND_ENC` is equivalent to Construction 3.31 of _MC_ and is CPA-secure per Theorem 3.29 of _MC_,
provided STROBE is a sufficiently strong pseudorandom function. Consequently, `veil.sres` is IND-CCA2 secure per
Theorem 7.3 of _Practical Signcryption_.

Instead of passing a ciphertext-dependent tag $\tau$ into the KEM's ${Encap}$ function, `veil.sres` begins ${Encap}$
operations using the STROBE protocol after the ciphertext has been encrypted with `SEND_ENC`. `SEND_ENC` populates the
protocol's state with the ciphertext of the operation, making the derivation of the challenge scalar $r$ from PRF output 
cryptographically dependent on the public keys $Q_S$ and $Q_R$, the shared secret $K$, and the ciphertext $C$. This is
equivalent to the dependency described in _Practical Signcryption_:

$$r \leftarrow H(\tau || {pk}_S || {pk}_R || \kappa)$$

The end result is a challenge scalar which is cryptographically dependent on the prior values and on the ciphertext as
sent (and not, as in previous insider-secure signcryption KEM constructions, the plaintext). This, and the ratcheting of
the protocol state, ensures the scalar $r$ and $s$ cannot leak information about the plaintext.

Finally, the inclusion of the masked scalars $S_0$ and $S_1$ prior to the `SEND_MAC` operation makes their masked bits
non-malleable.

## Indistinguishability From Random Noise

`veil.sres` ciphertexts are indistinguishable from random bitstrings.

The scalars $r$ and $s$ are uniformly distributed modulo $\ell \approx 2^{252} + \dots$,
which leaves the top four bits of the top byte effectively unset. These bits are masked with randomly-generated values
before being sent and cleared after being received. As a result, they are fully uniformly distributed and
indistinguishable from random noise. Any 256-bit string will be decoded into a valid scalar, making active
distinguishers impossible. This has been experimentally verified, with $10^7$ random scalars yielding a uniform
distribution of bits ($\mu=0.4999,\sigma=0.00016$).

The remainder of the ciphertext consists exclusively of STROBE `SEND_ENC` and `SEND_MAC` output. A passive adversary
capable of distinguishing between a valid ciphertext and a random bitstring would violate the CPA-security of STROBE.

## IK-CCA Security

`veil.sres` is IK-CCA secure (per [Bellare][ik-cca]), in that it is impossible for an attacker in possession of two
public keys to determine which of the two keys a given ciphertext was encrypted with in either chosen-plaintext or
chosen-ciphertext attacks.

Informally, `veil.sres` ciphertexts consist exclusively of STROBE ciphertext and PRF output; an attacker being able to
distinguish between ciphertexts based on keying material would imply the STROBE AEAD construction is not IND-CCA2.

## Forward Sender Security

Because the commitment scalar $x$ is discarded after encryption, a compromise of the sender's private key will not
compromise previously-encapsulated ciphertexts. A sender (or an attacker in possession of the sender's private key) will
be unable to re-calculate the commitment point $K$ and thus unable to re-derive the shared secret.

## Key Compromise Impersonation

Per [Strangio][kci]:

> \[S\]uppose an adversary (say Eve) has learned the private key of Alice either by compromising the machine running an
> instance of the protocol (e.g. with the private key stored in conventional memory as part of the current state) or
> perhaps by cloning Alice’s smart card while she inadvertently left it unattended. Eve may now be able to mount the
> following attacks against the protocol:
>
> 1. impersonate Alice in a protocol run;
> 2. impersonate a different party (e.g. Bob) in a protocol run with Alice;
> 3. obtain previously generated session keys established in honest-party runs of the protocol.
>
> In case 1. Eve can send messages on behalf of Alice and these will be accepted as authentic, in case 2. Eve could
> establish a session with Alice while masquerading as another party; this is known as Key Compromise Impersonation
> (KCI)...

A static Diffie-Hellman exchange is vulnerable to KCI attacks, in that the shared secret point ${Z}$ can be calculated
as $[{d_S}]{Q_R}$ by an authentic sender or as $[{d_R}]{Q_S}$ by an attacker in possession of the recipient's private
key $d_S$ and the sender's public key $Q_S$.

`veil.sres` prevents KCI attacks by using the sender's public key $d_S$ in the process of creating both the shared
secret $K$ and the proof scalar $s$. The recipient can use their own private key $d_R$ to reconstruct $K$ and
authenticate the plaintext $P$, but cannot themselves re-create $s$.

## Deniability

`veil.sres` authenticates the plaintext with what is effectively a designated-verifier signature. In order to decrypt
and verify a ciphertext, a recipient must calculate the shared secret point $K=[{d_R}s] (Q_S+[r]G)$, of which only the
recipient's private key $d_R$ is a non-public term.

As such, a dishonest recipient cannot prove to a third party that the messages was encrypted by the sender without
revealing their own private key. (A sender, of course, can keep the commitment scalar $x$ and re-create the message or
just reveal the message directly.)

## Ephemeral Scalar Hedging

In deriving the ephemeral scalar from a cloned context, `veil.sres` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.

In the event of an RNG failure, the commitment scalar $x$ will still be unique for each $(d_S, Q_R, P)$ combination.

[ik-cca]: https://iacr.org/archive/asiacrypt2001/22480568.pdf

[kci]: https://eprint.iacr.org/2006/252.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf
