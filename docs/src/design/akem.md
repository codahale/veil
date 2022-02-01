# Key Encapsulation

`veil.akem` implements a key encapsulation mechanism (KEM) with insider security, as formalized in
["Hybrid Signcryption Schemes with Insider Security" by Dent][dent].

## Encapsulation

Encapsulation takes a sender's key pair, $(d_S, Q_S)$, a recipient's public key, $Q_R$, a plaintext message $P$, and a
shared secret length $N_K$.

First, the protocol is initialized and the sender and recipient's public keys are sent and received, respectively:

```text
INIT('veil.akem', level=128)

AD('sender-public-key', meta=true)
AD(LE_U64(LEN(Q_S)),    meta=true, more=true)
SEND_CLR(Q_S)

AD('receiver-public-key', meta=true)
AD(LE_U64(LEN(Q_R)),      meta=true, more=true)
RECV_CLR(Q_R)
```

Second, the protocol's state is then cloned, the clone is keyed with the sender's private key, 64 bytes of random data,
and the plaintext message.

A commitment scalar $t$ is then derived from PRF output:

```text
AD('secret-value',  meta=true)
AD(LE_U64(N_d_S),   meta=true, more=true)
KEY(d_S)

AD('hedged-value', meta=true)
AD(LE_U64(64),     meta=true, more=true)
KEY(rand(64))

AD('plaintext',    meta=true)
AD(LE_U64(LEN(P)), meta=true, more=true)
KEY(P)

AD('commitment-scalar', meta=true)
AD(LE_U64(64),          meta=true, more=true)
PRF(64) -> k
```

Third, the commitment point $X=[t]Q_R$ is added as associated data:

```text
AD('commitment-point', meta=true)
AD(LE_U64(LEN(X)),     meta=true, more=true)
AD(X)
```

Fourth, a shared secret $k$ is extracted from PRF output:

```text
AD('shared-secret', meta=true)
AD(LE_U64(N_K),     meta=true, more=true)
PRF(N_K) -> k
```

Fifth, the plaintext $P$ is added as associated data and a challenge scalar $r$ is extracted from PRF output:

```text
AD('plaintext',    meta=true)
AD(LE_U64(LEN(P)), meta=true, more=true)
AD(P)

AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r
```

Finally, a proof scalar $s=t/(r+d_S)$ is calculated, and $(k, r, s)$ is returned.

## Decapsulation

Decapsulation takes a recipient's key pair, $(d_R, Q_R)$, a sender's public key, $Q_S$, a challenge scalar $r$, a proof
scalar $s$, and a shared secret length $N_K$.

First, the protocol is initialized and the sender and recipient's public keys are received and sent, respectively:

```text
INIT('veil.akem', level=128)

AD('sender-public-key', meta=true)
AD(LE_U64(LEN(Q_S)),    meta=true, more=true)
RECV_CLR(Q_S)

AD('receiver-public-key', meta=true)
AD(LE_U64(LEN(Q_R)),      meta=true, more=true)
SEND_CLR(Q_R)
```

Second, the commitment point $X=[{d_R}s] (Q_S+[r]G)$ is added as associated data:

```text
AD('commitment-point', meta=true)
AD(LE_U64(LEN(X)),     meta=true, more=true)
AD(X)
```

Third, a shared secret $k$ is extracted from PRF output:

```text
AD('shared-secret', meta=true)
AD(LE_U64(N_K),     meta=true, more=true)
PRF(N_K) -> k
```

At this point, $k$ is used to decrypt the unauthenticated plaintext $P'$ outside the `veil.akem` protocol.

Finally, the unauthenticated plaintext $P'$ is added as associated data and a counterfactual challenge scalar $r'$ is 
extracted from PRF output:

```text
AD('plaintext',    meta=true)
AD(LE_U64(LEN(P)), meta=true, more=true)
AD(P)

AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r'
```

If $r' \equiv r$, the plaintext $P'$ is authenticated as the original plaintext $P$ as sent by the owner of $d_S$ to the
owner of $d_R$.

## Insider Security

[Hybrid Signcryption Schemes with Insider Security][dent], Dent defines insider security:

> A signcryption KEM is said to be insider secure if it is IND-CCA2, INP-CCA2 and INT-CCA2 secure.

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

A static Diffie-Hellman exchange is vulnerable to KCI attacks, in that the shared secret point ${Z_S}$ can be calculated
as $[{d_S}]{Q_R}$ by an authentic sender or as $[{d_R}]{Q_S}$ by an attacker in possession of the recipient's private
key $d_S$ and the sender's public key $Q_S$.

`veil.akem` prevents KCI attacks by authenticating the plaintext with a designated-verifier signature. The signature
can be verified by but not constructed by the recipient; as such, a verified signature proves the ephemeral public key
is authentic. Because the signature cannot be verified without the recipient's private key, a dishonest recipient cannot
prove to a third party that the ephemeral public key was provided by the sender without revealing their own private key.

## Ephemeral Scalar Hedging

In deriving the ephemeral scalar from a cloned context, `veil.akem` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.

In the event of an RNG failure, the commitment scalar $t$ will still be unique for each $(d_S, Q_R, P)$ combination.

## Forward Sender Security

Because the commitment scalar $t$ is discarded after encapsulation, a compromise of the sender's private key will not
compromise previously-encapsulated ciphertexts. A sender (or an attacker in possession of the sender's private key) will
be unable to re-calculate the commitment point $X$ and thus unable to re-derive the shared secret.

[dent]: https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.107.3387&rep=rep1&type=pdf

[kci]: https://eprint.iacr.org/2006/252.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf
