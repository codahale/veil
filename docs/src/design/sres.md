# Single-recipient Messages

`veil.sres` implements a single-recipient, insider-secure, deniable signcryption scheme based on the Zheng signcryption
tag-KEM in _Practical Signcryption_ (Zheng-SCTK).

## Encryption

Encryption takes a sender's key pair, $(d_S, Q_S)$, a recipient's public key, $Q_R$, and a plaintext message $P$.

First, an unkeyed duplex is initialized and used to absorb the sender and recipient's public keys:

$$
\text{Cyclist}(\epsilon, \epsilon, \texttt{veil.sres}) \\
\text{Absorb}(Q_S) \\
\text{Absorb}(Q_R) \\
$$

Second, the duplex's state is cloned, and the clone absorbs the sender's private key, 64 bytes of random data, and the
plaintext. The commitment scalar $x$ is then derived from output:

$$
\text{Absorb}(d_S) \\
v \overset{R}{\gets} \mathbb{Z}_{2^{512}} \\
\text{Absorb}(v) \\
\text{Absorb}(P) \\
x \gets \text{SqueezeKey}(64) \bmod \ell \\
$$

Third, the shared secret point $K$ is calculated and used to key the duplex.

$$
K = [x]Q_R \\
\text{Cyclist}(K, \epsilon, \epsilon) \\
$$

Fourth, the duplex is used to encrypt plaintext $P$ as $C$, its state is ratcheted, a challenge scalar $r$ is derived
from output, and a proof scalar $s$ is calculated:

$$
C \gets \text{Encrypt}(P) \\
\text{Ratchet}() \\
r \gets \text{SqueezeKey}(64) \bmod \ell \\
s = (r+d_S)^{-1}x \\
$$

(In the rare event that $r+d_S=0$, the procedure is re-run with a different $x$.)

Fifth, the top four bits of both $r$ and $s$ are masked with random data as $S_0$ and $S_1$:

$$
m_0 \overset{R}{\gets} \mathbb{Z}_{2^{8}} \\
S_0 = r \lor (m_0 \ll 252) \\
m_1 \overset{R}{\gets} \mathbb{Z}_{2^{8}} \\
S_1 = s \lor (m_1 \ll 252) \\
$$

Finally, the masked scalars are absorbed and an authentication tag $T$ is derived from output and sent:

$$
\text{Absorb}(S_0) \\
\text{Absorb}(S_1) \\
T \gets \text{Squeeze}(16)
$$

The final ciphertext is $S_0 || S_1 || C || T$.

## Decryption

Encryption takes a recipient's key pair, $(d_R, Q_R)$, a sender's public key, $Q_S$, two masked scalars
$(S_0, S_1)$, a ciphertext $C$, and an authentication tag $T$.

First, an unkeyed duplex is used to absorb the sender and recipient's public keys:

$$
\text{Cyclist}(\epsilon, \epsilon, \texttt{veil.sres}) \\
\text{Absorb}(Q_S) \\
\text{Absorb}(Q_R) \\
$$

Second, the challenge scalar $r$ and the proof scalar $s$ are unmasked and used to calculate the shared secret $K$,
which is used to key the duplex:

$$
r = S_0 \land \lnot(2^8 \ll 252) \bmod \ell \\
s = S_1 \land \lnot(2^8 \ll 252) \bmod \ell \\
K = [{d_R}s] (Q_S+[r]G) \\
\text{Cyclist}(K, \epsilon, \epsilon) \\
$$

Third, the ciphertext $C$ is decrypted as the unauthenticated plaintext $P'$ and the duplex's is ratcheted:

$$
P' \gets \text{Decrypt}(C) \\
\text{Ratchet}() \\
$$

Fourth, a counterfactual challenge scalar $r'$ is derived from output and compared to the ciphertext challenge scalar
$r$:

$$
r' \gets \text{SqueezeKey}(64) \bmod \ell \\
r' \stackrel{?}{=} r \\
$$

If $r' \not = r$, an error is returned.

Finally, the masked scalars $S_0$ and $S_1$ are absorbed and a counterfactual authentication tag $T'$ is derived from
output and compared to the ciphertext authentication tag $T$:

$$
\text{Absorb}(S_0) \\
\text{Absorb}(S_1) \\
T' \gets \text{Squeeze}(16) \\
T' \stackrel{?}{=} T \\
$$

If the $T' \not = T$, an error is returned. Otherwise, the plaintext $P'$ is returned as authentic.

## IND-CCA2 Security

This construction combines the CCA2-secure Zheng-SCTK construction from _Practical Signcryption_ (Figure 7.6) with a
Xoodyak-based CCA2-secure authenticated encryption construction ($\text{Encrypt}$/$\text{Squeeze}$). Consequently,
`veil.sres` is IND-CCA2 secure per Theorem 7.3 of _Practical Signcryption_.

Instead of passing a ciphertext-dependent tag $\tau$ into the KEM's $\text{Encap}$ function, `veil.sres` begins
$\text{Encap}$ operations using the keyed duplex after the ciphertext has been encrypted with $\text{Encrypt}$ and the
state mutated with $\text{Ratchet}$.

This process ensures the derivation of the challenge scalar $r$ from $\text{SqueezeKey}$ output is cryptographically
dependent on the public keys $Q_S$ and $Q_R$, the shared secret $K$, and the ciphertext $C$. This is equivalent to the
dependency described in _Practical Signcryption_:

$$r \gets H(\tau || {pk}_S || {pk}_R || \kappa)$$

The end result is a challenge scalar which is cryptographically dependent on the prior values and on the ciphertext as
sent (and not, as in previous insider-secure signcryption KEM constructions, the plaintext). This, and the ratcheting of
the duplex's state, ensures the scalar $r$ and $s$ cannot leak information about the plaintext.

Finally, the inclusion of the masked scalars $S_0$ and $S_1$ prior to generating the authentication tag $T$ makes their
masked bits (and thus the entire ciphertext) non-malleable.

## Indistinguishability From Random Noise

`veil.sres` ciphertexts are indistinguishable from random bitstrings.

The scalars $r$ and $s$ are uniformly distributed modulo $\ell \approx 2^{252} + \dots$,
which leaves the top four bits of the top byte effectively unset. These bits are masked with randomly-generated values
before being sent and cleared after being received. As a result, they are fully uniformly distributed and
indistinguishable from random noise. Any 256-bit string will be decoded into a valid scalar, making active
distinguishers impossible. This has been experimentally verified, with $10^7$ random scalars yielding a uniform
distribution of bits ($\mu=0.4999,\sigma=0.00016$).

The remainder of the ciphertext consists exclusively of Xoodyak output. A passive adversary capable of distinguishing
between a valid ciphertext and a random bitstring would violate the CPA-security of Xoodyak.

## IK-CCA Security

`veil.sres` is IK-CCA secure (per [Bellare][ik-cca]), in that it is impossible for an attacker in possession of two
public keys to determine which of the two keys a given ciphertext was encrypted with in either chosen-plaintext or
chosen-ciphertext attacks.

Informally, `veil.sres` ciphertexts consist exclusively of Xoodyak ciphertext and PRF output; an attacker being able to
distinguish between ciphertexts based on keying material would imply the Xoodyak AEAD construction is not IND-CCA2.

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

In deriving the ephemeral scalar from a cloned duplex, `veil.sres` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.

In the event of an RNG failure, the commitment scalar $x$ will still be unique for each $(d_S, Q_R, P)$ combination.

[ik-cca]: https://iacr.org/archive/asiacrypt2001/22480568.pdf

[kci]: https://eprint.iacr.org/2006/252.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf
