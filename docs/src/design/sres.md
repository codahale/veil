# Single-recipient Messages

`veil.sres` implements a single-recipient, insider secure, deniable signcryption scheme based on the Zheng signcryption
tag-KEM in _Practical Signcryption_ (Zheng-SCTK).

## Encryption

Encryption takes a sender's key pair, $(d_S, Q_S)$, a recipient's public key, $Q_R$, and a plaintext message $P$.

First, a duplex is initialized with a constant key and used to absorb the sender and recipient's public keys:

$$
\text{Cyclist}(\texttt{veil.sres}, \epsilon, \epsilon) \\
\text{Absorb}(Q_S) \\
\text{Absorb}(Q_R) \\
$$

Second, a random byte $m$ is generated and absorbed:

$$
m \stackrel{R}{\gets} \mathbb{Z_{2^8}} \\
\text{Absorb}(m) \\
$$

Third, the duplex's state is cloned, and the clone absorbs the sender's private key, 64 bytes of random data, and the
plaintext. The commitment scalar $x$ is then derived from output:

$$
\text{Absorb}(d_S) \\
v \stackrel{R}{\gets} \mathbb{Z}_{2^{512}} \\
\text{Absorb}(v) \\
\text{Absorb}(P) \\
x \gets \text{SqueezeKey}(32) \bmod \ell \\
$$

Fourth, the shared secret point $K$ is calculated and used to re-key the duplex.

$$
K \gets [x]Q_R \\
\text{Cyclist}(K, \epsilon, \epsilon) \\
$$

Fifth, the duplex is used to encrypt plaintext $P$ as $C$, its state is ratcheted, a challenge scalar $r$ is derived
from output, and a proof scalar $s$ is calculated:

$$
C \gets \text{Encrypt}(P) \\
\text{Ratchet}() \\
r \gets \text{SqueezeKey}(32) \bmod \ell \\
s \gets (r+d_S)^{-1}x \\
$$

(In the rare event that $r+d_S=0$, the procedure is re-run with a different $x$.)

Finally, the top four bits of both $r$ and $s$ are masked with the top and bottom four bits of $m$, respectively, as 
$S_0$ and $S_1$:

$$
S_0 \gets r \lor ((m \land \texttt{0xF0}) \ll 252) \\
S_1 \gets s \lor ((m \ll 4) \ll 252) \\
$$

The final ciphertext is $S_0 || S_1 || C$.

## Decryption

Encryption takes a recipient's key pair, $(d_R, Q_R)$, a sender's public key, $Q_S$, two masked scalars
$(S_0, S_1)$, and a ciphertext $C$.

First, a duplex is initialized with a constant key and used to absorb the sender and recipient's public keys:

$$
\text{Cyclist}(\texttt{veil.sres}, \epsilon, \epsilon) \\
\text{Absorb}(Q_S) \\
\text{Absorb}(Q_R) \\
$$

Second, the mask byte $m$ is calculated from the masked bits of $S_0$ and $S_1$ and absorbed:

$$
m \gets ((S_0 \gg 252) \ll 4) | (S_1 \gg 252) \\
\text{Absorb}(m) \\
$$

Third, the challenge scalar $r$ and the proof scalar $s$ are unmasked and used to calculate the shared secret $K$, which
is used to re-key the duplex:

$$
r \gets S_0 \land \lnot(2^8 \ll 252) \bmod \ell \\
s \gets S_1 \land \lnot(2^8 \ll 252) \bmod \ell \\
K \gets [{d_R}s] (Q_S+[r]G) \\
\text{Cyclist}(K, \epsilon, \epsilon) \\
$$

Fourth, the ciphertext $C$ is decrypted as the unauthenticated plaintext $P'$, the duplex's state is ratcheted, and a
counterfactual challenge scalar $r'$ is derived from output:

$$
P' \gets \text{Decrypt}(C) \\
\text{Ratchet}() \\
r' \gets \text{SqueezeKey}(32) \bmod \ell \\
r' \stackrel{?}{=} r \\
$$

If $r' = r$, the plaintext $P'$ is returned as authentic; otherwise, an error is returned.

## Insider Security

This construction combines the Zheng-SCTK construction from _Practical Signcryption_ (Figure 7.6) with a
Xoodyak-based DEM ($\text{Encrypt}$).

Per Theorem 7.3 of _Practical Signcryption_:

> Let SC be a hybrid signcryption scheme constructed from a signcryption tag-KEM and a DEM. If the signcryption tag-KEM
> is IND-CCA2 secure and the DEM is IND-CPA secure, then SC is multi-user outsider FSO/FUO-IND-CCA2 secure with the
> bound
> 
> $$
{\varepsilon}_\text{SC,IND-CCA2} \leq 2{\varepsilon}_\text{SCTK,IND-CCA2} + {\varepsilon}_\text{DEM,IND-CPA}
$$
> Furthermore, if the signcryption tag-KEM is sUF-CMA secure, then SC is multi-user insider FSO/FUO-sUF-CMA secure with
> the bound
> 
> $$
{\varepsilon}_\text{SC,sUF-CMA} \leq {\varepsilon}_\text{SCTK,sUF-CMA}
$$
> 

For `veil.sres` to be insider secure (i.e multi-user insider FSO/FUO-sUF-CMA secure), we must demonstrate that
Zheng-SCTK is both IND-CCA2 secure and sUF-CMA secure, and that Xoodyak's $\text{Encrypt}$ operation is IND-CPA secure.

### Zheng-SCTK's Security

Per Theorem 4.1 of _Practical Signcryption_:

> If the GDH problem is hard and the symmetric encryption scheme is IND-CPA secure, then Zheng's scheme is multi-user
> outsider FSO/FUO-IND-CCA secure in the random oracle model.

Per Theorem 4.2 of _Practical Signcryption_:

> If the Gap Discrete Logarithm problem is hard, then Zheng's scheme is multi-user insider secret-key-ignorant
> FSO-UF-CMA-SKI secure in the random oracle model.

(FSO-UF-CMA-SKI is a weaker security model than FSO-sUF-CMA, where the attacker need not produce a valid secret key for
a forgery; thus FSO-UF-CMA-SKI implies FSO-sUF-CMA.)

Finally, [Bjørstad and Dent][bjørstad] built on [Abe et al.][abe]'s work on tag-KEMs, demonstrating that adapting
Zheng's signcryption scheme for the KEM/DEM construction preserves its security.

### Xoodyak's Security

Xoodyak is a [duplex construction][duplex], which is essentially a cascade of sponge functions. Sponge functions are
[negligibly distinguishable][sponge] from random oracles in the single-stage setting provided the underlying permutation
is random. The [Xoodyak spec][xoodyak] claims 128 bits of security for indistinguishability in the multi-user setting.

### Combined Security

Consequently, `veil.sres` is insider secure (i.e. FSO/FUO-IND-CCA2 and FSO/FUO-sUF-CMA in the multi-user setting).

## Adapting Zheng-SCTK To The Duplex

Instead of passing a ciphertext-dependent tag $\tau$ into the KEM's $\text{Encap}$ function, `veil.sres` begins
$\text{Encap}$ operations using the keyed duplex after the ciphertext has been encrypted with $\text{Encrypt}$ and the
state mutated with $\text{Ratchet}$.

This process ensures the derivation of the challenge scalar $r$ from $\text{SqueezeKey}$ output is cryptographically
dependent on the public keys $Q_S$ and $Q_R$, the shared secret $K$, and the ciphertext $C$. This is equivalent to the
dependency described in _Practical Signcryption_:

$$r \gets H(\tau || {pk}_S || {pk}_R || \kappa)$$

The end result is a challenge scalar which is cryptographically dependent on the prior values and on the ciphertext as
sent (and not, as in previous insider secure signcryption KEM constructions, the plaintext). This and the ratcheting of
the duplex's state ensure the scalars $r$ and $s$ cannot leak information about the plaintext.

Finally, the inclusion of the masked bits of scalars $S_0$ and $S_1$ prior to generating the challenge scalar $r$ makes
their masked bits (and thus the entire ciphertext) non-malleable.

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
distinguish between ciphertexts based on keying material would imply the Xoodyak $\text{Encrypt}$ operation is not
IND-CPA.

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

This is a key point of distinction between the Zheng-SCTK scheme and [the related scheme by Gamage et al.][gamage] which
offers public verifiability of ciphertexts. Where Gamage's scheme uses the curve's generator point $G$ to calculate the
shared secret, Zheng-SCTK uses the recipient's public key $Q_R$, requiring the use of the recipient's private key $d_R$
for decapsulation.

## Ephemeral Scalar Hedging

In deriving the ephemeral scalar from a cloned duplex, `veil.sres` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.

In the event of an RNG failure, the commitment scalar $x$ will still be unique for each $(d_S, Q_R, P)$ combination.

[ik-cca]: https://iacr.org/archive/asiacrypt2001/22480568.pdf

[kci]: https://eprint.iacr.org/2006/252.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf

[xoodyak]: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf

[bjørstad]: http://www.ii.uib.no/~tor/pdf/PKC_tagkem.pdf

[abe]: https://eprint.iacr.org/2005/027.pdf

[duplex]: https://keccak.team/files/SpongeDuplex.pdf

[sponge]: https://keccak.team/files/SpongeIndifferentiability.pdf

[gamage]: https://link.springer.com/chapter/10.1007/3-540-49162-7_6