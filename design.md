---
title: The Veil Cryptosystem
author: Coda Hale
lang: en-US
indent: true
colorlinks: true
---

\newcommand{\Cyclist}[1]{\text{Cyclist}(#1, \epsilon, \epsilon)}
\newcommand{\Absorb}[1]{\text{Absorb}(#1)}
\newcommand{\AbsorbMore}[2]{\text{AbsorbMore}(#1, #2)}
\newcommand{\Squeeze}[1]{\text{Squeeze}(#1)}
\newcommand{\SqueezeKey}[1]{\text{SqueezeKey}(#1)}
\newcommand{\Encrypt}[1]{\text{Encrypt}(#1)}
\newcommand{\Decrypt}[1]{\text{Decrypt}(#1)}
\newcommand{\Ratchet}[0]{\text{Ratchet}()}
\newcommand{\SqueezeScalar}[0]{\text{SqueezeKey}(64) \bmod \ell}
\newcommand{\rgets}[0]{\stackrel{R}{\gets}}
\newcommand{\checkeq}[0]{\stackrel{?}{=}}
\newcommand{\allbits}[1]{\mathbb{Z}_{2^{#1}}}
\newcommand{\literal}[1]{\texttt{#1}}
\newcommand{\invoke}[3]{\literal{#1::}\text{#2}(#3)}
\newcommand{\BigE}[0]{\mathcal{E}}
\newcommand{\BigS}[0]{\mathcal{S}}
\newcommand{\EtS}[0]{\mathcal{E}t\mathcal{S}}
\newcommand{\StE}[0]{\mathcal{S}t\mathcal{E}}
\newcommand{\Attacker}[0]{\mathcal{A}}
\newcommand{\LE}[2]{\text{#1}_\text{LE}(#2)}

## Design Principles

Veil is designed to be simple, understandable, and robust.

### Cryptographic Minimalism

Veil uses just two distinct primitives:

* [Xoodyak][xoodyak] for confidentiality, authentication, and integrity.
* [ristretto255][r255] for key encapsulation and authenticity.

The underlying philosophy is that expressed by [Adam Langley][agl]:

> There's a lesson in all this: have one joint and keep it well oiled. … \[O\]ne needs to minimise
> complexity, concentrate all extensibility in a single place and _actively defend it_.

As a result, the constructions in Veil depend primarily on two relatively stable cryptographic
assumptions: the Gap Diffie-Hellman assumption for ristretto255 and that Xoodoo is suitably close to
a random permutation.

#### ristretto255

[ristretto255][r255-why] uses a safe curve, is a prime-order cyclic group, has non-malleable
encodings, and has no co-factor concerns. This allows for the use of a wide variety of cryptographic
constructions built on group operations. It targets a 128-bit security level, lends itself to
constant-time implementations, and can run in constrained environments.

#### Xoodyak

Xoodyak is a cryptographic [duplex][duplex], a relatively new cryptographic primitive that provides
symmetric-key confidentiality, integrity, and authentication via a single object. Duplexes offer a
way to replace complex, ad-hoc constructions combining encryption algorithms, cipher modes, AEADs,
MACs, and hash algorithms using a single primitive.

Duplexes have security properties which reduce to the properties of the cryptographic
[sponge][sponge], which themselves reduce to the strength of the underlying permutation. Xoodyak is
based on the Xoodoo permutation, an adaptation of the Keccak-_p_ permutation (upon which SHA-3 is
built) for lower-resource environments. While Xoodyak is not standardized, it is currently a
finalist in the NIST Lightweight Cryptography standardization process.

Like Ristretto255, it targets a 128-bit security level, lends itself to constant-time
implementations, and can run in constrained environments.

### Integrated Constructions

Because Xoodyak provides a wide range of capabilities, it's possible to build fully integrated
cryptographic constructions. Leveraging transcript consistency–the fact that every operation changes
a Xoodyak duplex's state in a cryptographically secure manner–makes for much simpler constructions
with guarantees that are easier to understand.

Instead of combining a hash function and a digital signature algorithm, we have a single digital
signature construction. Instead of combining a KEM, a KDF, and an AEAD, we have a single hybrid
public key encryption construction. This integration bakes in logical dependencies on sent and
received data in a feed-forward mechanism, which removes it from the attackable surface area of the
protocol. Because Xoodyak outputs are cryptographically dependent on prior inputs, the need for
domain separation identifiers, padding, and framing is eliminated.

Xoodyak provides a _hash_ mode and a _keyed_ mode; Veil uses the _keyed_ mode exclusively,
initializing each duplex by passing a constant initialization string (e.g. `veil.mres`) as the key.
This allows for effectively unkeyed constructions (e.g. [digital signature
verification](#veil.schnorr)) which use Xoodyak's $\text{Encrypt}$/$\text{Decrypt}$ functionality
for indistinguishability and not confidentiality. Constructions which provide confidentiality do so
by calling the $\text{Cyclist}$ function with a secret key, essentially using the duplex's prior
state as authenticated data.

Finally, the use of Xoodyak means all protocols which end in $\text{Squeeze}$ outputs are [compactly
committing][cce].

### Confidentiality & Integrity

Veil messages are designed to provide confidentiality and integrity against all known attacks,
providing CCA2 security against both non-recipients _and_ recipients.

### Unforgeability & Non-malleability

Veil signatures are strongly unforgeable, non-malleable, and strongly bound to signers.

### Deniable Authenticity

Veil messages are authenticated, in that every recipient can prove to themselves that the message
was sent by the owner of a given public key and was not altered in any way. Unlike e.g. PGP,
however, this authenticity is deniable: the only way for a recipient to prove the authenticity of a
message to a third party without revealing their own private key.

### Indistinguishability From Random Noise

Both Veil messages and signatures are entirely indistinguishable from random noise. They contain no
plaintext metadata, no plaintext ristretto255 points, no plaintext framing or padding, and have
entirely arbitrary lengths. This makes them ideal for distribution via steganographic channels and
very resistant to traffic analysis.

## Message Digests {#veil.digest}

Veil can create message digests given a set of metadata and a message.

Given a set of metadata strings $V_0..V_n$ and a message in 16-byte blocks $M_0..M_n$, a duplex is
initialized with a constant key and used to absorb the metadata and message blocks. Finally, a
64-byte digest $D$ is squeezed:

\begin{gather*}
\Cyclist{\literal{veil.digest}} \\
\Absorb{V_0} \\
\Absorb{V_1} \\
\dots \\
\Absorb{V_n} \\
\AbsorbMore{M_0}{16} \\
\AbsorbMore{M_1}{16} \\
\dots \\
\AbsorbMore{M_n}{16} \\
D \gets \Squeeze{64}
\end{gather*}

### Message Authentication Codes

To create a MAC, pass a symmetric key as a piece of metadata.

## Hierarchical Key Derivation {#veil.hkd}

Each participant in Veil has a secret key, which is a string $S \rgets \allbits{512}$.

### Deriving The Root Key

To derive a root private key from a secret key, a duplex is initialized with a constant key and used
to absorb $S$. A scalar $d$ is then derived from output:

\begin{gather*}
\Cyclist{\literal{veil.hkd.root}} \\
\Absorb{S} \\
d \gets \SqueezeScalar \\
\end{gather*}

### Deriving A Private Key From Another Private Key

To derive a private key $d'$ from another private key $d$ with a label $L$, a duplex initialized
with a constant key is used to absorb $[d]G$ and $L$ and squeeze a scalar value:

\begin{gather*}
\Cyclist{\literal{veil.hkd.label}} \\
\Absorb{[d]G} \\
\Absorb{L} \\
r \gets \SqueezeScalar \\
d' \gets d + r \\
\end{gather*}

### Deriving A Public Key From Another Public Key

To derive a public key $Q'$ from another public key $Q$ with a label $L$, a duplex initialized with
a constant key is used to absorb $Q$ and $L$ and squeeze a scalar value:

\begin{gather*}
\Cyclist{\literal{veil.hkd.label}} \\
\Absorb{Q} \\
\Absorb{L} \\
r \gets \SqueezeScalar \\
Q' \gets Q + [r]G \\
\end{gather*}

### Hierarchical Keys

This is used to provide hierarchical key derivation, deriving a final key from a secret key via a
path of labels $L_0..L_n$.

Using a key path $\literal{friends} \to \literal{alice}$, the secret key is mapped to a private key
via `veil.scaldf.root`, which is then mapped to an intermediate private key via the label `friends`,
which is then mapped to the final private key via the label `alice`.

This allows a single secret key to be used to generate a tree of domain-separated keys:

```{.graphviz}
digraph hkd {
    node [style=rounded];
    secret_key [ label = "secret-key", shape = rect, style = bold ];
    root [ label = "root", shape = rect ];
    friends [ label = "friends", fontname = "Courier" ]
    work [ label = "work", fontname = "Courier" ]
    crime_fighting [ label = "crime-fighting", fontname = "Courier" ]
    superfriends [ label = "superfriends", fontname = "Courier" ]
    justice_league [ label = "justice-league", fontname = "Courier" ]
    avengers [ label = "avengers", fontname = "Courier" ]
    official_blog [ label = "official-blog", fontname = "Courier" ]
    packages [ label = "packages", fontname = "Courier" ]
    alice [ label = "alice", fontname = "Courier" ]
    carol [ label = "carol", fontname = "Courier" ]
    daphne [ label = "daphne", fontname = "Courier" ]

    secret_key -> root;
    root -> friends;
    root -> work;
    root -> crime_fighting;
    friends -> alice;
    friends -> carol;
    friends -> daphne;
    crime_fighting -> superfriends;
    crime_fighting -> justice_league;
    crime_fighting -> avengers;
    work -> official_blog;
    work -> packages;
}
```

### Disposable Keys

This design allows for the use of disposable, anonymous keys based on a single secret key.

If Alice wants to communicate anonymously with Bea, she can generate a private key with the key path
`ee4c176352b1d0b2df4a699d430ea48e` and share the corresponding public key with Bea via an anonymous
channel. Unless Bea can guess that key path, Bea will be unable to determine if her anonymous pen
pal is Alice even if she has Alice's key.

These disposable keys are stateless, as well: if Alice wants to burn that key, all she needs to do
is forget the key path.

## Digital Signatures {#veil.schnorr}

`veil.schnorr` implements a Schnorr digital signature scheme.

### Signing A Message

Signing is as follows, given a message in 16-byte blocks $M_0..M_n$, a private scalar $d$, and a
public point $Q$.

First, a duplex is initialized with a constant key and used to absorb the message blocks and the
signer's public key:

\begin{gather*}
\Cyclist{\literal{veil.schnorr}} \\
\AbsorbMore{M_0}{16} \\
\AbsorbMore{M_1}{16} \\
\dots \\
\AbsorbMore{M_n}{16} \\
\Absorb{Q} \\
\end{gather*}

(The signer's public key is absorbed after the message to allow [`veil.mres`](#veil.mres) to search
for a header without having to buffer the results.)

The duplex's state is cloned, and the clone absorbs the signer's private key and 64 bytes of random
data. The ephemeral scalar $k$ is then derived from output:

\begin{gather*}
\Absorb{d} \\
v \rgets \allbits{512} \\
\Absorb{v} \\
k \gets \SqueezeScalar \\
\end{gather*}

The clone's state is discarded, and $k$ is returned to the parent. The commitment point $I$ is
calculated and encrypted as $S_0$:

\begin{gather*}
I \gets [k]G \\
S_0 \gets \Encrypt{I} \\
\end{gather*}

A challenge scalar $r$ is derived from output and used to calculate the proof scalar $s$ which is
encrypted as $S_1$:

\begin{gather*}
r \gets \SqueezeScalar \\
s \gets dr + k \\
S_1 \gets \Encrypt{s}
\end{gather*}

The final signature is $S_0 || S_1$.

### Verifying A Signature

Verification is as follows, given a message in 16-byte blocks $M_0..M_n$, a public point $Q$, and a
signature $S_0 || S_1$.

First, a duplex is created, initialized with a constant key, and used to absorb the message blocks
and the signer's public key:

\begin{gather*}
\Cyclist{\literal{veil.schnorr}} \\
\AbsorbMore{M_0}{16} \\
\AbsorbMore{M_1}{16} \\
\dots \\
\AbsorbMore{M_n}{16} \\
\Absorb{Q} \\
\end{gather*}

$S_0$ is decrypted and decoded as $I$ and $r$ is re-derived from output:

\begin{gather*}
I \gets \Decrypt{S_0} \\
r \gets \SqueezeScalar \\
\end{gather*}

$S_1$ is decrypted and decoded as $s$ and the counterfactual commitment point $I'$ is calculated and
compared to the signature commitment point $I$:

\begin{gather*}
s \gets \Decrypt{S_1} \\
I' \gets [s]G - [r]Q \\
I' \checkeq I \\
\end{gather*}

The signature is valid if-and-only-if $I' = I$.

### Security, Forgeability, and Malleability

The Schnorr signature scheme is the application of the Fiat-Shamir transform to the Schnorr
identification scheme.

Per Theorem 13.10 of _Modern Cryptography 3e_:

> Let $\Pi$ be an identification scheme, and let $\Pi'$ be the signature scheme that results by
> applying the Fiat-Shamir transform to it. If $\Pi$ is secure and $H$ is modeled as a random
> oracle, then $\Pi'$ is secure.

Per Theorem 13.11 of _Modern Cryptography 3e_:

> If the discrete-logarithm problem is hard relative to $\mathcal{G}$, then the Schnorr
> identification scheme is secure.

This construction uses the Xoodyak duplex as a hash function. Consequently, the security of this
construction assumes the fitness of Xoodyak as a random oracle and the hardness of the
discrete-logarithm problem relative to ristretto255.

Unlike Construction 13.12 of _Modern Cryptography 3e_, `veil.schnorr` transmits the commitment point
$I$ as part of the signature and the verifier calculates $I'$ vs transmitting the challenge scalar
$r$ and calculating $r'$. In this way, `veil.schnorr` is closer to [EdDSA][ed25519] or the Schnorr
variant proposed in the [STROBE][strobe] paper.

Some Schnorr/EdDSA implementations (e.g. [ed25519][ed25519]) suffer from malleability issues,
allowing for multiple valid signatures for a given signer and message. [Chalkias et al.][eddsa]
describe a strict verification function for Ed25519 which achieves sUF-CMA security in addition to
strong binding:

> 1. Reject the signature if $S \not\in \{0,\ldots,L-1\}$.
> 2. Reject the signature if the public key $A$ is one of 8 small order points.
> 3. Reject the signature if $A$ or $R$ are non-canonical.
> 4. Compute the hash $\text{SHA2}_{512}(R||A||M)$ and reduce it mod $L$ to get a scalar $h$.
> 5. Accept if $8(S·B)-8R-8(h·A)=0$.

Rejecting $S \geq L$ makes the scheme sUF-CMA secure, and rejecting small order $A$ values makes the
scheme strongly binding. `veil.schnorr`'s use of ristretto255's canonical point and scalar encoding
routines obviate the need for these checks. Likewise, ristretto255 is a prime order group, which
obviates the need for cofactoring in verification.

When implemented with a prime order group and canonical encoding routines, The Schnorr signature
scheme is [strongly unforgeable under chosen message attack (sUF-CMA) in the random oracle
model][schnorr-cma] and [even with practical cryptographic hash functions][schnorr-hash]. As a
consequence, the signatures are non-malleable.

### Indistinguishability and Pseudorandomness

Per [Fleischhacker et al.][ind-sig], this construction produces indistinguishable signatures (i.e.,
signatures which do not reveal anything about the signing key or signed message). When encrypted
with an unrelated key (i.e., via $\text{Encrypt}$), the construction is isomorphic to Fleischhacker
et al.'s DRPC compiler for producing pseudorandom signatures, which are indistinguishable from
random.

### Ephemeral Scalar Hedging For Signatures

In deriving the ephemeral scalar from a cloned context, `veil.schnorr` uses [Aranha et al.'s "hedged
signature" technique][hedge] to mitigate against both catastrophic randomness failures and
differential fault attacks against purely deterministic signature schemes.

## Single-recipient Headers {#veil.sres}

`veil.sres` implements a single-recipient, insider secure, deniable signcryption scheme based on the
Zheng signcryption tag-KEM in _Practical Signcryption_ (Zheng-SCTK).

### Header Encryption

Encryption takes a sender's key pair, $(d_S, Q_S)$, a recipient's public key, $Q_R$, and a plaintext
message $P$.

First, a duplex is initialized with a constant key and used to absorb the sender and recipient's
public keys:

\begin{gather*}
\Cyclist{\literal{veil.sres}} \\
\Absorb{Q_S} \\
\Absorb{Q_R} \\
\end{gather*}

Second, a random byte $m$ is generated and absorbed:

\begin{gather*}
m \rgets \allbits{8} \\
\Absorb{m} \\
\end{gather*}

Third, the duplex's state is cloned, and the clone absorbs the sender's private key, 64 bytes of
random data, and the plaintext. The commitment scalar $x$ is then derived from output:

\begin{gather*}
\Absorb{d_S} \\
v \rgets \allbits{512} \\
\Absorb{v} \\
\Absorb{P} \\
x \gets \SqueezeScalar \\
\end{gather*}

Fourth, the shared secret point $K$ is calculated and used to re-key the duplex.

\begin{gather*}
K \gets [x]Q_R \\
\Cyclist{K} \\
\end{gather*}

Fifth, the duplex is used to encrypt plaintext $P$ as $C$, its state is ratcheted, a challenge
scalar $r$ is derived from output, and a proof scalar $s$ is calculated:

\begin{gather*}
C \gets \Encrypt{P} \\
\Ratchet \\
r \gets \SqueezeScalar \\
s \gets (r+d_S)^{-1}x \\
\end{gather*}

(In the rare event that $r+d_S=0$, the procedure is re-run with a different $x$.)

Finally, the top four bits of both $r$ and $s$ are masked with the top and bottom four bits of $m$,
respectively, as $S_0$ and $S_1$:

\begin{gather*}
S_0 \gets r \lor ((m \land \literal{0xF0}) \ll 252) \\
S_1 \gets s \lor ((m \ll 4) \ll 252) \\
\end{gather*}

The final ciphertext is $S_0 || S_1 || C$.

### Header Decryption

Encryption takes a recipient's key pair, $(d_R, Q_R)$, a sender's public key, $Q_S$, two masked
scalars $(S_0, S_1)$, and a ciphertext $C$.

First, a duplex is initialized with a constant key and used to absorb the sender and recipient's
public keys:

\begin{gather*}
\Cyclist{\literal{veil.sres}} \\
\Absorb{Q_S} \\
\Absorb{Q_R} \\
\end{gather*}

Second, the mask byte $m$ is calculated from the masked bits of $S_0$ and $S_1$ and absorbed:

\begin{gather*}
m \gets ((S_0 \gg 252) \ll 4) | (S_1 \gg 252) \\
\Absorb{m} \\
\end{gather*}

Third, the challenge scalar $r$ and the proof scalar $s$ are unmasked and used to calculate the shared secret $K$, which
is used to re-key the duplex:

\begin{gather*}
r \gets S_0 \land \lnot(2^8 \ll 252) \bmod \ell \\
s \gets S_1 \land \lnot(2^8 \ll 252) \bmod \ell \\
K \gets [{d_R}s] ([r]G+Q_S) \\
\Cyclist{K} \\
\end{gather*}

Fourth, the ciphertext $C$ is decrypted as the unauthenticated plaintext $P'$, the duplex's state is ratcheted, and a
counterfactual challenge scalar $r'$ is derived from output:

\begin{gather*}
P' \gets \Decrypt{C} \\
\Ratchet \\
r' \gets \SqueezeScalar \\
r' \checkeq r \\
\end{gather*}

If $r' = r$, the plaintext $P'$ is returned as authentic; otherwise, an error is returned.

### Insider Security Of Headers

This construction combines the Zheng-SCTK construction from _Practical Signcryption_ (Figure 7.6) with a
Xoodyak-based DEM ($\text{Encrypt}$).

Per Theorem 7.3 of _Practical Signcryption_:

> Let SC be a hybrid signcryption scheme constructed from a signcryption tag-KEM and a DEM. If the
> signcryption tag-KEM is IND-CCA2 secure and the DEM is IND-CPA secure, then SC is multi-user
> outsider FSO/FUO-IND-CCA2 secure with the bound
>
> $${\varepsilon}_\text{SC,IND-CCA2} \leq \ 2{\varepsilon}_\text{SCTK,IND-CCA2} + {\varepsilon}_\text{DEM,IND-CPA}$$
>
> Furthermore, if the signcryption tag-KEM is sUF-CMA secure, then SC is multi-user insider
> FSO/FUO-sUF-CMA secure with the bound
>
> $${\varepsilon}_\text{SC,sUF-CMA} \leq {\varepsilon}_\text{SCTK,sUF-CMA}$$
>

For `veil.sres` to be insider secure (i.e multi-user insider FSO/FUO-sUF-CMA secure), we must
demonstrate that Zheng-SCTK is both IND-CCA2 secure and sUF-CMA secure, and that Xoodyak's
$\text{Encrypt}$ operation is IND-CPA secure.

#### Zheng-SCTK's Security

Per Theorem 4.1 of _Practical Signcryption_:

> If the GDH problem is hard and the symmetric encryption scheme is IND-CPA secure, then Zheng's
> scheme is multi-user outsider FSO/FUO-IND-CCA secure in the random oracle model.

Per Theorem 4.2 of _Practical Signcryption_:

> If the Gap Discrete Logarithm problem is hard, then Zheng's scheme is multi-user insider
> secret-key-ignorant FSO-UF-CMA-SKI secure in the random oracle model.

(FSO-UF-CMA-SKI is a stronger security notion than FSO-sUF-CMA, where the attacker need not produce
a valid secret key for a forgery; FSO-UF-CMA-SKI implies FSO-sUF-CMA.)

Finally, [Bjørstad and Dent][bjørstad] built on [Abe et al.][abe]'s work on tag-KEMs, demonstrating
that adapting Zheng's signcryption scheme for the KEM/DEM construction preserves its security.

#### Xoodyak's Security

Xoodyak is a [duplex construction][duplex], which is essentially a cascade of sponge functions.
Sponge functions are [negligibly distinguishable][sponge] from random oracles in the single-stage
setting provided the underlying permutation is random. The [Xoodyak spec][xoodyak] claims 128 bits
of security for indistinguishability in the multi-user setting.

#### Combined Security

Consequently, `veil.sres` is insider secure (i.e. FSO/FUO-IND-CCA2 and FSO/FUO-sUF-CMA in the
multi-user setting).

#### Adapting Zheng-SCTK To The Duplex

Instead of passing a ciphertext-dependent tag $\tau$ into the KEM's $\text{Encap}$ function,
`veil.sres` begins $\text{Encap}$ operations using the keyed duplex after the ciphertext has been
encrypted with $\text{Encrypt}$ and the state mutated with $\text{Ratchet}$.

This process ensures the derivation of the challenge scalar $r$ from $\text{SqueezeKey}$ output is
cryptographically dependent on the public keys $Q_S$ and $Q_R$, the shared secret $K$, and the
ciphertext $C$. This is equivalent to the dependency described in _Practical Signcryption_:

$$r \gets H(\tau || {pk}_S || {pk}_R || \kappa)$$

The end result is a challenge scalar which is cryptographically dependent on the prior values and on
the ciphertext as sent (and not, as in previous insider secure signcryption KEM constructions, the
plaintext). This and the ratcheting of the duplex's state ensure the scalars $r$ and $s$ cannot leak
information about the plaintext.

Finally, the inclusion of the masked bits of scalars $S_0$ and $S_1$ prior to generating the
challenge scalar $r$ makes their masked bits (and thus the entire ciphertext) non-malleable.

### Header Indistinguishability From Random Noise

`veil.sres` ciphertexts are indistinguishable from random bitstrings.

The scalars $r$ and $s$ are uniformly distributed modulo $\ell \approx 2^{252} + \dots$, which
leaves the top four bits of the top byte effectively unset. These bits are masked with
randomly-generated values before being sent and cleared after being received. As a result, they are
fully uniformly distributed and indistinguishable from random noise. Any 256-bit string will be
decoded into a valid scalar, making active distinguishers impossible. This has been experimentally
verified, with $10^7$ random scalars yielding a uniform distribution of bits
($\mu=0.4999,\sigma=0.00016$).

The remainder of the ciphertext consists exclusively of Xoodyak output. A passive adversary capable
of distinguishing between a valid ciphertext and a random bitstring would violate the CPA-security
of Xoodyak.

### IK-CCA Security

`veil.sres` is IK-CCA secure (per [Bellare][ik-cca]), in that it is impossible for an attacker in
possession of two public keys to determine which of the two keys a given ciphertext was encrypted
with in either chosen-plaintext or chosen-ciphertext attacks.

Informally, `veil.sres` ciphertexts consist exclusively of Xoodyak ciphertext and PRF output; an
attacker being able to distinguish between ciphertexts based on keying material would imply the
Xoodyak $\text{Encrypt}$ operation is not IND-CPA.

### Forward Sender Security

Because the commitment scalar $x$ is discarded after encryption, a compromise of the sender's
private key will not compromise previously-encapsulated ciphertexts. A sender (or an attacker in
possession of the sender's private key) will be unable to re-calculate the commitment point $K$ and
thus unable to re-derive the shared secret.

### Key Compromise Impersonation

Per [Strangio][kci]:

> \[S\]uppose an adversary (say Eve) has learned the private key of Alice either by compromising the
> machine running an instance of the protocol (e.g. with the private key stored in conventional
> memory as part of the current state) or perhaps by cloning Alice’s smart card while she
> inadvertently left it unattended. Eve may now be able to mount the following attacks against the
> protocol:
>
> 1. impersonate Alice in a protocol run;
> 2. impersonate a different party (e.g. Bob) in a protocol run with Alice;
> 3. obtain previously generated session keys established in honest-party runs of the protocol.
>
> In case 1. Eve can send messages on behalf of Alice and these will be accepted as authentic, in
> case 2. Eve could establish a session with Alice while masquerading as another party; this is
> known as Key Compromise Impersonation (KCI)...

A static Diffie-Hellman exchange is vulnerable to KCI attacks (e.g. [HPKE][hpke], in that the shared
secret point ${Z}$ can be calculated as $[{d_S}]{Q_R}$ by an authentic sender or as $[{d_R}]{Q_S}$
by an attacker in possession of the recipient's private key $d_S$ and the sender's public key $Q_S$.

`veil.sres` prevents KCI attacks by using the sender's public key $d_S$ in the process of creating
both the shared secret $K$ and the proof scalar $s$. The recipient can use their own private key
$d_R$ to reconstruct $K$ and authenticate the plaintext $P$, but cannot themselves re-create $s$.

### Header Deniability

`veil.sres` authenticates the plaintext with what is effectively a designated-verifier signature. In
order to decrypt and verify a ciphertext, a recipient must calculate the shared secret point
$K=[{d_R}s] (Q_S+[r]G)$, of which only the recipient's private key $d_R$ is a non-public term.

As such, a dishonest recipient cannot prove to a third party that the messages was encrypted by the
sender without revealing their own private key. (A sender, of course, can keep the commitment scalar
$x$ and re-create the message or just reveal the message directly.)

This is a key point of distinction between the Zheng-SCTK scheme and [the related scheme by Gamage
et al.][gamage] which offers public verifiability of ciphertexts. Where Gamage's scheme uses the
curve's generator point $G$ to calculate the shared secret, Zheng-SCTK uses the recipient's public
key $Q_R$, requiring the use of the recipient's private key $d_R$ for decapsulation.

### Ephemeral Scalar Hedging For Headers

In deriving the ephemeral scalar from a cloned duplex, `veil.sres` uses [Aranha et al.'s "hedged
signature" technique][hedge] to mitigate against both catastrophic randomness failures and
differential fault attacks against purely deterministic signature schemes.

In the event of an RNG failure, the commitment scalar $x$ will still be unique for each $(d_S, Q_R,
P)$ combination.

## Multi-recipient Messages {#veil.mres}

`veil.mres` is a multi-recipient signcryption scheme, using an encrypt-then-sign construction with
an IND-CCA2 secure encryption construction and a sUF-CMA secure signature scheme.

### Message Encryption

Encrypting a message begins as follows, given the sender's key pair, $d_S$ and $Q_S$, a plaintext
message in blocks $P_0..P_n$, a list of recipient public keys, $Q_{R^0}..Q_{R^m}$, and a DEK size
$N_{K}$.

First, a duplex is initialized with a constant key and used to absorb the sender's public key:

\begin{gather*}
\Cyclist{\literal{veil.mres}} \\
\Absorb{Q_S} \\
\end{gather*}

The duplex's state is cloned and keyed with the sender's private key and a random nonce and used to
derive a data encryption key, $K$, and an ephemeral key pair, $(d_E, Q_E)$:

\begin{gather*}
\Absorb{d_S} \\
v \rgets \allbits{512} \\
\Absorb{v} \\
K \gets \SqueezeKey{N_K} \\
d_E \gets \SqueezeScalar \\
Q_E \gets [{d_E}]G \\
\end{gather*}

$(d_E,Q_E)$ are returned to the original context and the cloned duplex is discarded:

$K$, $Q_E$, and the message offset are encoded into a fixed-length header and copies of it are
encrypted with [`veil.sres`](#veil.sres) for each recipient using $(d_S, Q_S)$. Optional random
padding is added to the end, and the resulting headers $H_0..H_n||H_{pad}$ are absorbed in 32KiB
blocks:

\begin{gather*}
h \gets K || Q_E || O \\
H_0 \gets \invoke{veil.sres}{Encrypt}{d_S, Q_S, Q_{R_0}, h} \\
\Absorb{H_0} \\
\dots \\
H_n \gets \invoke{veil.sres}{Encrypt}{d_S, Q_S, Q_{R_n}, h} \\
\Absorb{H_n} \\
H_\text{pad} \rgets \allbits{\text{pad}} \\
\Absorb{H_\text{pad}} \\
\end{gather*}

The duplex is keyed with $K$, the plaintext message is divided into 32KiB blocks $P_0 || P_1 ||
\dots P_i \dots || P_n$. Each block $P_i$ is encrypted as ciphertext $C_i$ and an authentication tag
$T_i$ is generated and appended. After each block, the duplex state is ratcheted to prevent
rollback:

\begin{gather*}
\Cyclist{K} \\
\dots \\
C_i \gets \Encrypt{P_i} \\
T_i \gets \Squeeze{N_T} \\
\Ratchet \\
\dots \\
\end{gather*}

Finally, a [`veil.schnorr`](#veil.schnorr) signature $s$ of the entire ciphertext (headers, padding,
and DEM ciphertext) is created with $d_E$ and encrypted as $S$:

\begin{gather*}
s \gets \invoke{veil.schnorr}{Sign}{d_E, Q_E, H_0..H_n || H_{pad} || ((C_0,T_0)..(C_n,T_n))} \\
S \gets \Encrypt{S} \\
\end{gather*}

The resulting ciphertext then contains, in order: the [`veil.sres`](#veil.sres)-encrypted headers,
random padding, a series of ciphertext and authentication tag block pairs, and a
[`veil.schnorr`](#veil.schnorr) signature of the entire ciphertext.

### Message Decryption

Decryption begins as follows, given the recipient's key pair, $d_R$ and $Q_R$, the sender's public
key, $Q_S$.

First, a duplex is initialized with a constant key and used to absorb the sender's public key:

\begin{gather*}
\Cyclist{\literal{veil.mres}} \\
\Absorb{Q_S} \\
\end{gather*}

The recipient reads through the ciphertext in header-sized blocks, looking for one which is
decryptable given their key pair and the sender's public key. Having found one, they recover the
data encryption key $K$, the ephemeral public key $Q_E$, and the message offset. They then absorb
the remainder of the block of encrypted headers $H_0..H_n$ and padding $H_{pad}$:

\begin{gather*}
\Absorb{H_0} \\
\dots \\
\Absorb{H_n} \\
\Absorb{H_{pad}} \\
\end{gather*}

The duplex is keyed with $K$ and used to decrypt the ciphertext blocks and verify the authentication
tags:

\begin{gather*}
\Cyclist{K} \\
\dots \\
P_i \gets \Decrypt{C_i} \\
T_i' \gets \Squeeze{N_T} \\
T_i' \checkeq T_i \\
\Ratchet \\
\dots \\
\end{gather*}

If any $T_i' \not = T_i$, the decryption is halted with an error.

Finally, the signature $S$ is decrypted and verified against the entire ciphertext:

\begin{gather*}
s \gets \Decrypt{S} \\
v \gets \invoke{veil.schnorr}{Verify}{s, Q_E, H_0..H_n || H_{pad} || ((C_0,T_0)..(C_n,T_n)} \\
\end{gather*}

The message is considered successfully decrypted if $v$ is true.

### Insider Security Of Messages

While `veil.mres` has some similarity to the Encrypt-then-Sign ($\EtS$) sequential signcryption
construction, unlike $\EtS$ it offers multi-user insider security (i.e. FSO/FUO-IND-CCA2 and
FSO/FUO-sUF-CMA in the multi-user setting).

_Practical Signcryption_ (p. 32) describes the tradeoffs inherent in the sequential constructions:

> If we consider the signcryption security corresponding to the security of the operation performed
> _first_ (i.e., privacy in the $\EtS$ method and authenticity in the $\StE$ method), then results
> differ depending on the security models and the composition methods. In the insider security
> model, the security of the first operation is not preserved against the strongest security notions
> of privacy and authenticity (i.e., IND-CCA2 security and sUF-CMA security) although it is
> preserved against weaker security notions (e.g., IND-CPA, IND-gCCA2, and UF-CMA security). This is
> because the adversary who knows the secret key of the other component (i.e., the signature scheme
> in the $\EtS$ method and the encryption scheme in the $\StE$ method) can manipulate the given
> signcryption ciphertext by re-signing it and submitting the modified ciphertext as a
> unsigncryption oracle query (in the attack against the IND-CCA2 security of the $\EtS$ method) or
> re-encrypting it and submit the modified ciphertext as a forgery (in the attack against the
> sUF-CMA security of the $\StE$ method). Intuitively, this tells us that achieving the strongest
> security corresponding to the security of the operation performed first is not possible when the
> adversary knows the secret key of the operation performed last.

Given that the [`veil.schnorr`](#veil.schnorr) signature is the final operation in `veil.mres` and
is sUF-CMA secure, we can conclude that `veil.mres` is sUF-CMA secure in the insider security model
per Theorem 2.1 of _Practical Signcryption_:

> If $\S$ is sUF-CMA secure, then the signcryption scheme $\Pi$ built using the $\EtS$ method is
> sUF-CMA secure in the insider model. \[…\]

Proof 1 of Theorem 2.2 of _Practical Signcryption_ describes a successful distinguisher $\Attacker$
in the IND-CCA2 game in the insider security model against the $\EtS$ construction:

> Given the induced decryption oracle $\text{Decrypt}$ and the induced encryption key ${pk}^{enc}$,
> $\Attacker$ picks two messages $(m_0,m_1)$, where $m_0 = 0$ and $m_1 = 1$, and then outputs them
> to get the challenge ciphertext $C = (c, \sigma )$. Next, $\Attacker$ gets the message part $c$
> and re-signs $c$ by computing a "new" signature $\sigma' \rgets \text{Sign}({sk}^{sig}_S,c)$ of
> $c$, where $\sigma' \not = \sigma$, and then queries the induced decryption oracle with $C' =
> (c,\sigma')$. Notice that since we assumed $\S$ is probabilistic (not deterministic), with a
> non-negligible probability one can find a different signature for the same message in polynomial
> time. Since $C' \not = C$, and $\sigma'$ is a valid signature of $c$, $\Attacker$ can obtain the
> decryption of $c$. Once the decrypted message $m$ is obtained, $\Attacker$ compares it with its
> own message pair $(m_0,m_1)$ and outputs the bit $b$ where $m_b = m$.

Unlike the $\EtS$ construction, however, `veil.mres` does not use the same key for privacy as it
does for authenticity. The signature is generated using the ephemeral private key $d_E$, which is
known only to the sender at the time of sending. The receiver only obtains $Q_E$, its corresponding
public key, by decrypting a header. The headers are each encrypted with ['veil.sres`](#veil.sres),
which provides insider security (i.e. IND-CCA2 and sUF-CMA).

Because `veil.mres` uses an ephemeral signing key, $\Attacker$ is not in possession of
${sk}^{sig}_S$ and can neither compute $\sigma'$ nor receive it from any available oracle, as the
security model does not provide $\Attacker$ access to nonce values. The use of an ephemeral singing
key effectively forces $\Attacker$ from the insider security model into the outsider security model
with respect to the IND-CCA2 game.

In the outsider security model, `veil.mres` is IND-CCA2 secure per Theorem 2.3 of _Practical
Signcryption_:

> If $\BigE$ is IND-CPA secure and $\BigS$ is sUF-CMA secure, then the signcryption scheme $\Pi$
> built using $\EtS$ is IND-CCA2 secure in the outsider security model.

Xoodyak's $\text{Encrypt}$ operation is IND-CPA secure (see [`veil.sres`](#veil.sres)) and
[`veil.schnorr`](#veil.schnorr) is sUF-CMA secure, thus `veil.mres` is IND-CCA2 secure (and sUF-CMA
secure) in both the insider and outsider security models.

### Authenticated Encryption And Partial Decryption

The division of the plaintext stream into blocks takes its inspiration from the [CHAIN
construction][oae2], but the use of Xoodyak allows for a significant reduction in complexity.
Instead of using the nonce and associated data to create a feed-forward ciphertext dependency, the
Xoodyak duplex ensures all encryption operations are cryptographically dependent on the ciphertext
of all previous encryption operations. Likewise, because the `veil.mres` ciphertext is terminated
with a [`veil.schnorr`](#veil.schnorr) signature, using a special operation for the final message
block isn't required.

The major limitation of such a system is the possibility of the partial decryption of invalid
ciphertexts. If an attacker flips a bit on the fourth block of a ciphertext, `veil.mres` will
successfully decrypt the first three before returning an error. If the end-user interface displays
that, the attacker may be successful in radically altering the semantics of an encrypted message
without the user's awareness. The first three blocks of a message, for example, could say `PAY
MALLORY $100`, `GIVE HER YOUR CAR`, `DO WHAT SHE SAYS`, while the last block might read `JUST
KIDDING`.

### Message Deniability

The headers are signcrypted with [`veil.sres`](#veil.sres), which achieves both authentication and
deniability. The message itself is encrypted with a randomly-generated symmetric key, which isn't
tied to any identity. The final [`veil.schnorr`](#veil.schnorr) signature is created with a
randomly-generated ephemeral key.

Despite providing strong authenticity, `veil.mres` produces fully deniable ciphertexts.

### Ephemeral Key Hedging

In deriving the DEK and ephemeral private key from a cloned duplex, `veil.mres` uses [Aranha et
al.'s "hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures
and differential fault attacks against purely deterministic encryption schemes.

## Passphrase-based Encryption {#veil.pbenc}

`veil.pbenc` implements memory-hard password-based encryption using [balloon hashing][bh] and
Xoodyak's AEAD construction.

### Initialization

The protocol is initialized as follows, given a passphrase $P$, a salt $S \rgets \allbits{128}$,
time parameter $0 <= N_T < 256$, space parameter $0 <= N_S < 256$, delta constant $D = 3$, and
block size constant $N_B = 32$.

A duplex is initialized with a constant key and used to absorb the passphrase, salt, and parameters:

\begin{gather*}
\Cyclist{\literal{veil.pbenc}} \\
\Absorb{P} \\
\Absorb{S} \\
\Absorb{N_T} \\
\Absorb{N_S} \\
\Absorb{N_B} \\
\Absorb{D} \\
\end{gather*}

For each iteration of the balloon hashing algorithm, given a counter $C$, input blocks $(B_L, B_R)$,
and an output block $B_O$, the counter is encoded as a little-endian 64-bit integer and absorbed,
the blocks are absorbed left-to-right, and the output block is filled with duplex output:

\begin{gather*}
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{B_L} \\
\Absorb{B_R} \\
B_O \gets \Squeeze{N_B} \\
\end{gather*}

The expanding phase of the algorithm is performed as described by [Boneh et al][bh], with $2^{N_T}$
iterations of the time loop and $2^{N_S}$ iterations in the space loop.

For the mixing phase of the algorithm, the loop variables $t$, $m$, and $i$ are encoded in a block
$b$ and absorbed along with the salt $S$:

\begin{gather*}
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{S} \\
b \gets \LE{U64}{t} || \LE{U64}{m} || \LE{U64}{i} \\
\Absorb{b} \\
\end{gather*}

A 64-bit little-endian integer is derived from duplex output. That integer is mapped to a block
index:

\begin{gather*}
v \gets \Squeeze{8} \bmod N_B \\
\end{gather*}

Block $B_v$ is hashed along with the counter and block $B_m$ is filled with output:

\begin{gather*}
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{B_v} \\
\Absorb{\epsilon} \\
B_m \gets \Squeeze{N_B} \\
\end{gather*}

Finally, the last block $B_n$ of the buffer is used to re-key the duplex:

\begin{gather*}
\Cyclist{B_n} \\
\end{gather*}

### Encryption

Given an initialized, keyed duplex, the encryption of a message $P$ is as follows:

\begin{gather*}
C \gets \Encrypt{P} \\
T \gets \Squeeze{N_T} \\
\end{gather*}

The returned ciphertext consists of the following:

\begin{gather*}
N_T || N_S || S || C || M
\end{gather*}

### Decryption

Given an initialized, keyed duplex, the decryption of a ciphertext $C$ and authentication tag $T$ is
as follows:

\begin{gather*}
P' \gets \Encrypt{C} \\
T' \gets \Squeeze{N_T} \\
T' \checkeq T \\
\end{gather*}

If the $T' = T$, the plaintext $P'$ is returned as authentic.

It should be noted that there is no standard balloon hashing algorithm, so this protocol is in the
very, very tall grass of cryptography and should never be used.

[abe]: https://eprint.iacr.org/2005/027.pdf
[agl]: https://www.imperialviolet.org/2016/05/16/agility.html
[bh]: https://eprint.iacr.org/2016/027.pdf
[bjørstad]: http://www.ii.uib.no/~tor/pdf/PKC_tagkem.pdf
[cce]: https://eprint.iacr.org/2017/664.pdf
[duplex]: https://keccak.team/files/SpongeDuplex.pdf
[duplex]: https://keccak.team/files/SpongeDuplex.pdf
[ed25519]: https://eprint.iacr.org/2020/823.pdf
[eddsa]: https://eprint.iacr.org/2020/1244.pdf
[gamage]: https://link.springer.com/chapter/10.1007/3-540-49162-7_6
[hedge]: https://eprint.iacr.org/2019/956.pdf
[hpke]: https://www.rfc-editor.org/rfc/rfc9180.html#name-key-compromise-impersonatio
[ik-cca]: https://iacr.org/archive/asiacrypt2001/22480568.pdf
[ind-sig]: https://eprint.iacr.org/2011/673.pdf
[kci]: https://eprint.iacr.org/2006/252.pdf
[keccak]: https://keccak.team/third_party.html
[oae2]: https://eprint.iacr.org/2015/189.pdf
[r255-why]: https://ristretto.group/why_ristretto.html
[r255]: https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-03.html
[schnorr-cma]: https://www.di.ens.fr/david.pointcheval/Documents/Papers/2000_joc.pdf
[schnorr-hash]: http://www.neven.org/papers/schnorr.pdf
[sponge]: https://keccak.team/files/SpongeIndifferentiability.pdf
[sponge]: https://keccak.team/files/SpongeIndifferentiability.pdf
[strobe]: https://eprint.iacr.org/2017/003.pdf
[xoodyak]: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
