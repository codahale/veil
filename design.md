---
title: The Veil Cryptosystem
author: Coda Hale
lang: en-US
indent: true
colorlinks: true
csl: ieee.csl
link-citations: true
bibliography: references.bib
abstract: |
  Veil is a cryptosystem that provides confidentiality, authenticity, and integrity services for messages of arbitrary
  sizes and multiple recipients. This document describes its cryptographic constructions, their security properties, and
  how they are combined to implement Veil's feature set.
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
\newcommand{\rgets}[0]{\stackrel{\$}{\gets}}
\newcommand{\checkeq}[0]{\stackrel{?}{=}}
\newcommand{\allbits}[1]{\{0,1\}^{#1}}
\newcommand{\literal}[1]{\texttt{#1}}
\newcommand{\invoke}[3]{\literal{#1::}\text{#2}(#3)}
\newcommand{\BigE}[0]{\mathcal{E}}
\newcommand{\BigS}[0]{\mathcal{S}}
\newcommand{\EtS}[0]{\mathcal{E}t\mathcal{S}}
\newcommand{\StE}[0]{\mathcal{S}t\mathcal{E}}
\newcommand{\Attacker}[0]{\mathcal{A}}
\newcommand{\Sender}[0]{\mathcal{S}}
\newcommand{\Receiver}[0]{\mathcal{R}}
\newcommand{\LE}[2]{\text{#1}_\text{LE}(#2)}

# Design Goals, Techniques, And Principles

## Security Models And Notions

Veil's intended security model is based on the SecNT concept developed by Badertscher et al. [@badertscher2018], which
combines a signcryption scheme, an insecure network, a permissionless certificate authority, and a possibly-insecure
local memory service into a gracefully-degrading communication network with the following properties:

> 1. If two uncompromised legitimate users communicate, then the secure network guarantees that the network attacker
> learns at most the length of the messages and the attacker cannot inject any message into this communication: the
> communication between them can be called secure.
> 
> 2. If, however, the legitimate sender is compromised, but not the receiver, then the network allows the attacker to
> inject messages in the name of this sender. Still, Eve does not learn the contents of the messages to the receiver:
> the communication is thus only confidential.
> 
> 3. If, on the other hand, the legitimate receiver is compromised, but not the sender, the secure network allows Eve to
> read the contents of the messages sent to this compromised user. Still, no messages can be injected into this
> communication: the communication is only authentic.
> 
> 4. If both, sender and receiver, are compromised, then the network does not give any guarantee on their communication,
> Eve can read every message and inject anything at will.

Veil adds three additional properties:

1. A sender can send a single message to multiple receivers with the same security properties as if the sender had sent
   the same message to each receiver.
2. If sender and receivers are uncompromised, Eve cannot distinguish between valid messages and random noise and can
   learn at most the maximum possible message length or the maximum possible number of recipients but not both.
3. A receiver cannot prove the authenticity of a message to a third party without revealing their own private key.

These properties are key for a censorship-resistant messaging system, as motivated by Bernstein in [@bernstein2013]:

> Censorship-circumvention tools are in an arms race against censors. The censors study all traffic passing into and out
> of their controlled sphere, and try to disable censorship-circumvention tools without completely shutting down the
> Internet. Tools aim to shape their traffic patterns to match unblocked programs, so that simple traffic profiling
> cannot identify the tools within a reasonable number of traces; the censors respond by deploying firewalls with
> increasingly sophisticated deep-packet inspection.
> 
> Cryptography hides patterns in user data but does not evade censorship if the censor can recognize patterns in the
> cryptography itself.

A single-recipient system with ciphertexts indistinguishable from random noise cannot be easily raised to a
multi-recipient system with the same property. A naive system might simply encrypt multiple copies of a single message,
which leaves receivers without assurance that they received the same message as others. Further, a naive system risks
leaking metadata about receivers' identities or their aggregated number. In contrast, Veil preserves the semantics of a
single statement to a fixed group of recipients. Finally, Veil has deniable authenticity, requiring a dishonest receiver
to reveal their private key to a third party in order to prove the authenticity of a message.

The multi-recipient setting also further motivates Badertscher et al.'s emphasis on full insider security 
([contra @an2010, p. 29; @baek2010, p. 46]):

> One crucial point of our main theorem is that it is insider security that provably assures that the secure network
> degrades gracefully as a function of compromised keys and does not lose the security guarantees in a coarse-grained
> fashion (for example per pair of parties instead of a single party). This view assigns a more crucial, practical role
> to the insider security model than what is commonly assumed.

Given a probability of an individual key compromise $P$, a multi-user system of $N$ users has an overall $1-(1-P)^N$
probability of at least one key being compromised. A system with an exponentially increasing likelihood of losing all
confidentiality and authenticity properties is not acceptable.

### Multi-User Insider Security

To accomplish these properties, Veil adopts the multi-user insider security (MIS) notion of Badertscher et al.
[@badertscher2018] as the combination of multi-user insider confidentiality (MIS-Conf) and multi-user insider
authenticity (MIS-Auth), which correspond to multi-user insider confidentiality in the FSO/FUO-IND-CCA2 sense and
multi-user insider unforgeability in the FSO/FUO-sUF-CMA sense in the BSZ model [@baek2010].

Badertscher et al. define MIS-Conf with a real-or-random distinguishing game, in which an attacker $\Attacker$ must
distinguish between a "real" pair of signcryption/unsigncryption oracles instantiated with the signcryption scheme under
attack and an "ideal" pair of oracles which signcrypt uniformly random messages with non-negligible advantage.
$\Attacker$ is allowed to query the signcryption oracle using arbitrary sender key pairs and arbitrary receiver public
keys and to query the unsigncryption oracle using arbitrary sender private keys.

MIS-Auth is defined as a forging game, in which attacker $\Attacker$ must forge a ciphertext which successfully decrypts
using an arbitrary receiver key pair and arbitrary sender public key to an arbitrary plaintext. $\Attacker$ is given
access to key generation and signcryption oracles in addition to a verifying unsigncryption oracle.

Veil extends these games by mapping single receiver keys to non-empty sets of keys of arbitrary cardinality and
precluding $\Attacker$ from including any public key they control.

## Cryptographic Primitives

Veil uses just two distinct cryptographic primitives:

* Xoodyak [@daemen2020] for confidentiality, authentication, and integrity.
* ristretto255 [@deValence2020] for key agreement and authenticity.

### Xoodyak

Xoodyak is a cryptographic duplex, a cryptographic primitive that provides symmetric-key confidentiality, integrity, and
authentication via a single object. Duplexes offer a way to replace complex, ad-hoc constructions combining encryption
algorithms, cipher modes, AEADs, MACs, and hash algorithms using a single primitive [@daemen2020; @bertoni2011].

Duplexes have security properties which reduce to the properties of the cryptographic, which themselves reduce to the
strength of the underlying permutation [@bertoni2008]. Xoodyak is based on the Xoodoo permutation, an adaptation of the
Keccak-_p_ permutation (upon which SHA-3 is built) for lower-resource environments. While Xoodyak is not standardized,
it is currently a finalist in the NIST Lightweight Cryptography standardization process. It targets a 128-bit security
level, lends itself to constant-time implementations, and can run in constrained environments [@daemen2020].

Veil's security assumes that Xoodyak's $\text{Encrypt}$ operation is IND-CPA secure, its $\text{Squeeze}$ operation is
sUF-CMA secure, and its $\text{Encrypt}/\text{Squeeze}$-based AEAD construction is IND-CCA2 secure.

### ristretto255

ristretto255 uses a safe curve, is a prime-order cyclic group, has non-malleable encodings, and has no co-factor
concerns. This allows for the use of a wide variety of cryptographic constructions built on group operations. Like
Xoodyak, it targets a 128-bit security level, lends itself to constant-time implementations, and can run in constrained
environments [@deValence2018].

Veil's security assumes that the Gap Discrete Logarithm and Gap Diffie-Hellman problems are hard relative to
ristretto255.

## Construction Techniques

Veil uses a few common construction techniques in its design which bear specific mention.

### Integrated Constructions

Xoodyak is a cryptographic duplex, thus each operation is cryptographically dependent on the previous operations. Veil
makes use of this by integrating different types of constructions to produce a unified construction. Instead of having
to pass forward specific values (e.g. hashes of values or derived keys) to ensure cryptographic dependency, Xoodyak
allows for constructions which simply absorb all values, thus ensuring transcript integrity of complex protocols.

For example, a traditional hybrid encryption scheme like HPKE [@rfc9180] will describe a key encapsulation mechanism
(KEM) like ephemeral Diffie-Hellman and a data encapsulation mechanism (DEM) like AES-GCM and link the two together via
a key derivation function (KDF) like HKDF by deriving a key and nonce for the DEM from the KEM output.

In contrast, the same construction using Xoodyak would be the following three operations, in order:

\begin{gather}
\Cyclist{[d_E]Q_R} \\
C \gets \Encrypt{P} \\
T \gets \Squeeze{16}
\end{gather}

The duplex is keyed with the shared secret point ($1$), used to encrypt the plaintext ($2$), and finally used to squeeze
an authentication tag ($3$). Each operation modifies the duplex's state, making the final $\text{Squeeze}$ operation
dependent on both the previous $\text{Encrypt}$ operation (and its argument, $P$) but also the $\text{Cyclist}$
operation before it.

This is both a dramatically clearer way of expressing the overall hybrid public-key encryption construction and more
efficient: because the ephemeral shared secret point is unique, no nonce need be derived (or no all-zero nonce need be
justified in an audit).

### Nested Constructions

The fact that Xoodyak's output is dependent on its process history (i.e. the sequence of operations and their arguments)
allows for different constructions to be easily nested to produce novel constructions. For example, an ephemeral
Diffie-Hellman KEM/DEM scheme can be nested within a static Diffie-Hellman KEM/DEM scheme.

To encrypt:

\begin{gather*}
\Cyclist{[d_S]Q_R} \\
C_0 \gets \Encrypt{Q_E} \\
\Cyclist{[d_E]Q_R} \\
C_1 \gets \Encrypt{P} \\
T \gets \Squeeze{16}
\end{gather*}

To decrypt:

\begin{gather*}
\Cyclist{[d_R]Q_S} \\
Q_E \gets \Decrypt{C_0} \\
\Cyclist{[d_R]Q_E} \\
P \gets \Encrypt{C_1} \\
T' \gets \Squeeze{16} \\
T' \checkeq T
\end{gather*}

The end result is a novel construction which combines the benefits of both approaches. The outer construction provides
confidentiality of the ephemeral public key, the inner construction provides forward-secure confidentiality of the
plaintext, and the final authentication tag ensures authenticity.

### Hedged Ephemeral Values

When generating ephemeral values, Veil uses Aranha et al.'s "hedged signature" technique [@aranha2020] to mitigate
against both catastrophic randomness failures and differential fault attacks against purely deterministic schemes.

Specifically, the duplex's state is cloned, and the clone absorbs a context-specific secret value (e.g. the signer's 
private key in a digital signature scheme) and a 64-byte random. The clone duplex is used to produce the ephemeral value
or values for the scheme.

For example, the following operations would be performed on the cloned duplex:

\begin{gather*}
\Absorb{d} \\
v \rgets \allbits{512} \\
\Absorb{v} \\
k \gets \SqueezeScalar \\
\end{gather*}

The ephemeral scalar $k$ is returned to the context of the original construction and the cloned duplex is discarded.
This ensures that even in the event of a catastrophic failure of the random number generator, $k$ is still unique
relative to $d$.

# Cryptopgraphic Constructions

## `veil.hkd`

Each participant in Veil has a secret key, which is a string $S \rgets \allbits{512}$.

### Deriving The Root Key

To derive a root private key from a secret key, a duplex is initialized with a constant key and used to absorb $S$. A
scalar $d$ is then derived from output:

\begin{gather*}
\Cyclist{\literal{veil.hkd.root}} \\
\Absorb{S} \\
d \gets \SqueezeScalar \\
\end{gather*}

### Deriving A Private Key From Another Private Key

To derive a private key $d'$ from another private key $d$ with a label $L$, a duplex initialized with a constant key is
used to absorb $[d]G$ and $L$ and squeeze a scalar value:

\begin{gather*}
\Cyclist{\literal{veil.hkd.label}} \\
\Absorb{[d]G} \\
\Absorb{L} \\
r \gets \SqueezeScalar \\
d' \gets d + r \\
\end{gather*}

### Deriving A Public Key From Another Public Key

To derive a public key $Q'$ from another public key $Q$ with a label $L$, a duplex initialized with a constant key is
used to absorb $Q$ and $L$ and squeeze a scalar value:

\begin{gather*}
\Cyclist{\literal{veil.hkd.label}} \\
\Absorb{Q} \\
\Absorb{L} \\
r \gets \SqueezeScalar \\
Q' \gets Q + [r]G \\
\end{gather*}

### Hierarchical Keys

This is used to provide hierarchical key derivation, deriving a final key from a secret key via a path of labels
$L_0..L_n$.

Using a key path $\literal{friends} \to \literal{alice}$, the secret key is mapped to a private key via
`veil.scaldf.root`, which is then mapped to an intermediate private key via the label `friends`, which is then mapped to
the final private key via the label `alice`.

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
`ee4c176352b1d0b2df4a699d430ea48e` and share the corresponding public key with Bea via an anonymous channel. Unless Bea
can guess that key path, Bea will be unable to determine if her anonymous pen pal is Alice even if she has Alice's key.

These disposable keys are stateless, as well: if Alice wants to burn that key, all she needs to do is forget the key
path.

## `veil.schnorr`

`veil.schnorr` implements a Schnorr digital signature scheme.

### Signing A Message

Signing is as follows, given a message in 16-byte blocks $M_0..M_n$, a private scalar $d$, and a public point $Q$.

First, a duplex is initialized with a constant key and used to absorb the message blocks and the signer's public key:

\begin{gather*}
\Cyclist{\literal{veil.schnorr}} \\
\AbsorbMore{M_0}{16} \\
\AbsorbMore{M_1}{16} \\
\dots \\
\AbsorbMore{M_n}{16} \\
\Absorb{Q} \\
\end{gather*}

The signer's public key is absorbed after the message to allow [`veil.mres`](#veilmres) to search for a header without
having to buffer the results.)

A [hedged ephemeral scalar](#hedged-ephemeral-values) $k$ is derived the signer's private key $d_S$, and the commitment
point $I=[k]G$ is calculated and encrypted as $S_0$:

\begin{gather*}
I \gets [k]G \\
S_0 \gets \Encrypt{I} \\
\end{gather*}

A challenge scalar $r$ is derived from output and used to calculate the proof scalar $s$ which is encrypted as $S_1$:

\begin{gather*}
r \gets \SqueezeScalar \\
s \gets dr + k \\
S_1 \gets \Encrypt{s}
\end{gather*}

The final signature is $S_0 || S_1$.

### Verifying A Signature

Verification is as follows, given a message in 16-byte blocks $M_0..M_n$, a public point $Q$, and a signature $S_0 ||
S_1$.

First, a duplex is created, initialized with a constant key, and used to absorb the message blocks and the signer's
public key:

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

$S_1$ is decrypted and decoded as $s$ and the counterfactual commitment point $I'$ is calculated and compared to the
signature commitment point $I$:

\begin{gather*}
s \gets \Decrypt{S_1} \\
I' \gets [s]G - [r]Q \\
I' \checkeq I \\
\end{gather*}

The signature is valid if-and-only-if $I' = I$.

### Security, Forgeability, and Malleability

The Schnorr signature scheme is the application of the Fiat-Shamir transform to the Schnorr identification scheme.

Per Theorem 13.10 of [@katz2020, p. 478], this construction is sUF-CMA secure if the Schnorr identification scheme is
secure and the hash function is secure:

> Let $\Pi$ be an identification scheme, and let $\Pi'$ be the signature scheme that results by
> applying the Fiat-Shamir transform to it. If $\Pi$ is secure and $H$ is modeled as a random
> oracle, then $\Pi'$ is secure.

Per Theorem 13.11 of [@katz2020, p. 481], the security of the Schnorr identification scheme is conditioned on the
hardness of the discrete logarithm problem:

> If the discrete-logarithm problem is hard relative to $\mathcal{G}$, then the Schnorr
> identification scheme is secure.

This construction uses the Xoodyak duplex as a hash function. Consequently, the security of this construction assumes
the fitness of Xoodyak as a random oracle and the hardness of the discrete-logarithm problem relative to ristretto255.

Unlike Construction 13.12 of [@katz2020, p. 482], `veil.schnorr` transmits the commitment point $I$ as part of the
signature and the verifier calculates $I'$ vs transmitting the challenge scalar $r$ and calculating $r'$. In this
way, `veil.schnorr` is closer to EdDSA [@brendel2021] or the Schnorr variant proposed by Hamburg in [@hamburg2017].

Some Schnorr/EdDSA implementations (e.g. ed25519) suffer from malleability issues, allowing for multiple valid
signatures for a given signer and message [@brendel2021]. Chalkias et al. [@chalkias2020] describe a strict verification
function for Ed25519 which achieves sUF-CMA security in addition to strong binding:

> 1. Reject the signature if $S \not\in \{0,\ldots,L-1\}$.
> 2. Reject the signature if the public key $A$ is one of 8 small order points.
> 3. Reject the signature if $A$ or $R$ are non-canonical.
> 4. Compute the hash $\text{SHA2}_{512}(R||A||M)$ and reduce it mod $L$ to get a scalar $h$.
> 5. Accept if $8(S \cdot B)-8R-8(h \cdot A)=0$.

Rejecting $S \geq L$ makes the scheme sUF-CMA secure, and rejecting small order $A$ values makes the scheme strongly
binding. `veil.schnorr`'s use of ristretto255's canonical point and scalar encoding routines obviate the need for these
checks. Likewise, ristretto255 is a prime order group, which obviates the need for cofactoring in verification.

When implemented with a prime order group and canonical encoding routines, The Schnorr signature scheme is strongly
unforgeable under chosen message attack (sUF-CMA) in the random oracle model [@pointcheval2000] and even with practical
cryptographic hash functions [@neven2009]. Thus, the signatures are non-malleable.

### Indistinguishability and Pseudorandomness

Per Fleischhacker et al. [@fleischhacker2013], this construction produces indistinguishable signatures (i.e., signatures
which do not reveal anything about the signing key or signed message). When encrypted with an unrelated key (i.e., via
$\text{Encrypt}$), the construction is isomorphic to Fleischhacker et al.'s DRPC compiler for producing pseudorandom
signatures, which are indistinguishable from random.

## `veil.sres`

`veil.sres` implements a single-receiver, deniable signcryption scheme which [nests](#nested-constructions) an
ephemeral Diffie-Hellman hybrid encryption scheme within the Zheng signcryption tag-KEM (Zheng-SCTK, as described by
Bjørstad [@bjorstad2010]) and [integrates](#integrated-constructions) a Xoodyak-based DEM. It is
[MIS secure](#multi-user-insider-security).

### Encrypting A Header

Header encryption takes a sender's key pair, $(d_S, Q_S)$, an ephemeral key pair $(d_E, Q_E)$, a receiver's public key,
$Q_R$, and a plaintext header $P$.

First, a duplex is initialized with a constant key and used to absorb the sender's public key $Q_S$ and the receiver's
public key $Q_R$:

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

Third, the duplex's state is cloned, and the clone absorbs the sender's private key, 64 bytes of random data, and the
plaintext. The commitment scalar $x$ is then derived from output:

\begin{gather*}
\Absorb{d_S} \\
v \rgets \allbits{512} \\
\Absorb{v} \\
\Absorb{P} \\
x \gets \SqueezeScalar \\
\end{gather*}

Fourth, the Zheng shared secret point $K_0$ is calculated and used to re-key the duplex and the ephemeral public key
$Q_E$ is encrypted as $C_0$:

\begin{gather*}
K_0 \gets [x]Q_R \\
\Cyclist{K_0} \\
C_0 \gets \Encrypt{Q_E} \\
\end{gather*}

Fifth, the Diffie-Hellman shared secret point $K_1$ is calculated and used to re-key the duplex and the plaintext $P$
is encrypted as $C_1$:

\begin{gather*}
K_1 \gets [d_E]Q_R \\
\Cyclist{K_1} \\
C_1 \gets \Encrypt{P} \\
\end{gather*}

Sixth, the duplex's state is ratcheted, a challenge scalar $r$ is derived from output, and a proof scalar $s$ is
calculated:

\begin{gather*}
\Ratchet \\
r \gets \SqueezeScalar \\
s \gets (r+d_S)^{-1}x \\
\end{gather*}

(In the rare event that $r+d_S=0$, the procedure is re-run with a different $x$.)

Finally, the top four bits of both $r$ and $s$ are masked with the top and bottom four bits of $m$, respectively, as
$S_0$ and $S_1$:

\begin{gather*}
S_0 \gets r \lor ((m \land \literal{0xF0}) \ll 252) \\
S_1 \gets s \lor ((m \ll 4) \ll 252) \\
\end{gather*}

The final ciphertext is $C_0||C_1||S_0||S_1$.

### Decrypting A Header

Decryption takes a receiver's key pair, $(d_R, Q_R)$, a sender's public key, $Q_S$, and an encrypted header
$C=C_0||C_1||S_0||S_1$.

First, a duplex is initialized with a constant key and used to absorb the sender's public key $Q_S$ and the receiver's
public key $Q_R$:

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

Third, the challenge scalar $r$ and the proof scalar $s$ are unmasked and used to calculate the Zheng shared secret
$K_0$, which is used to re-key the duplex:

\begin{gather*}
r \gets S_0 \land \lnot(2^8 \ll 252) \bmod \ell \\
s \gets S_1 \land \lnot(2^8 \ll 252) \bmod \ell \\
K \gets [{d_R}s] ([r]G+Q_S) \\
\Cyclist{K_0} \\
\end{gather*}

Fourth, the ephemeral public key $Q_E$ is decrypted and used to calculate the Diffie-Hellman shared secret $K_1$, which
is used to re-key the duplex:

\begin{gather*}
Q_E \gets \Decrypt{C_0} \\
K_1 \gets [d_R]Q_E \\
\Cyclist{K_1} \\
\end{gather*}

Fifth, the ciphertext $C_1$ is decrypted as the unauthenticated plaintext $P'$, the duplex's state is ratcheted, and a
counterfactual challenge scalar $r'$ is derived from output:

\begin{gather*}
P' \gets \Decrypt{C_1} \\
\Ratchet \\
r' \gets \SqueezeScalar \\
r' \checkeq r \\
\end{gather*}

If $r' = r$, the ephemeral public key $Q_E$ and plaintext $P'$ are returned as authentic; otherwise, an error is
returned.

### Adapting Zheng-SCTK To The Duplex

Instead of passing a ciphertext-dependent tag $\tau$ into the KEM's $\text{Encap}$ function, `veil.sres` begins
$\text{Encap}$ operations using the keyed duplex after the ciphertext has been encrypted with $\text{Encrypt}$ and the
state mutated with $\text{Ratchet}$.

This process ensures the derivation of the challenge scalar $r$ from $\text{SqueezeKey}$ output is cryptographically
dependent on the public keys $Q_S$ and $Q_R$, the shared secret $K_0$, and the ciphertext $C$. This is equivalent to the
dependency described by Bjørstad [@bjorstad2010, p. 141]:

\begin{gather*}
r \gets H(\tau || {pk}_S || {pk}_R || \kappa)
\end{gather*}

The end result is a challenge scalar which is cryptographically dependent on the prior values and on the ciphertext as
sent (and not, as in previous insider secure signcryption KEM constructions, the plaintext). This and the ratcheting of
the duplex's state ensure the scalars $r$ and $s$ cannot leak information about the plaintext.

Finally, the inclusion of the masked bits of scalars $S_0$ and $S_1$ prior to generating the challenge scalar $r$ makes
their masked bits (and thus the entire ciphertext) non-malleable.

### MIS-Conf Security of `veil.sres`

The [outer construction](#nested-constructions) of `veil.sres` is the Zheng signcryption tag-KEM (Zheng-SCTK, as
described by Bjørstad [@bjorstad2010])

Theorem 7.3 of Bjørstad [@bjorstad2010, p. 143] conditions `veil.sres`'s confidentiality in the multi-user **outsider**
setting on Zheng-SCTK's IND-CCA2 security and [Xoodyak's IND-CPA security](#xoodyak):

> Let SC be a hybrid signcryption scheme constructed from a signcryption tag-KEM and a DEM. If the
> signcryption tag-KEM is IND-CCA2 secure and the DEM is IND-CPA secure, then SC is multi-user
> outsider FSO/FUO-IND-CCA2 secure...

Theorem 4.1 of Barreto et al. [@barreto2010, p. 61] conditions the multi-user outsider FSO/FUO-IND-CCA security of
Zheng's scheme on the Gap Diffie-Hellman assumption and Xoodyak's IND-CPA security:

> If the GDH problem is hard and the symmetric encryption scheme is IND-CPA secure, then Zheng's
> scheme is multi-user outsider FSO/FUO-IND-CCA secure in the random oracle model.

Critically, this outer construction is not **insider** secure by itself, as an attacker in possession of the sender's
private key $d_S$ can re-compute the ephemeral $x=s(r + d_S)$ and decrypt arbitrary ciphertexts. This vulnerability is
addressed by the inner construction.

The [inner construction](#nested-constructions) of `veil.sres` is an ECIES-style hybrid encryption scheme, equivalent to
Construction 12.23 of [@katz2020, p. 435], and per Corollary 12.24 of [@katz2020, p. 436], is IND-CCA2 secure. After
re-keying the duplex with the Diffie-Hellman shared secret, the ciphertext is then encrypted with what is effectively a
combination of both the Zheng-SCTK KEM output and the ECIES KEM output. An attacker in possession of $d_S$ will be
unable to re-compute $d_E$ and thus unable to decrypt the ciphertext. This offers the attacker a distinguisher between
ciphertexts and random noise (i.e. can the first 32 bytes be decrypted into a valid ephemeral public key), but no
advantage in distinguishing between two ciphertexts.

Thus, `veil.sres` is [MIS-Conf secure](#multi-user-insider-security).

### MIS-Auth Security Of `veil.sres`

In evaluating the unforgeability of `veil.sres`, only the [outer construction Zheng-SCTK](#nested-constructions) need be
considered: the final pair of scalars close over the inner ephemeral Diffie-Hellman construction. Theorem 7.3 of
Bjørstad [@bjorstad2010, p. 143] establishes `veil.sres` as unforgeable in the multi-user insider setting if Zheng-SCTK
is sUF-CMA secure:

> Furthermore, if the signcryption tag-KEM is sUF-CMA secure, then SC is multi-user insider
> FSO/FUO-sUF-CMA secure...

Theorem 4.2 of Barreto et al. [@barreto2010, p. 61] conditions the multi-user insider unforgeability of Zheng's
signcryption scheme on the Gap Discrete Logarithm problem:

> If the Gap Discrete Logarithm problem is hard, then Zheng's scheme is multi-user insider
> secret-key-ignorant FSO-UF-CMA-SKI secure in the random oracle model.

FSO-UF-CMA-SKI is a stronger notion than FSO-SUF-CMA; any scheme which is FSO-UF-CMA-SKI secure is also FSO-SUF-CMA
secure. Thus, `veil.sres` is [MIS-Auth secure](#multi-user-insider-security).

### Indistinguishability Of `veil.sres` Ciphertexts From Random Noise

`veil.sres` ciphertexts are indistinguishable from random bitstrings.

The scalars $r$ and $s$ are uniformly distributed modulo $\ell \approx 2^{252} + \dots$, which leaves the top four bits
of the top byte effectively unset. These bits are masked with randomly-generated values before being sent and cleared
after being received. As a result, they are fully uniformly distributed and indistinguishable from random noise. Any
256-bit string will be decoded into a valid scalar, making active distinguishers impossible. This has been
experimentally verified, with $10^7$ random scalars yielding a uniform distribution of bits
($\mu=0.4999,\sigma=0.00016$).

The remainder of the ciphertext consists exclusively of Xoodyak output. A passive adversary capable of distinguishing
between a valid ciphertext and a random bitstring would violate the CPA-security of Xoodyak.

### Key Compromise Impersonation In `veil.sres`

Per Strangio [@strangio2006]:

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

A static Diffie-Hellman exchange is vulnerable to KCI attacks (e.g. HPKE [@rfc9180, Section 9.1.1], in that the shared
secret point ${Z}$ can be calculated as $[{d_S}]{Q_R}$ by an authentic sender or as $[{d_R}]{Q_S}$ by an attacker in
possession of the recipient's private key $d_S$ and the sender's public key $Q_S$.

`veil.sres` prevents KCI attacks by using the sender's public key $d_S$ in the process of creating both the shared
secret $K_0$ and the proof scalar $s$. The recipient can use their own private key $d_R$ to reconstruct $K_0$ and
authenticate the plaintext $P$, but cannot themselves re-create $s$.

This is effectively the difference between a MOS-Auth secure scheme like static Diffie-Hellman (in which outsiders
cannot forge messages) and a MIS-Auth secure scheme like `veil.sres` (in which insiders cannot forge messages).

### Deniability Of `veil.sres` Ciphertexts

`veil.sres` authenticates the plaintext with what is effectively a designated-verifier signature. In order to decrypt
and verify a ciphertext, a recipient must calculate the shared secret point $K_0=[{d_R}s] (Q_S+[r]G)$, of which only the
recipient's private key $d_R$ is a non-public term.

As such, a dishonest recipient cannot prove to a third party that the messages was encrypted by the sender without
revealing their own private key. (A sender, of course, can keep the commitment scalar $x$ and re-create the message or
just reveal the message directly.)

This is a key point of distinction between the Zheng-SCTK scheme and the related scheme by Gamage et al. which offers
public verifiability of ciphertexts [@gamage1999]. Where Gamage's scheme uses the curve's generator point $G$ to
calculate the shared secret, Zheng-SCTK uses the recipient's public key $Q_R$, requiring the use of the recipient's
private key $d_R$ for decapsulation.

## `veil.mres`

`veil.mres` is a multi-recipient signcryption scheme, using a modified encrypt-then-sign construction with an
[MIS](#multi-user-insider-security) secure encryption construction and an sUF-CMA secure signature scheme.

### Encrypting A Message

Encrypting a message begins as follows, given the sender's key pair, $d_S$ and $Q_S$, a plaintext message in blocks
$P_0..P_n$, a list of recipient public keys, $Q_{R^0}..Q_{R^m}$, and a DEK size $N_{K}$.

First, a duplex is initialized with a constant key and used to absorb the sender's public key:

\begin{gather*}
\Cyclist{\literal{veil.mres}} \\
\Absorb{Q_S} \\
\end{gather*}

A [hedged ephemeral](#hedged-ephemeral-values) data encryption key $K$ and ephemeral private key $d_E$ are derived from
the signer's private key $d_S$ and the ephemeral public key $Q_E=[d_E]G$ is calculated. $K$, $Q_E$, and the message
offset are encoded into a fixed-length header and copies of it are encrypted with [`veil.sres`](#veilsres) for each
recipient using $(d_S, Q_S)$. Optional random padding is added to the end, and the resulting headers $H_0..H_n||H_{pad}$
are absorbed in 32KiB blocks:

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

The duplex is keyed with $K$, the plaintext message is divided into 32KiB blocks $P_0 || P_1 || \dots P_i \dots || P_n$.
Each block $P_i$ is encrypted as ciphertext $C_i$ and an authentication tag $T_i$ is generated and appended. After each
block, the duplex state is ratcheted to prevent rollback:

\begin{gather*}
\Cyclist{K} \\
\dots \\
C_i \gets \Encrypt{P_i} \\
T_i \gets \Squeeze{N_T} \\
\Ratchet \\
\dots \\
\end{gather*}

Finally, a [`veil.schnorr`](#veilschnorr) signature $s$ of the entire ciphertext (headers, padding, and DEM ciphertext)
is created with $d_E$ and encrypted as $S$:

\begin{gather*}
s \gets \invoke{veil.schnorr}{Sign}{d_E, Q_E, H_0..H_n || H_{pad} || ((C_0,T_0)..(C_n,T_n))} \\
S \gets \Encrypt{S} \\
\end{gather*}

The resulting ciphertext then contains, in order: the [`veil.sres`](#veilsres)-encrypted headers, random padding, a
series of ciphertext and authentication tag block pairs, and a [`veil.schnorr`](#veilschnorr) signature of the entire
ciphertext.

### Decrypting A Message

Decryption begins as follows, given the recipient's key pair, $d_R$ and $Q_R$, the sender's public key, $Q_S$.

First, a duplex is initialized with a constant key and used to absorb the sender's public key:

\begin{gather*}
\Cyclist{\literal{veil.mres}} \\
\Absorb{Q_S} \\
\end{gather*}

The recipient reads through the ciphertext in header-sized blocks, looking for one which is decryptable given their key
pair and the sender's public key. Having found one, they recover the data encryption key $K$, the ephemeral public key
$Q_E$, and the message offset. They then absorb the remainder of the block of encrypted headers $H_0..H_n$ and padding
$H_{pad}$:

\begin{gather*}
\Absorb{H_0} \\
\dots \\
\Absorb{H_n} \\
\Absorb{H_{pad}} \\
\end{gather*}

The duplex is keyed with $K$ and used to decrypt the ciphertext blocks and verify the authentication tags:

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

### MIS Security Of `veil.mres`

As `veil.mres` is the most novel of the constructions in Veil, it bears a more thorough analysis. In the
[MIS-Conf](#multi-user-insider-security) game, the attacker $\Attacker$ is an insider adversary acting as a sender and
attempting to distinguish between ciphertexts created by a real oracle and those created by an oracle which substitutes
its messages for random strings of equal length. They are allowed to make any number of requests to both real and ideal
signcryption oracles as well as to an unsigncryption oracle, with the main limitation being that they cannot make
distinguishing guesses about ciphertexts which include receivers that $\Attacker$ controls.

In order for a `veil.mres` ciphertext to be successfully decrypted by a receiver, the following conditions must all be
true:

1. There must be a [`veil.sres`-encrypted header](#veilsres) encrypted by the sender for the receiver, containing a 
   well-formed ephemeral public key, data encryption key, and message offset.
2. The data encryption key must successfully decrypt and authenticate all the message blocks and then decrypt the final
   [`veil.schnorr`](#veilschnorr) signature.
3. The signature must be a valid signature by the ephemeral private key of the entire ciphertext minus the signature.

From the perspective of a receiver, a `veil.mres` ciphertext consists of the following components:

1. A [`veil.sres`-encrypted header](#veilsres) intended for the receiver
2. A number of headers, either valid and intended for other receivers or invalid and used to disguise receiver counts
3. A sequence of random padding bytes used to disguise the message length
4. A sequence of Xoodyak ciphertexts and authentication tags
5. An encrypted [`veil.schnorr`](#veilschnorr) signature

While `veil.mres` has some similarity to the Encrypt-then-Sign ($\EtS$) sequential signcryption construction, unlike
$\EtS$ it offers [multi-user insider security](#multi-user-insider-security).

An and Rabin [@an2010, p. 32] describe the tradeoffs inherent in the sequential constructions (i.e $\EtS$ and $\StE$):

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

The effects of these tradeoffs are magnified in the multi-user setting [@an2010, pp. 40-41]:

> We can see that the signcryption algorithms that are built by generic composition of encryption and signature schemes
> (i.e., $\EtS$ and $\StE$) are not secure in the multi-user setting. If the $\EtS$ method is used in the multi-user
> setting, then the adversary $\Attacker$ can easily break the CCA2 security, even in the outsider model. Indeed, given
> the challenge $C=(c,\sigma,ID_S,ID_R)$, where $c \stackrel{R}{\gets} \text{Encrypt}(pk_R,m_b)$ and
> $\sigma \stackrel{R}{\gets} \text{Sign}(sk_S, c)$, $\Attacker$ can replace the sender's signature with its own by
> computing $C' = (c,\sigma',ID_{S'},ID_R)$, where $\sigma' \stackrel{R}{\gets} Sign(sk_{S'},c)$. If $\Attacker$ queries
> the unsigncryption oracle on $C'$ then the oracle will respond with $m_b$ and $\Attacker$ can trivially break the 
> IND-CCA2 security of the scheme. 

Unlike the $\EtS$ construction, however, `veil.mres` does not use the same key for confidentiality as it does for
authenticity. The signature is generated using the ephemeral private key $d_E$, which is known only to the sender at the
time of sending. The receiver only obtains $Q_E$, its corresponding public key, by decrypting a header. The headers are
each encrypted with [`veil.sres`](#veilsres), which provides insider security (i.e. IND-CCA2 and sUF-CMA).

Because `veil.mres` uses an ephemeral signing key, $\Attacker$ is not in possession of ${sk}^{sig}_S$ and can neither
compute $\sigma'$ nor receive it from any available oracle, as the security model does not provide $\Attacker$ access to
nonce values. The use of an ephemeral singing key effectively forces $\Attacker$ from the insider security model into
the outsider security model with respect to the IND-CCA2 game.

In the outsider security model, `veil.mres` is IND-CCA2 secure per Theorem 2.3 of An and Rabin [@an2010, p. 35]:

> If $\BigE$ is IND-CPA secure and $\BigS$ is sUF-CMA secure, then the signcryption scheme $\Pi$
> built using $\EtS$ is IND-CCA2 secure in the outsider security model.

Xoodyak's $\text{Encrypt}$ operation is IND-CPA secure (see [`veil.sres`](#veilsres)) and [`veil.schnorr`](#veilschnorr)
is sUF-CMA secure, thus `veil.mres` is IND-CCA2 secure (and sUF-CMA secure) in both the insider and outsider security
models.

### Authenticated Encryption And Partial Decryption

The division of the plaintext stream into blocks takes its inspiration from the CHAIN construction [@hoang2015], but the
use of Xoodyak allows for a significant reduction in complexity. Instead of using the nonce and associated data to
create a feed-forward ciphertext dependency, the Xoodyak duplex ensures all encryption operations are cryptographically
dependent on the ciphertext of all previous encryption operations. Likewise, because the `veil.mres` ciphertext is
terminated with a [`veil.schnorr`](#veilschnorr) signature, using a special operation for the final message block isn't
required.

The major limitation of such a system is the possibility of the partial decryption of invalid ciphertexts. If an
attacker flips a bit on the fourth block of a ciphertext, `veil.mres` will successfully decrypt the first three before
returning an error. If the end-user interface displays that, the attacker may be successful in radically altering the
semantics of an encrypted message without the user's awareness. The first three blocks of a message, for example, could
say `PAY MALLORY $100`, `GIVE HER YOUR CAR`, `DO WHAT SHE SAYS`, while the last block might read `JUST KIDDING`.

### Message Deniability

The headers are signcrypted with [`veil.sres`](#veilsres), which achieves both authentication and deniability. The
message itself is encrypted with a randomly-generated symmetric key, which isn't tied to any identity. The final
[`veil.schnorr`](#veilschnorr) signature is created with a randomly-generated ephemeral key, which isn't tied to the
sender's identity.

Despite providing strong authenticity, `veil.mres` produces fully deniable ciphertexts.

## `veil.digest`

Veil can create message digests given a set of metadata and a message.

Given a set of metadata strings $V_0..V_n$ and a message in 16-byte blocks $M_0..M_n$, a duplex is initialized with a
constant key and used to absorb the metadata and message blocks. Finally, a 64-byte digest $D$ is squeezed:

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

By passing a symmetric key as a metadata string, `veil.digest` can be adapted to produce message authentication codes.

## `veil.pbenc`

`veil.pbenc` implements memory-hard passphrase-based encryption using balloon hashing [@boneh2016] and Xoodyak's AEAD
construction. This construction is used to secure secret keys.

### Initialization

The protocol is initialized as follows, given a passphrase $P$, a salt $S \rgets \allbits{128}$, time parameter $0 <=
N_T < 256$, space parameter $0 <= N_S < 256$, delta constant $D = 3$, and block size constant $N_B = 32$.

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

For each iteration of the balloon hashing algorithm, given a counter $C$, input blocks $(B_L, B_R)$, and an output block
$B_O$, the counter is encoded as a little-endian 64-bit integer and absorbed, the blocks are absorbed left-to-right, and
the output block is filled with duplex output:

\begin{gather*}
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{B_L} \\
\Absorb{B_R} \\
B_O \gets \Squeeze{N_B} \\
\end{gather*}

The expanding phase of the algorithm is performed as described by Boneh et al. [@boneh2016], with $2^{N_T}$ iterations
of the time loop and $2^{N_S}$ iterations in the space loop.

For the mixing phase of the algorithm, the loop variables $t$, $m$, and $i$ are encoded in a block $b$ and absorbed
along with the salt $S$:

\begin{gather*}
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{S} \\
b \gets \LE{U64}{t} || \LE{U64}{m} || \LE{U64}{i} \\
\Absorb{b} \\
\end{gather*}

A 64-bit little-endian integer is derived from duplex output. That integer is mapped to a block index:

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

# References
