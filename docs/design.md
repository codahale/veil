# The Veil Cryptosystem

Veil is a public-key cryptosystem that provides confidentiality, authenticity, and integrity
services for messages of arbitrary sizes and multiple receivers. This document describes its
cryptographic constructions, their security properties, and how they are combined to implement
Veil's feature set.

## Contents

* [Motivation](#motivation)
* [Security Model And Notions](#security-model-and-notions)
* [Cryptographic Primitives](#cryptographic-primitives)
* [Construction Techniques](#construction-techniques)
* [Digital Signatures](#digital-signatures)
* [Encrypted Headers](#encrypted-headers)
* [Encrypted Messages](#encrypted-messages)
* [Passphrase-Based Encryption](#passphrase-based-encryption)
* [References](#references)

## Motivation

Veil is a clean-slate effort to build a secure, asynchronous, PGP-like messaging cryptosystem using
modern tools and techniques to resist new attacks from modern adversaries. PGP provides confidential
and authentic multi-receiver messaging, but with many deficiencies.

### Cryptographic Agility

PGP was initially released in 1991 using a symmetric algorithm called BassOmatic invented by Phil
Zimmerman himself. Since then, it's supported IDEA, DES, Triple-DES, CAST5, Blowfish, SAFER-SK128,
AES-128, AES-192, AES-256, Twofish, and Camellia, with proposed support for ChaCha20. For hash
algorithms, it's supported MD5, SHA-1, RIPE-MD160, MD2, "double-width SHA", TIGER/192, HAVAL,
SHA2-256, SHA2-384, SHA2-512, SHA2-224. For public key encryption, it's supported RSA, ElGamal,
Diffie-Hellman, and ECDH, all with different parameters. For digital signatures, it's supported RSA,
DSA, ElGamal, ECDSA, and EdDSA, again, all with different parameters.

As Adam Langley said regarding TLS [[Lan16]](#lan16):

> Cryptographic agility is a huge cost. Implementing and supporting multiple algorithms means more
code. More code begets more bugs. More things in general means less academic focus on any one thing,
and less testing and code-review per thing. Any increase in the number of options also means more
combinations and a higher chance for a bad interaction to arise.

At best, each of these algorithms represents a geometrically increasing burden on implementors,
analysts, and users. At worst, they represent a catastrophic risk to the security of the system
[[Ngu04]](#ngu04) [[BSW21]](#bsw21).

A modern system would use a limited number of cryptographic primitives and use a single instance of
each.

### Informal Constructions

PGP messages use a Sign-Then-Encrypt (StE) construction, which is insecure given an encryption
oracle ([[AR10]](#ar10), p. 41):

> In the StE scheme, the adversary `A` can easily break the sUF-CMA security in the outsider model.
It can ask the encryption oracle to signcrypt a message `m` for `R′` and get
`C=(Encrypt(pk_R′,mǁσ),ID_S,ID_R′)` where `σ=Sign(pk_S,m)`. Then, it can recover `mǁσ` using `sk_R′`
and forge the signcryption ciphertext `C=(Encrypt(pk_R,mǁσ),ID_S,ID_R)`.

This may seem like an academic distinction, but this attack is trivial to mount. If you send your
boss an angry resignation letter signed and encrypted with PGP, your boss can re-transmit that to
your future boss, encrypted with her public key.

A modern system would use established, analyzed constructions with proofs in established models to
achieve established notions with reasonable reductions to weak assumptions.

### Non-Repudiation

A standard property of digital signatures is that of _non-repudiation_, or the inability of the
signer to deny they signed a message. Any possessor of the signer's public key, a message, and a
signature can verify the signature for themselves. For explicitly signed, public messages, this is a
very desirable property. For encrypted, confidential messages, this is not.

Similar to the vindictive boss scenario above, an encrypted-then-signed PGP message can be decrypted
by an intended receiver (or someone in possession of their private key) and presented to a third
party as an unencrypted, signed message without having to reveal anything about themselves. The
inability of PGP to preserve the privacy context of confidential messages should rightfully have a
chilling effect on its users [[BGB04]](#bgb04).

A modern system would be designed to provide some level of deniability to confidential messages.

### Global Passive Adversaries

A new type of adversary which became immediately relevant to the post-Snowden era is the Global
Passive Adversary, which monitors all traffic on all links of a network. For an adversary with an
advantaged network position (e.g. a totalitarian state), looking for cryptographically-protected
messages is trivial given the metadata they often expose. Even privacy features like GnuPG's
`--hidden-recipients` still produce encrypted messages which are trivially identifiable as encrypted
messages, because PGP messages consist of packets with explicitly identifiable metadata. In addition
to being secure, privacy-enhancing technologies must be undetectable.

Bernstein summarized this dilemma [[BHKL13]](#bhkl13):

> Cryptography hides patterns in user data but does not evade censorship if the censor can recognize
patterns in the cryptography itself.

A modern system would produce messages without recognizable metadata or patterns.

## Security Model And Notions

Veil has three main security goals:

1. Veil should be secure--i.e. provide both confidentiality and integrity--in the multi-user insider
   setting.
2. Veil should provide as much deniability as possible.
3. Veil ciphertexts should be entirely indistinguishable from random noise.

### Multi-User Confidentiality

To evaluate the confidentiality of a scheme, we consider an adversary `A` attempting to attack a
sender and receiver ([[BS10]](#bs10), p. 44). `A` creates two equal-length messages `(m₀,m₁)`, the
sender selects one at random and encrypts it, and `A` guesses which of the two has been encrypted
without tricking the receiver into decrypting it for them. To model real-world possibilities, we
assume `A` has three capabilities:

1. `A` can create their own key pairs. Veil does not have a centralized certificate authority and
   creating new key pairs is intentionally trivial.
2. `A` can trick the sender into encrypting arbitrary plaintexts with arbitrary public keys. This
   allows us to model real-world flaws such as servers which return encrypted error messages with
   client-provided data [[YHR04]](#yhr04).
3. `A` can trick the receiver into decrypting arbitrary ciphertexts from arbitrary senders. This
   allows us to model real-world flaws such as padding oracles [[RD10]](#rd10).

Given these capabilities, `A` can mount an attack in two different settings: the outsider setting
and the insider setting.

#### Outsider Confidentiality

In the multi-user outsider model, we assume `A` knows the public keys of all users but none of their
private keys ([[BS10]](#bs10), p. 44).

The multi-user outsider model is useful in evaluating the strength of a scheme against adversaries
who have access to some aspect of the sender and receiver's interaction with messages (e.g. a
padding oracle) but who have not compromised the private keys of either.

#### Insider Confidentiality

In the multi-user insider model, we assume `A` knows the sender's private key in addition to the
public keys of both users ([[BS10]](#bs10), p.45-46).

The multi-user insider model is useful in evaluating the strength of a scheme against adversaries
who have compromised a user.

##### Forward Sender Security

A scheme which provides confidentiality in the multi-user insider setting is called _forward sender
secure_ because an adversary who compromises a sender cannot read messages that sender has
previously encrypted [[CHK03]](#chk03).

### Multi-User Authenticity

To evaluate the authenticity of a scheme, we consider an adversary `A` attempting to attack a sender
and receiver ([[BS10]](#bs10) p. 47). `A` attempts to forge a ciphertext which the receiver will
decrypt but which the sender never encrypted. To model real-world possibilities, we again assume `A`
has three capabilities:

1. `A` can create their own key pairs.
2. `A` can trick the sender into encrypting arbitrary plaintexts with arbitrary public keys.
3. `A` can trick the receiver into decrypting arbitrary ciphertexts from arbitrary senders.

As with multi-user confidentiality, this can happen in the outsider setting and the insider setting.

#### Outsider Authenticity

In the multi-user outsider model, we again assume `A` knows the public keys of all users but none of
their private keys ([[BS10]](#bs10), p. 47).

Again, this is useful to evaluate the strength of a scheme in which `A` has some insight into
senders and receivers but has not compromised either.

#### Insider Authenticity

In the multi-user insider model, we assume `A` knows the receiver's private key in addition to the
public keys of both users ([[BS10]](#bs10), p. 47).

##### Key Compromise Impersonation

A scheme which provides authenticity in the multi-user insider setting effectively resists _key
compromise impersonation_, in which `A`, given knowledge of a receiver's private key, can forge
messages to that receiver from arbitrary senders [Str06](#str06). The classic example is
authenticated Diffie-Hellman (e.g. [[RFC9180]](#rfc9180) [[ABHKLR21]](#abhklr21)), in which the
static Diffie-Hellman shared secret point `K=[d_S]Q_R` is used to encrypt a message and its
equivalent `K′=[d_R]Q_S` is used to decrypt it. An attacker in possession of the receiver's private
key `d_R` and the sender's public key `Q_S` can simply encrypt the message using `K′=[d_R]Q_S`
without ever having knowledge of `d_S`. Digital signatures are a critical element of schemes which
provide insider authenticity, as they give receivers a way to verify the authenticity of a message
using authenticators they (or an adversary with their private key) could never construct themselves.

### Insider vs. Outsider Security

The multi-receiver setting motivates a focus on insider security over the traditional emphasis on
outsider security (contra [[AR10]](#ar10) p. 26, [[BS10]](#bs10) p. 46; see [[BBM18]](#bbm18)).
Given a probability of an individual key compromise `P`, a multi-user system of `N` users has an
overall `1-((1-P)^N)` probability of at least one key being compromised. A system with an
exponentially increasing likelihood of losing all confidentiality and authenticity properties is not
acceptable.

### Indistinguishable From Random Noise

Indistinguishability from random noise is a critical property for censorship-resistant communication
[[BHKL13]](#bhkl13):

> Censorship-circumvention tools are in an arms race against censors. The censors study all traffic
passing into and out of their controlled sphere, and try to disable censorship-circumvention tools
without completely shutting down the Internet. Tools aim to shape their traffic patterns to match
unblocked programs, so that simple traffic profiling cannot identify the tools within a reasonable
number of traces; the censors respond by deploying firewalls with increasingly sophisticated
deep-packet inspection.
>
> Cryptography hides patterns in user data but does not evade censorship if the censor can recognize
patterns in the cryptography itself.

### Limited Deniability

The inability of a receiver (or an adversary in possession of a receiver's private key) to prove the
authenticity of a message to a third party is critical for privacy. Other privacy-sensitive
protocols achieve this by forfeiting insider authenticity or authenticity altogether
[[BGB04]](#bgb04). Veil achieves a limited version of deniability: a receiver can only prove the
authenticity of a message to a third party by revealing their own private key. This deters a
dishonest receiver from selectively leaking messages and requires all-or-nothing disclosure from an
adversary who compromises an honest receiver.

## Cryptographic Primitives

In the interests of cryptographic minimalism, Veil uses just three distinct cryptographic
primitives: [Lockstitch](https://github.com/codahale/lockstitch) for all symmetric-key operations
and the jq255e elliptic curve [[Por22]](#por22) for all asymmetric-key operations.

### Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption) in
complex protocols. It combines BLAKE3 and ChaCha8 to provide GiB/sec performance on modern
processors at a 128-bit security level. More information on the design of Lockstitch can be found
[here](https://github.com/codahale/lockstitch/blob/main/design.md).

Veil's security assumes that Lockstitch's `Encrypt` operation is IND-CPA secure if the protocol's
prior state is probabilistic, its `Tag` operation is sUF-CMA secure if the protocol's prior state is
secret, and its `Encrypt`/`Tag`-based authenticated encryption construction is IND-CCA2 secure if
the two are IND-CPA and sUF-CMA secure, respectively.

### jq255e

jq255e is a double-odd elliptic curve selected for efficiency and simplicity [[Por20]](#por20)
[[Por22]](#por22). It provides a prime-order group, has non-malleable encodings, and has no
co-factor concerns. This allows for the use of a wide variety of cryptographic constructions built
on group operations. It targets a 128-bit security level, lends itself to constant-time
implementations, and can run in constrained environments.

Veil's security assumes that the Gap Discrete Logarithm and Gap Diffie-Hellman problems are hard
relative to jq255e.

## Construction Techniques

Veil uses a few common construction techniques in its design which bear specific mention.

### Integrated Constructions

Lockstitch is a cryptographically secure stateful object, thus each operation is cryptographically
dependent on the previous operations. Veil makes use of this by integrating different types of
constructions to produce a single, unified construction. Instead of having to pass forward specific
values (e.g. hashes of values or derived keys) to ensure cryptographic dependency, Lockstitch allows
for constructions which simply mixes in all values, thus ensuring transcript integrity of complex
protocols.

For example, a traditional hybrid encryption scheme like HPKE [[RFC9180]](#rfc9180) will describe a
key encapsulation mechanism (KEM) like X25519 and a data encapsulation mechanism (DEM) like AES-GCM
and link the two together via a key derivation function (KDF) like HKDF by deriving a key and nonce
for the DEM from the KEM output.

In contrast, the same construction using Lockstitch would be the following three operations, in
order:

```text
function HPKE(d_E, Q_R, p):
  state ← Initialize("com.example.hpke") // Initialize a Lockstitch protocol with a domain string. 
  state ← Mix(state, [d_E]Q_R)           // Mix the ECDH shared secret into the protocol's state.
  (state, c) ← Encrypt(state, p)         // Encrypt the plaintext.
  (state, t) ← Tag(state)                // Create an authentication tag.
  return cǁt                             // Return ciphertext and tag.
```

The protocol is keyed with the shared secret point, used to encrypt the plaintext, and finally used
to create an authentication tag. Each operation modifies the protocol's state, making the final
`Tag` operation's output dependent on both the previous `Encrypt` operation (and its argument, `p`)
but also the `Mix` and `Initialize` operations before it.

This is both a dramatically clearer way of expressing the overall hybrid public-key encryption
construction and more efficient: because the ephemeral shared secret point is unique, no nonce need
be derived (or no all-zero nonce need be justified in an audit).

#### Process History As Hidden State

A subtle but critical benefit of integrating constructions via a stateful cryptographic object is
that authenticators produced via `Tag` operations are dependent on the entire process history of the
protocol, not just on the emitted ciphertext. The DEM components of our HPKE analog (i.e.
`Encrypt`/`Tag`) are superficially similar to an Encrypt-then-MAC (EtM) construction, but where an
adversary in possession of the MAC key can forge authenticators given an EtM ciphertext, the
protocol-based approach makes that infeasible. With Lockstitch, the key used to create the
authenticator tag is derived via BLAKE3 from the protocol's state, which is itself dependent on the
ECDH shared secret. An adversary attempting to forge an authenticator given only the ciphertext and
the key used to produce the tag will be unable to reconstruct the protocol's state and thus unable
to compute their forgery.

### Hedged Ephemeral Values

When generating ephemeral values, Veil uses Aranha et al.'s "hedged signature" technique to mitigate
against both catastrophic randomness failures and differential fault attacks against purely
deterministic schemes [[AOTZ20]](#aotz20).

Specifically, hedging clones the protocol's state and mixes both a context-specific secret value
(e.g. the signer's private key in a digital signature scheme) and a 64-byte random value into the
clone. The cloned protocol is used to produce the ephemeral value or values for the scheme.

For example, the following operations would be performed on the cloned protocol:

```text
function HedgedScalar(state, d):
  with clone ← Clone(state) do  // Clone the protocol's current state.
    clone ← Mix(clone, d)       // Mix in the private value.
    v ← Rand(64)                // Generate a 64-byte random value.
    clone ← Mix(clone, v)       // Mix in the random value.
    x ← Derive(clone, 32) mod q // Derive a scalar from the clone.
    return x                    // Return the scalar to the outer context.
  end clone                     // Destroy the cloned protocol's state.
```

The ephemeral scalar `x` is returned to the context of the original construction and the cloned
protocol is discarded. This ensures that even in the event of a catastrophic failure of the random
number generator, `x` is still unique relative to `d`. Depending on the uniqueness needs of the
construction, an ephemeral value can be hedged with a plaintext in addition to a private key.

For brevity, a hedged ephemeral value `x` derived from a protocol `state` and a private input value
`y` is denoted as `x ← Hedge(state, y, Derive(32) mod q)`.

## Digital Signatures

`veil.schnorr` implements an EdDSA-style Schnorr digital signature scheme.

### Signing A Message

Signing a message requires a signer's private key `d` and a message `m` of arbitrary length.

```text
function Sign(d, m):
  state ← Initialize("veil.schnorr")     // Initialize a protocol.
  state ← Mix(state, [d]G)               // Mix the signer's public key into the protocol.
  state ← Mix(state, m)                  // Mix the message into the protocol.
  k ← Hedge(state, d, Derive(32) mod q)  // Derive a hedged commitment scalar.
  I ← [k]G                               // Calculate the commitment point.
  (state, S₀) ← Encrypt(state, I)        // Encrypt the commitment point.
  (state, r) ← Derive(state, 16)         // Derive a short challenge scalar.
  s ← d×️r + k                            // Calculate the proof scalar.
  (state, S₁) ← Encrypt(state, s)        // Encrypt the proof scalar.
  return S₀ǁS₁                           // Return the commitment point and proof scalar.
```

### Verifying A Signature

Verifying a signature requires a signer's public key `Q`, a message `m`, and a signature
`S₀ǁS₁`.

```text
function Verify(Q, m, S₀ǁS₁):
  state ← Initialize("veil.schnorr") // Initialize a protocol.
  state ← Mix(state, Q)              // Mix the signer's public key into the protocol.
  state ← Mix(state, m)              // Mix the message into the protocol.
  (state, I) ← Decrypt(state, S₀)    // Decrypt the commitment point.
  (state, r′) ← Derive(state, 16)    // Derive a counterfactual challenge scalar.
  (state, s) ← Decrypt(state, S₁)    // Decrypt the proof scalar.
  I′ ← [s]G - [r′]Q                  // Calculate the counterfactual commitment point.
  return I = I′                      // The signature is valid if both points are equal.
```

### Constructive Analysis Of `veil.schnorr`

The Schnorr signature scheme is the application of the Fiat-Shamir transform to the Schnorr
identification scheme.

Unlike Construction 13.12 of [[KL20]](#kl20) (p. 482), `veil.schnorr` transmits the commitment point
`I` as part of the signature and the verifier calculates `I′` vs transmitting the challenge scalar
`r` and calculating `r′`. In this way, `veil.schnorr` is closer to EdDSA [[BCJZ21]](#bcjz21) or the
Schnorr variant proposed by Hamburg [[Ham17]](#ham17). Short challenge scalars are used which allow
for faster verification with no loss in security [[Por22]](#por22). In addition, this construction
allows for the use of variable-time optimizations during signature verification
[[Por20+1]](#por201).

### UF-CMA Security

Per Theorem 13.10 of [[KL20]](#kl20) (p. 478), this construction is UF-CMA secure if the Schnorr
identification scheme is secure and the hash function is secure:

> Let `Π` be an identification scheme, and let `Π′` be the signature scheme that results by applying
the Fiat-Shamir transform to it. If `Π` is secure and `H` is modeled as a random oracle, then `Π′`
is secure.

Per Theorem 13.11 of [[KL20]](#kl20) (p. 481), the security of the Schnorr identification scheme is
conditioned on the hardness of the discrete logarithm problem:

> If the discrete-logarithm problem is hard relative to `G`, then the Schnorr identification scheme
is secure.

Thus, `veil.schnorr` is UF-CMA if the discrete-logarithm problem is hard relative to jq255e and
BLAKE3 is indistinguishable from a random oracle.

### sUF-CMA Security

Some Schnorr/EdDSA implementations (e.g. Ed25519) suffer from malleability issues, allowing for
multiple valid signatures for a given signer and message [[BCJZ21]](#bcjz21). [[CGN20]](#cgn20)
describe a strict verification function for Ed25519 which achieves sUF-CMA security in addition to
strong binding:

1. Reject the signature if `S ∉ {0,…,L-1}`.
2. Reject the signature if the public key `A` is one of 8 small order points.
3. Reject the signature if `A` or `R` are non-canonical.
4. Compute the hash `SHA2_512(RǁAǁM)` and reduce it mod `L` to get a scalar `h`.
5. Accept if `8(S·B)-8R-8(h·A)=0`.

Rejecting `S≥L` makes the scheme sUF-CMA secure, and rejecting small order `A` values makes the
scheme strongly binding. `veil.schnorr`'s use of canonical point and scalar encoding routines
obviate the need for these checks. Likewise, jq255e is a prime order group, which obviates the need
for cofactoring in verification.

When implemented with a prime order group and canonical encoding routines, the Schnorr signature
scheme is strongly unforgeable under chosen message attack (sUF-CMA) in the random oracle model and
even with practical cryptographic hash functions [[PS00]](#ps00) [[NSW09]](#nsw09).

### Key Privacy

The EdDSA variant (i.e. `S=(I,s)` ) is used over the traditional Schnorr construction (i.e.
`S=(r,s)`) to enable the variable-time computation of `I′=[s]G-[r]Q`, which provides a ~30%
performance improvement. That construction, however, allows for the recovery of the signing public
key given a signature and a message: given the commitment point `I`, one can calculate
`Q=-[r^-1](I-[s]G)`.

For Veil, this behavior is not desirable. A global passive adversary should not be able to discover
the identity of a signer from a signed message.

To eliminate this possibility, `veil.schnorr` encrypts both components of the signature with a
protocol effectively keyed with the signer's public key in addition to the message. An attack which
recovers the plaintext of either signature component in the absence of the public key would imply
that either BLAKE3 is not collision-resistant or that ChaCha8 is not PRF secure.

### Indistinguishability From Random Noise

Given that both signature components are encrypted with ChaCha8, an attack which distinguishes
between a `veil.schnorr` and random noise would also imply that ChaCha8 is distinguishable from a
random function.

## Encrypted Headers

`veil.sres` implements a single-receiver, deniable signcryption scheme which Veil uses to encrypt
message headers. It integrates an ephemeral ECDH KEM, a Lockstitch DEM, and a designated-verifier
Schnorr signature scheme to provide multi-user insider security with limited deniability.

### Encrypting A Header

Encrypting a header requires a sender's private key `d_S`, an ephemeral private key `d_E`, the
receiver's public key `Q_R`, a nonce `N`, and a plaintext `P`.

```text
function EncryptHeader(d_S, d_E, Q_R, N, P):
  state ← Initialize("veil.sres")       // Initialize a protocol.
  state ← Mix(state, [d_S]G)            // Mix the sender's public key into the protocol.
  state ← Mix(state, Q_R)               // Mix the receiver's public key into the protocol.
  state ← Mix(state, N)                 // Mix the nonce into the protocol.
  state ← Mix(state, [d_S]Q_R)          // Mix the static ECDH shared secret into the protocol.
  (state, C₀) ← Encrypt(state, [d_E]G)  // Encrypt the ephemeral public key.
  state ← Mix([d_E]Q_R)                 // Mix the ephemeral ECDH shared secret into the protocol.
  (state, C₁) ← Encrypt(P)              // Encrypt the plaintext.
  k ← Hedge(state, d, Derive(32) mod q) // Derive a hedged commitment scalar.
  I ← [k]G                              // Calculate the commitment point.
  (state, S₀) ← Encrypt(state, I)       // Encrypt the commitment point.
  (state, r) ← Derive(state, 32) mod q  // Derive a challenge scalar.
  s ← d_S✕r + k                         // Calculate the proof scalar.
  X ← [s]Q_R                            // Calculate the proof point.
  (state, S₁) ← Encrypt(state, X)       // Encrypt the proof point.
  return C₀ǁC₁ǁS₀ǁS₁
```

### Decrypting A Header

Decrypting a header requires a receiver's private key `d_R`, the sender's public key `Q_R`, a nonce
`N`, and a ciphertext `C₀ǁC₁ǁS₀ǁS₁`.

```text
function DecryptHeader(d_R, Q_S, N, C₀ǁC₁ǁS₀ǁS₁):
  state ← Initialize("veil.sres")       // Initialize a protocol.
  state ← Mix(state, Q_S)               // Mix the sender's public key into the protocol.
  state ← Mix(state, [d_R]G)            // Mix the receiver's public key into the protocol.
  state ← Mix(state, N)                 // Mix the nonce into the protocol.
  state ← Mix(state, [d_R]Q_S)          // Mix the static ECDH shared secret into the protocol.
  (state, Q_E) ← Decrypt(state, C₀)     // Decrypt the ephemeral public key.
  state ← Mix([d_R]Q_E)                 // Mix the ephemeral ECDH shared secret into the protocol.
  (state, P) ← Decrypt(C₁)              // Decrypt the plaintext.
  (state, I) ← Decrypt(state, S₀)       // Decrypt the commitment point.
  (state, r′) ← Derive(state, 32) mod q // Derive a counterfactual challenge scalar.
  (state, X) ← Decrypt(state, S₁)       // Decrypt the proof point.
  X′ ← [d_R](I + [r′]Q_S)               // Calculate a counterfactual proof point.
  if X ≠ X′:                            // Return an error if the points are not equal.
    return ⊥
  return (Q_E, P)                       // Otherwise, return the ephemeral public key and plaintext.
```

### Constructive Analysis Of `veil.sres`

`veil.sres` is an integration of two well-known constructions: an ECIES-style hybrid public key
encryption scheme and a designated-verifier Schnorr signature scheme.

The initial portion of `veil.sres` is equivalent to ECIES (see Construction 12.23 of
[[KL20]](#kl20), p. 435), (with the commitment point `I` as an addition to the ciphertext, and the
challenge scalar `r` serving as the authentication tag for the data encapsulation mechanism) and is
IND-CCA2 secure (see Corollary 12.14 of [[KL20]](#kl20), p. 436).

The latter portion of `veil.sres` is a designated-verifier Schnorr signature scheme which adapts an
EdDSA-style Schnorr signature scheme by multiplying the proof scalar `s` by the receiver's public
key `Q_R` to produce a designated-verifier point `X` [[SWP04]](#swp04). The EdDSA-style Schnorr
signature is sUF-CMA secure when implemented in a prime order group and a cryptographic hash
function [[BCJZ21]](#bcjz21) [[CGN20]](#cgn20) [[PS00]](#ps00) [[NSW09]](#nsw09) (see also
[`veil.schnorr`](#digital-signatures).

### Multi-User Confidentiality Of Headers

One of the two main goals of the `veil.sres` is confidentiality in the multi-user setting (see
[Multi-User Confidentiality](#multi-user-confidentiality)), or the inability of an adversary `A` to
learn information about plaintexts.

#### Outsider Confidentiality Of Headers

First, we evaluate the confidentiality of `veil.sres` in the multi-user outsider setting (see
[Outsider Confidentiality](#outsider-confidentiality)), in which the adversary `A` knows the public
keys of all users but none of their private keys ([[BS10]](#bs10), p. 44).

The classic multi-user attack on the generic Encrypt-Then-Sign (EtS) construction sees `A` strip the
signature `σ` from the challenge ciphertext `C=(c,σ,Q_S,Q_R)` and replace it with `σ ← Sign(d_A,c)`
to produce an attacker ciphertext `C′=(c,σ′,Q_A,Q_R)` at which point `A` can trick the receiver into
decrypting the result and giving `A` the randomly-chosen plaintext `m₀ ⊕ m₁` [[AR10]](#ar10). This
attack is not possible with `veil.sres`, as the sender's public key is strongly bound during
encryption and decryption.

`A` is unable to forge valid signatures for existing ciphertexts, limiting them to passive attacks.
A passive attack on any of the four components of `veil.sres` ciphertexts--`C₀`, `C₁`, `S₀`,
`S₁`--would only be possible if either BLAKE3 is not collision-resistant or ChaCha8 is not PRF
secure.

Therefore, `veil.sres` provides confidentiality in the multi-user outsider setting.

#### Insider Confidentiality Of Headers

Next, we evaluate the confidentiality of `veil.sres` in the multi-user insider setting (see [Insider
Confidentiality](#insider-confidentiality), in which the adversary `A` knows the sender's private
key in addition to the public keys of both users ([[BS10]](#bs10), p. 45-46).

`A` cannot decrypt the message by themselves, as they do not know either `d_E` or `d_R` and cannot
calculate the ECDH shared secret `[d_E]Q_R=[d_R]Q_E=[d_E{d_R}G]`.

`A` also cannot trick the receiver into decrypting an equivalent message by replacing the signature,
despite `A`'s ability to use `d_S` to create new signatures. In order to generate a valid signature
on a ciphertext `c′` (e.g. `c′=cǁ1`), `A` would have to derive a valid challenge scalar `r′` from
the protocol state. Unlike the signature hash function in the generic EtS composition, however, the
protocol state is cryptographically dependent on values `A` does not know, specifically the ECDH
shared secret `[d_E]Q_S` (via the `Mix` operation).

Therefore, `veil.sres` provides confidentiality in the multi-user insider setting.

### Multi-User Authenticity Of Headers

The second of the two main goals of the `veil.sres` is authenticity in the multi-user setting (see
[Multi-User Authenticity](#multi-user-authenticity)), or the inability of an adversary `A` to forge
valid ciphertexts.

#### Outsider Authenticity Of Headers

First, we evaluate the authenticity of `veil.sres` in the multi-user outsider setting (see [Outsider
Authenticity](#outsider-authenticity)), in which the adversary `A` knows the public keys of all
users but none of their private keys ([[BS10]](#bs10), p. 47).

Because the Schnorr signature scheme is sUF-CMA secure, it is infeasible for `A` to forge a
signature for a new message or modify an existing signature for an existing message. Therefore,
`veil.sres` provides authenticity in the multi-user outsider setting.

#### Insider Authenticity Of Headers

Next, we evaluate the authenticity of `veil.sres` in the multi-user insider setting (see [Insider
Authenticity](#insider-authenticity)), in which the adversary `A` knows the receiver's private key
in addition to the public keys of both users ([[BS10]](#bs10), p. 48).

Again, the Schnorr signature scheme is sUF-CMA secure and the signature is created using the
signer's private key. The receiver (or `A` in possession of the receiver's private key) cannot forge
signatures for new messages. Therefore, `veil.sres` provides authenticity in the multi-user insider
setting.

### Limited Deniability Of Headers

`veil.sres`'s use of a designated-verifier Schnorr scheme provides limited deniability for senders
(see [Limited Deniability](#limited-deniability)). Without revealing `d_R`, the receiver cannot
prove the authenticity of a message (including the identity of its sender) to a third party.

### Indistinguishability Of Headers From Random Noise Of Encrypted Headers

All of the components of a `veil.sres` ciphertext--`C₀`, `C₁`, `S₀`, and `S₁`--are ChaCha8
ciphertexts using keys derived via BLAKE3.  An adversary in the outsider setting (i.e. knowing only
public keys) is unable to calculate any of the key material used to produce the ciphertexts; a
distinguishing attack would imply that either BLAKE3 is not collision-resistant or that ChaCha8 is
not PRF secure.

### Re-use Of Ephemeral Keys

The re-use of an ephemeral key pair `(d_E,Q_E)` across multiple ciphertexts does not impair the
confidentiality of the scheme provided `(N,Q_R)` pairs are not re-used [[BBS03]](#bbs03). An
adversary who compromises a retained ephemeral private key would be able to decrypt all messages the
sender encrypted using that ephemeral key, thus the forward sender security is bounded by the
sender's retention of the ephemeral private key.

## Encrypted Messages

`veil.mres` implements a multi-receiver signcryption scheme.

### Encrypting A Message

Encrypting a message requires a sender's private key `d_S`, receiver public keys `[Q_R_0,…,Q_R_n]`,
padding length `N_P`, and plaintext `P`.

```text
function EncryptMessage(d_S, [Q_R_0,…,Q_R_n], N_P, P):
  state ← Initialize("veil.mres")                // Initialize a protocol.
  state ← Mix(state, [d_S]G)                     // Mix the sender's public key into the protocol.
  k ← Hedge(state, d_S, Derive(32) mod q)        // Hedge a commitment scalar.
  d_E ← Hedge(state, d_S, Derive(32) mod q)      // Hedge an ephemeral private key.
  K ← Hedge(state, d_S, Derive(32))              // Hedge a data encryption key.
  N ← Hedge(state, d_S, Derive(16))              // Hedge a nonce.
  C ← N                                          // Write the nonce.
  state ← Mix(state, N)                          // Mix the nonce into the protocol.
  H ← KǁN_QǁN_P                                  // Encode the DEK and params in a header.

  for Q_R_i in [Q_R_0,…,Q_R_n]:             
    (state, N_i) ← Derive(state, 16)             // Derive a nonce for each header.
    E_i ← EncryptHeader(d_S, d_E, Q_R_i, H, N_i) // Encrypt the header for each receiver.
    state ← Mix(state, E_i)                      // Mix the encrypted header into the protocol.
    C ← CǁE_i

  y ← Rand(N_P)                                  // Generate random padding.
  state ← Mix(state, y)                          // Mix the padding into the protocol.
  C ← Cǁy                                        // Append padding to ciphertext.

  state ← Mix(K)                                 // Mix the DEK into the protocol.

  for 32KiB blocks p in P:                       // Encrypt and tag each block.
    (state, C_i) ← Encrypt(state, p)
    (state, T_i) ← Tag(state)
    C ← CǁC_iǁT_i

  I ← [k]G                                       // Calculate the commitment point.
  (state, S₀) ← Encrypt(state, I)                // Encrypt the commitment point.
  r ← Derive(state, 16)                          // Derive a short challenge scalar.
  s ← d_E×️r + k                                  // Calculate the proof scalar.
  (state, S₁) ← Encrypt(state, s)                // Encrypt the proof scalar.
  C ← CǁS₀ǁS₁

  return C
```

### Decrypting A Message

Decrypting a message requires a receiver's private key `d_R`, sender's public key `Q_S`, and
ciphertext `C`.

```text
function DecryptMessage(d_R, Q_S, C):
  state ← Initialize("veil.mres") // Initialize a protocol.
  state ← Mix(state, Q_S)         // Mix the sender's public key into the protocol.
  state ← Mix(state, C[0..16])    // Mix the nonce into the protocol.
  C ← C[16..]

  (i, N_Q) ← (0, ∞)               // Go through ciphertext looking for a decryptable header.
  while i < N_Q:
  for each possible encrypted header E_i in C:
    (state, N_i) ← Derive(state, 16)
    (E_i, C) ← C[..HEADER_LEN]ǁC[HEADER_LEN..]
    state ← Derive(state, E_i)
    x ← DecryptHeader(d_R, Q_S, N_i, E_i)
    if x ≠ ⊥:
      (Q_E, KǁN_QǁN_P) ← x        // Once we decrypt a header, process the remaining headers.

  state ← Mix(state, C[..N_P])    // Mix the padding into the protocol.
  C ← C[N_P..]                    // Skip to the message beginning.

  state ← Mix(state, K)           // Mix the DEK into the protocol.

  P ← ϵ
  for 32KiB blocks c_iǁt_i in C:  // Decrypt each block, checking tags.
    (state, p_i) ← Decrypt(state, c_i)
    (state, ok) ← CheckTag(state, t_i)
    if !ok:
      return ⊥
    P ← Pǁp_i

  S₀ǁS₁ ← C                       // Split the last 64 bytes of the message.
  (state, I) ← Decrypt(state, S₀) // Decrypt the commitment point.
  (state, r′) ← Tag(state)        // Derive a counterfactual challenge scalar.
  (state, s) ← Decrypt(state, S)  // Decrypt the proof scalar.
  I′ ← [s]G - [r′]Q               // Calculate the counterfactual commitment scalar.
  if I ≠ I′:                      // Verify the signature.
    return ⊥
  return P
```

### Constructive Analysis Of `veil.mres`

`veil.mres` is an integration of two well-known constructions: a multi-receiver hybrid encryption
scheme and an EdDSA-style Schnorr signature scheme.

The initial portion of `veil.mres` is a multi-receiver hybrid encryption scheme, with per-receiver
copies of a symmetric data encryption key (DEK) encrypted in headers with the receivers' public keys
[[Kur02]](#kur02) [[BBS03]](#bbs03) [[BBKS07]](#bbks07) [[RFC4880]](#rfc4880). The headers are
encrypted with the `veil.sres` construction (see [`veil.sres`](#encrypted-headers)), which provides
full insider security (i.e. IND-CCA2 and sUF-CMA in the multi-user insider setting), using a
per-header `Derive` value as a nonce. The message itself is divided into a sequence of 32KiB blocks,
each encrypted with a sequence of Lockstitch `Encrypt`/`Tag` operations, which is IND-CCA2 secure.

The latter portion of `veil.mres` is an EdDSA-style Schnorr signature scheme. The EdDSA-style
Schnorr signature is sUF-CMA secure when implemented in a prime order group and a cryptographic hash
function [[BCJZ21]](#bcjz21) [[CGN20]](#cgn20) [[PS00]](#ps00) [[NSW09]](#nsw09) (see also
[`veil.schnorr`](#digital-signatures)). Short challenge scalars are used which allow for faster
verification with no loss in security [[Por22]](#por22). In addition, this construction allows for
the use of variable-time optimizations during signature verification [[Por20+1]](#por201).

### Multi-User Confidentiality Of Messages

One of the two main goals of the `veil.mres` is confidentiality in the multi-user setting (see
[Multi-User Confidentiality](#multi-user-confidentiality)), or the inability of an adversary `A` to
learn information about plaintexts. As `veil.mres` is a multi-receiver scheme, we adopt Bellare et
al.'s adaptation of the multi-user setting, in which `A` may compromise any subset of receivers
[[BBKS]](#bbks07).

#### Outsider Confidentiality Of Messages

First, we evaluate the confidentiality of `veil.mres` in the multi-user outsider setting (see
[Outsider Confidentiality](#outsider-confidentiality)), in which the adversary `A` knows the public
keys of all users but none of their private keys ([[BS10]](#bs10), p. 44).

As with [`veil.sres`](#encrypted-headers), `veil.mres` superficially resembles an Encrypt-Then-Sign
(EtS) scheme, which are vulnerable to an attack where by `A` strips the signature from the challenge
ciphertext and either signs it themselves or tricks the sender into signing it, thereby creating a
new ciphertext they can then trick the receiver into decrypting for them. Again, as with
`veil.sres`, the identity of the sender is strongly bound during encryption encryption and
decryption making this infeasible.

`A` is unable to forge valid signatures for existing ciphertexts, limiting them to passive attacks.
`veil.mres` ciphertexts consist of ephemeral keys, encrypted headers, random padding, encrypted
message blocks, and encrypted signature points. Each component of the ciphertext is dependent on the
previous inputs (including the headers, which use `Derive`-derived nonce to link the `veil.sres`
ciphertexts to the `veil.mres` state). A passive attack on any of those would only be possible if
either BLAKE3 is not collision-resistant or ChaCha8 is not PRF secure.

#### Insider Confidentiality Of Messages

Next, we evaluate the confidentiality of `veil.mres` in the multi-user insider setting (see [Insider
Confidentiality](#insider-confidentiality)), in which the adversary `A` knows the sender's private
key in addition to the public keys of all users ([[BS10]](#bs10), p. 45-46). `A` cannot decrypt the
message by themselves, as they do not know either `d_E` or any `d_R` and cannot decrypt any of the
`veil.sres`-encrypted headers. As with [`veil.sres`](#multi-user-confidentiality-of-headers) `A`
cannot trick the receiver into decrypting an equivalent message by replacing the signature, despite
`A`'s ability to use `d_S` to create new headers. In order to generate a valid signature on a
ciphertext `c′` (e.g. `c′=cǁ1`), `A` would have to derive a valid challenge scalar `r′` from the
protocol state. Unlike the signature hash function in the generic EtS composition, however, the
protocol state is cryptographically dependent on a value `A` does not know, specifically the data
encryption key `K` (via the `Mix` operation) and the plaintext blocks `p_{0..n}` (via the `Encrypt`
operation).

Therefore, `veil.mres` provides confidentiality in the multi-user insider setting.

### Multi-User Authenticity Of Messages

The second of the two main goals of the `veil.mres` is authenticity in the multi-user setting (see
[Multi-User Authenticity](#multi-user-authenticity)), or the inability of an adversary `A` to forge
valid ciphertexts.

#### Outsider Authenticity Of Messages

First, we evaluate the authenticity of `veil.mres` in the multi-user outsider setting (see [Outsider
Authenticity](#outsider-authenticity)), in which the adversary `A` knows the public keys of all
users but none of their private keys ([[BS10]](#bs10), p. 47).

Because the Schnorr signature scheme is sUF-CMA secure, it is infeasible for `A` to forge a
signature for a new message or modify an existing signature for an existing message. Therefore,
`veil.mres` provides authenticity in the multi-user outsider setting.

#### Insider Authenticity Of Messages

Next, we evaluate the authenticity of `veil.mres` in the multi-user insider setting (see [Insider
Authenticity](#insider-authenticity)), in which the adversary `A` knows some receivers' private keys
in addition to the public keys of both users ([[BS10]](#bs10), p. 47).

Again, the Schnorr signature scheme is sUF-CMA secure and the signature is created using the
ephemeral private key, which `A` does not possess. The receiver (or `A` in possession of the
receiver's private key) cannot forge signatures for new messages. Therefore, `veil.mres` provides
authenticity in the multi-user insider setting.

### Limited Deniability Of Messages

The only portion of `veil.mres` ciphertexts which are creating using the sender's private key (and
thus tying a particular message to their identity) are the `veil.sres`-encrypted headers. All other
components are creating using the data encryption key or ephemeral private key, neither of which are
bound to identity. `veil.sres` provides limited deniability (see [Limited
Deniability](#limited-deniability)), therefore `veil.mres` does as well.

### Indistinguishability Of Messages From Random Noise

`veil.mres` ciphertexts are indistinguishable from random noise. All components of an `veil.mres`
ciphertext are ChaCha8 ciphertexts; a successful distinguishing attack on them would imply that
BLAKE3 is not collision-resistant or ChaCha8 is not PRF secure.

### Partial Decryption

The division of the plaintext stream into blocks takes its inspiration from the CHAIN construction
[[HRRV]](#hrrv15), but the use of Lockstitch allows for a significant reduction in complexity.
Instead of using the nonce and associated data to create a feed-forward ciphertext dependency, the
Lockstitch protocol ensures all encryption operations are cryptographically dependent on the
ciphertext of all previous encryption operations. Likewise, because the `veil.mres` ciphertext is
terminated with a Schnorr signature (see [`veil.schnorr`](#digital-signatures)), using a special
operation for the final message block isn't required.

The major limitation of such a system is the possibility of the partial decryption of invalid
ciphertexts. If an attacker flips a bit on the fourth block of a ciphertext, `veil.mres` will
successfully decrypt the first three before returning an error. If the end-user interface displays
that, the attacker may be successful in radically altering the semantics of an encrypted message
without the user's awareness. The first three blocks of a message, for example, could say `PAY
MALLORY $100`, `GIVE HER YOUR CAR`, `DO WHAT SHE SAYS`, while the last block might read `JUST
KIDDING`.

## Passphrase-Based Encryption

`veil.pbenc` implements a memory-hard authenticated encryption scheme to encrypt private keys at
rest.

### Initialization

Initializing a keyed protocol requires a passphrase `P`, salt `S`, time parameter `N_T`, space
parameter `N_S`, delta constant `D=3`, and block size constant `N_B=1024`.

```text
function HashBlock(C, [B_0..B_n], N):
  state ← Initialize("veil.pbenc.iter") // Initialize a protocol.
  state ← Mix(state, C)                 // Mix the counter into the protocol.
  C ← C + 1                             // Increment the counter.

  for B_i in [B_0..B_n]:                // Mix each input block into the protocol.
    state ← Mix(state, B_i)

  return Derive(state, N)               // Derive N bytes of output.

procedure InitFromPassphrase(P, S, N_T, N_S):
  C ← 0                                                  // Initialize a counter.
  B ← [[0x00 ✕ N_B] ✕ N_S]                               // Initialize a buffer.

  B[0] ← HashBlock(C, [P, S], N_B)                       // Expand input into buffer.
  for m in 1..N_S:
    B[m] ← HashBlock(C, [B[m-1]], N_B)                   // Fill remainder of buffer with hash chain.

  for t in 0..N_T:                                       // Mix buffer contents.
    for m in 0..N_S:
      m_prev ← (m-1) mod N_S
      B[m] = HashBlock(C, [B[(m-1) mod N_S], B[m]], N_B) // Hash previous and current blocks.

      for i in 0..D:
        r ← HashBlock(C, [S, t, m, i], 8)                // Hash salt and loop indexes.
        B[m] ← HashBlock(C, [[B[m], B[r]]], N_B)         // Hash pseudo-random and current blocks.

  state ← Initialize("veil.pbenc")                       // Initialize a protocol.
  state ← Mix(state, B[N_S-1])                           // Mix the last block into the protocol.
  return state
```

### Encrypting A Private Key

Encrypting a private key requires a passphrase `P`, time parameter `N_T`, space parameter `N_S`, and
private key `d`.

```text
function EncryptPrivateKey(P, N_T, N_S, d):
  S ← Rand(16)                               // Generate a random salt.
  state ← InitFromPassphrase(P, S, N_T, N_S) // Perform the balloon hashing.
  (state, C) ← Encrypt(state, d)             // Encrypt the private key.
  (state, T) ← Tag(state)                    // Create an authentication tag.
  return N_TǁN_SǁSǁCǁT
```

### Decrypting A Private Key

Decrypting a private key requires a passphrase `P` and ciphertext `C=N_TǁN_SǁSǁCǁT`.

```text
function DecryptPrivateKey(P, N_T, N_S, d):
  state ← InitFromPassphrase(P, S, N_T, N_S) // Perform the balloon hashing.
  (state, d′) ← Decrypt(state, C)            // Decrypt the ciphertext.
  (state, T′) ← Tag(state)                   // Create an authentication tag.
  if T ≠ T′:                                 // Return an error if the tags are not equal.
    return ⊥
  return d′
```

### Constructive Analysis Of `veil.pbenc`

`veil.pbenc` is an integration of a memory-hard key derivation function (adapted for Lockstitch) and
a standard Lockstitch authenticated encryption scheme.

The `InitFromPassphrase` procedure of `veil.pbenc` implements balloon hashing, a memory-hard hash
function intended for hashing low-entropy passphrases [[BCGS16]](#bcgs16). Memory-hard functions are
a new and active area of cryptographic research, making the evaluation of schemes difficult. Balloon
hashing was selected for its resilience to timing attacks, its reliance on a single hash primitive,
and its relatively well-developed security proofs. The use of a PRF as a wide block labeling
function is not covered by the security proofs in Appendix B.3 of [[BCGS16]](#bcgs16) but aligns
with the use of BLAKE2b in Argon2 [[RFC9106]](#rfc9106).

The `EncryptPrivateKey` and `DecryptPrivateKey` functions use `InitFromPassphrase` to initialize the
protocol state, after which they implement a standard authenticated encryption scheme, which is
IND-CCA2 secure.

## References

### ABHKLR21

Joël Alwen, Bruno Blanchet, Eduard Hauck, Eike Kiltz, Benjamin Lipp, and Doreen Riepel.
2021.
[_Analysing the HPKE standard._](https://eprint.iacr.org/2020/1499.pdf)
[`DOI:10.1007/978-3-030-77870-5_4`](https://doi.org/10.1007/978-3-030-77870-5_4)

### AOTZ20

Diego F Aranha, Claudio Orlandi, Akira Takahashi, and Greg Zaverucha.
2020.
[_Security of hedged Fiat–Shamir signatures under fault attacks._](https://eprint.iacr.org/2019/956.pdf)
[`DOI:10.1007/978-3-030-45721-1_23`](https://doi.org/10.1007/978-3-030-45721-1_23)

### AR10

Jee Hea An and Tal Rabin.
2010.
_Security for signcryption: the two-user model._ In _Practical Signcryption._ pp 21–42.
[`DOI:10.1007/978-3-540-89411-7`](https://doi.org/10.1007/978-3-540-89411-7)

### BBKS07

Mihir Bellare, Alexandra Boldyreva, Kaoru Kurosawa, and Jessica Staddon.
2007.
[_Multi-recipient encryption schemes: Efficient constructions and their security._](https://faculty.cc.gatech.edu/~aboldyre/papers/bbks.pdf)

### BBM18

Christian Badertscher, Fabio Banfi, and Ueli Maurer.
2018.
[_A constructive perspective on signcryption security._](https://eprint.iacr.org/2018/050.pdf)

### BBS03

Mihir Bellare, Alexandra Boldyreva, and Jessica Staddon.
2003.
[_Randomness re-use in multi-recipient encryption schemeas._](https://www.iacr.org/archive/pkc2003/25670085/25670085.pdf)
[`DOI:10.1007/3-540-36288-6_7`](https://doi.org/10.1007/3-540-36288-6_7)

### BCGS16

Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter.
2016.
[_Balloon hashing: A memory-hard function providing provable protection against sequential attacks._](https://eprint.iacr.org/2016/027.pdf)
[`DOI:10.1007/978-3-662-53887-6_8`](https://doi.org/10.1007/978-3-662-53887-6_8)

### BCJZ21

Jacqueline Brendel, Cas Cremers, Dennis Jackson, and Mang Zhao.
2021.
[_The provable security of Ed25519: Theory and practice._](https://eprint.iacr.org/2020/823.pdf)
[`DOI:10.1109/SP40001.2021.00042`](https://doi.org/10.1109/SP40001.2021.00042)

### BGB04

Nikita Borisov, Ian Goldberg, and Eric Brewer.
2004.
[_Off-the-record communication, or, why not to use PGP._](https://otr.cypherpunks.ca/otr-wpes.pdf)
[`DOI:10.1145/1029179.1029200`](https://doi.org/10.1145/1029179.1029200)

### BHKL13

Daniel J Bernstein, Mike Hamburg, Anna Krasnova, and Tanja Lange.
2013.
[_Elligator: Elliptic-curve points indistinguishable from uniform random strings._](https://elligator.cr.yp.to/elligator-20130828.pdf)
[`DOI:10.1145/2508859.2516734`](https://doi.org/10.1145/2508859.2516734)

### BS10

Joonsang Baek and Ron Steinfeld.
2010.
_Security for signcryption: the multi-user model._ In _Practical Signcryption_. pp 43–53.
[`DOI:10.1007/978-3-540-89411-7`](https://doi.org/10.1007/978-3-540-89411-7)

### BSW21

Jenny Blessing, Michael A. Specter, and Daniel J. Weitzner.
2021.
[_You really shouldn't roll your own crypto: an empirical study of vulnerabilities in cryptographic libraries._](https://arxiv.org/abs/2107.04940)
[`DOI:10.48550/arXiv.2107.04940`](https://doi.org/10.48550/arXiv.2107.04940)

### CGN20

Konstantinos Chalkias, François Garillot, and Valeria Nikolaenko.
2020.
[_Taming the many EdDSAs._](https://eprint.iacr.org/2020/1244.pdf)
[`DOI:10.1007/978-3-030-64357-7_4`](https://doi.org/10.1007/978-3-030-64357-7_4)

### CHK03

Ran Canetti, Shai Halevi, and Jonathan Katz.
2003.
[_A forward-secure public-key encryption scheme._](https://eprint.iacr.org/2003/083.pdf)
[`DOI:10.1007/3-540-39200-9_16`](https://doi.org/10.1007/3-540-39200-9_16)

### HRRV15

Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár.
2015.
[_Online authenticated-encryption and its nonce-reuse misuse-resistance._](https://eprint.iacr.org/2015/189.pdf)
[`DOI:10.1007/978-3-662-47989-6_24`](https://doi.org/10.1007/978-3-662-47989-6_24)

### Ham17

Mike Hamburg.
2017.
[_The STROBE protocol framework._](https://eprint.iacr.org/2017/003.pdf)

### KL20

Jonathan Katz and Yehuda Lindell.
2020.
_Introduction to Modern Cryptography._
[`DOI:10.1201/9781351133036`](https://doi.org/10.1201/9781351133036)

### Kur02

Kaoru Kurosawa.
2002.
[_Multi-recipient public-key encryption with shortened ciphertext._](https://eprint.iacr.org/2001/071)
[`DOI:10.1007/3-540-45664-3_4`](https://doi.org/10.1007/3-540-45664-3_4)

### Lan16

Adam Langley.
2016.
[_Cryptographic agility._](https://www.imperialviolet.org/2016/05/16/agility.html)

### NSW09

Gregory Neven, Nigel P Smart, and Bogdan Warinschi.
2009.
[_Hash function requirements for Schnorr signatures._](http://www.neven.org/papers/schnorr.pdf)
[`DOI:10.1515/JMC.2009.004`](https://doi.org/10.1515/JMC.2009.004)

### Ngu04

Phong Q Nguyen.
2004.
[_Can we trust cryptographic software? Cryptographic flaws in GNU Privacy Guard v1.2.3._](https://link.springer.com/content/pdf/10.1007%252F978-3-540-24676-3_33.pdf)
[`DOI:10.1007/978-3-540-24676-3_33`](https:/doi.org/10.1007/978-3-540-24676-3_33)

### PS00

David Pointcheval and Jacques Stern.
2000.
[_Security arguments for digital signatures and blind signatures._](https://www.di.ens.fr/david.pointcheval/Documents/Papers/2000_joc.pdf)
[`DOI:10.1007/s001450010003`](https://doi.org/10.1007/s001450010003)

### Por20

Thomas Pornin.
2020.
[_Double-Odd elliptic curves._](https://eprint.iacr.org/2020/1558.pdf)

### Por20+1

Thomas Pornin.
2020.
[_Optimized lattice basis reduction in dimension 2, and fast Schnorr and EdDSA signature verification._](https://eprint.iacr.org/2020/454)

### Por22

Thomas Pornin.
2022.
[_Double-Odd Jacobi quartic._](https://eprint.iacr.org/2022/1052)

### RD10

Juliano Rizzo and Thai Duong.
2010.
[_Practical padding oracle attacks._](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf)

### RFC4880

J. Callas, L. Donnerhacke, H. Finney, D. Shaw, and R. Thayer.
2007.
[_OpenPGP Message Format._](http://www.rfc-editor.org/rfc/rfc4880.html)

### RFC9106

A. Biryukov, D. Dinu, D. Khovratovich, and S. Josefsson. 2021.
[_Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications._](http://www.rfc-editor.org/rfc/rfc9106.html)

### RFC9180

R. Barnes, K. Bhargavan, B. Lipp, and C. Wood.
2022.
[_Hybrid Public Key Encryption._](http://www.rfc-editor.org/rfc/rfc9180.html)

### SWP04

Ron Steinfeld, Huaxiong Wang, and Josef Pieprzyk.
2004.
[_Efficient extension of standard Schnorr/RSA signatures into universal designated-verifier signatures._](https://www.iacr.org/archive/pkc2004/29470087/29470087.pdf)
[`DOI:10.1007/978-3-540-24632-9_7`](https://doi.org/10.1007/978-3-540-24632-9_7)

### Str06

Maurizio Adriano Strangio.
2006.
[_On the resilience of key agreement protocols to key compromise impersonation._](https://eprint.iacr.org/2006/252.pdf)
[`DOI:10.1007/11774716_19`](https://doi.org/10.1007/11774716_19)

### YHR04

Tom Yu, Sam Hartman, and Kenneth Raeburn.
2004.
[_The perils of unauthenticated encryption: Kerberos version 4._](https://web.mit.edu/tlyu/papers/krb4peril-ndss04.pdf)
