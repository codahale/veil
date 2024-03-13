# The Veil Cryptosystem

Veil is a hybrid post-quantum public-key cryptosystem that provides confidentiality, authenticity,
and integrity services for messages of arbitrary sizes and multiple receivers. This document
describes its cryptographic constructions, their security properties, and how they are combined to
implement Veil's feature set.

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

### Quantum Adversaries

Despite the current lack of viable quantum computers for cryptographic applications, the development
of one poses an existential risk to modern cryptographic systems:

> If we do not encrypt our data with a quantum-secure algorithm right now, an attacker who is able
> to store current communication will be able to decrypt it in as soon as a decade. This
> store-now-decrypt-later attack is the main motivator behind the current adoption of post-quantum
> cryptography (PQC), but other future quantum computing threats also require a well-thought out
> plan for migrating our current, classical cryptographic algorithms to PQC.
>
> – [Google's Threat model for Post-Quantum Cryptography](https://bughunters.google.com/blog/5108747984306176/google-s-threat-model-for-post-quantum-cryptography)

While groups such as the NSA recommend wholesale migration to post-quantum algorithms like ML-KEM
and ML-DSA, the relative newness of those algorithms and the number of entirely broken proposed
post-quantum algorithms lend weight to the more conservative approach of _hybrid post-quantum_
constructions. These combine classical algorithms and post-quantum algorithms such that a loss of
security of one (i.e. due to either the development of a cryptographically-relevant quantum computer
or novel cryptanalysis of a post-quantum algorithm) does not reduce the overall security of the
system.

A modern system would defend against both classical and quantum adversaries.

## Security Model And Notions

Veil has two main security goals:

1. Veil should be secure--i.e. provide both confidentiality and integrity--in the multi-user insider
   setting.
2. Veil ciphertexts should be entirely indistinguishable from random noise.

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
> passing into and out of their controlled sphere, and try to disable censorship-circumvention tools
> without completely shutting down the Internet. Tools aim to shape their traffic patterns to match
> unblocked programs, so that simple traffic profiling cannot identify the tools within a reasonable
> number of traces; the censors respond by deploying firewalls with increasingly sophisticated
> deep-packet inspection.
>
> Cryptography hides patterns in user data but does not evade censorship if the censor can recognize
patterns in the cryptography itself.

## Cryptographic Primitives

In the interests of cryptographic minimalism, Veil uses the following cryptographic primitives:

1. [Lockstitch](https://github.com/codahale/lockstitch) for all symmetric-key operations.
2. [X25519](https://www.rfc-editor.org/rfc/rfc7748.html) for classical key agreement.
3. [ML-KEM-768](https://csrc.nist.gov/pubs/fips/203/ipd) for post-quantum key encapsulation.
4. [Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html) for digital signatures.
5. [ML-DSA-65](https://csrc.nist.gov/pubs/fips/204/ipd) for post-quantum digital signatures.

### Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption) in
complex protocols. It combines TurboSHAKE128 and AEGIS-128L to provide ~10 GiB/sec performance on
modern processors at a 128-bit security level. More information on the design of Lockstitch can be
found [here](https://github.com/codahale/lockstitch/blob/main/design.md).

Veil's security assumes that Lockstitch's `Encrypt` operation is IND-CPA-secure if the protocol's
prior state is probabilistic, its `Derive` operation is sUF-CMA-secure if the protocol's prior state
is secret, and its `Seal` operation is IND-CCA2-secure.

### X25519

X25519 implements elliptic curve Diffie-Hellman key agreement on the Montgomery form of Curve25519.

Veil's security assumes that the Gap Diffie-Hellman problem is hard relative to Curve25519 for
classical adversaries.

### ML-KEM-768

ML-KEM-768 implements a key encapsulation construction based on the hardness of the Module Learning
With Errors problem.

Veil's security assumes that ML-KEM-768 is IND-CCA2-secure.

### Ed25519

Ed25519 implements a Schnorr-style digital signature on the Edwards form of Curve25519 using
SHA-512.

Veil's security assumes that Ed25519 is sUF-CMA-secure for classical adversaries.

### ML-DSA-65

ML-DSA-65 implements a digital signature construction based on the hardness of the Module Learning
With Errors problem.

Veil's security assumes that ML-DSA-65 is sUF-CMA-secure for quantum adversaries.

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
  state ← Initialize("com.example.hpke")       // Initialize a Lockstitch protocol with a domain string. 
  state ← Mix(state, "ecdh", X25519(d_E, Q_R)) // Mix the ECDH shared secret into the protocol's state.
  (state, c) ← Seal(state, "message", p)       // Seal the plaintext.
  return c                                     // Return ciphertext.
```

The protocol is keyed with the shared secret point and used to seal the plaintext. Each operation
modifies the protocol's state, making the final `Seal` operation's output dependent not just on its
input `p` but also the `Mix` and `Initialize` operations before it.

This is both a dramatically clearer way of expressing the overall hybrid public-key encryption
construction and more efficient: because the ephemeral shared secret point is unique, no nonce need
be derived (or no all-zero nonce need be justified in an audit).

#### Process History As Hidden State

A subtle but critical benefit of integrating constructions via a stateful cryptographic object is
that authenticators produced via `Derive` or `Seal` operations are dependent on the entire process
history of the protocol, not just on the emitted ciphertext. The DEM components of our HPKE analog
(i.e. `Seal`) are superficially similar to an Encrypt-then-MAC (EtM) construction, but where an
adversary in possession of the MAC key can forge authenticators given an EtM ciphertext, the
protocol-based approach makes that infeasible. With Lockstitch, the key used to create the
authenticator tag is derived via TurboSHAKE128 from the protocol's state, which is itself dependent
on the ECDH shared secret. An adversary attempting to forge an authenticator given only the
ciphertext and the key used to produce the tag will be unable to reconstruct the protocol's state
and thus unable to compute their forgery.

## Digital Signatures

`veil.sig` implements a hybrid post-quantum digital signature scheme using Ed25519 and ML-DSA-65.

### Signing A Message

Signing a message requires a signer's public key `pk`, a signer's Ed25519 private key `sk_c`, a
signer's ML-DSA-65 private key `sk_pq`, and a message `m` of arbitrary length.

```text
function Sign(pk, sk_c, sk_pq, m):
  state ← Initialize("veil.sig")                          // Initialize a protocol.
  state ← Mix(state, "signer", pk)                        // Mix the signer's public key into the protocol.
  n ← Rand(16)                                            // Generate a random nonce.
  state ← Mix(state, "nonce", n)                          // Mix the nonce into the protocol.
  state ← Mix(state, "message", m)                        // Mix the message into the protocol.
  (state, d) ← Derive(state, "signature-digest", 64)      // Derive a 512-bit digest.
  s₀ ← Ed25519::Sign(sk_c, d)                             // Sign the digest with Ed25519.
  s₁ ← ML_DSA_65::Sign(sk_pq, d)                          // Sign the digest with ML-DSA-65.
  (state, c₀) ← Encrypt(state, s₀)                        // Encrypt the Ed25519 signature.
  (state, c₁) ← Encrypt(state, s₁)                        // Encrypt the ML-DSA-65 signature.
  return nǁc₀ǁc₁
```

### Verifying A Signature

Verifying a signature requires a signer's public key `pk`, a message `m`, and a signature `nǁc₀ǁc₁`.

```text
function Verify(pk, m, nǁc₀ǁc₁):
  state ← Initialize("veil.sig")                     // Initialize a protocol.
  state ← Mix(state, "signer", pk)                   // Mix the signer's public key into the protocol.
  state ← Mix(state, "nonce", n)                     // Mix the nonce into the protocol.
  state ← Mix(state, "message", m)                   // Mix the message into the protocol.
  (state, d) ← Derive(state, "signature-digest", 64) // Derive a 512-bit digest.
  (state, s₀) ← Encrypt(state, c₀)                   // Decrypt the Ed25519 signature.
  (state, s₁) ← Encrypt(state, c₁)                   // Decrypt the ML-DSA-65 signature.
  v₀ ← Ed25519::Verify(pk.vk_c, s₀, d)               // Verify the Ed25519 signature.
  v₁ ← ML_DSA_65::Verify(pk.vk_pq, s₁, d)            // Verify the ML-DSA-65 signature.
  return v₀ ∧ v₁                                     // The signature is valid iff both components are valid.
```

### Constructive Analysis Of `veil.sig`

Both Ed25519 and ML-DSA-65 are well-studied digital signature schemes. The novelty of `veil.sig`
lies in its use of symmetric cryptography to pre-hash the inputs and to encrypt the two signatures.

First, the signer's public key, the nonce, and the message are used to derive a 512-bit digest.
Using the signer's public key strongly binds the signature to the signer's identity. Including the
nonce ensures that the digest and the deterministic Ed25519 and ML-DSA-65 signatures of the digest
are randomized, reducing the threat of fault-injection attacks.

Second, both Ed25519 and ML-DSA-65 signatures are encrypted with keys derived from the inputs to the
protocol.

### sUF-CMA Security

#### Ed25519 sUF-CMA Security

Some Ed25519 implementations suffer from malleability issues, allowing for multiple valid
signatures for a given signer and message [[BCJZ21]](#bcjz21) (i.e. are eUF-CMA secure and not
sUF-CMA secure). [[CGN20]](#cgn20) describe a strict verification function for Ed25519 which
achieves sUF-CMA security in addition to strong binding:

1. Reject the signature if `S ∉ {0,…,L-1}`.
2. Reject the signature if the public key `A` is one of 8 small order points.
3. Reject the signature if `A` or `R` are non-canonical.
4. Compute the hash `SHA2_512(RǁAǁM)` and reduce it mod `L` to get a scalar `h`.
5. Accept if `8(S·B)-8R-8(h·A)=0`.

Strong binding in `veil.sig` is achieved by including the signer's public key as an input to the
digest, therefore rejecting of signatures with `S≥L` the critical component to Ed25519's sUF-CMA
security in the context of `veil.sig`.

#### ML-DSA-65 sUF-CMA Security

ML-DSA claims sUF-CMA security.

### Key Privacy

As the signer's public key is included as the inputs to a secure hash function, it is not possible
to recover the public key given a signature and a message.

Further, `veil.sig` encrypts both components of the signature with a protocol effectively keyed with
the signer's public key in addition to the message. An attack which recovers the plaintext of either
signature component in the absence of the public key would imply that either TurboSHAKE128 is not
collision-resistant or that AEGIS-128L is not PRF secure.

### Resilience Against Fault Attacks

Per [[PSSLR17]](#psslr17), purely deterministic signature schemes like RFC 6979 and EdDSA are
vulnerable to fault attacks, in which an adversary induces a signer to generate multiple invalid
signatures by injecting a fault (e.g. a random bit-flip via RowHammer attack, thus leaking bits of
the private key.

Because `veil.sig` messages are arbitrary bitstrings, a randomized nonce is added to the
protocol's state in order to ensure that the signatures are probabilistic and thus immune to fault
attacks.

### Indistinguishability From Random Noise

Given that both signature components are encrypted with AEGIS-128L, an attack which distinguishes
between a `veil.sig` and random noise would also imply that AEGIS-128L is distinguishable from
a random function over short messages.

## Encrypted Headers

`veil.sres` implements a single-receiver, deniable signcryption scheme which Veil uses to encrypt
message headers. It integrates an ephemeral ECDH KEM, a Lockstitch DEM, and a designated-verifier
Schnorr signature scheme to provide multi-user insider security with limited deniability.

### Encrypting A Header

Encrypting a header requires a sender's private key `d_S`, a sender's secret nonce `z_S`, an
ephemeral private key `d_E`, the receiver's public key `Q_R`, a nonce `N`, and a plaintext `P`.

```text
function EncryptHeader(d_S, z_S, d_E, Q_R, N, P):
  state ← Initialize("veil.sres")                          // Initialize a protocol.
  state ← Mix(state, "sender", [d_S]G)                     // Mix the sender's public key into the protocol.
  state ← Mix(state, "receiver", Q_R)                      // Mix the receiver's public key into the protocol.
  state ← Mix(state, "nonce", N)                           // Mix the nonce into the protocol.
  state ← Mix(state, "static-ecdh", [d_S]Q_R)              // Mix the static ECDH shared secret into the protocol.
  (state, C₀) ← Encrypt(state, "ephemeral-key", [d_E]G)    // Encrypt the ephemeral public key.
  state ← Mix(state, "ephemeral-ecdh", [d_E]Q_R)           // Mix the ephemeral ECDH shared secret into the protocol.
  (state, C₁) ← Encrypt(state, "message", P)               // Encrypt the plaintext.
  clone ← Mix(state, "signer-nonce", z)                    // Mix the signer's nonce into a cloned protocol.
  k ← Derive(clone, "commitment-scalar", 32) mod ℓ         // Derive a commitment scalar.
  I ← [k]G                                                 // Calculate the commitment point.
  (state, S₀) ← Encrypt(state, "commitment-point", I)      // Encrypt the commitment point.
  (state, r) ← Derive(state, "challenge-scalar", 32) mod ℓ // Derive a challenge scalar.
  s ← d_S✕r + k                                            // Calculate the proof scalar.
  X ← [s]Q_R                                               // Calculate the proof point.
  (state, S₁) ← Encrypt(state, "proof-point", X)           // Encrypt the proof point.
  return C₀ǁC₁ǁS₀ǁS₁
```

### Decrypting A Header

Decrypting a header requires a receiver's private key `d_R`, the sender's public key `Q_R`, a nonce
`N`, and a ciphertext `C₀ǁC₁ǁS₀ǁS₁`.

```text
function DecryptHeader(d_R, Q_S, N, C₀ǁC₁ǁS₀ǁS₁):
  state ← Initialize("veil.sres")                           // Initialize a protocol.
  state ← Mix(state, "sender", Q_S)                         // Mix the sender's public key into the protocol.
  state ← Mix(state, "receiver", [d_R]G)                    // Mix the receiver's public key into the protocol.
  state ← Mix(state, "nonce", N)                            // Mix the nonce into the protocol.
  state ← Mix(state, "static-ecdh", [d_R]Q_S)               // Mix the static ECDH shared secret into the protocol.
  (state, Q_E) ← Decrypt(state, "ephemeral-key", C₀)        // Decrypt the ephemeral public key.
  state ← Mix(state, "ephemeral-ecdh", [d_R]Q_E)            // Mix the ephemeral ECDH shared secret into the protocol.
  (state, P) ← Decrypt(state, "message", C₁)                // Decrypt the plaintext.
  (state, I) ← Decrypt(state, "commitment-point", S₀)       // Decrypt the commitment point.
  (state, r′) ← Derive(state, "challenge-scalar", 32) mod ℓ // Derive a counterfactual challenge scalar.
  (state, X) ← Decrypt(state, "proof-point", S₁)            // Decrypt the proof point.
  X′ ← [d_R](I + [r′]Q_S)                                   // Calculate a counterfactual proof point.
  if X ≠ X′:                                                // Return an error if the points are not equal.
    return ⊥
  return (Q_E, P)                                           // Otherwise, return the ephemeral public key and plaintext.
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
[`veil.sig`](#digital-signatures).

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
`S₁`--would only be possible if either TurboSHAKE128 is not collision-resistant or AEGIS-128L is not
PRF secure.

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

Because `veil.sres` is only ever used to encrypt unique messages, the use of a deterministic
signature scheme is not vulnerable to fault injection attacks.

### Indistinguishability Of Headers From Random Noise Of Encrypted Headers

All of the components of a `veil.sres` ciphertext--`C₀`, `C₁`, `S₀`, and `S₁`--are AEGIS-128L
ciphertexts using keys derived via TurboSHAKE128. An adversary in the outsider setting (i.e.
knowing only public keys) is unable to calculate any of the key material used to produce the
ciphertexts; a distinguishing attack would imply that either TurboSHAKE128 is not
collision-resistant or that AEGIS-128L is not PRF secure.

### Re-use Of Ephemeral Keys

The re-use of an ephemeral key pair `(d_E,Q_E)` across multiple ciphertexts does not impair the
confidentiality of the scheme provided `(N,Q_R)` pairs are not re-used [[BBS03]](#bbs03). An
adversary who compromises a retained ephemeral private key would be able to decrypt all messages the
sender encrypted using that ephemeral key, thus the forward sender security is bounded by the
sender's retention of the ephemeral private key.

## Encrypted Messages

`veil.mres` implements a multi-receiver signcryption scheme.

### Encrypting A Message

Encrypting a message requires a sender's private key `d_S`, a sender's secret nonce `z_S`, receiver
public keys `[Q_R_0,…,Q_R_n]`, and plaintext `P`.

```text
function EncryptMessage(d_S, z_S, [Q_R_0,…,Q_R_n], P):
  state ← Initialize("veil.mres")                // Initialize a protocol.
  state ← Mix(state, "sender", [d_S]G)           // Mix the sender's public key into the protocol.
  d_E ← Rand(32) mod ℓ                           // Generate a random ephemeral private key.
  K ← Rand(32)                                   // Generate a random data encryption key.
  N ← Rand(16)                                   // Generate a random nonce.
  C ← N                                          // Write the nonce.
  state ← Mix(state, "nonce", N)                 // Mix the nonce into the protocol.
  H ← KǁN_Q                                      // Encode the DEK and params in a header.

  for Q_R_i in [Q_R_0,…,Q_R_n]:
    (state, N_i) ← Derive(state, "header-nonce", 16) // Derive a nonce for each header.
    E_i ← EncryptHeader(d_S, d_E, Q_R_i, H, N_i)     // Encrypt the header for each receiver.
    state ← Mix(state, "header", E_i)                // Mix the encrypted header into the protocol.
    C ← CǁE_i

  state ← Mix(state, "dek", K) // Mix the DEK into the protocol.

  for all blocks p in P:
    H_i ← Seal(state, "block-header", 0x00ǁLE_24(|p|)) // Encrypt each block with a header.
    C_i ← Seal(state, "block", p)
    C ← CǁH_iǁC_i

  N_P ← PADME(|P|)                                   // Generate a block of random padding.
  H_p ← Seal(state, "block-header", 0x01ǁLE_24(N_P))
  C_p ← Seal(state, "block", Rand(N_P))
  C ← CǁH_pǁC_p

  k ← Rand(32) mod ℓ                                     // Generate a random commitment scalar.
  I ← [k]G                                               // Calculate the commitment point.
  (state, S₀) ← Encrypt(state, "commitment-point", I)    // Encrypt the commitment point.
  (state, r₀ǁr₁) ← Derive(state, "challenge-scalar", 16) // Derive two short challenge scalars.
  r ← r₀ +️️ µ×r₁️                                          // Calculate the full challenge scalar using the zeta endomorphism.
  s ← d_E×r + k                                          // Calculate the proof scalar.
  (state, S₁) ← Encrypt(state, "proof-scalar", s)        // Encrypt the proof scalar.

  C ← CǁS₀ǁS₁

  return C
```

### Decrypting A Message

Decrypting a message requires a receiver's private key `d_R`, sender's public key `Q_S`, and
ciphertext `C`.

```text
function DecryptMessage(d_R, Q_S, C):
  state ← Initialize("veil.mres")       // Initialize a protocol.
  state ← Mix(state, "sender", Q_S)     // Mix the sender's public key into the protocol.
  state ← Mix(state, "nonce", C[0..16]) // Mix the nonce into the protocol.
  C ← C[16..]

  (i, N_Q) ← (0, ∞)                     // Go through ciphertext looking for a decryptable header.
  while i < N_Q:
  for each possible encrypted header E_i in C:
    (state, N_i) ← Derive(state, "header-nonce", 16)
    (E_i, C) ← C[..HEADER_LEN]ǁC[HEADER_LEN..]
    state ← Mix(state, "header", E_i)
    x ← DecryptHeader(d_R, Q_S, N_i, E_i)
    if x ≠ ⊥:
      (Q_E, KǁN_Q) ← x // Once we decrypt a header, process the remaining headers.

  state ← Mix(state, "dek", K)                 // Mix the DEK into the protocol.

  P ← ϵ
  for each encrypted block header E_i in C:    // Read and open each block header and block.
      TǁN_i ← Open(state, "block_header", E_i)
      (C_i, C) ← (C[..N_i], C[N_i..])
      P_i ← Open(state, "block", C_i)
      if t = 0x00:
        P ← Pǁp_i
      else:
        break

  S₀ǁS₁ ← C                                                // Split the last bytes of the message.
  (state, I) ← Decrypt(state, "commitment-point", S₀)      // Decrypt the commitment point.
  (state, r₀′ǁr₁′) ← Derive(state, "challenge-scalar", 16) // Derive two counterfactual short challenge scalars.
  (state, s) ← Decrypt(state, "proof-scalar", S₁)          // Decrypt the proof scalar.
  I′ ← [s]G - [r₀′]Q_E - [r₁'µ]Q_E                         // Calculate the counterfactual commitment point.
  if I ≠ I′:                                               // Verify the signature.
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
each encrypted with a sequence of Lockstitch `Seal` operations, which is IND-CCA2 secure.

The latter portion of `veil.mres` is an EdDSA-style Schnorr signature scheme. The EdDSA-style
Schnorr signature is sUF-CMA secure when implemented in a prime order group and a cryptographic hash
function [[BCJZ21]](#bcjz21) [[CGN20]](#cgn20) [[PS00]](#ps00) [[NSW09]](#nsw09) (see also
[`veil.sig`](#digital-signatures)). In addition, this construction allows for the use of
variable-time optimizations during signature verification [[Por20]](#por20).

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
`veil.mres` ciphertexts consist of ephemeral keys, encrypted headers, encrypted message blocks, and
encrypted signature points. Each component of the ciphertext is dependent on the previous inputs
(including the headers, which use `Derive`-derived nonce to link the `veil.sres` ciphertexts to the
`veil.mres` state). A passive attack on any of those would only be possible if either TurboSHAKE128
is not collision-resistant or AEGIS-128L is not PRF secure.

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

Because `veil.mres` is only ever used to encrypt unique messages, the use of a deterministic
signature scheme is not vulnerable to fault injection attacks.

### Indistinguishability Of Messages From Random Noise

`veil.mres` ciphertexts are indistinguishable from random noise. All components of an `veil.mres`
ciphertext are AEGIS-128L ciphertexts; a successful distinguishing attack on them would imply that
TurboSHAKE128 is not collision-resistant or AEGIS-128L is not PRF secure.

### Partial Decryption

The division of the plaintext stream into blocks takes its inspiration from the CHAIN construction
[[HRRV]](#hrrv15), but the use of Lockstitch allows for a significant reduction in complexity.
Instead of using the nonce and associated data to create a feed-forward ciphertext dependency, the
Lockstitch protocol ensures all encryption operations are cryptographically dependent on the
ciphertext of all previous encryption operations. Likewise, because the `veil.mres` ciphertext is
terminated with a Schnorr signature (see [`veil.sig`](#digital-signatures)), using a special
operation for the final message block isn't required.

The major limitation of such a system is the possibility of the partial decryption of invalid
ciphertexts. If an attacker flips a bit on the fourth block of a ciphertext, `veil.mres` will
successfully decrypt the first three before returning an error. If the end-user interface displays
that, the attacker may be successful in radically altering the semantics of an encrypted message
without the user's awareness. The first three blocks of a message, for example, could say `PAY
MALLORY $100`, `GIVE HER YOUR CAR`, `DO WHAT SHE SAYS`, while the last block might read `JUST
KIDDING`.

## Passphrase-Based Encryption

`veil.pbenc` implements a memory-hard authenticated encryption scheme to encrypt secrets at rest.

### Initialization

Initializing a keyed protocol requires a passphrase `P`, salt `S`, time parameter `N_T`, space
parameter `N_S`, delta constant `D=3`, and block size constant `N_B=1024`.

```text
function HashBlock(C, [B_0..B_n], N):
  state ← Initialize("veil.pbenc.iter") // Initialize a protocol.
  state ← Mix(state, "counter", C)      // Mix the counter into the protocol.
  C ← C + 1                             // Increment the counter.

  for B_i in [B_0..B_n]:                // Mix each input block into the protocol.
    state ← Mix(state, "block", B_i)

  return Derive(state, "output", N)     // Derive N bytes of output.

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
  state ← Mix(state, "expanded-key", B[N_S-1])           // Mix the last block into the protocol.
  return state
```

### Encrypting A Private Key

Encrypting a private key requires a passphrase `P`, time parameter `N_T`, space parameter `N_S`, and
private key `d`.

```text
function EncryptPrivateKey(P, N_T, N_S, d):
  S ← Rand(16)                               // Generate a random salt.
  state ← InitFromPassphrase(P, S, N_T, N_S) // Perform the balloon hashing.
  (state, C) ← Seal(state, "secret", d)      // Seal the private key.
  return N_TǁN_SǁSǁC
```

### Decrypting A Private Key

Decrypting a private key requires a passphrase `P` and ciphertext `C=N_TǁN_SǁSǁCǁT`.

```text
function DecryptPrivateKey(P, N_T, N_S, C):
  state ← InitFromPassphrase(P, S, N_T, N_S) // Perform the balloon hashing.
  (state, d′) ← Open(state, "secret", C)     // Open the ciphertext.
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

### AA22

Marius A. Aardal, Diego F. Aranha.
2022.
[_2DT-GLS: Faster and exception-free scalar multiplication in the GLS254 binary curve_.](https://eprint.iacr.org/2022/748)

### ABHKLR21

Joël Alwen, Bruno Blanchet, Eduard Hauck, Eike Kiltz, Benjamin Lipp, and Doreen Riepel.
2021.
[_Analysing the HPKE standard._](https://eprint.iacr.org/2020/1499)
[`DOI:10.1007/978-3-030-77870-5_4`](https://doi.org/10.1007/978-3-030-77870-5_4)

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
[_A constructive perspective on signcryption security._](https://eprint.iacr.org/2018/050)

### BBS03

Mihir Bellare, Alexandra Boldyreva, and Jessica Staddon.
2003.
[_Randomness re-use in multi-recipient encryption schemeas._](https://www.iacr.org/archive/pkc2003/25670085/25670085.pdf)
[`DOI:10.1007/3-540-36288-6_7`](https://doi.org/10.1007/3-540-36288-6_7)

### BCGS16

Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter.
2016.
[_Balloon hashing: A memory-hard function providing provable protection against sequential attacks._](https://eprint.iacr.org/2016/027)
[`DOI:10.1007/978-3-662-53887-6_8`](https://doi.org/10.1007/978-3-662-53887-6_8)

### BCJZ21

Jacqueline Brendel, Cas Cremers, Dennis Jackson, and Mang Zhao.
2021.
[_The provable security of Ed25519: Theory and practice._](https://eprint.iacr.org/2020/823)
[`DOI:10.1109/SP40001.2021.00042`](https://doi.org/10.1109/SP40001.2021.00042)

### BDD23

Mihir Bellare and Hannah Davis and Zijing Di.
2023.
[_Hardening Signature Schemes via Derive-then-Derandomize: Stronger Security Proofs for EdDSA_](https://eprint.iacr.org/2023/298)

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
[_Taming the many EdDSAs._](https://eprint.iacr.org/2020/1244)
[`DOI:10.1007/978-3-030-64357-7_4`](https://doi.org/10.1007/978-3-030-64357-7_4)

### CHK03

Ran Canetti, Shai Halevi, and Jonathan Katz.
2003.
[_A forward-secure public-key encryption scheme._](https://eprint.iacr.org/2003/083)
[`DOI:10.1007/3-540-39200-9_16`](https://doi.org/10.1007/3-540-39200-9_16)

### HRRV15

Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár.
2015.
[_Online authenticated-encryption and its nonce-reuse misuse-resistance._](https://eprint.iacr.org/2015/189)
[`DOI:10.1007/978-3-662-47989-6_24`](https://doi.org/10.1007/978-3-662-47989-6_24)

### Ham17

Mike Hamburg.
2017.
[_The STROBE protocol framework._](https://eprint.iacr.org/2017/003)

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
[_Optimized lattice basis reduction in dimension 2, and fast Schnorr and EdDSA signature verification._](https://eprint.iacr.org/2020/454)

### Por22

Thomas Pornin.
2022.
[_Efficient and Complete Formulas for Binary Curves._](https://eprint.iacr.org/2022/1325)

### Por23

Thomas Pornin.
2023.
[_Faster Complete Formulas for the GLS254 Binary Curve._](https://eprint.iacr.org/2023/1688)

### PSSLR17

Damian Poddebniak, Juraj Somorovsky, Sebastian Schinzel, Manfred Lochter, and Paul Rösler.
2017
[Attacking Deterministic Signature Schemes using Fault Attacks](https://eprint.iacr.org/2017/1014)
[`DOI:10.1109/EuroSP.2018.00031`](https://doi.org/10.1109/EuroSP.2018.00031)

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
