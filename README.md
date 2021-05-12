# veil-rs

_Stupid crypto tricks._

WARNING: You should, under no circumstances, use this.

## What is Veil?

Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
encrypted. As a result, a global passive adversary would be unable to gain any information from a
Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
true length, and fake recipients can be added to disguise their true number from other recipients.
Further, Veil supports hierarchical key derivation, allowing for domain-specific and disposable
keys.

## Design Criteria

### Cryptographic Minimalism

Veil uses just two distinct primitives:

* [STROBE][strobe] for confidentiality, authentication, and integrity.
* [ristretto255][r255] for key agreement and signing.

[ristretto255][r255-why] uses a safe curve, is a prime-order cyclic group, has non-malleable
encodings, and has no co-factor concerns. STROBE is built on the Keccak 𝑓-\[1600\] permutation, the
core of SHA-3, which has seen [significant scrutiny over the last decade][keccak].

The underlying philosophy is that expressed by [Adam Langley][agl]:

> There's a lesson in all this: have one joint and keep it well oiled. … \[O\]ne needs to minimise
> complexity, concentrate all extensibility in a single place and _actively defend it_.

As a result, the constructions in Veil depend primarily on two relatively stable cryptographic
assumptions: the Gap Diffie-Hellman assumption for ristretto255 and that Keccak 𝑓-\[1600\] is
suitably close to a random permutation.

### Integrated Constructions

Because STROBE provides a wide range of capabilities, it's possible to build fully integrated
cryptographic constructions. Leveraging transcript consistency–the fact that every operation changes
a STROBE protocol's state in a cryptographically secure manner–makes for much simpler protocols with
guarantees that are easier to understand.

Instead of combining a hash function and a digital signature algorithm, we have a single digital
signature protocol. Instead of combining a key exchange, a KDF, and an AEAD, we have a single hybrid
public key encryption protocol. This integration bakes in logical dependencies on sent and received
data in a feed-forward mechanism, which removes it from the attackable surface area of the protocol.
Because STROBE operations are cryptographically dependent on prior operations, the need for domain
separation identifiers, padding, and framing is eliminated.

Finally, the use of STROBE means all protocols which end in `RECV_MAC` calls
are [compactly committing][cce].

### Indistinguishable From Random Noise

Veil messages are entirely indistinguishable from random noise. They contain no plaintext metadata,
no plaintext ristretto255 elements, no plaintext framing or padding, and have entirely arbitrary
lengths. This makes them ideal for distribution via steganographic channels and very resistant to
traffic analysis.

## Algorithms & Constructions

### Hierarchical Key Derivation

Each participant in Veil has a secret key, which is a 64-byte random string. To derive a private key
from a secret key, the secret key is mapped to a ristretto255 scalar. A delta scalar is derived from
an opaque label value and added to the secret scalar to form a private key. The process is repeated
to derive a private key from another private key. To derive a public key from a public key, the
delta scalar is first multiplied by the curve's base element, then added to the public key element.

This is used iterative to provide hierarchical key derivation. Public keys are created using
hierarchical IDs like `/friends/alice`, in which the private key `/` is used to derive the private
key `friends`, which is in turn used to derive the private key `alice`.

### STROBE Protocols

#### `veil.akem`

`veil.akem` implements an authenticated `C(1e, 2s, ECC DH)` key encapsulation mechanism with
ristretto255 and STROBE. It provides authentication, sender forward security (i.e. if the sender's
private key is compromised, the messages they sent remain confidential), as well as the novel
property of sending no values in cleartext: the ephemeral public key is encrypted with the static
shared secret before sending.

#### `veil.mres`

`veil.mres` implements the multi-recipient encryption system for encrypted Veil messages.

Messages begin with a set of `veil.akem`-encrypted headers containing copies of the data encryption
key and the length of the encrypted headers. Next, the message is encrypted with STROBE using the
data encryption key. Finally, a `veil.schnorr` signature of the entire ciphertext created with an
ephemeral private key is appended.

To decrypt, readers search for a decryptable header, recover the DEK, the ephemeral public key, and
headers length, decrypt the message, and finally verify the signature.

This provides strong confidentiality and authenticity guarantees while still providing
repudiability (no recipient can prove a message's contents and origin without revealing their
private key) and forward security for senders (compromise of a sender's private key will not
compromise past messages they sent).

#### `veil.pbenc`

`veil.pbenc` implements a memory-hard AEAD using Balloon Hashing, suitable for encrypting secret
keys.

#### `veil.scaldf.*`

`veil.scaldf.*` provides various algorithms for deriving ristretto255 scalars from secret or
non-uniform values. Veil uses them to derive private keys and label scalars.

#### `veil.schnorr`

`veil.schnorr` implements a fully integrated Schnorr signature algorithm over ristretto255, as
described by [Fleischhacker et al.][schnorr]. It produces _indistinguishable_ signatures (i.e.,
signatures which do not reveal anything about the signing key or signed message) and when encrypted
with an unrelated key (i.e. by `veil.mres`) are _pseudorandom_
(i.e. indistinguishable from random noise).

## License

Copyright © 2021 Coda Hale

Distributed under the Apache License 2.0.


[strobe]: https://strobe.sourceforge.io

[r255]: https://ristretto.group

[r255-why]: https://ristretto.group/why_ristretto.html

[keccak]: https://keccak.team/third_party.html

[agl]: https://www.imperialviolet.org/2016/05/16/agility.html

[cce]: https://eprint.iacr.org/2019/016.pdf

[schnorr]: https://eprint.iacr.org/2011/673.pdf
