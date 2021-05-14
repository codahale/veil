## Design

Veil is designed to be simple, understandable, and robust.

### Cryptographic Minimalism

Veil uses just two distinct primitives:

* [STROBE][strobe] for confidentiality, authentication, and integrity.
* [ristretto255][r255] for key agreement and signing.

[ristretto255][r255-why] uses a safe curve, is a prime-order cyclic group, has non-malleable encodings, and has no
co-factor concerns. STROBE is built on the Keccak 𝑓-\[1600\] permutation, the core of SHA-3, which has
seen [significant scrutiny over the last decade][keccak].

The underlying philosophy is that expressed by [Adam Langley][agl]:

> There's a lesson in all this: have one joint and keep it well oiled. … \[O\]ne needs to minimise
> complexity, concentrate all extensibility in a single place and _actively defend it_.

As a result, the constructions in Veil depend primarily on two relatively stable cryptographic assumptions: the Gap
Diffie-Hellman assumption for ristretto255 and that Keccak 𝑓-\[1600\] is suitably close to a random permutation.

### Integrated Constructions

Because STROBE provides a wide range of capabilities, it's possible to build fully integrated cryptographic
constructions. Leveraging transcript consistency–the fact that every operation changes a STROBE protocol's state in a
cryptographically secure manner–makes for much simpler protocols with guarantees that are easier to understand.

Instead of combining a hash function and a digital signature algorithm, we have a single digital signature protocol.
Instead of combining a key exchange, a KDF, and an AEAD, we have a single hybrid public key encryption protocol. This
integration bakes in logical dependencies on sent and received data in a feed-forward mechanism, which removes it from
the attackable surface area of the protocol. Because STROBE operations are cryptographically dependent on prior
operations, the need for domain separation identifiers, padding, and framing is eliminated.

Finally, the use of STROBE means all protocols which end in `RECV_MAC` calls are [compactly committing][cce].

### Indistinguishable From Random Noise

Veil messages are entirely indistinguishable from random noise. They contain no plaintext metadata, no plaintext
ristretto255 elements, no plaintext framing or padding, and have entirely arbitrary lengths. This makes them ideal for
distribution via steganographic channels and very resistant to traffic analysis.

[strobe]: https://strobe.sourceforge.io

[r255]: https://ristretto.group

[r255-why]: https://ristretto.group/why_ristretto.html

[keccak]: https://keccak.team/third_party.html

[agl]: https://www.imperialviolet.org/2016/05/16/agility.html

[cce]: https://eprint.iacr.org/2019/016.pdf
