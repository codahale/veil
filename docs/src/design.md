# Design

Veil is designed to be simple, understandable, and robust.

## Cryptographic Minimalism

Veil uses just two distinct primitives:

* [Xoodyak][xoodyak] for confidentiality, authentication, and integrity.
* [ristretto255][r255] for key agreement and signing.

[ristretto255][r255-why] uses a safe curve, is a prime-order cyclic group, has non-malleable encodings, and has no
co-factor concerns. Xoodyak is an advanced cryptographic duplex based on a strong permutation.

The underlying philosophy is that expressed by [Adam Langley][agl]:

> There's a lesson in all this: have one joint and keep it well oiled. … \[O\]ne needs to minimise
> complexity, concentrate all extensibility in a single place and _actively defend it_.

As a result, the constructions in Veil depend primarily on two relatively stable cryptographic assumptions: the Gap
Diffie-Hellman assumption for ristretto255 and that Xoodoo is suitably close to a random permutation.

## Integrated Constructions

Because Xoodyak provides a wide range of capabilities, it's possible to build fully integrated cryptographic
constructions. Leveraging transcript consistency–the fact that every operation changes a Xoodyak hash's state in a
cryptographically secure manner–makes for much simpler constructions with guarantees that are easier to understand.

Instead of combining a hash function and a digital signature algorithm, we have a single digital signature construction.
Instead of combining a KEM, a KDF, and an AEAD, we have a single hybrid public key encryption construction. This
integration bakes in logical dependencies on sent and received data in a feed-forward mechanism, which removes it from
the attackable surface area of the protocol. Because Xoodyak outputs are cryptographically dependent on prior inputs,
the need for domain separation identifiers, padding, and framing is eliminated.

Finally, the use of Xoodyak means all protocols which end in $\text{Squeeze}$ outputs are [compactly committing][cce].

## Confidentiality & Integrity

Veil messages are designed to provide confidentiality and integrity against all known attacks, providing CCA2
security against both non-recipients _and_ recipients. 

## Unforgeability & Non-malleability

Veil signatures are strongly unforgeable, non-malleable, and strongly bound to signers.

## Deniable Authenticity

Veil messages are authenticated, in that every recipient can prove to themselves that the message was sent by the owner
of a given public key and was not altered in any way. Unlike e.g. PGP, however, this authenticity is deniable: the only
way for a recipient to prove the authenticity of a message to a third party without revealing their own private key.

## Indistinguishability From Random Noise

Both Veil messages and signatures are entirely indistinguishable from random noise. They contain no plaintext metadata,
no plaintext ristretto255 points, no plaintext framing or padding, and have entirely arbitrary lengths. This makes them
ideal for distribution via steganographic channels and very resistant to traffic analysis.

[r255]: https://ristretto.group

[r255-why]: https://ristretto.group/why_ristretto.html

[keccak]: https://keccak.team/third_party.html

[agl]: https://www.imperialviolet.org/2016/05/16/agility.html

[cce]: https://eprint.iacr.org/2017/664.pdf

[xoodyak]: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf