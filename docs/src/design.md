# Design

Veil is designed to be simple, understandable, and robust.

## Cryptographic Minimalism

Veil uses just two distinct primitives:

* [Xoodyak][xoodyak] for confidentiality, authentication, and integrity.
* [ristretto255][r255] for key encapsulation and authenticity.

The underlying philosophy is that expressed by [Adam Langley][agl]:

> There's a lesson in all this: have one joint and keep it well oiled. … \[O\]ne needs to minimise
> complexity, concentrate all extensibility in a single place and _actively defend it_.

As a result, the constructions in Veil depend primarily on two relatively stable cryptographic assumptions: the Gap
Diffie-Hellman assumption for ristretto255 and that Xoodoo is suitably close to a random permutation.

### ristretto255

[ristretto255][r255-why] uses a safe curve, is a prime-order cyclic group, has non-malleable encodings, and has no
co-factor concerns. This allows for the use of a wide variety of cryptographic constructions built on group operations.
It targets a 128-bit security level, lends itself to constant-time implementations, and can run in constrained
environments.

### Xoodyak

Xoodyak is a cryptographic [duplex][duplex], a relatively new cryptographic primitive that provides symmetric-key
confidentiality, integrity, and authentication via a single object. Duplexes offer a way to replace complex, ad-hoc
constructions combining encryption algorithms, cipher modes, AEADs, MACs, and hash algorithms using a single primitive.

Duplexes have security properties which reduce to the properties of the cryptographic [sponge][sponge], which themselves
reduce to the strength of the underlying permutation. Xoodyak is based on the Xoodoo permutation, an adaptation of the
Keccak-_p_ permutation (upon which SHA-3 is built) for lower-resource environments. While Xoodyak is not standardized,
it is currently a finalist in the NIST Lightweight Cryptography standardization process.

Like Ristretto255, it targets a 128-bit security level, lends itself to constant-time implementations, and can run in
constrained environments.

## Integrated Constructions

Because Xoodyak provides a wide range of capabilities, it's possible to build fully integrated cryptographic
constructions. Leveraging transcript consistency–the fact that every operation changes a Xoodyak duplex's state in a
cryptographically secure manner–makes for much simpler constructions with guarantees that are easier to understand.

Instead of combining a hash function and a digital signature algorithm, we have a single digital signature construction.
Instead of combining a KEM, a KDF, and an AEAD, we have a single hybrid public key encryption construction. This
integration bakes in logical dependencies on sent and received data in a feed-forward mechanism, which removes it from
the attackable surface area of the protocol. Because Xoodyak outputs are cryptographically dependent on prior inputs,
the need for domain separation identifiers, padding, and framing is eliminated.

Xoodyak provides a _hash_ mode and a _keyed_ mode; Veil uses the _keyed_ mode exclusively, initializing each duplex by
passing a constant initialization string (e.g. `veil.mres`) as the key. This allows for effectively unkeyed
constructions (e.g. [digital signature verification](design/schnorr.md)) which use Xoodyak's
$\text{Encrypt}$/$\text{Decrypt}$ functionality for indistinguishability and not confidentiality. Constructions which
provide confidentiality do so by calling the $\text{Cyclist}$ function with a secret key, essentially using the duplex's
prior state as authenticated data.

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

[r255]: https://htmlpreview.github.io/?https://github.com/FiloSottile/draft-irtf-cfrg-ristretto255/blob/master/draft-irtf-cfrg-ristretto255-decaf448.html

[r255-why]: https://ristretto.group/why_ristretto.html

[keccak]: https://keccak.team/third_party.html

[agl]: https://www.imperialviolet.org/2016/05/16/agility.html

[cce]: https://eprint.iacr.org/2017/664.pdf

[xoodyak]: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf

[duplex]: https://keccak.team/files/SpongeDuplex.pdf

[sponge]: https://keccak.team/files/SpongeIndifferentiability.pdf