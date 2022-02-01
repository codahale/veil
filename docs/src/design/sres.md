# Single-recipient Messages

TK TK TK

## IK-CCA Security

`veil.sres` is IK-CCA (per [Bellare][ik-cca]), in that it is impossible for an attacker in possession of two public keys
to determine which of the two keys a given ciphertext was encrypted with in either chosen-plaintext or chosen-ciphertext
attacks. Informally, `veil.sres` ciphertexts consist exclusively of STROBE ciphertext and PRF output; an attacker being
able to distinguish between ciphertexts based on keying material would imply STROBE's AEAD construction is not IND-CCA2.

Consequently, a passive adversary scanning for encoded points would first need the parties' static Diffie-Hellman secret
in order to distinguish messages from random noise.

