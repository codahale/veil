# Multi-recipient Messages

`veil.mres` is a multi-recipient signcryption scheme, using an encrypt-then-sign construction with a CCA2-secure
encryption construction and a SUF-CMA-secure signature scheme.

## Encryption

Encrypting a message begins as follows, given the sender's key pair, $d_S$ and $Q_S$, a plaintext message in blocks
$P_0...P_N$, a list of recipient public keys, $Q_{R^0}...Q_{R^M}$, and a DEK size $N_{DEK}$:

```text
INIT('veil.mres', level=128)
AD('sender',    meta=true)
AD(LE_U64(N_Q), meta=true, more=true)
SEND_CLR(Q_s)
```

The protocol context is cloned and keyed with the sender's private key and a random nonce and used to derive a data
encryption key, $K_{DEK}$, and an ephemeral private key, $d_E$:

```text
AD('secret-value', meta=true)
AD(LE_U64(N_d),     meta=true, more=true)
KEY(d_S)

AD('hedged-value', meta=true)
AD(LE_U64(64),     meta=true, more=true)
KEY(rand(64))

AD('ephemeral-private-key', meta=true)
AD(LE_U64(64),              meta=true, more=true)
PRF(64) -> d_E

AD('data-encryption-key', meta=true)
AD(LE_U64(N_DEK),         meta=true, more=true)
PRF(N_DEK) -> K_DEK
```

The ephemeral public key is computed as $Q_E = [{d_E}]G$, and the cloned context is discarded:

$K_{DEK}$, $Q_E$, and the message offset are encoded into a fixed-length header and copies of it are encrypted with
[`veil.sres`](sres.md) for each recipient using $(d_S, Q_S)$. Optional random padding is added to the end, and the
resulting blocks $H_0..H_N,H_{pad}$ is written:

```text
AD('headers',   meta=true)
SEND_CLR('')
SEND_CLR(H_0,   more=true)
…
SEND_CLR(H_N,   more=true)
SEND_CLR(H_pad, more=true)
```

As the final setup step, the protocol is keyed with $K_{DEK}$:

```text
AD('data-encryption-key', meta=true)
AD(LE_U64(N_DEK),         meta=true, more=true)
KEY(K_DEK)
```

The plaintext message is divided into 32KiB-sized blocks $P_0 || P_1 || \dots P_i \dots || P_n$. Each block $P_i$ is
encrypted as ciphertext $C_i$ and a MAC $M_i$ is generated and appended. After each block, the protocol state is
ratcheted to prevent rollback:

```text
...
AD('block',          meta=true)
AD(LE_U64(LEN(P_i)), meta=true, more=true)
SEND_ENC(P_i) -> C_i

AD('mac',       meta=true)
AD(LE_U64(N_M), meta=true, more=true)
SEND_MAC(N_M) -> M_i

AD('post-block', meta=true)
AD(LE_U64(32),   meta=true, more=true)
RATCHET(32)
...
```

Finally, a [`veil.schnorr`](schnorr.md) signature $S$ of the entire ciphertext (headers, padding, and DEM ciphertext) is
created with $d_E$ and encrypted:

```text
AD('signature',   meta=true)
AD(LE_U64(LEN(S)), meta=true, more=true)
SEND_ENC(S)
```

The resulting ciphertext then contains, in order: the [`veil.sres`](sres.md)-encrypted headers, random padding,
a series of ciphertext and MAC block pairs, and a [`veil.schnorr`](schnorr.md) signature of the entire ciphertext.

## Decryption

Decryption begins as follows, given the recipient's key pair, $d_R$ and $Q_R$, the sender's public key, $Q_S$:

```text
AD('sender',    meta=true)
AD(LE_U64(N_Q), meta=true, more=true)
RECV_CLR(Q_s)
```

The recipient reads through the ciphertext in header-sized blocks, looking for one which is decryptable given their key
pair and the sender's public key. Having found one, they recover the data encryption key $K_{DEK}$, the ephemeral public
key $Q_E$, and the message offset. They then read the remainder of the block of encrypted headers and padding 
$H_0..H_N,H_{pad}$:

```text
AD('headers',   meta=true)
RECV_CLR('')
RECV_CLR(H_0,   more=true)
…
RECV_CLR(H_N,   more=true)
RECV_CLR(H_pad, more=true)
```

The protocol is keyed with $K_{DEK}$, and the plaintext is decrypted and verified:

```text
AD('data-encryption-key', meta=true)
AD(LE_U64(N_DEK),         meta=true, more=true)
KEY(K_DEK)

...
AD('block',          meta=true)
AD(LE_U64(LEN(C_i)), meta=true, more=true)
SEND_ENC(C_i) -> P_i

AD('mac',            meta=true)
AD(LE_U64(LEN(M_i)), meta=true, more=true)
RECV_MAC(M_i)

AD('post-block', meta=true)
AD(LE_U64(32),   meta=true, more=true)
RATCHET(32)
...
```

If any `RECV_MAC` operation fails, the decryption is halted with an error.

Finally, the signature $S$ is decrypted and verified against the entire ciphertext:

```text
AD('signature',   meta=true)
AD(LE_U64(N_d*2), meta=true, more=true)
RECV_ENC(S)
```

## Multi-Recipient Confidentiality

To evaluate the confidentiality of this construction, consider an attacker provided with an encryption oracle for the
sender's private key and a decryption oracle for each recipient, engaged in an IND-CCA2 game with the goal of gaining an
advantage against any individual recipient. The elements available for them to analyze and manipulate are the encrypted
headers, the random padding, the message ciphertext, and the signature.

Each recipient's header is an IND-CCA2-secure [`veil.sres`](sres.md) ciphertext, so an attacker can gain no advantage
there. Further, the attacker cannot modify the copy of the DEK, the ephemeral public key, or the header length each
recipient receives.

The encrypted headers and padding are IND-CCA2-secure for all recipients, as the first message block MAC essentially
forms an AEAD with the encrypted headers and padding as authenticated data. Any modification of headers for other
recipients or of the padding will result in an invalid MAC and thus a decryption error.

## Multi-Recipient Authenticity

Similarly, an attacker engaged in parallel CMA games with recipients has negligible advantage in forging messages.
The [`veil.schnorr`](schnorr.md) signature covers the entirety of the ciphertext.

The standard KEM/DEM hybrid construction (i.e. Construction 12.20 from _Modern Cryptography 3e_) provides strong
confidentiality (per Theorem 12.14), but no authenticity. A compromised recipient can replace the DEM component of the
ciphertext with an arbitrary message encrypted with the same DEK. Even if the KEM provides strong authenticity against
insider attacks, the KEM/DEM construction does not. [Alwen et al.][hpke] detail this attack against the proposed HPKE
standard.

In the single-recipient setting, the practical advantages of this attack are limited: the attacker can forge messages
which appear to be from a sender but are only decryptable by the attacker. In the multi-recipient setting, however, the
practical advantage is much greater: the attacker can present forged messages which appear to be from a sender to other,
honest recipients.

`veil.mres` eliminates this attack by using the ephemeral key pair to sign the entire ciphertext and including only the
public key in the KEM ciphertext. Re-using the KEM ciphertexts with a new message requires forging a new signature for a
SUF-CMA-secure scheme. The use of an authenticated KEM serves to authenticate the ephemeral public key and thus the
message: only the possessor of the sender's private key can calculate the static shared secret used to encrypt the
ephemeral public key, and the recipient can only forge KEM ciphertexts with themselves as the intended recipient.

## Authenticated Encryption And Partial Decryption

The division of the plaintext stream into blocks takes its inspiration from the [CHAIN construction][oae2], but the
use of STROBE allows for a significant reduction in complexity. Instead of using the nonce and associated data to create
a feed-forward ciphertext dependency, the STROBE sponge ensures all encryption operations are cryptographically
dependent on the ciphertext of all previous encryption operations. Likewise, because the `veil.mres` ciphertext is
terminated with a [`veil.schnorr`](schnorr.md) signature, using a special operation for the final message block isn't
required.

The major limitation of such a system is the possibility of the partial decryption of invalid ciphertexts. If an
attacker flips a bit on the fourth block of a ciphertext, `veil.mres` will successfully decrypt the first three before
returning an error. If the end-user interface displays that, the attacker may be successful in radically altering the
semantics of an encrypted message without the user's awareness. The first three blocks of a message, for example, could
say `PAY MALLORY $100`, `GIVE HER YOUR CAR`, `DO WHAT SHE SAYS`, while the last block might read `JUST KIDDING`.

## Deniability

The headers are signcrypted with [`veil.sres`](sres.md), which achieves both authentication and deniability. The message
itself is encrypted with a randomly-generated symmetric key, which isn't tied to any identity. The final
[`veil.schnorr`](schnorr.md) signature is created with a randomly-generated ephemeral key.

Despite providing strong authenticity, `veil.mres` produces fully deniable ciphertexts.

## Ephemeral Scalar Hedging

In deriving the DEK and ephemeral private key from a cloned context, `veil.mres`
uses [Aranha et al.'s "hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and
differential fault attacks against purely deterministic encryption schemes.

[hpke]: https://eprint.iacr.org/2020/1499.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf

[oae2]: https://eprint.iacr.org/2015/189.pdf