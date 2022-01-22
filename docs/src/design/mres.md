# Multi-recipient Messages

## Encryption

Encrypting a message begins as follows, given the sender's key pair, $d_S$ and $Q_S$, a plaintext message in blocks
$P_0...P_N$, a list of recipient public keys, $Q_{R^0}...Q_{R^M}$, and a DEK size $N_{DEK}$:

```text
INIT('veil.mres', level=128)
AD('sender',    meta=true)
AD(LE_U32(N_Q), meta=true, more=true)
SEND_CLR(Q_s)
```

The protocol context is cloned and keyed with the sender's private key and a random nonce and used to derive a data
encryption key, $K_{DEK}$, and an ephemeral private key, $d_E$:

```text
AD('secret-value', meta=true)
AD(LE_U32(N_d),     meta=true, more=true)
KEY(d_S)

AD('hedged-value', meta=true)
AD(LE_U32(64),     meta=true, more=true)
KEY(rand(64))

AD('ephemeral-private-key', meta=true)
AD(LE_U32(64),              meta=true, more=true)
PRF(64) -> d_E

AD('data-encryption-key', meta=true)
AD(LE_U32(N_DEK),         meta=true, more=true)
PRF(N_DEK) -> K_DEK

```

The ephemeral public key is computed as $Q_E = [{d_E}]G$, and the cloned context is discarded:

The data encryption key and message offset are encoded into a fixed-length header and copies of it are encrypted
with `veil.akem` for each recipient using $d_E$ and $Q_E$. Optional random padding is added to the end, and the
resulting blocks $H_0..H_N,H_{pad}$ is written:

```text
AD('headers',   meta=true)
SEND_CLR('')
SEND_CLR(H_0,   more=true)
…
SEND_CLR(H_N,   more=true)
SEND_CLR(H_pad, more=true)
```

The protocol is keyed with the DEK and the encrypted message is written:

```text
AD('data-encryption-key', meta=true)
AD(LE_U32(N_DEK),         meta=true, more=true)
KEY(K_dek)

AD('message', meta=true)
SEND_ENC('')
SEND_ENC(P_0, more=true)
…
SEND_ENC(P_N, more=true)
```

Finally, a Schnorr signature $S$ of the entire ciphertext (headers, padding, and DEM ciphertext) is created with $d_E$
and encrypted:

```text
AD('signature',   meta=true)
AD(LE_U32(N_d*2), meta=true, more=true)
SEND_ENC(S)
```

The resulting ciphertext then contains, in order: the `veil.akem`-encrypted headers, random padding, message ciphertext,
and a Schnorr signature of the headers, padding, and ciphertext.

## Decryption

Decryption begins as follows, given the recipient's key pair, $d_R$ and $Q_R$, the sender's public key, $Q_S$:

```text
AD('sender',    meta=true)
AD(LE_U32(N_Q), meta=true, more=true)
RECV_CLR(Q_s)
```

The recipient reads through the ciphertext in header-sized blocks, looking for one which is decryptable given their key
pair and the sender's public key. Having found one, they recover the data encryption key $K_{DEK}$, the message offset,
and the ephemeral public key $Q_E$. They then read the remainder of the block of encrypted headers and padding 
$H_0..H_N,H_{pad}$:

```text
AD('headers',   meta=true)
RECV_CLR('')
RECV_CLR(H_0,   more=true)
…
RECV_CLR(H_N,   more=true)
RECV_CLR(H_pad, more=true)
```

The protocol is keyed with the DEK, and the plaintext is decrypted:

```text
AD('data-encryption-key', meta=true)
AD(LE_U32(N_DEK),         meta=true, more=true)
KEY(K_dek)

AD('message',     meta=true)
RECV_ENC('')
RECV_ENC(C_0,     more=true)
…
RECV_ENC(C_N,     more=true)
```

Finally, the signature $S$ is decrypted and verified against the entire ciphertext:

```text
AD('signature',   meta=true)
AD(LE_U32(N_d*2), meta=true, more=true)
RECV_ENC(S)
```

## Multi-Recipient Confidentiality

To evaluate the confidentiality of this construction, consider an attacker provided with an encryption oracle for the
sender's private key and a decryption oracle for each recipient, engaged in an IND-CCA2 game with the goal of gaining an
advantage against any individual recipient. The elements available for them to analyze and manipulate are the encrypted
headers, the random padding, the message ciphertext, and the signature.

Each recipient's header is an IND-CCA2-secure ciphertext, so an attacker can gain no advantage there. Further, the
attacker cannot modify the copy of the DEK, the ephemeral public key, or the header length each recipient receives.

The encrypted headers and/or padding for other recipients are not IND-CCA2-secure for all recipients, so the attacker
may modify those without producing invalid headers. Similarly, the encrypted message is only IND-CPA-secure. Any
attacker attempting to modify any of those, however, will have to forge a valid signature for the overall message to be
valid. As `veil.schnorr` is SUF-CMA-secure, this is not possible.

## Multi-Recipient Authenticity

Similarly, an attacker engaged in parallel CMA games with recipients has negligible advantage in forging messages.
The `veil.schnorr` signature covers the entirety of the ciphertext.

The standard KEM/DEM hybrid construction (i.e. Construction 12.20 from Modern Cryptography 3e)
provides strong confidentiality (per Theorem 12.14), but no authenticity. A compromised recipient can replace the DEM
component of the ciphertext with an arbitrary message encrypted with the same DEK. Even if the KEM provides strong
authenticity against insider attacks, the KEM/DEM construction does not. [Alwen et al.][hpke] detail this attack against
the proposed HPKE standard.

In the single-recipient setting, the practical advantages of this attack are limited: the attacker can forge messages
which appear to be from a sender but are only decryptable by the attacker. In the multi-recipient setting, however, the
practical advantage is much greater: the attacker can present forged messages which appear to be from a sender to other,
honest recipients.

`veil.mres` eliminates this attack by using the ephemeral key pair to sign the entire ciphertext and including only the
public key in the KEM ciphertext. Re-using the KEM ciphertexts with a new message requires forging a new signature for a
SUF-CMA-secure scheme. The use of an authenticated KEM serves to authenticate the ephemeral public key and thus the
message: only the possessor of the sender's private key can calculate the static shared secret used to encrypt the
ephemeral public key, and the recipient can only forge KEM ciphertexts with themselves as the intended recipient.

## Repudiability

Because the sender's private key is only used to calculate shared secrets, a `veil.mres` ciphertext is entirely
repudiable unless a recipient reveals their public key. The `veil.schnorr` keys are randomly generated for each message
and all other forms of sender identity which are transmitted are only binding on public information.

## Randomness Re-Use

The ephemeral key pair, $d_E$ and $Q_E$, are used multiple times: once for each `veil.akem`
header and finally once for the end signature. This improves the efficiency of the scheme without reducing its security,
per [Bellare et al.'s treatment of Randomness Reusing Multi-Recipient Encryption Schemes][rr-mres].

## Ephemeral Scalar Hedging

In deriving the DEK and ephemeral scalar from a cloned context, `veil.mres`
uses [Aranha et al.'s "hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and
differential fault attacks against purely deterministic encryption schemes.

[hpke]: https://eprint.iacr.org/2020/1499.pdf

[rr-mres]: http://cseweb.ucsd.edu/~Mihir/papers/bbs.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf