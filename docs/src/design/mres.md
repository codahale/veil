# Multi-recipient Messages

`veil.mres` is a multi-recipient signcryption scheme, using an encrypt-then-sign construction with an IND-CCA2 secure
encryption construction and a SUF-CMA secure signature scheme.

## Encryption

Encrypting a message begins as follows, given the sender's key pair, $d_S$ and $Q_S$, a plaintext message in blocks
$P_0..P_n$, a list of recipient public keys, $Q_{R^0}..Q_{R^m}$, and a DEK size $N_{K}$. 

First, a duplex is initialized with a constant key and used to absorb the sender's public key:

$$
\text{Cyclist}(\texttt{veil.mres}, \epsilon, \epsilon) \\
\text{Absorb}(Q_S) \\
$$

The duplex's state is cloned and keyed with the sender's private key and a random nonce and used to derive a data
encryption key, $K$, and an ephemeral key pair, $(d_E, Q_E)$:

$$
\text{Absorb}(d_S) \\
v \overset{R}{\gets} \mathbb{Z}_{2^{512}} \\
\text{Absorb}(v) \\
K \gets \text{SqueezeKey}(N_K) \\
d_E \gets \text{SqueezeKey}(32) \bmod \ell \\
Q_E \gets [{d_E}]G \\
$$

$(d_E,Q_E)$ are returned to the original context and the cloned duplex is discarded:

$K$, $Q_E$, and the message offset are encoded into a fixed-length header and copies of it are encrypted with
[`veil.sres`](sres.md) for each recipient using $(d_S, Q_S)$. Optional random padding is added to the end, and the
resulting headers $H_0..H_n||H_{pad}$ are absorbed in 32KiB blocks:

$$
h \gets K || Q_E || O \\
H_0 \gets \texttt{veil.sres.}\text{Encrypt}(d_S, Q_S, Q_{R_0}, h) \\
\text{Absorb}(H_0) \\
\dots \\
H_n \gets \texttt{veil.sres.}\text{Encrypt}(d_S, Q_S, Q_{R_n}, h) \\
\text{Absorb}(H_n) \\
H_{pad} \overset{R}{\gets} \mathbb{Z}_{2^{pad}} \\
\text{Absorb}(H_{pad}) \\
$$

The duplex is keyed with $K$, the plaintext message is divided into 32KiB blocks
$P_0 || P_1 || \dots P_i \dots || P_n$. Each block $P_i$ is encrypted as ciphertext $C_i$ and an authentication tag 
$T_i$ is generated and appended. After each block, the duplex state is ratcheted to prevent rollback:

$$
\text{Cyclist}(K, \epsilon, \epsilon) \\
\dots \\
C_i \gets \text{Encrypt}(P_i) \\
T_i \gets \text{Squeeze}(N_T) \\
\text{Ratchet}() \\
\dots \\
$$

Finally, a [`veil.schnorr`](schnorr.md) signature $s$ of the entire ciphertext (headers, padding, and DEM ciphertext) is
created with $d_E$ and encrypted as $S$:

$$
s \gets \texttt{veil.schnorr.}\text{Sign}(d_E, Q_E, H_0..H_n || H_{pad} || ((C_0,T_0)..(C_n,T_n))) \\
S \gets \text{Encrypt}(S) \\
$$

The resulting ciphertext then contains, in order: the [`veil.sres`](sres.md)-encrypted headers, random padding,
a series of ciphertext and authentication tag block pairs, and a [`veil.schnorr`](schnorr.md) signature of the entire
ciphertext.

## Decryption

Decryption begins as follows, given the recipient's key pair, $d_R$ and $Q_R$, the sender's public key, $Q_S$.

First, a duplex is initialized with a constant key and used to absorb the sender's public key:

$$
\text{Cyclist}(\texttt{veil.mres}, \epsilon, \epsilon) \\
\text{Absorb}(Q_S) \\
$$

The recipient reads through the ciphertext in header-sized blocks, looking for one which is decryptable given their key
pair and the sender's public key. Having found one, they recover the data encryption key $K$, the ephemeral public key
$Q_E$, and the message offset. They then absorb the remainder of the block of encrypted headers $H_0..H_n$ and padding
$H_{pad}$:

$$
\text{Absorb}(H_0) \\
\dots \\
\text{Absorb}(H_n) \\
\text{Absorb}(H_{pad}) \\
$$

The duplex is keyed with $K$ and used to decrypt the ciphertext blocks and verify the authentication tags:

$$
\text{Cyclist}(K, \epsilon, \epsilon) \\
\dots \\
P_i \gets \text{Decrypt}(C_i) \\
T_i' \gets \text{Squeeze}(N_T) \\
\text{Ratchet}() \\
\dots \\
$$

If any $T_i' \not = T_i$, the decryption is halted with an error.

Finally, the signature $S$ is decrypted and verified against the entire ciphertext:

$$
s \gets \text{Decrypt}(S) \\
v \gets \texttt{veil.schnorr.}\text{Verify}(s, Q_E, H_0..H_n || H_{pad} || ((C_0,T_0)..(C_n,T_n)) \\
$$

The message is considered successfully decrypted if $v$ is true.

## Insider Security

While `veil.mres` has some similarity to the Encrypt-then-Sign ($\mathcal{E}t\mathcal{S}$) sequential signcryption 
construction, unlike $\mathcal{E}t\mathcal{S}$ it offers multi-user insider security (i.e. FSO/FUO-IND-CCA2 and 
FSO/FUO-sUF-CMA in the multi-user setting).

_Practical Signcryption_ (p. 32) describes the tradeoffs inherent in the sequential constructions:

> If we consider the signcryption security corresponding to the security of the operation performed _first_ (i.e., 
> privacy in the $\mathcal{E}t\mathcal{S}$ method and authenticity in the $\mathcal{S}t\mathcal{E}$ method), then 
> results differ depending on the security models and the composition methods. In the insider security model, the 
> security of the first operation is not preserved against the strongest security notions of privacy and authenticity 
> (i.e., IND-CCA2 security and sUF-CMA security) although it is preserved against weaker security notions (e.g., 
> IND-CPA, IND-gCCA2, and UF-CMA security). This is because the adversary who knows the secret key of the other
> component (i.e., the signature scheme in the $\mathcal{E}t\mathcal{S}$ method and the encryption scheme in the 
> $\mathcal{S}t\mathcal{E}$ method) can manipulate the given signcryption ciphertext by re-signing it and submitting the
> modified ciphertext as a unsigncryption oracle query (in the attack against the IND-CCA2 security of the 
> $\mathcal{E}t\mathcal{S}$ method) or re-encrypting it and submit the modified ciphertext as a forgery (in the attack
> against the sUF-CMA security of the $\mathcal{S}t\mathcal{E}$ method). Intuitively, this tells us that achieving the
> strongest security corresponding to the security of the operation performed first is not possible when the adversary
> knows the secret key of the operation performed last.

Given that the [`veil.schnorr`](schnorr.md) signature is the final operation in `veil.mres` and is sUF-CMA secure, we
can conclude that `veil.mres` is sUF-CMA secure in the insider security model per Theorem 2.1 of
_Practical Signcryption_:

> If $\mathcal{S}$ is sUF-CMA secure, then the signcryption scheme $\Pi$ built using the $\mathcal{E}t\mathcal{S}$
> method is sUF-CMA secure in the insider model. \[…\]

Proof 1 of Theorem 2.2 of _Practical Signcryption_ describes a successful distinguisher $\mathcal{A}$ in the IND-CCA2
game in the insider security model against the $\mathcal{E}t\mathcal{S}$ construction:

> Given the induced decryption oracle $\text{Decrypt}$ and the induced encryption key ${pk}^{enc}$, $\mathcal{A}$ picks
> two messages $(m_0,m_1)$, where $m_0 = 0$ and $m_1 = 1$, and then outputs them to get the challenge ciphertext
> $C = (c, σ )$. Next, $\mathcal{A}$ gets the message part $c$ and re-signs $c$ by computing a "new" signature
> $\sigma' \stackrel{R}{\gets} \text{Sign}({sk}^{sig}_S,c)$ of $c$, where $\sigma' \not = \sigma$, and then queries the
> induced decryption oracle with $C' = (c,\sigma')$. Notice that since we assumed $\mathcal{S}$ is probabilistic (not
> deterministic), with a non-negligible probability one can find a different signature for the same message in
> polynomial time. Since $C' \not = C$, and $\sigma'$ is a valid signature of $c$, $\mathcal{A}$ can obtain the
> decryption of $c$. Once the decrypted message $m$ is obtained, $\mathcal{A}$ compares it with its own message pair
> $(m_0,m_1)$ and outputs the bit $b$ where $m_b = m$.

Unlike the $\mathcal{E}t\mathcal{S}$ construction, however, `veil.mres` does not use the same key for privacy as it does
for authenticity. The signature is generated using the ephemeral private key $d_E$, which is known only to the sender at
the time of sending. The receiver only obtains $Q_E$, its corresponding public key, by decrypting a header. The headers
are each encrypted with ['veil.sres`](sres.md), which provides insider security (i.e. IND-CCA2 and sUF-CMA).

Because `veil.mres` uses an ephemeral signing key, $\mathcal{A}$ is not in possession of ${sk}^{sig}_S$ and can neither
compute $\sigma'$ nor receive it from any available oracle, as the security model does not provide $\mathcal{A}$ access
to nonce values. The use of an ephemeral singing key effectively forces $\mathcal{A}$ from the insider security model
into the outsider security model with respect to the IND-CCA2 game.

In the outsider security model, `veil.mres` is IND-CCA2 secure per Theorem 2.3 of _Practical Signcryption_:

> If $\mathcal{E}$ is IND-CPA secure and $\mathcal{S}$ is sUF-CMA secure, then the signcryption scheme $\Pi$ built using
> $\mathcal{E}t\mathcal{S}$ is IND-CCA2 secure in the outsider security model.

Xoodyak's $\text{Encrypt}$ operation is IND-CPA secure (see [`veil.sres`](sres.md)) and [`veil.schnorr`](schnorr.md) is
sUF-CMA secure, thus `veil.mres` is IND-CCA2 secure (and sUF-CMA secure) in both the insider and outsider security
models.

## Authenticated Encryption And Partial Decryption

The division of the plaintext stream into blocks takes its inspiration from the [CHAIN construction][oae2], but the
use of Xoodyak allows for a significant reduction in complexity. Instead of using the nonce and associated data to
create a feed-forward ciphertext dependency, the Xoodyak duplex ensures all encryption operations are cryptographically
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

In deriving the DEK and ephemeral private key from a cloned duplex, `veil.mres`
uses [Aranha et al.'s "hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and
differential fault attacks against purely deterministic encryption schemes.

[hedge]: https://eprint.iacr.org/2019/956.pdf

[oae2]: https://eprint.iacr.org/2015/189.pdf