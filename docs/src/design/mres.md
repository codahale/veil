# Multi-recipient Messages

`veil.mres` is a multi-recipient signcryption scheme, using an encrypt-then-sign construction with a CCA2-secure
encryption construction and a SUF-CMA-secure signature scheme.

## Encryption

Encrypting a message begins as follows, given the sender's key pair, $d_S$ and $Q_S$, a plaintext message in blocks
$P_0...P_N$, a list of recipient public keys, $Q_{R^0}...Q_{R^M}$, and a DEK size $N_{K}$. First, an unkeyed duplex is
initialized and used to absorb the sender's public key:

$$
\text{Cyclist}(\texttt{veil.mres}, \epsilon, \epsilon) \\
\text{Absorb}(Q_S) \\
$$

The duplex's state is cloned and keyed with the sender's private key and a random nonce and used to derive a data
encryption key, $K$, and an ephemeral private key, $d_E$:

$$
\text{Absorb}(d_S) \\
v \overset{R}{\gets} \mathbb{Z}_{2^{512}} \\
\text{Absorb}(v) \\
K \gets \text{SqueezeKey}(N_K) \\
d_E \gets \text{SqueezeKey}(64) \bmod \ell \\
$$

The ephemeral public key is computed as $Q_E = [{d_E}]G$, and the cloned duplex is discarded:

$K$, $Q_E$, and the message offset are encoded into a fixed-length header and copies of it are encrypted with
[`veil.sres`](sres.md) for each recipient using $(d_S, Q_S)$. Optional random padding is added to the end, and the
resulting headers $H_0..H_N||H_{pad}$ are absorbed in 32KiB blocks:

$$
h = K || Q_E || O \\
H_0 \gets \texttt{veil.sres.}\text{Encrypt}(d_S, Q_S, Q_{R_0}, h) \\
\text{Absorb}(H_0) \\
\dots \\
H_N \gets \texttt{veil.sres.}\text{Encrypt}(d_S, Q_S, Q_{R_N}, h) \\
\text{Absorb}(H_N) \\
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
s \gets \texttt{veil.schnorr.}\text{Sign}(d_E, Q_E, H_0..H_N || H_{pad} || ((C_0,T_0)..(C_N,T_N))) \\
S \gets \text{Encrypt}(S) \\
$$

The resulting ciphertext then contains, in order: the [`veil.sres`](sres.md)-encrypted headers, random padding,
a series of ciphertext and authentication tag block pairs, and a [`veil.schnorr`](schnorr.md) signature of the entire
ciphertext.

## Decryption

Decryption begins as follows, given the recipient's key pair, $d_R$ and $Q_R$, the sender's public key, $Q_S$. An
unkeyed duplex is initialized and used to absorb the sender's public key:

$$
\text{Cyclist}(\texttt{veil.mres}, \epsilon, \epsilon) \\
\text{Absorb}(Q_S) \\
$$

The recipient reads through the ciphertext in header-sized blocks, looking for one which is decryptable given their key
pair and the sender's public key. Having found one, they recover the data encryption key $K$, the ephemeral public key
$Q_E$, and the message offset. They then absorb the remainder of the block of encrypted headers $H_0..H_N$ and padding
$H_{pad}$:

$$
\text{Absorb}(H_0) \\
\dots \\
\text{Absorb}(H_N) \\
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

If any $T_i' \not\equiv T_i$, the decryption is halted with an error.

Finally, the signature $S$ is decrypted and verified against the entire ciphertext:

$$
s \gets \text{Decrypt}(S) \\
v \gets \texttt{veil.schnorr.}\text{Verify}(s, Q_E, H_0..H_N || H_{pad} || ((C_0,T_0)..(C_N,T_N)) \\
$$

The message is considered successfully decrypted if $v$ is true.

## Multi-Recipient Confidentiality

To evaluate the confidentiality of this construction, consider an attacker provided with an encryption oracle for the
sender's private key and a decryption oracle for each recipient, engaged in an IND-CCA2 game with the goal of gaining an
advantage against any individual recipient. The elements available for them to analyze and manipulate are the encrypted
headers, the random padding, the message ciphertext, and the signature.

Each recipient's header is an IND-CCA2-secure [`veil.sres`](sres.md) ciphertext, so an attacker can gain no advantage
there. Further, the attacker cannot modify the copy of the DEK, the ephemeral public key, or the header length each
recipient receives.

The encrypted headers and padding are IND-CCA2-secure for all recipients, as the authentication tag of the first message
block constitutes an AEAD with the encrypted headers and padding as authenticated data. Any modification of headers for
other recipients or of the padding will result in an invalid tag and thus a decryption error.

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

[hpke]: https://eprint.iacr.org/2020/1499.pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf

[oae2]: https://eprint.iacr.org/2015/189.pdf