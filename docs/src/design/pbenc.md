# Passphrase-based Encryption

`veil.pbenc` implements memory-hard password-based encryption using [balloon hashing][bh] and Xoodyak's AEAD
construction.

## Initialization

The protocol is initialized as follows, given a passphrase $P$, a 128-bit salt $S$, time parameter $N_T$, space
parameter $N_S$, delta constant $D$, and block size $N_B$. An unkeyed duplex is initialized and used to absorb the
passphrase and parameters:

$$
\text{Cyclist}(\epsilon, \epsilon, \epsilon) \\
\text{Absorb}(\texttt{veil.pbenc}) \\
\text{Absorb}(P) \\
\text{Absorb}(S) \\
\text{Absorb}(\text{U64}_{LE}(N_T)) \\
\text{Absorb}(\text{U64}_{LE}(N_S)) \\
\text{Absorb}(\text{U64}_{LE}(N_B)) \\
\text{Absorb}(\text{U64}_{LE}(D)) \\
$$

For each iteration of the balloon hashing algorithm, given a counter $C$, input blocks $(B_L, B_R)$, and an output block
$B_O$, the counter is encoded as a little-endian 64-bit integer and absorbed, the blocks are absorbed left-to-right, and
the output block is filled with duplex output:

$$
\text{Absorb}(\text{U64}_{LE}(C)) \\
C = C+1 \\
\text{Absorb}(B_L) \\
\text{Absorb}(B_R) \\
B_O \gets \text{Squeeze}(N_B) \\
$$

The expanding phase of the algorithm is performed as described by [Boneh et al][bh].

For the mixing phase of the algorithm, the loop variables $t$, $m$, and $i$ are encoded in a 24-byte block which is
absorbed along with the salt $S$, and a 64-bit little-endian integer is derived from duplex output. That integer is
mapped to a block, which is absorbed:

$$
b \gets \text{U64}_{LE}(t) || \text{U64}_{LE}(m) || \text{U64}_{LE}(i) \\
\text{Absorb}(\text{U64}_{LE}(C)) \\
C = C+1 \\
\text{Absorb}(S) \\
\text{Absorb}(b) \\
v \gets \text{Squeeze}(8) \bmod N_B
\text{Absorb}(\text{U64}_{LE}(C)) \\
C = C+1 \\
\text{Absorb}(B_v) \\
\text{Absorb}(\empty) \\
B_m \gets \text{Squeeze}(N_B) \\
$$

Finally, the last block $B_N$ of the buffer is absorbed and a 44-byte key $Z$ extracted and used to initialize a keyed
duplex:

$$
\text{Absorb}(B_N) \\
Z \gets \text{SqueezeKey}(44) \\
\text{Cyclist}(Z, \epsilon, \epsilon) \\
$$

## Encryption

Given an initialized, keyed duplex, the encryption of a message $P$ is as follows:

$$
C \gets \text{Encrypt}(P) \\
T \gets \text{Squeeze}(N_T) \\
$$

The returned ciphertext consists of the following:

$$
\text{U32}_{LE}(N_T) || \text{U32}_{LE}(N_S) || S || C || M
$$

## Decryption

Given an initialized, keyed duplex, the decryption of a ciphertext $C$ and authentication tag $T$ is as follows:

$$
P' \gets \text{Encrypt}(C) \\
T' \gets \text{Squeeze}(N_T) \\
T' \stackrel{?}{=} T \\
$$

If the $T' = T$, the plaintext $P'$ is returned as authentic.

It should be noted that there is no standard balloon hashing algorithm, so this protocol is in the very, very tall grass
of cryptography and should never be used.

[bh]: https://eprint.iacr.org/2016/027.pdf