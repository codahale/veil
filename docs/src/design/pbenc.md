# Passphrase-based Encryption

`veil.pbenc` implements memory-hard password-based encryption using [balloon hashing][bh] and Xoodyak's AEAD
construction.

## Initialization

The protocol is initialized as follows, given a passphrase $P$, a salt $S \rgets \allbits{128}$, time parameter $N_T$, space
parameter $N_S$, delta constant $D$, and block size $N_B$. 

A duplex is initialized with a constant key and used to absorb the passphrase, salt, and parameters:

$$
\Cyclist{\literal{veil.pbenc}} \\
\Absorb{P} \\
\Absorb{S} \\
\Absorb{\LE{U64}{N_T}} \\
\Absorb{\LE{U64}{N_S}} \\
\Absorb{\LE{U64}{N_B}} \\
\Absorb{\LE{U64}{D}} \\
 \\
$$

For each iteration of the balloon hashing algorithm, given a counter $C$, input blocks $(B_L, B_R)$, and an output block
$B_O$, the counter is encoded as a little-endian 64-bit integer and absorbed, the blocks are absorbed left-to-right, and
the output block is filled with duplex output:

$$
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{B_L} \\
\Absorb{B_R} \\
B_O \gets \Squeeze{N_B} \\
$$

The expanding phase of the algorithm is performed as described by [Boneh et al][bh].

For the mixing phase of the algorithm, the loop variables $t$, $m$, and $i$ are encoded in a block $b$:

$$
b \gets \LE{U64}{t} || \LE{U64}{m} || \LE{U64}{i} \\
$$

This is absorbed along with the salt $S$:

$$
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{S} \\
\Absorb{b} \\
$$

A 64-bit little-endian integer is derived from duplex output. That integer is mapped to a block index:

$$
v \gets \Squeeze{8} \bmod N_B \\
$$

Block $B_v$ is hashed along with the counter and block $B_m$ is filled with output:

$$
\Absorb{\LE{U64}{C}} \\
C \gets C+1 \\
\Absorb{B_v} \\
\Absorb{\epsilon} \\
B_m \gets \Squeeze{N_B} \\
$$

Finally, the last block $B_n$ of the buffer is used to re-key the duplex:

$$
\Cyclist{B_n} \\
$$

## Encryption

Given an initialized, keyed duplex, the encryption of a message $P$ is as follows:

$$
C \gets \Encrypt{P} \\
T \gets \Squeeze{N_T} \\
$$

The returned ciphertext consists of the following:

$$
\LE{U32}{N_T} || \LE{U32}{N_S} || S || C || M
$$

## Decryption

Given an initialized, keyed duplex, the decryption of a ciphertext $C$ and authentication tag $T$ is as follows:

$$
P' \gets \Encrypt{C} \\
T' \gets \Squeeze{N_T} \\
T' \check T \\
$$

If the $T' = T$, the plaintext $P'$ is returned as authentic.

It should be noted that there is no standard balloon hashing algorithm, so this protocol is in the very, very tall grass
of cryptography and should never be used.

[bh]: https://eprint.iacr.org/2016/027.pdf