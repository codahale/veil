# Passphrase-based Encryption

Veil implements memory-hard password-based encryption via STROBE using [balloon hashing][bh].

## Initialization

The protocol is initialized as follows, given a passphrase $P$, a 128-bit salt $S$, delta constant $D$, space parameter
$N_{space}$, time parameter $N_{time}$, block size $N_{block}$, and MAC size $N_{mac}$:

```text
INIT('veil.kdf.balloon', level=256)
AD(LE_U32(D),            meta=true)
AD(LE_U32(N_block),      meta=true)
AD(LE_U32(N_mac),        meta=true)
AD(LE_U32(N_time),       meta=true)
AD(LE_U32(N_space),      meta=true)
KEY(P)
AD(S)
```

Then, for each iteration of the balloon hashing algorithm, given a counter $C$, a left block $L$, and a right block $R$:

```text
AD(LE_U64(C))
AD(L)
AD(R)
PRF(N)
```

The final block $B_n$ of the balloon hashing algorithm is then used to key the protocol:

```text
KEY(B_n)
```

## Encryption

Encryption of a message $M$ is as follows:

```text
SEND_ENC(M)
SEND_MAC(T)
```

The returned ciphertext contains the following:

```text
LE_U32(N_time) || LE_U32(N_space) || S || C || T
```

## Decryption

Decryption of a ciphertext parses $N_{time}$, $N_{space}$, $S$, $C$ and MAC $T$, initializes the protocol, and performs
the inverse of encryption:

```text
RECV_ENC(C) -> P
RECV_MAC(T)
```

If the `RECV_MAC` call is successful, the plaintext $P$ is returned.

It should be noted that there is no standard balloon hashing algorithm, so this protocol is in the very, very tall grass
of cryptography and should never be used.


[bh]: https://eprint.iacr.org/2016/027.pdf