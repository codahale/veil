# Passphrase-based Encryption

Veil implements memory-hard password-based encryption via STROBE using [balloon hashing][bh].

## Initialization

The protocol is initialized as follows, given a passphrase $P$, a 128-bit salt $S$, delta constant $D$, space parameter
$N_S$, time parameter $N_T$, block size $N_B$, and MAC size $N_M$:

```text
INIT('veil.kdf.balloon', level=256)
AD(LE_U32(D),            meta=true)
AD(LE_U32(N_B),          meta=true)
AD(LE_U32(N_M),          meta=true)
AD(LE_U32(N_T),          meta=true)
AD(LE_U32(N_S),          meta=true)
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

The final block $B_N$ of the balloon hashing algorithm is then used to key the protocol:

```text
KEY(B_N)
```

## Encryption

Encryption of a message $P$ is as follows:

```text
SEND_ENC(P) -> C
SEND_MAC(N_M) -> M
```

The returned ciphertext contains the following:

```text
LE_U32(N_T) || LE_U32(N_S) || S || C || M
```

## Decryption

Decryption of a ciphertext parses $N_T$, $N_S$, $S$, $C$ and $M$, initializes the protocol, and performs the inverse of
encryption:

```text
RECV_ENC(C) -> P
RECV_MAC(M)
```

If the `RECV_MAC` call is successful, the plaintext $P$ is returned.

It should be noted that there is no standard balloon hashing algorithm, so this protocol is in the very, very tall grass
of cryptography and should never be used.


[bh]: https://eprint.iacr.org/2016/027.pdf