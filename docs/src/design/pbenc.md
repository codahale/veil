# Passphrase-based Encryption

`veil.pbenc` implements memory-hard password-based encryption via STROBE using [balloon hashing][bh].

## Initialization

The protocol is initialized as follows, given a passphrase $P$, a 128-bit salt $S$, delta constant $D$, space parameter
$N_S$, time parameter $N_T$, block size $N_B$, and MAC size $N_M$:

```text
INIT('veil.pbenc', level=128)

AD('passphrase',   meta=true)
AD(LE_U64(LEN(P)), meta=true, more=true)
KEY(P)

AD('salt',         meta=true)
AD(LE_U64(LEN(S)), meta=true, more=true)
AD(S)

AD('time',    meta=true)
AD(LE_U64(8), meta=true, more=true)
AD(LE_U64(N_T))

AD('space',   meta=true)
AD(LE_U64(8), meta=true, more=true)
AD(LE_U64(N_S))

AD('blocksize', meta=true)
AD(LE_U64(8),   meta=true, more=true)
AD(LE_U64(N_B))

AD('delta',   meta=true)
AD(LE_U64(8), meta=true, more=true)
AD(LE_U64(D))
```

For each iteration of the balloon hashing algorithm, given a counter $C$, a left block $L$, and a right block $R$:

```text
hash_counter(L, R):
  AD('counter', meta=true)
  AD(LE_U64(8), meta=true, more=true)
  AD(LE_U64(C))
  
  AD('left',      meta=true)
  AD(LE_U64(N_L), meta=true, more=true)
  AD(L)
  
  AD('right',      meta=true)
  AD(LE_U64(N_R),  meta=true, more=true)
  AD(R)
  
  AD('out',        meta=true)
  AD(LE_U64(N_B),  meta=true, more=true)
  PRF(N)
```


For the expanding phase of the algorithm, the step name and loop variables are included as metadata:

```text
hash_counter(passphrase, salt, buf[0])
for m in 1..N_S: 
  hash_counter(buf[m - 1], nil, buf[m])

```

For the mixing phase of the algorithm, the step name and loop variables are included as metadata:

```text
for t in 0..N_T:
  for m in 0..N_S: 
    hash_counter(buf[prev], buf[m], buf[m])
    
    for i in 0..D:
      idx = LE_U64(t) + LE_U64(m) + LE_U64(i) 
      hash_counter(salt, idx) // output step is skipped
      
      AD('idx',      meta=true)
      AD(LE_U64(16), meta=true, more=true)
      PRF(8) AS U64 -> v
      hash_counter(buf[v % space], nil, buf[m])
```

The final block $B_N$ of the balloon hashing algorithm is then used to key the protocol:

```text
AD('extract', meta=true)
AD(LE_U64(N), meta=true, more=true)
KEY(B_N)
```

## Encryption

Encryption of a message $P$ is as follows:

```text
AD('ciphertext', meta=true)
AD(LE_U64(N_P),  meta=true, more=true)
SEND_ENC(P) -> C

AD('mac',       meta=true)
AD(LE_U64(N_M), meta=true, more=true)
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
AD('ciphertext', meta=true)
AD(LE_U64(N_C),  meta=true, more=true)
RECV_ENC(C) -> P

AD('mac',       meta=true)
AD(LE_U64(N_M), meta=true, more=true)
RECV_MAC(M)
```

If the `RECV_MAC` call is successful, the plaintext $P$ is returned.

It should be noted that there is no standard balloon hashing algorithm, so this protocol is in the very, very tall grass
of cryptography and should never be used.


[bh]: https://eprint.iacr.org/2016/027.pdf