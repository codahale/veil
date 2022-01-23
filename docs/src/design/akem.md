# Key Encapsulation

`veil.akem` combines static Diffie-Hellman key agreement, designated-verifier Schnorr signatures, ephemeral
Diffie-Hellman key agreement, and authenticated encryption to provide key encapsulation with confidentiality,
authenticity, and deniability.

## Encapsulation

Encapsulation is as follows, given the sender's key pair, $d_S$ and $Q_S$, an ephemeral key pair, $d_E$ and $Q_E$, the
receiver's public key, $Q_R$, a plaintext message $P$, message size $N_P$, MAC size $N_M$, compressed point size $N_Q$,
and scalar size $N_d$:

```text
INIT('veil.akem', level=128)
```

First, the sender's public key is sent via cleartext:

```text
AD('sender-public-key', meta=true)
AD(LE_U64(N_Q),         meta=true, more=true)
SEND_CLR(Q_S)
```

Second, the receiver's public key is received via cleartext:

```text
AD('receiver-public-key', meta=true)
AD(LE_U64(N_Q),           meta=true, more=true)
RECV_CLR(Q_R)
```

The static shared secret point is calculated ${ZZ_S}=[{d_S}]{Q_R}=[{d_R}{d_S}]G$ and used to key the protocol:

```text
AD('static-shared-secret', meta=true)
AD(LE_U64(N_Q),            meta=true, more=true)
KEY(ZZ_S)
```

The ephemeral public key $Q_E$ is encrypted and sent:

```text
AD('ephemeral-public-key', meta=true)
AD(LE_U64(N_Q),            meta=true, more=true)
SEND_ENC(Q_E) -> E_1
```

The protocol's state is then cloned, the clone is keyed with both 64 bytes of random data and the sender's private key,
a commitment scalar $k$ is derived from PRF output:

```text
AD('secret-value', meta=true)
AD(LE_U64(N_d),     meta=true, more=true)
KEY(d_S)

AD('hedged-value', meta=true)
AD(LE_U64(64),     meta=true, more=true)
KEY(rand(64))

AD('commitment-scalar', meta=true)
AD(LE_U64(64),          meta=true, more=true)
PRF(64) -> k
```

The commitment point $U = [k]G$ is calculated and encrypted:

```text
AD('commitment-point', meta=true)
AD(LE_U64(N_Q),        meta=true, more=true)
SEND_ENC(U) -> E_2
```

A challenge scalar $r$ is extracted:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r
```

The signature scalar $s = k+{d_S}r$ is calculated and bound to the recipient as the signature point $K = [s]Q_V$, which
is then encrypted:

```text
AD('signature-point', meta=true)
AD(LE_U64(N_Q),       meta=true, more=true)
SEND_ENC(K) -> E_3
```

The ephemeral shared secret point is calculated ${ZZ_E}=[{d_E}]{Q_R}=[{d_R}{d_E}]G$ and used as a key:

```text
AD('ephemeral-shared-secret', meta=true)
AD(LE_U64(N_Q),               meta=true, more=true)
KEY(ZZ_E)
```

Finally, the plaintext is encrypted and a MAC created:

```text
AD('ciphertext', meta=true)
AD(LE_U64(N_P),  meta=true, more=true)
SEND_ENC(P)     -> C

AD('mac',       meta=true)
AD(LE_U64(N_M), meta=true, more=true)
SEND_MAC(N_M)   -> M
```

The resulting ciphertext is $E_1 || E_2 || E_3 || C || M$.

## Decapsulation

Decapsulation is then the inverse of encryption, given the recipient's key pair, $d_R$ and $Q_R$, and the sender's
public key $Q_S$:

```text
INIT('veil.akem', level=128)
```

First, the sender's public key is received via cleartext:

```text
AD('sender-public-key', meta=true)
AD(LE_U64(N_Q),         meta=true, more=true)
RECV_CLR(Q_S)
```

Second, the receiver's public key is sent via cleartext:

```text
AD('receiver-public-key', meta=true)
AD(LE_U64(N_Q),           meta=true, more=true)
SEND_CLR(Q_R)
```

The static shared secret point is calculated ${ZZ_S}=[{d_R}]{Q_S}=[{d_R}{d_S}]G$ and used as a key:

```text
AD('static-shared-secret', meta=true)
AD(LE_U64(N_Q),            meta=true, more=true)
KEY(ZZ_S)
```

The ephemeral public key $Q_E$ is decrypted:

```text
AD('ephemeral-public-key', meta=true)
AD(LE_U64(N_Q),            meta=true, more=true)
RECV_ENC(E_1) -> Q_E
```

The commitment point $U$ is decrypted:

```text
AD('commitment-point', meta=true)
AD(LE_U64(N_Q),        meta=true, more=true)
RECV_ENC(E_2) -> U 
```

The challenge scalar $r$ is extracted from PRF output:

```text
AD('challenge-scalar', meta=true)
AD(LE_U64(64),         meta=true, more=true)
PRF(64) -> r
```

The signature point $K$ is decrypted:

```text
AD('signature-point', meta=true)
AD(LE_U64(N_Q),       meta=true, more=true)
RECV_ENC(E_3) -> K
```

The counterfactual signature point $K' = [{d_R}](U + [r]{Q_S})$ is calculated, and if $K' \equiv K$, the decryption
continues. At this point, the receiver knows that $Q_E$ is authentic.

The ephemeral shared secret point is calculated ${ZZ_E}=[{d_R}]{Q_E}=[{d_R}{d_E}]G$ and used as a key:

```text
AD('ephemeral-shared-secret', meta=true)
AD(LE_U64(N_Q),               meta=true, more=true)
KEY(ZZ_E)
```

Finally, the ciphertext is decrypted and the MAC is verified:

```text
AD('ciphertext', meta=true)
AD(LE_U64(N_P),  meta=true, more=true)
RECV_ENC(C)     -> P

AD('mac',       meta=true)
AD(LE_U64(N_M), meta=true, more=true)
RECV_MAC(M)
```

If the `RECV_MAC` call is successful, the ephemeral public key $Q_E$ and the plaintext message $P$ are returned.

## IND-CCA2 Security

This construction combines two overlapping KEM/DEM constructions: an "El Gamal-like" KEM combined with a STROBE-based
AEAD, and an ephemeral ECIES-style KEM combined with a STROBE-based AEAD.

The STROBE-based AEAD is equivalent to Construction 5.6 of Modern Cryptography 3e and is CCA-secure per Theorem 5.7,
provided STROBE's encryption is CPA-secure. STROBE's `SEND_ENC` is equivalent to Construction 3.31 and is CPA-secure per
Theorem 3.29, provided STROBE is a sufficiently strong pseudorandom function.

The first KEM/DEM construction is equivalent to Construction 12.19 of Modern Cryptography 3e, and is CCA-secure per
Theorem 12.22, provided the gap-CDH problem is hard relative to ristretto255 and STROBE is modeled as a random oracle.

The second KEM/DEM construction is equivalent to Construction 12.23 of Modern Cryptography 3e, and is CCA-secure per
Corollary 12.24, again provided that the gap-CDH problem is hard relative to ristretto255 and STROBE is modeled as a
random oracle.

## IK-CCA Security

`veil.akem` is IK-CCA (per [Bellare][ik-cca]), in that it is impossible for an attacker in possession of two public keys
to determine which of the two keys a given ciphertext was encrypted with in either chosen-plaintext or chosen-ciphertext
attacks. Informally, `veil.akem` ciphertexts consist exclusively of STROBE ciphertext and PRF output; an attacker being
able to distinguish between ciphertexts based on keying material would imply STROBE's AEAD construction is not IND-CCA2.

Consequently, a passive adversary scanning for encoded points would first need the parties' static Diffie-Hellman secret
in order to distinguish messages from random noise.

## Forward Sender Security

Because the ephemeral private key is discarded after encryption, a compromise of the sender's private key will not
compromise previously-created ciphertexts. If the sender's private key is compromised, the most an attacker can discover
about previously sent messages is the ephemeral public key, not the message itself.

## Insider Authenticity

This construction is secure against insider attacks on authenticity. A recipient attempting to forge a ciphertext which
appears to be from a sender by re-using the ephemeral public key and encrypting an alternate plaintext will be unable to
construct the signature point $K$.

## Randomness Re-Use

The ephemeral key pair, $d_E$ and $Q_E$, are generated outside this construction and can be used multiple times for
multiple recipients. This improves the efficiency of the scheme without reducing its security, per Bellare et al.'s
treatment of [Randomness Reusing Multi-Recipient Encryption Schemes][rr-mres].

## Signature Security, Forgeability, and Malleability

The designated-verifier signature construction is [Steinfeld et al.'s] modification of 
[Schnorr's signature scheme][schnorr]. Schnorr's scheme is equivalent to Construction 13.12 of Modern Cryptography 3e, 
and is the combination of the Fiat-Shamir transform applied to the Schnorr identification scheme, and per Theorem 13.11,
secure if the discrete-logarithm problem is hard relative to ristretto255.

## Designated Verification

Steinfeld et al.'s modification binds verification of the signature to the holder of a private scalar. This allows the
signer to prove the authenticity of a message to a verifier without providing the verifier a way to re-prove that to a
third party. Consequently, `veil.akem` ciphertexts are repudiable provided the recipient does not disclose their own
private key.

## Key Compromise Impersonation

Per [Strangio][kci]:

> \[S\]uppose an adversary (say Eve) has learned the private key of Alice either by compromising the machine running an
> instance of the protocol (e.g. with the private key stored in conventional memory as part of the current state) or
> perhaps by cloning Alice’s smart card while she inadvertently left it unattended. Eve may now be able to mount the
> following attacks against the protocol:
> 
> 1. impersonate Alice in a protocol run;
> 2. impersonate a different party (e.g. Bob) in a protocol run with Alice;
> 3. obtain previously generated session keys established in honest-party runs of the protocol.
> 
> In case 1. Eve can send messages on behalf of Alice and these will be accepted as authentic, in case 2. Eve could 
> establish a session with Alice while masquerading as another party; this is known as Key Compromise Impersonation
> (KCI)...

A static Diffie-Hellman exchange is vulnerable to KCI attacks, in that the shared secret point ${ZZ_S}$ can be 
calculated as $[{d_S}]{Q_R}$ by an authentic sender or as $[{d_R}]{Q_S}$ by an attacker in possession of the recipient's
private key $d_S$ and the sender's public key $Q_S$.

`veil.akem` prevents KCI attacks by including a designated-verifier signature of the ephemeral public key. The signature
can be verified by but not constructed by the recipient; as such, a verified signature proves the ephemeral public key
is authentic. Because the signature cannot be verified without the recipient's private key, a dishonest recipient cannot
prove to a third party that the ephemeral public key was provided by the sender without revealing their own private key.

## Delegatability

[Steinfeld et al.'s][steinfeld] construction is delegatable, which means the delegated form of the signature can be
created by someone other than the signer. If the signer provides a third party with $s$ and $r$, anyone in possession of
the signer and verifier's public keys can calculate $U$ and $K$.

Non-delegatability is critical when designing protocols to constrain potentially dishonest signers, but in this context
the signature is used exclusively to provide deniable authentication of ephemeral public keys. The signatures are
encrypted using the static Diffie-Hellman shared secret point $ZZ_S$, so a sender attempting to delegate verifier
designation would either have to reveal their private key to the delegate or encrypt the designated signature
themselves.

## Ephemeral Scalar Hedging

In deriving the ephemeral scalar from a cloned context, `veil.akem` uses [Aranha et al.'s
"hedged signature" technique][hedge] to mitigate against both catastrophic randomness failures and differential fault
attacks against purely deterministic signature schemes.

[delegatability]: https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.66.1075&rep=rep1&type=pdf

[ik-cca]: https://iacr.org/archive/asiacrypt2001/22480568.pdf

[kci]: https://eprint.iacr.org/2006/252.pdf

[rr-mres]: http://cseweb.ucsd.edu/~Mihir/papers/bbs.pdf

[delegatability]: https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.66.1075&rep=rep1&type=pdf

[hedge]: https://eprint.iacr.org/2019/956.pdf

[schnorr]: https://d-nb.info/1156214580/34

[steinfeld]: https://www.iacr.org/archive/pkc2004/29470087/29470087.pdf
