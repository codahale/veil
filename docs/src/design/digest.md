# Message Digests

Veil can create message digests given a set of metadata and a message.

Given a set of metadata strings $V_0..V_n$ and a message in 16-byte blocks $M_0..M_n$, a duplex is
initialized with a constant key and used to absorb the metadata and message blocks. Finally, a
64-byte digest $D$ is squeezed:

$$
\Cyclist{\literal{veil.digest}} \\
\Absorb{V_0} \\
\Absorb{V_1} \\
\dots \\
\Absorb{V_n} \\
\AbsorbMore{M_0}{16} \\
\AbsorbMore{M_1}{16} \\
\dots \\
\AbsorbMore{M_n}{16} \\
D \gets \Squeeze{64}
$$

## Message Authentication Codes

To create a MAC, pass a symmetric key as a piece of metadata.
