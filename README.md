# veil

_Stupid crypto tricks._

WARNING: You should, under no circumstances, use this.

Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
authentic multi-receiver messages which are indistinguishable from random noise by an attacker.

Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
encrypted. As a result, a global passive adversary would be unable to gain any information from a
Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
true length, and fake receivers can be added to disguise their true number from other receivers.

See the `docs` directory for more.

## License

Copyright © 2021-2022 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
