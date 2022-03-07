# What is Veil?

Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
authentic multi-recipient messages which are indistinguishable from random noise by an attacker.

Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
encrypted. As a result, a global passive adversary would be unable to gain any information from a
Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
true length, and fake recipients can be added to disguise their true number from other recipients.

Further, Veil supports hierarchical key derivation (allowing for domain-separated and disposable
keys), message digests, and message authentication codes.
