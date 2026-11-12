# Threat model

## Trust boundaries

All source and wire specifications are public. Device private keys, administrative
credentials, and release-signing private keys are secret. Enrollment codes and
room PINs are short-lived access credentials, never conversation keys.

Clients encrypt application messages using MLS (RFC 9420). The gateway has no
conversation decryption keys. It necessarily learns IP addresses, device keys,
room membership, packet sizes, and timing. A configured reverse proxy sees
connection metadata too. TLS protects each network transport; MLS protects
application content between room members.

The enrollment and directory authority is trusted to bind device keys correctly.
There is no independent identity verification in v1. A malicious authority can
introduce attacker-controlled identities. Nicknames are unverified display labels.
Server-side membership policy must not be confused with cryptographic proof of a
human identity.

## Threats addressed

- Unauthorized enrollment and repeated guessing, within explicit rate limits.
- Replay of device authentication and encrypted messages.
- Ciphertext alteration and sender spoofing.
- Continued room access by a removed registered key.
- Old room credentials after room destruction or server restart.
- Unbounded protocol input, relay queues, and terminal control injection.
- Unsigned or rolled-back software updates.

## Limitations

An authorized member can copy received content. Compromised clients, terminals,
operating systems, privileged malware, swap, and memory dumps can reveal content.
No guaranteed secure memory erasure is claimed. Removing key references and
clearing application buffers does not establish physical erasure.

A public-key ban identifies a key, not a person. A new key with a newly issued
enrollment code is a new identity. No IP, MAC, or hardware fingerprint is used as
an identity key. Availability against distributed denial of service is bounded
by host and network resources, not guaranteed.

Forward secrecy and post-compromise recovery are limited by MLS operation,
correct state disposal, client compromise, and successful subsequent updates.
No retained conversation history or offline delivery is implemented. Crash
diagnostics and operational logs must exclude message bodies and credentials.

## Room lifetime

The host's connection owns the room. Explicit disconnection, transport failure,
revocation, or heartbeat expiry destroys it. There is no grace period, migration,
or restoration. During every membership change, application forwarding stops
until the new epoch has been validated by every remaining member. A failed
transition destroys the room.
