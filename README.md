# Latch

Latch is an independently self-hosted, terminal-based encrypted communications
system. The client and server are separate Go applications. Group encryption uses
an embedded OpenMLS library; the gateway relays opaque ciphertext.

**Release preparation in progress. No supported production release is published yet.** See
[the implementation checklist](docs/IMPLEMENTATION.md) for verified capabilities
and outstanding release gates. No private signing keys or production credentials
are included in this repository.

Public verification inputs are in [`release/`](release/README.md).

## Build boundaries

- `client/`: independent Go module, native terminal client, Rust crypto bridge.
- `server/`: independent Go module, gateway and private administration.
- `protocol/`: implementation-independent specification and conformance fixtures.
- `scripts/`: local verification and build tooling.
- `tools/release/`: independent build-only signing and native receipt utility.

Applications do not import each other's source code. No particular hosting
provider, production DNS name, reverse proxy, or remote service is required.

## Security

Read [the threat model](docs/THREAT_MODEL.md) and [security policy](SECURITY.md).
Security assumes public source code. Private cryptographic keys and protected
configuration are the security boundary, not implementation secrecy.

Signed installation, publisher setup and terminal update instructions are in
[release verification](docs/RELEASES.md). All four platform suites pass locally;
all six QA artifacts reproduce byte-for-byte. Production signing and release
distribution remain outstanding. Private vulnerability reports go to the
maintainer address in [the security policy](SECURITY.md).

Licensed under the [MIT License](LICENSE).
