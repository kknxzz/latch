# Release verification inputs

These public files identify Latch's initial production signing authority. They
contain no private keys. The private authority is stored outside this checkout.

- `publisher.pub`: P-256 public key for bootstrap/checksum signatures.
- `root.json`: initial self-verified TUF root, with a two-of-three root threshold.

Publisher public-key fingerprint (SHA-256 of SubjectPublicKeyInfo DER):

```text
67d05bdf1e4745371e149dfd5aeeac5072498a1a7aaee28d7ba434de3020b3f7
```

Initial `root.json` file SHA-256:

```text
4460396e723eeb1979e9c79928f93d5a9e37d7c70307c94a6ccc90ba766fb589
```

Check the publisher fingerprint with:

```sh
openssl pkey -pubin -in release/publisher.pub -outform DER | openssl dgst -sha256
```

Authenticate the expected fingerprint through a trusted maintainer channel
before first installation. A key fetched only from an unfamiliar download mirror
does not establish that mirror's authority. See [release verification](../docs/RELEASES.md)
for signature, checksum, metadata and update checks.

The QA artifacts documented in `docs/VERIFICATION.md` use a different, temporary
authority. They must not be substituted for the final production-root builds.
