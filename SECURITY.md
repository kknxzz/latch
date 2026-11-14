# Security policy

The supported release is v0.1.0. Verify release signatures before installation.
Development builds are not supported production releases.

## Private reports

Email **levin@ferriteworks.com** to report a vulnerability privately. Do not put
exploit details, credentials, private keys, or message contents in an issue.
The initial repository is private; GitHub's public-repository vulnerability
reporting feature is not required to contact the maintainer.

For sensitive material, first send a brief description and request an encrypted
exchange. Ordinary email does not provide end-to-end confidentiality. Never
send real conversation contents or production private keys.

Include the affected version or commit, platform, reproduction steps, expected
and actual behavior, and the security impact. Use synthetic test data. Maintainers
should acknowledge reports within seven days and coordinate disclosure and
release timing with the researcher. These are handling targets, not a guarantee
of a fix by a particular date.

Reports concerning authentication, enrollment, terminal injection, updater
verification, membership enforcement, encryption, metadata leakage, and denial
of service are in scope. Avoid disrupting other people's deployments or accessing
their data. Recognition is opt-in.

The threat model and limitations are in `docs/THREAT_MODEL.md`. An upstream
cryptographic audit does not constitute an audit of Latch.
