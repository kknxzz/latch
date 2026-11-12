# Security policy

Latch is under active development and has no supported production release yet.
Do not deploy development builds for sensitive conversations.

## Private reports

Use the repository's **Security → Report a vulnerability** feature to send a
private GitHub vulnerability report. Do not put exploit details, credentials,
private keys, or message contents in a public issue.

If this option is unavailable, the repository is not ready for public release:
maintainers must enable private vulnerability reporting before publishing a
supported release. There is no invented reporting address in this policy.

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
