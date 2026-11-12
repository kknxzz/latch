# Initial release bootstrap

Initial software trust is distinct from device enrollment. The six-digit code
authorizes registration with a particular network; it does not authenticate a
software publisher. Obtain the publisher public key through an independently
authenticated channel before running any installer.

The operator chooses the HTTPS distribution base. No hostname is built in.

## Public files

```text
BASE/start.sh
BASE/start.sh.sig
BASE/server-install.sh
BASE/server-install.sh.sig
BASE/latch-server.service
BASE/manifest.txt
BASE/manifest.sig
BASE/publisher.pub
BASE/root.json
BASE/LICENSE
BASE/latch-{darwin,linux}-{arm64,amd64}
BASE/latch-server-linux-{arm64,amd64}
BASE/ARTIFACT.build.json
BASE/updates/metadata/...
BASE/updates/targets/...
```

The detached signatures are ECDSA P-256 ASN.1 DER signatures over the SHA-256
digest of the corresponding exact file bytes. They can be verified by OpenSSL.
The public key uses SubjectPublicKeyInfo PEM. Its fingerprint is SHA-256 of its
DER encoding. The targets role in the separately threshold-signed TUF root uses
the same public key. The manifest covers all six binaries, installer scripts,
service unit, public keys, license and native build receipts.

The UTF-8 manifest uses LF line endings, this exact header and field layout:

```text
Latch-Release 1
Version 0.1.0
Expires UNIX_SECONDS
Source LOWERCASE_40_HEX_COMMIT
SHA256 LOWERCASE_64_HEX_DIGEST FILENAME
```

There is exactly one version, expiry and source line. Checksum lines are sorted
by filename. Names are fixed by the release tooling, without paths. Version
components are unsigned 32-bit integers without leading zeroes. The manifest
must expire in the next eight days. The bootstrap verifies its detached signature
before interpreting its fields or downloading an executable. It selects the
exact platform name, checks its SHA-256 digest, and only then runs `version`.
The running script must also match the manifest's `start.sh` checksum.

An initial installation has no previous trusted metadata high-water mark. A
mirror can replay an authentic manifest until its expiration. Independent trust
in the publisher key and a correct system clock are required. Subsequent client
upgrades use the TUF profile in [UPDATES.md](UPDATES.md); bootstrap refuses to
replace an existing client installation.

## Bootstrap interface

```text
sh start.sh --repository HTTPS_BASE --publisher-key TRUSTED_FILE \
  --server SERVER_HTTPS_URL [--bin-dir DIR] [--config-dir DIR] [--nick NAME]

sh start.sh --repository HTTPS_BASE --publisher-key TRUSTED_FILE \
  --server SERVER_HTTPS_URL --non-interactive --enrollment-fd 3 ...

sudo sh start.sh --repository HTTPS_BASE --publisher-key TRUSTED_FILE \
  --component server [--upgrade] [-- SERVER_SETUP_ARGUMENTS]
```

The script itself must first be verified against `start.sh.sig`. Enrollment
happens inside the authenticated client, reading `/dev/tty` invisibly or an
explicit inherited descriptor numbered at least three. No PIN is placed in an
argument or environment variable. The installed client saves `BASE/updates` as
its explicit software repository. `--no-start` installs the client without
enrollment; it grants no network access. `--dev` permits explicit loopback-only
cleartext gateway testing and does not weaken release download TLS.

Server mode authenticates the Linux binary, installation script and service unit
before invoking the installer. It requires root and running systemd; it forwards
setup flags after `--`. The server's configuration, state and enrollment flow are
independent of the publisher's signing directory.

## Dependencies and bounds

The installed applications need no Go, Rust, Node or Python runtime. The initial
shell bootstrap requires standard macOS/Linux command-line utilities, OpenSSL
with ECDSA P-256 verification, and curl with TLS 1.3 support. Some macOS system
curl builds cannot enforce TLS 1.3; use a compatible curl such as Homebrew's, or
set `LATCH_CURL_BIN` to an independently installed compatible executable. The
script refuses a download failure and never falls back to weaker TLS.

Downloads use HTTPS, require TLS 1.3, do not follow redirects, and ignore curl's
configuration file. Connection timeout is five seconds; each download is limited
to two minutes. Limits: manifest 32 KiB, signature 1 KiB, binary 64 MiB, script
64 KiB and service unit 16 KiB. Modern curl enforces transfer size limits; the
script checks file size again before processing. Installation uses a private
temporary directory and same-directory staging/rename into a directory owned by
the invoking user and not writable by others. It rejects a destination symlink
or existing client binary.
