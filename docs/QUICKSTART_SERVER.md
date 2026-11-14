# Install a Latch server

Signed v0.1.0 assets are available in the
[private release repository](https://github.com/kknxzz/latch/releases/tag/v0.1.0).
You need repository access to
download them; an installed Latch network does not contact GitHub.

Use a dedicated Ubuntu 24.04 VM with systemd, on AMD64 or ARM64. You need
OpenSSL and `tar`. No Go, Rust, Docker or external runtime is needed.

## Download

On a computer authenticated to GitHub CLI (`gh auth login`), download the server
bundle for your VM's architecture:

```sh
gh release download v0.1.0 --repo kknxzz/latch \
  --pattern 'latch-server-linux-amd64.tar.gz*' --pattern publisher.pub
```

For ARM64, use the pattern `latch-server-linux-arm64.tar.gz*`. Download both the
archive and its `.sig` file. You can download through the
[release page](https://github.com/kknxzz/latch/releases) instead and transfer the
archive, signature and publisher key to the VM with `scp`; GitHub CLI is not
required on the server.

Check the separately downloaded publisher key before extracting anything:

```sh
openssl pkey -pubin -in publisher.pub -outform DER | openssl dgst -sha256
```

Compare the printed publisher fingerprint with the value independently
authenticated through the maintainer or a trusted checkout:

```text
67d05bdf1e4745371e149dfd5aeeac5072498a1a7aaee28d7ba434de3020b3f7
```

A key and fingerprint supplied only by the same unfamiliar download are not
independent verification.

## Verify and install

Authenticate the archive before extraction, then extract as your ordinary user:

```sh
openssl dgst -sha256 -verify publisher.pub \
  -signature latch-server-linux-amd64.tar.gz.sig latch-server-linux-amd64.tar.gz && \
mkdir -m 700 latch-release && \
tar -xzf latch-server-linux-amd64.tar.gz -C latch-release && \
cd latch-release
```

Use the ARM64 filenames on ARM64. Continue only if verification and extraction
succeed. Verify the bootstrap and run guided setup:

```sh
openssl dgst -sha256 -verify publisher.pub -signature start.sh.sig start.sh && \
sudo sh ./start.sh --component server --offline-directory "$PWD" \
  --publisher-key "$PWD/publisher.pub"
```

The verified bootstrap checks the signed manifest, expiration and checksums of
the server, installer and service unit before executing them. An expired bundle
needs refreshed signed metadata. It does not need a release mirror or enrollment
code to set up a server.

The wizard asks for the public URL, a separate private dashboard hostname,
certificate setup, administrator password and authenticator confirmation. Have
DNS and your chosen TLS arrangement ready. The default certificate mode needs
public HTTP port 80 for certificate validation. Existing certificates and a
local reverse proxy are supported; see [deployment](DEPLOYMENT.md).

The installer creates the unprivileged service account, protected configuration
and state, then starts the systemd service. It leaves your firewall and existing
proxy configuration for you to configure.

```sh
sudo systemctl status latch-server
sudo /usr/local/bin/latch-server doctor --config /etc/latch/server.json
```

Access the private dashboard through WireGuard or the SSH forwarding procedure
in [deployment](DEPLOYMENT.md#private-dashboard-access), then generate a
single-use device enrollment code. Users enter your server URL and that code in
their verified client.

## Upgrade or uninstall

Download and verify the new bundle, then use the same bootstrap command with
`--upgrade`. Upgrading restarts the gateway and destroys active rooms.

To uninstall, use the verified bundle's installer:

```sh
sudo sh ./server-install.sh uninstall
```

Uninstall preserves configuration, enrollment state and permanent bans. See
[deployment](DEPLOYMENT.md) for backup, rollback and TLS details.
