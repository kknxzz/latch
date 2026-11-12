# Server deployment

Setup and signed download tooling are implemented. Genuine release publication
and fresh Linux/systemd installation qualification are still release gates. The
local commands below require a locally built or independently verified Linux
server binary; they do not establish release authenticity themselves. For the
verified download command, see [release verification](RELEASES.md).

## A dedicated VM

Use a small dedicated Linux VM with systemd on Proxmox. No Proxmox API, Cloudflare
account or particular DNS name is required by Latch. Install the distribution's
`systemd`, `passwd`/`shadow` and `util-linux` tools if they are absent. The installer
checks its required commands and refuses to modify a conflicting service account.
Go and Rust are build tools; deployed servers need neither runtime.

From a checkout containing a matching Linux binary:

```sh
sudo sh server/scripts/install.sh install --binary ./bin/latch-server
```

The wizard asks for your public HTTPS URL, a different hostname for private
administration, agreement to the certificate authority's terms, a password, and
authenticator confirmation. It creates protected configuration/security state,
then installs and starts the unprivileged systemd service. Existing configuration
and credentials are preserved on subsequent installation. Setup does not adjust
your DNS, router, firewall, WireGuard or existing proxy.

The public and administrative hostnames must differ because browser cookies do
not have a port boundary. Device users only need the public URL and a single-use
code. No device registration uses the administrator password or authenticator.

## Automatic TLS

The default mode uses Go's [ACME certificate manager](https://pkg.go.dev/golang.org/x/crypto/acme/autocert).
Only the two configured names may obtain certificates. Their DNS must route
public HTTP port 80 to this VM's challenge listener. The public HTTPS listener
defaults to port 443; administration binds `127.0.0.1:8443`. The HTTP listener
serves ACME challenges and returns 404 for other routes.

Certificates are obtained on the first TLS connection and renewed by the library.
Both names need successful validation, including the private dashboard name.
The [HTTP-01 challenge requires public port 80](https://letsencrypt.org/docs/challenge-types/);
the dashboard application itself stays private. Certificate names are visible in
public certificate-transparency records. Use externally managed certificate
files if your private dashboard name cannot be publicly validated.

Behind a proxy, route `/.well-known/acme-challenge/` to the challenge listener
without authentication or HTTPS redirects. Blocked challenges prevent issuance
and renewal. No DNS-provider API credential is needed. ACME account keys and
certificate keys live in `/var/lib/latch/acme` with private permissions; preserve
that directory across restarts and upgrades to avoid unnecessary issuance.

## Private dashboard access

Prefer a WireGuard address for `--admin-listen`, for example `10.7.0.1:8443`, and
private DNS mapping the administrative hostname to that address for operators.
Public DNS can still route HTTP-01 validation to the VM's public address. Never
publish the administrative listener through the public proxy or router.

The default loopback binding also supports SSH:

```sh
ssh -N -L 127.0.0.1:8443:127.0.0.1:8443 operator@your-vm
```

On the operator's computer, map the configured administrative hostname to
`127.0.0.1` using local DNS or a hosts entry. Visit
`https://admin.example:8443/admin/` using your actual hostname. Its certificate
must validate normally. Do not bypass browser certificate errors.

The wizard displays an authenticator secret only on its controlling terminal.
Store your password and authenticator recovery material safely. Codes cannot be
replayed, including after a gateway restart. Use the next code after setup.

## Existing TLS or reverse proxy

Choose a mode explicitly when using the installer:

```sh
sudo sh server/scripts/install.sh install --binary ./bin/latch-server -- \
  --tls files \
  --public-url https://chat.example \
  --admin-url https://admin.example:8443 \
  --cert /etc/latch/tls/public.pem --key /etc/latch/tls/public.key \
  --admin-cert /etc/latch/tls/admin.pem --admin-key /etc/latch/tls/admin.key
```

Certificate/key files must be regular files, readable by the `latch` service
account, with keys mode `0600`. Their parent directories must permit access by
that account. Put copies in a dedicated directory owned by `latch`; do not relax
permissions on another service's private keys. Setup checks hostname, validity
dates and key pairing before publishing configuration. Files are loaded at
startup; restart Latch after an external renewal. This intentionally ends rooms.

For an existing proxy on the same VM, select `--tls proxy` with explicit
`--trusted-proxies 127.0.0.1/32` (or its exact loopback CIDR). That mode binds the
plaintext backend to loopback only. External proxies must connect to Latch with
TLS using `files` or `acme`. Forward WebSocket upgrades for `/c/`, preserve Host,
and overwrite or safely append `X-Forwarded-For`. Trust only actual proxy CIDRs.
Set an idle timeout longer than Latch's heartbeat timeout. Public endpoints are
`/v1/info`, `/v1/enroll/challenge`, `/v1/enroll` and `/c/`; no public route is
provided for administration.

Cloudflare is optional. When used, require
[Full (strict) origin TLS](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/),
enable TLS 1.3, configure trusted proxy ranges explicitly, and restrict direct
origin access using your existing network controls. Keep ACME validation reachable
or manage certificates externally. The installer does not modify firewall rules.
The proxy can observe connection metadata and terminate transport TLS; message
encryption remains client-side.

## Diagnostics and recovery

```sh
sudo -u latch /usr/local/bin/latch-server doctor --config /etc/latch/server.json
systemctl status latch-server
journalctl -u latch-server
sudo /usr/local/bin/latch-server admin reset --config /etc/latch/server.json
```

`doctor` checks local configuration, TLS material and administrator state. It does
not claim DNS, issuance, reachability or firewall verification. It works while
the service runs through the owner-only administrative socket. HTTP internals
are reduced to fixed event names in the private in-memory security ring; request
payloads, addresses and panic values are not sent to the journal.

The service reports readiness only after its listeners are bound. Restarting it
destroys all rooms and session metadata. The default caps are 100 active devices,
20 rooms and 16 members per room. TCP sockets are also bounded: public device cap
plus 32, administrative 16, and challenge 32. systemd limits the service to 4096
file descriptors, 256 tasks and 512 MiB. Raising application caps requires reviewing
these service limits using measurements.

## Upgrades and uninstall

Verify the replacement binary before invoking an upgrade:

```sh
sudo sh server/scripts/install.sh upgrade --binary /path/to/verified/latch-server
sudo sh server/scripts/install.sh uninstall
```

The installer checks the replacement against existing local configuration before
atomically installing it, retains the previous binary, and attempts rollback if
systemd rejects the upgrade. Configuration and security state are preserved.
Upgrades and rollback restart the gateway and destroy rooms. No database migration
rollback is promised; back up private state before future versions that introduce
state migrations. Protect backups like live state because they contain TOTP,
enrollment security material and device metadata.

Uninstall stops/disables the service and removes its binary/unit. It retains the
service account, configuration, keys and security database, including permanent
bans. Delete those manually only when you intend to discard the network identity.

## Automated setup

`latch-server setup --non-interactive` accepts all deployment choices through
flags. Initial administrator input comes from `--credentials-fd 3`, referencing
an already-open private regular file containing `password`, `totp_secret` and
`confirmation`. Generate unique credentials and a current authenticator code;
there is no fixed test password or enrollment bypass. Explicit
`--accept-acme-terms` is required for noninteractive ACME setup. Never include
passwords, enrollment codes or TOTP secrets in process arguments or shell history.

No genuine release trust root or signed public bootstrap is published yet.
`latch update`, signed bootstrap and publisher contract tests pass locally;
independent reproducible release builds and deployment qualification remain
unfinished. See [the evidence ledger](IMPLEMENTATION.md) before deploying.
