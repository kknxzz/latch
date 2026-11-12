# Latch server

Under implementation; production setup is not complete. Persistent security state
and protocol packages can be tested independently of the client and Rust:

```sh
go test -race ./...
go vet ./...
```

The state directory must have mode `0700` and the database mode `0600`. Existing
unsafe modes are rejected, not silently changed. No room or conversation data is
stored in the database.

For a local gateway, run from repository root:

```sh
sh scripts/dev-local.sh
```

An isolated temporary code can be requested using `--enrollment-file PATH`, where
PATH does not already exist. The code is written with mode `0600`, never printed
to operational logs. Development mode binds only loopback and is explicitly
required for cleartext transport. Credentials still expire and are single-use.

While the server runs, `latch-server enrollment-code --state-dir DIR` issues a new
code through an owner-only Unix socket in the private state directory. This
explicit administrative command displays the code to its caller; the daemon does
not log it. The socket never listens on TCP. Use a short state-directory path
(at most 89 bytes) to fit Unix socket limits on all supported platforms.

The embedded private dashboard provides code generation, device nicknames/UUIDs/
IDs, permanent public-key removal, gateway counts and bounded in-memory security
events. Removal disconnects the device and destroys any room it hosts. No message
contents or room keys are available to administration.

Initialize administration locally before production startup:

```sh
latch-server admin init --state-dir /var/lib/latch
```

Run this as the service account. Setup reads the password from the controlling
terminal with echo disabled, displays a fresh authenticator enrollment key, and
requires its current code. Use the next code to sign in. Local recovery uses
`admin reset` with the same arguments; existing sessions immediately lose access.
For automation, `--credentials-fd 3` reads a private regular file containing
`password`, `totp_secret` and `confirmation`; never put these values in arguments.

Production supports automatic ACME certificates, explicit certificate files or an explicitly trusted
loopback reverse proxy. Administration uses a separate private listener with TLS
and a hostname different from the public relay (cookies are not isolated by port).
Use WireGuard or an SSH forward to access that listener. Never proxy `/admin/`
through the public gateway. Development uses a separate loopback HTTP listener;
`--admin-listen 127.0.0.1:0` selects an unused port for local tests.

`latch-server setup` guides configuration and administrator initialization;
`latch-server doctor --config FILE` checks local settings both offline and while
the daemon runs. Setup never overwrites an existing configuration. TLS material
is checked before listeners are reported ready. Automatic TLS requires explicit
certificate-authority terms acceptance and public HTTP-01 validation for both
configured hostnames.

The optional `distribution_dir` configuration serves verified public release
files at `/start.sh` and `/client-dist/` on the public listener. It requires a
separate public directory, rejects links/private files and bounds concurrent
downloads. No additional web server is needed. See the deployment guide for
configuration and publication details; hosting does not establish publisher trust.

The Linux installer, systemd unit, upgrade and uninstall commands are described
in [the deployment guide](../docs/DEPLOYMENT.md). They are written but have not yet
been executed in a fresh Linux VM. Opt-in systemd lifecycle tests compile for
both Linux architectures; CI VM execution remains outstanding. Signed client
bootstrap passes local process integration. Platform qualification and genuine
release publication remain incomplete. See [the acceptance ledger](../docs/IMPLEMENTATION.md).
