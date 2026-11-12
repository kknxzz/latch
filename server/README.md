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

Production configuration currently supports explicit certificate files or a
private backend behind an explicitly trusted reverse proxy. The private dashboard
and automatic TLS wizard are not implemented yet.

The final installer must provide guided setup, systemd installation, private
dashboard authentication, TLS, idempotent upgrades, and `latch-server doctor`.
See `../docs/IMPLEMENTATION.md` for the full acceptance criteria.
