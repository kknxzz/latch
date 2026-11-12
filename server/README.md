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

The final installer must provide guided setup, systemd installation, private
dashboard authentication, TLS, idempotent upgrades, and `latch-server doctor`.
See `../docs/IMPLEMENTATION.md` for the full acceptance criteria.
