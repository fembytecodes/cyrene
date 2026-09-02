# Cyrene local application starter

This is the smallest useful Cyrene application: one typed collection, one
durable write, and no networking ceremony.

Copy this directory, choose a package name, and run `cargo run`. The first run
creates `tasks.db`, no account, daemon, server, relay, or configuration is
needed.

While developing inside the Cyrene repository, the manifest uses a relative
path dependency. After the first published release, replace it with the desired
version from the compatibility policy. Give document names and field IDs
intentional durable identities before shipping.

Next steps: add a loss-detecting subscription for your UI, run
`cyrene database backup tasks.db tasks-backup.db`, then follow the repository's
sharing recipe only if the product actually needs multiple people or devices.

```console
cargo run --manifest-path templates/local-app/Cargo.toml
```

The generated `tasks.db` is ignored by Git. Delete it only when you intentionally
want a fresh local identity and data set.
