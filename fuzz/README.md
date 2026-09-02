# Fuzzing Cyrene's hostile-input boundaries

Cyrene assumes every remote byte is untrusted. These targets feed malformed,
oversized, truncated, and surprising inputs through the same public decoders
used by applications and peers.

## Targets

- `relay_request` parses and verifies signed relay operations and bounds.
- `recovery_bundle` exercises the bounded binary recovery envelope.
- `replicated_change` decodes authenticated change payload structure.
- `share_invitation` decodes public invitation structure.

## Run a local campaign

Install nightly Rust and `cargo-fuzz` without changing the project's stable
toolchain:

```console
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

Then run from the repository root:

```console
cargo +nightly fuzz run relay_request -- -max_total_time=300
cargo +nightly fuzz run recovery_bundle -- -max_total_time=300
cargo +nightly fuzz run replicated_change -- -max_total_time=300
cargo +nightly fuzz run share_invitation -- -max_total_time=300
```

Use `FUZZ_SECONDS=300 ./scripts/fuzz-all.sh` to run the same set and record a
small evidence summary.

## When a target crashes

1. Preserve the generated artifact and exact commit/toolchain.
2. Reproduce with `cargo +nightly fuzz run TARGET ARTIFACT`.
3. Minimize it with `cargo +nightly fuzz tmin TARGET ARTIFACT`.
4. Fix the lowest responsible parser or state machine.
5. Add the minimized input as a permanent regression fixture or corpus seed.
6. Re-run every target because bounds and shared types often overlap.
