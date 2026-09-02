# Contributing to Cyrene

Cyrene is ambitious infrastructure with a deliberately small public surface.
Contributions are welcome, especially ones that make the common path calmer,
clearer, or more trustworthy.

## Start here

You need the pinned Rust toolchain, a C toolchain for bundled SQLite and crypto
dependencies, Git, and a current Node.js/npm installation for Markdown checks.

```console
git clone https://github.com/fembytecodes/cyrene.git
cd cyrene
cargo test --workspace --all-features
```

Run the starter or notes example before changing internals:

```console
cargo run --manifest-path templates/local-app/Cargo.toml
cargo run -p cyrene-example-notes -- local notes.db
```

## Before opening a pull request

```console
./scripts/quality-gate.sh
```

Please include:

- the developer or user problem;
- the guarantee or behavior that changes;
- tests at the lowest useful state-machine layer;
- an integration test when a persistence or transport boundary changes;
- documentation for new public behavior and honest limitations.

Do not weaken durability, signature, authorization, schema, or hostile-input
bounds to make a test or benchmark pass.

## Design changes

Consequential changes need a short architecture decision record in
`docs/decisions/`. Copy the structure of a nearby ADR and explain the problem,
constraints, decision, alternatives, consequences, and what evidence would
change the choice.

New abstraction layers should be pulled by a real application experience. A
future possibility is not enough reason to stabilize a public trait.

## Code style

- Use Rust 2024 and the workspace lints.
- Keep the ordinary API small; put sharp protocol details in focused crates.
- Prefer explicit bounds and structured errors at trust boundaries.
- Preserve user changes in a dirty worktree.
- Keep logs free of content, keys, invitations, capabilities, and stable routing
  identifiers unless a documented diagnostic explicitly requires them.
- Add prose only when it helps a reader act or understand a guarantee.

## Tests and fuzzing

State-machine correctness comes before socket integration. Use property tests
for algebraic behavior, deterministic simulation for partitions/reordering,
crash tests for persistence boundaries, compatibility fixtures for stable
formats, and fuzz targets for hostile bytes.

Fuzzing needs nightly Rust and `cargo-fuzz`; see [fuzz/README.md](fuzz/README.md).

## Security reports

Do not open a public issue for a suspected vulnerability.

## License

Unless stated otherwise, contributions are accepted under the repository's
dual MIT or Apache-2.0 license.
