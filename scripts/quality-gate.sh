#!/usr/bin/env bash
set -euo pipefail

cyrene_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$cyrene_root"

"$cyrene_root/scripts/docs-check.sh"

printf '%s\n' '→ formatting'
cargo fmt --all -- --check

printf '%s\n' '→ clippy (every workspace target and feature)'
cargo clippy --workspace --all-targets --all-features -- -D warnings

printf '%s\n' '→ workspace tests'
cargo test --workspace --all-features

printf '%s\n' '→ hostile-input target builds'
cargo check --manifest-path fuzz/Cargo.toml --bins

printf '%s\n' '→ standalone starter build'
cargo check --manifest-path templates/local-app/Cargo.toml

printf '%s\n' '✓ Cyrene quality gate passed'
